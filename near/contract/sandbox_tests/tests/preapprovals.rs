//! Backend API -> Ed25519 proof -> real oracle WASM -> scoped router payment.
mod common;

use common::*;
use near_workspaces::types::{Gas, NearToken};
use serde_json::{json, Value};
use std::{path::Path, process::Command};

async fn approval(r: &RouterEnv, nonce: &str) -> anyhow::Result<Value> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let output = Command::new(root.join(".venv/bin/python"))
        .current_dir(&root)
        .args(["-m", "near.service.test_preapprovals"])
        .arg(
            json!({"oracle_id": r.env.oracle.id(), "consumer_id": r.router.id(),
            "agent_id": r.agent.id(), "receiver_id": r.shop.id(),
            "amount": near(1).as_yoctonear().to_string(), "nonce": nonce,
            "now_ns": now_ns(&r.env.worker).await?})
            .to_string(),
        )
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "API failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

async fn set_key(r: &RouterEnv, key: Value) -> anyhow::Result<()> {
    r.env
        .owner
        .call(r.env.oracle.id(), "set_preapproval_key")
        .args_json(json!({"public_key": key}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;
    Ok(())
}

#[tokio::test]
async fn api_signature_pays_without_verdict_and_cannot_be_replayed() -> anyhow::Result<()> {
    let r = router_env().await?;
    let starting_balance = yocto(&agent_state(&r).await?["balance"]);
    let proof = approval(&r, "0").await?;
    assert_eq!(
        view(
            &r.env.oracle,
            "verify_preapproval",
            proof["verify_args"].clone()
        )
        .await?,
        false
    );
    set_key(&r, proof["public_key"].clone()).await?;
    assert_eq!(
        view(
            &r.env.oracle,
            "verify_preapproval",
            proof["verify_args"].clone()
        )
        .await?,
        true
    );
    let before = r.shop.view_account().await?.balance;
    let result = r
        .agent
        .call(r.router.id(), "pay")
        .args_json(&proof["pay_args"])
        .gas(Gas::from_tgas(100))
        .transact()
        .await?
        .into_result()?;
    assert!(result.json::<bool>()?);
    assert_eq!(
        r.shop.view_account().await?.balance,
        before.checked_add(near(1)).unwrap()
    );
    assert_eq!(
        view(
            &r.router,
            "get_preapproval_nonce",
            json!({"agent_id": r.agent.id()})
        )
        .await?,
        "1"
    );
    let replay = r
        .agent
        .call(r.router.id(), "pay")
        .args_json(&proof["pay_args"])
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    assert_fails_with(&replay, "nonce already used");
    assert_eq!(
        yocto(&agent_state(&r).await?["balance"]),
        starting_balance - near(1).as_yoctonear()
    );
    Ok(())
}

#[tokio::test]
async fn tampering_is_refused_and_restores_funds_but_consumes_nonce() -> anyhow::Result<()> {
    let r = router_env().await?;
    let starting_balance = yocto(&agent_state(&r).await?["balance"]);
    let proof = approval(&r, "0").await?;
    set_key(&r, proof["public_key"].clone()).await?;
    for (field, value) in [
        ("consumer_id", json!(r.shop.id())),
        ("agent_id", json!(r.shop.id())),
        ("receiver_id", json!(r.agent.id())),
        ("amount", json!("2")),
    ] {
        let mut args = proof["verify_args"].clone();
        args[field] = value;
        assert_eq!(
            view(&r.env.oracle, "verify_preapproval", args).await?,
            false,
            "{field}"
        );
    }
    for (field, value) in [
        ("nonce", "1"),
        ("key_generation", "2"),
        ("issued_at_ns", "0"),
        ("expires_at_ns", "1"),
        ("signature", "AAAA"),
    ] {
        let mut args = proof["verify_args"].clone();
        args["preapproval"][field] = json!(value);
        assert_eq!(
            view(&r.env.oracle, "verify_preapproval", args).await?,
            false,
            "{field}"
        );
    }
    let mut args = proof["pay_args"].clone();
    args["amount"] = json!(near(2).as_yoctonear().to_string());
    let before = r.shop.view_account().await?.balance;
    let refused = r
        .agent
        .call(r.router.id(), "pay")
        .args_json(args)
        .gas(Gas::from_tgas(100))
        .transact()
        .await?
        .into_result()?;
    assert!(!refused.json::<bool>()?);
    assert_eq!(r.shop.view_account().await?.balance, before);
    let state = agent_state(&r).await?;
    assert_eq!(yocto(&state["balance"]), starting_balance);
    assert_eq!(yocto(&state["spent_today"]), 0);
    assert_eq!(
        view(
            &r.router,
            "get_preapproval_nonce",
            json!({"agent_id": r.agent.id()})
        )
        .await?,
        "1"
    );
    Ok(())
}

#[tokio::test]
async fn owner_rotation_expiry_and_blocks_override_signatures() -> anyhow::Result<()> {
    let r = router_env().await?;
    let proof = approval(&r, "0").await?;
    let denied = r
        .env
        .attester
        .call(r.env.oracle.id(), "set_preapproval_key")
        .args_json(json!({"public_key": proof["public_key"]}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    assert_fails_with(&denied, "only the owner");
    set_key(&r, proof["public_key"].clone()).await?;
    let mut expired = proof["verify_args"].clone();
    expired["preapproval"]["expires_at_ns"] = json!("1");
    assert_eq!(
        view(&r.env.oracle, "verify_preapproval", expired).await?,
        false
    );
    let expires = now_ns(&r.env.worker).await? + ONE_HOUR_NS;
    submit_verdict(&r.env, r.shop.id(), "block", expires)
        .await?
        .into_result()?;
    assert_eq!(
        view(
            &r.env.oracle,
            "verify_preapproval",
            proof["verify_args"].clone()
        )
        .await?,
        false
    );
    submit_verdict(&r.env, r.shop.id(), "warn", expires)
        .await?
        .into_result()?;
    assert_eq!(
        view(
            &r.env.oracle,
            "verify_preapproval",
            proof["verify_args"].clone()
        )
        .await?,
        true
    );
    let report = r.env.owner.call(r.env.oracle.id(), "report")
        .args_json(json!({"account_id": r.shop.id(), "evidence_url": "https://example.org/evidence", "evidence_sha256": EVIDENCE_SHA}))
        .deposit(near(1)).transact().await?.into_result()?.json::<String>()?;
    r.env
        .attester
        .call(r.env.oracle.id(), "confirm_report")
        .args_json(json!({"report_id": report}))
        .transact()
        .await?
        .into_result()?;
    let refused = r
        .agent
        .call(r.router.id(), "pay")
        .args_json(&proof["pay_args"])
        .gas(Gas::from_tgas(100))
        .transact()
        .await?
        .into_result()?;
    assert!(!refused.json::<bool>()?);
    r.env
        .owner
        .call(r.env.oracle.id(), "unblock")
        .args_json(json!({"account_id": r.shop.id()}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;
    set_key(&r, Value::Null).await?;
    assert_eq!(
        view(
            &r.env.oracle,
            "verify_preapproval",
            proof["verify_args"].clone()
        )
        .await?,
        false
    );
    set_key(&r, proof["public_key"].clone()).await?;
    assert_eq!(
        view(
            &r.env.oracle,
            "verify_preapproval",
            proof["verify_args"].clone()
        )
        .await?,
        false,
        "reinstalling a key must not revive its old signatures"
    );
    Ok(())
}
