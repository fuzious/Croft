//! security_oracle on a real sandbox: access control, verdicts, report → confirm/dismiss flow.
mod common;

use common::*;
use near_workspaces::types::NearToken;
use serde_json::{json, Value};

#[tokio::test]
async fn only_attesters_submit_verdicts_and_only_owner_manages_attesters() -> anyhow::Result<()> {
    let env = oracle_env().await?;
    let target = account(&env.root, "target", near(1)).await?;
    let expires = now_ns(&env.worker).await? + ONE_HOUR_NS;

    let outsider = account(&env.root, "outsider", near(5)).await?;
    let res = outsider
        .call(env.oracle.id(), "submit_verdict")
        .args_json(json!({
            "account_id": target.id(), "code_hash": "x", "verdict": "allow", "score_bps": 1,
            "reasons_hash": REASONS_HASH, "expires_at_ns": expires.to_string(),
        }))
        .transact()
        .await?;
    assert_fails_with(&res, "only an attester");
    assert_eq!(
        view(
            &env.oracle,
            "get_verdict",
            json!({ "account_id": target.id() })
        )
        .await?,
        Value::Null
    );

    submit_verdict(&env, target.id(), "Warn", expires)
        .await?
        .into_result()?;
    let v = view(
        &env.oracle,
        "get_verdict",
        json!({ "account_id": target.id() }),
    )
    .await?;
    assert_eq!(v["verdict"], "warn");
    assert_eq!(v["score_bps"], 1200);
    assert_eq!(v["attester"], env.attester.id().as_str());
    assert_eq!(v["expires_at_ns"], expires.to_string());

    let past = now_ns(&env.worker).await? - 1;
    assert_fails_with(
        &submit_verdict(&env, target.id(), "allow", past).await?,
        "must be in the future",
    );

    // add_attester: owner only, and only with one yoctoNEAR (a full-access key).
    let res = env
        .owner
        .call(env.oracle.id(), "add_attester")
        .args_json(json!({ "attester": outsider.id() }))
        .transact()
        .await?;
    assert_fails_with(&res, "Requires attached deposit of exactly 1 yoctoNEAR");
    let res = outsider
        .call(env.oracle.id(), "add_attester")
        .args_json(json!({ "attester": outsider.id() }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    assert_fails_with(&res, "only the owner");
    env.owner
        .call(env.oracle.id(), "add_attester")
        .args_json(json!({ "attester": outsider.id() }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;
    assert_eq!(
        view(
            &env.oracle,
            "is_attester",
            json!({ "account_id": outsider.id() })
        )
        .await?,
        true
    );

    env.owner
        .call(env.oracle.id(), "remove_attester")
        .args_json(json!({ "attester": env.attester.id() }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;
    assert_fails_with(
        &submit_verdict(&env, target.id(), "allow", expires).await?,
        "only an attester",
    );
    Ok(())
}

#[tokio::test]
async fn submit_verdict_validates_score_and_hash() -> anyhow::Result<()> {
    let env = oracle_env().await?;
    let expires = now_ns(&env.worker).await? + ONE_HOUR_NS;
    let base = json!({
        "account_id": env.owner.id(), "code_hash": "x", "verdict": "allow", "score_bps": 10_001,
        "reasons_hash": REASONS_HASH, "expires_at_ns": expires.to_string(),
    });
    let res = env
        .attester
        .call(env.oracle.id(), "submit_verdict")
        .args_json(&base)
        .transact()
        .await?;
    assert_fails_with(&res, "score_bps must be <= 10000");
    let mut bad_hash = base.clone();
    bad_hash["score_bps"] = json!(10);
    bad_hash["reasons_hash"] = json!("not-a-hash");
    let res = env
        .attester
        .call(env.oracle.id(), "submit_verdict")
        .args_json(&bad_hash)
        .transact()
        .await?;
    assert_fails_with(&res, "reasons_hash must be 64 hex chars");
    Ok(())
}

#[tokio::test]
async fn report_needs_storage_deposit_refunds_excess_and_confirm_blocks() -> anyhow::Result<()> {
    let env = oracle_env().await?;
    let scam = account(&env.root, "scam", near(1)).await?;
    let reporter = account(&env.root, "reporter", near(10)).await?;
    let report_args = json!({ "account_id": scam.id(), "evidence_url": "https://example.org/postmortem", "evidence_sha256": EVIDENCE_SHA });

    let res = reporter
        .call(env.oracle.id(), "report")
        .args_json(&report_args)
        .transact()
        .await?;
    assert_fails_with(&res, "for storage");

    // An attested `allow` must not survive a confirmed report.
    allow_for_an_hour(&env, scam.id()).await?;

    let before = reporter.view_account().await?.balance;
    let res = reporter
        .call(env.oracle.id(), "report")
        .args_json(&report_args)
        .deposit(near(1))
        .transact()
        .await?;
    assert!(res.is_success(), "{res:?}");
    assert_eq!(res.json::<String>()?, "0");
    let spent = before.saturating_sub(reporter.view_account().await?.balance);
    assert!(
        spent < NearToken::from_millinear(50),
        "excess deposit not refunded: spent {spent}"
    );

    let reports = view(
        &env.oracle,
        "get_reports",
        json!({ "account_id": scam.id() }),
    )
    .await?;
    assert_eq!(reports.as_array().unwrap().len(), 1);
    assert_eq!(reports[0]["status"], "pending");
    assert_eq!(reports[0]["reporter"], reporter.id().as_str());
    let kept: u128 = reports[0]["deposit"].as_str().unwrap().parse()?;
    assert!(
        kept > 0 && spent.as_yoctonear() >= kept,
        "deposit {kept} vs spent {spent}"
    );
    assert_eq!(
        view(
            &env.oracle,
            "is_blocked",
            json!({ "account_id": scam.id() })
        )
        .await?,
        false
    );

    let res = reporter
        .call(env.oracle.id(), "confirm_report")
        .args_json(json!({ "report_id": "0" }))
        .transact()
        .await?;
    assert_fails_with(&res, "only an attester");

    env.attester
        .call(env.oracle.id(), "confirm_report")
        .args_json(json!({ "report_id": "0" }))
        .transact()
        .await?
        .into_result()?;
    assert_eq!(
        view(
            &env.oracle,
            "is_blocked",
            json!({ "account_id": scam.id() })
        )
        .await?,
        true
    );
    let v = view(
        &env.oracle,
        "get_verdict",
        json!({ "account_id": scam.id() }),
    )
    .await?;
    assert_eq!(v["verdict"], "block");
    assert_eq!(v["score_bps"], 10_000);
    assert_eq!(v["reasons_hash"], EVIDENCE_SHA);
    let r = view(&env.oracle, "get_report", json!({ "report_id": "0" })).await?;
    assert_eq!(r["status"], "confirmed");
    assert_eq!(r["resolved_by"], env.attester.id().as_str());

    let res = env
        .attester
        .call(env.oracle.id(), "dismiss_report")
        .args_json(json!({ "report_id": "0" }))
        .transact()
        .await?;
    assert_fails_with(&res, "already resolved");

    // A later allow verdict still reads as block while the account is blocked.
    allow_for_an_hour(&env, scam.id()).await?;
    let v = view(
        &env.oracle,
        "get_verdict",
        json!({ "account_id": scam.id() }),
    )
    .await?;
    assert_eq!(v["verdict"], "block");

    // Only the owner (with one yoctoNEAR) lifts a block.
    let res = env
        .attester
        .call(env.oracle.id(), "unblock")
        .args_json(json!({ "account_id": scam.id() }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    assert_fails_with(&res, "only the owner");
    env.owner
        .call(env.oracle.id(), "unblock")
        .args_json(json!({ "account_id": scam.id() }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;
    assert_eq!(
        view(
            &env.oracle,
            "is_blocked",
            json!({ "account_id": scam.id() })
        )
        .await?,
        false
    );
    assert_eq!(
        view(
            &env.oracle,
            "get_verdict",
            json!({ "account_id": scam.id() })
        )
        .await?["verdict"],
        "allow"
    );
    Ok(())
}

#[tokio::test]
async fn dismissed_report_does_not_block() -> anyhow::Result<()> {
    let env = oracle_env().await?;
    let target = account(&env.root, "target", near(1)).await?;
    let reporter = account(&env.root, "reporter", near(10)).await?;
    reporter
        .call(env.oracle.id(), "report")
        .args_json(json!({ "account_id": target.id(), "evidence_url": "https://example.org/claim", "evidence_sha256": EVIDENCE_SHA }))
        .deposit(near(1))
        .transact()
        .await?
        .into_result()?;
    let res = env
        .attester
        .call(env.oracle.id(), "dismiss_report")
        .args_json(json!({ "report_id": "0" }))
        .transact()
        .await?;
    assert!(res.is_success(), "{res:?}");
    assert!(has_log(&res, &["EVENT_JSON", "report_dismissed"]));
    assert_eq!(
        view(
            &env.oracle,
            "is_blocked",
            json!({ "account_id": target.id() })
        )
        .await?,
        false
    );
    assert_eq!(
        view(
            &env.oracle,
            "get_reports",
            json!({ "account_id": target.id() })
        )
        .await?[0]["status"],
        "dismissed"
    );
    Ok(())
}

#[tokio::test]
async fn exposes_nep330_source_metadata() -> anyhow::Result<()> {
    let env = oracle_env().await?;
    let meta = view(&env.oracle, "contract_source_metadata", json!({})).await?;
    assert_eq!(meta["link"], "https://github.com/fuzious/security_oracle");
    let standards: Vec<String> = meta["standards"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["standard"].as_str().unwrap().to_string())
        .collect();
    assert!(standards.contains(&"nep330".to_string()), "{meta}");
    Ok(())
}

#[tokio::test]
async fn submit_verdict_caps_expiry_at_seven_days() -> anyhow::Result<()> {
    let env = oracle_env().await?;
    let target = account(&env.root, "target", near(1)).await?;
    let too_far = now_ns(&env.worker).await? + SEVEN_DAYS_NS + ONE_HOUR_NS;
    assert_fails_with(
        &submit_verdict(&env, target.id(), "allow", too_far).await?,
        "expiry too far",
    );
    assert_eq!(
        view(
            &env.oracle,
            "get_verdict",
            json!({ "account_id": target.id() })
        )
        .await?,
        Value::Null
    );

    let max = now_ns(&env.worker).await? + SEVEN_DAYS_NS;
    submit_verdict(&env, target.id(), "allow", max)
        .await?
        .into_result()?;
    assert_eq!(
        view(
            &env.oracle,
            "get_verdict",
            json!({ "account_id": target.id() })
        )
        .await?["expires_at_ns"],
        max.to_string()
    );
    Ok(())
}

#[tokio::test]
async fn removed_attesters_verdicts_are_ignored_but_their_confirmed_blocks_stand(
) -> anyhow::Result<()> {
    let env = oracle_env().await?;
    let target = account(&env.root, "target", near(1)).await?;
    let scam = account(&env.root, "scam", near(1)).await?;
    let reporter = account(&env.root, "reporter", near(10)).await?;
    allow_for_an_hour(&env, target.id()).await?;
    reporter
        .call(env.oracle.id(), "report")
        .args_json(json!({ "account_id": scam.id(), "evidence_url": "https://example.org/drain", "evidence_sha256": EVIDENCE_SHA }))
        .deposit(near(1))
        .transact()
        .await?
        .into_result()?;
    env.attester
        .call(env.oracle.id(), "confirm_report")
        .args_json(json!({ "report_id": "0" }))
        .transact()
        .await?
        .into_result()?;

    env.owner
        .call(env.oracle.id(), "remove_attester")
        .args_json(json!({ "attester": env.attester.id() }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;

    assert_eq!(
        view(
            &env.oracle,
            "get_verdict",
            json!({ "account_id": target.id() })
        )
        .await?,
        Value::Null,
        "a removed attester's allow must not be served"
    );
    let v = view(
        &env.oracle,
        "get_verdict",
        json!({ "account_id": scam.id() }),
    )
    .await?;
    assert_eq!(v["verdict"], "block");
    assert_eq!(v["attester"], env.attester.id().as_str());
    assert_eq!(v["reasons_hash"], EVIDENCE_SHA);

    env.owner
        .call(env.oracle.id(), "add_attester")
        .args_json(json!({ "attester": env.attester.id() }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;
    assert_eq!(
        view(
            &env.oracle,
            "get_verdict",
            json!({ "account_id": target.id() })
        )
        .await?,
        Value::Null,
        "re-adding an attester must not revive its old allow"
    );
    assert_eq!(
        view(
            &env.oracle,
            "get_verdict",
            json!({ "account_id": scam.id() })
        )
        .await?["verdict"],
        "block",
        "confirmed reports remain blocked after operator recovery"
    );
    allow_for_an_hour(&env, target.id()).await?;
    assert_eq!(
        view(
            &env.oracle,
            "get_verdict",
            json!({ "account_id": target.id() })
        )
        .await?["verdict"],
        "allow",
        "a recovered attester can publish a fresh verdict"
    );
    Ok(())
}
