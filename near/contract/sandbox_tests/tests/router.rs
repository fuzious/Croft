//! guarded_router on a real sandbox with the real oracle: the agent pays only `allow` receivers,
//! everything else is refused and rolled back, and its function-call key can do nothing else.
mod common;

use common::*;
use near_workspaces::types::{Gas, NearToken};
use serde_json::json;

#[tokio::test]
async fn allow_verdict_transfers() -> anyhow::Result<()> {
    let r = router_env().await?;
    allow_for_an_hour(&r.env, r.shop.id()).await?;
    let shop_before = r.shop.view_account().await?.balance;
    let balance_before = yocto(&agent_state(&r).await?["balance"]);

    let res = pay(&r.agent, &r.router, r.shop.id(), near(2)).await?;
    assert!(res.is_success(), "{res:?}");
    assert!(
        has_log(&res, &["EVENT_JSON", "payment_sent"]),
        "{:?}",
        res.logs()
    );
    assert!(res.json::<bool>()?);

    assert_eq!(
        r.shop.view_account().await?.balance.as_yoctonear(),
        shop_before.as_yoctonear() + near(2).as_yoctonear()
    );
    let agent = agent_state(&r).await?;
    assert_eq!(
        yocto(&agent["balance"]),
        balance_before - near(2).as_yoctonear()
    );
    assert_eq!(yocto(&agent["spent_today"]), near(2).as_yoctonear());
    Ok(())
}

async fn assert_refused(
    r: &RouterEnv,
    receiver: &near_workspaces::AccountId,
    reason: &str,
) -> anyhow::Result<()> {
    let receiver_before = r
        .env
        .worker
        .view_account(receiver)
        .await
        .map(|a| a.balance.as_yoctonear())
        .ok();
    let before = agent_state(r).await?;
    let res = pay(&r.agent, &r.router, receiver, near(1)).await?;
    assert!(
        res.is_success(),
        "a refusal is logged, not a failed tx: {res:?}"
    );
    assert!(
        has_log(&res, &["EVENT_JSON", "payment_refused", reason]),
        "want {reason}, logs {:?}",
        res.logs()
    );
    assert!(!res.json::<bool>()?);
    let after = agent_state(r).await?;
    assert_eq!(
        after["balance"], before["balance"],
        "balance not rolled back"
    );
    assert_eq!(
        after["spent_today"], before["spent_today"],
        "daily allowance not rolled back"
    );
    let receiver_after = r
        .env
        .worker
        .view_account(receiver)
        .await
        .map(|a| a.balance.as_yoctonear())
        .ok();
    assert_eq!(receiver_after, receiver_before, "receiver got paid");
    Ok(())
}

#[tokio::test]
async fn block_warn_and_missing_verdicts_are_refused_and_rolled_back() -> anyhow::Result<()> {
    let r = router_env().await?;
    let expires = now_ns(&r.env.worker).await? + ONE_HOUR_NS;

    let drainer = account(&r.env.root, "drainer", near(1)).await?;
    submit_verdict(&r.env, drainer.id(), "block", expires)
        .await?
        .into_result()?;
    assert_refused(&r, drainer.id(), "verdict_block").await?;

    let fresh = account(&r.env.root, "fresh", near(1)).await?;
    submit_verdict(&r.env, fresh.id(), "warn", expires)
        .await?
        .into_result()?;
    assert_refused(&r, fresh.id(), "verdict_warn").await?;

    let unknown = account(&r.env.root, "unknown", near(1)).await?;
    assert_refused(&r, unknown.id(), "no_verdict").await?;
    Ok(())
}

#[tokio::test]
async fn confirmed_report_blocks_despite_allow_verdict() -> anyhow::Result<()> {
    let r = router_env().await?;
    let scam = account(&r.env.root, "scam", near(1)).await?;
    allow_for_an_hour(&r.env, scam.id()).await?;
    let reporter = account(&r.env.root, "reporter", near(5)).await?;
    reporter
        .call(r.env.oracle.id(), "report")
        .args_json(json!({ "account_id": scam.id(), "evidence_url": "https://example.org/drain", "evidence_sha256": EVIDENCE_SHA }))
        .deposit(near(1))
        .transact()
        .await?
        .into_result()?;
    r.env
        .attester
        .call(r.env.oracle.id(), "confirm_report")
        .args_json(json!({ "report_id": "0" }))
        .transact()
        .await?
        .into_result()?;
    assert_refused(&r, scam.id(), "receiver_blocked").await?;
    Ok(())
}

#[tokio::test]
async fn allow_from_a_removed_attester_is_refused() -> anyhow::Result<()> {
    let r = router_env().await?;
    allow_for_an_hour(&r.env, r.shop.id()).await?;
    r.env
        .owner
        .call(r.env.oracle.id(), "remove_attester")
        .args_json(json!({ "attester": r.env.attester.id() }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;
    assert_refused(&r, r.shop.id(), "no_verdict").await?;
    r.env
        .owner
        .call(r.env.oracle.id(), "add_attester")
        .args_json(json!({ "attester": r.env.attester.id() }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;
    assert_refused(&r, r.shop.id(), "no_verdict").await?;
    allow_for_an_hour(&r.env, r.shop.id()).await?;
    assert!(pay(&r.agent, &r.router, r.shop.id(), near(1))
        .await?
        .json::<bool>()?);
    Ok(())
}

#[tokio::test]
async fn expired_verdict_is_refused() -> anyhow::Result<()> {
    let r = router_env().await?;
    let expires = now_ns(&r.env.worker).await? + 5_000_000_000;
    submit_verdict(&r.env, r.shop.id(), "allow", expires)
        .await?
        .into_result()?;
    while now_ns(&r.env.worker).await? <= expires {
        r.env.worker.fast_forward(20).await?;
    }
    assert_refused(&r, r.shop.id(), "verdict_expired").await?;
    Ok(())
}

#[tokio::test]
async fn transfer_to_missing_account_is_rolled_back() -> anyhow::Result<()> {
    let r = router_env().await?;
    let ghost: near_workspaces::AccountId = format!("ghost.{}", r.env.root.id()).parse()?;
    allow_for_an_hour(&r.env, &ghost).await?;
    let before = agent_state(&r).await?;
    let res = pay(&r.agent, &r.router, &ghost, near(1)).await?;
    assert!(
        has_log(&res, &["EVENT_JSON", "payment_failed"]),
        "{:?}",
        res.logs()
    );
    let after = agent_state(&r).await?;
    assert_eq!(after["balance"], before["balance"]);
    assert_eq!(after["spent_today"], before["spent_today"]);
    Ok(())
}

#[tokio::test]
async fn daily_limit_is_enforced_and_only_owner_changes_it() -> anyhow::Result<()> {
    let r = router_env().await?;
    allow_for_an_hour(&r.env, r.shop.id()).await?;
    assert!(pay(&r.agent, &r.router, r.shop.id(), near(3))
        .await?
        .is_success());
    assert_fails_with(
        &pay(&r.agent, &r.router, r.shop.id(), near(3)).await?,
        "daily limit exceeded",
    );
    assert!(pay(&r.agent, &r.router, r.shop.id(), near(2))
        .await?
        .is_success());
    assert_eq!(
        yocto(&agent_state(&r).await?["spent_today"]),
        near(DAILY_LIMIT_NEAR).as_yoctonear()
    );

    let raise =
        json!({ "agent_id": r.agent.id(), "daily_limit": near(8).as_yoctonear().to_string() });
    let res = r
        .human
        .call(r.router.id(), "set_limit")
        .args_json(&raise)
        .transact()
        .await?;
    assert_fails_with(&res, "Requires attached deposit of exactly 1 yoctoNEAR");
    let res = r
        .env
        .owner
        .call(r.router.id(), "set_limit")
        .args_json(&raise)
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    assert_fails_with(&res, "only the agent's owner");
    r.human
        .call(r.router.id(), "set_limit")
        .args_json(&raise)
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;
    assert!(pay(&r.agent, &r.router, r.shop.id(), near(3))
        .await?
        .is_success());
    assert_fails_with(
        &pay(&r.agent, &r.router, r.shop.id(), near(1)).await?,
        "daily limit exceeded",
    );
    Ok(())
}

#[tokio::test]
async fn pay_rejects_non_agents_overdrafts_and_low_gas() -> anyhow::Result<()> {
    let r = router_env().await?;
    allow_for_an_hour(&r.env, r.shop.id()).await?;
    let stranger = account(&r.env.root, "stranger", near(5)).await?;
    assert_fails_with(
        &pay(&stranger, &r.router, r.shop.id(), near(1)).await?,
        "caller is not a registered agent",
    );
    assert_fails_with(
        &pay(&r.human, &r.router, r.shop.id(), near(1)).await?,
        "caller is not a registered agent",
    );

    let res = r
        .agent
        .call(r.router.id(), "pay")
        .args_json(
            json!({ "receiver_id": r.shop.id(), "amount": near(1).as_yoctonear().to_string() }),
        )
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;
    assert_fails_with(&res, "attach at least");

    r.human
        .call(r.router.id(), "set_limit")
        .args_json(
            json!({ "agent_id": r.agent.id(), "daily_limit": near(50).as_yoctonear().to_string() }),
        )
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;
    assert_fails_with(
        &pay(&r.agent, &r.router, r.shop.id(), near(11)).await?,
        "insufficient balance",
    );
    Ok(())
}

#[tokio::test]
async fn deposit_and_withdraw_are_owner_only() -> anyhow::Result<()> {
    let r = router_env().await?;
    let squatter = account(&r.env.root, "squatter", near(10)).await?;
    let other_agent = account(&r.human, "other", near(1)).await?;
    let res = squatter
        .call(r.router.id(), "deposit")
        .args_json(json!({ "agent_id": other_agent.id(), "daily_limit": "1" }))
        .deposit(near(1))
        .transact()
        .await?;
    assert_fails_with(&res, "direct sub-account");
    let res = squatter
        .call(r.router.id(), "deposit")
        .args_json(json!({ "agent_id": r.agent.id() }))
        .deposit(near(1))
        .transact()
        .await?;
    assert_fails_with(&res, "only the agent's owner can deposit");

    let take = json!({ "agent_id": r.agent.id(), "amount": near(4).as_yoctonear().to_string() });
    let res = squatter
        .call(r.router.id(), "withdraw")
        .args_json(&take)
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;
    assert_fails_with(&res, "only the agent's owner");
    let res = r
        .human
        .call(r.router.id(), "withdraw")
        .args_json(&take)
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;
    assert_fails_with(&res, "Requires attached deposit of exactly 1 yoctoNEAR");

    let res = r
        .human
        .call(r.router.id(), "withdraw")
        .args_json(&take)
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(15))
        .transact()
        .await?;
    assert_fails_with(&res, "attach at least 20 Tgas");

    let human_before = r.human.view_account().await?.balance;
    let balance_before = yocto(&agent_state(&r).await?["balance"]);
    let res = r
        .human
        .call(r.router.id(), "withdraw")
        .args_json(&take)
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;
    assert!(res.is_success() && has_log(&res, &["withdrawn"]), "{res:?}");
    assert_eq!(
        yocto(&agent_state(&r).await?["balance"]),
        balance_before - near(4).as_yoctonear()
    );
    let gained = r
        .human
        .view_account()
        .await?
        .balance
        .saturating_sub(human_before);
    assert!(
        gained > NearToken::from_millinear(3_900),
        "owner got {gained}"
    );

    let too_much =
        json!({ "agent_id": r.agent.id(), "amount": near(100).as_yoctonear().to_string() });
    let res = r
        .human
        .call(r.router.id(), "withdraw")
        .args_json(&too_much)
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;
    assert_fails_with(&res, "insufficient balance");
    Ok(())
}

/// The agent's only key is a function-call key for router/`pay`: it cannot move NEAR directly,
/// call another router method, call another contract, or attach a deposit.
#[tokio::test]
async fn agent_function_call_key_cannot_do_anything_but_pay() -> anyhow::Result<()> {
    let r = router_env().await?;
    let keys = r.agent.view_access_keys().await?;
    assert_eq!(
        keys.len(),
        1,
        "agent should hold only the function-call key"
    );

    let shop_before = r.shop.view_account().await?.balance;
    let err = r
        .agent
        .transfer_near(r.shop.id(), NearToken::from_yoctonear(1))
        .await
        .expect_err("direct transfer must be rejected");
    assert!(format!("{err:?}").contains("RequiresFullAccess"), "{err:?}");

    let err = r
        .agent
        .call(r.router.id(), "withdraw")
        .args_json(json!({ "agent_id": r.agent.id(), "amount": "1" }))
        .transact()
        .await
        .expect_err("other router method must be rejected");
    assert!(format!("{err:?}").contains("MethodNameMismatch"), "{err:?}");

    let err = r
        .agent
        .call(r.env.oracle.id(), "report")
        .args_json(json!({ "account_id": r.shop.id(), "evidence_url": "x", "evidence_sha256": EVIDENCE_SHA }))
        .transact()
        .await
        .expect_err("another contract must be rejected");
    assert!(format!("{err:?}").contains("ReceiverMismatch"), "{err:?}");

    let err = r
        .agent
        .call(r.router.id(), "pay")
        .args_json(json!({ "receiver_id": r.shop.id(), "amount": "1" }))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await
        .expect_err("deposit with a function-call key must be rejected");
    assert!(
        format!("{err:?}").contains("DepositWithFunctionCall"),
        "{err:?}"
    );

    assert_eq!(r.shop.view_account().await?.balance, shop_before);
    Ok(())
}

/// Callbacks are private: calling one directly would otherwise credit a balance without a debit.
#[tokio::test]
async fn callbacks_cannot_be_called_directly() -> anyhow::Result<()> {
    let r = router_env().await?;
    let stranger = account(&r.env.root, "stranger", near(5)).await?;
    let before = agent_state(&r).await?;
    let args = json!({
        "agent_id": r.agent.id(), "receiver_id": r.shop.id(),
        "amount": near(3).as_yoctonear().to_string(), "day": before["day"].to_string(),
    });
    for method in ["on_verdict", "on_transfer"] {
        let res = stranger
            .call(r.router.id(), method)
            .args_json(&args)
            .gas(Gas::from_tgas(100))
            .transact()
            .await?;
        assert_fails_with(&res, &format!("Method {method} is private"));
    }
    let res = stranger
        .call(r.router.id(), "on_withdraw")
        .args_json(json!({ "agent_id": r.agent.id(), "owner_id": r.human.id(), "amount": near(3).as_yoctonear().to_string() }))
        .transact()
        .await?;
    assert_fails_with(&res, "Method on_withdraw is private");
    assert_eq!(agent_state(&r).await?, before);
    Ok(())
}
