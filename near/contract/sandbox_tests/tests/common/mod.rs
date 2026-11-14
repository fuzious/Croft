//! Shared sandbox setup: builds both contracts once per test binary (cargo-near), deploys them on a
//! fresh near-sandbox, and creates the accounts the tests use.
#![allow(dead_code)]
use near_workspaces::network::Sandbox;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{AccessKey, Gas, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, AccountId, Contract, Worker};
use serde_json::{json, Value};
use tokio::sync::OnceCell;

static ORACLE_WASM: OnceCell<Vec<u8>> = OnceCell::const_new();
static ROUTER_WASM: OnceCell<Vec<u8>> = OnceCell::const_new();

pub const REASONS_HASH: &str = "a3f1c0de00000000000000000000000000000000000000000000000000000001";
pub const EVIDENCE_SHA: &str = "e1de4ce000000000000000000000000000000000000000000000000000000002";
pub const ONE_HOUR_NS: u64 = 3_600 * 1_000_000_000;
pub const SEVEN_DAYS_NS: u64 = 7 * 24 * ONE_HOUR_NS;

pub async fn oracle_wasm() -> &'static [u8] {
    ORACLE_WASM
        .get_or_init(|| async {
            near_workspaces::compile_project("../security_oracle")
                .await
                .expect("build security_oracle")
        })
        .await
}

pub async fn router_wasm() -> &'static [u8] {
    ROUTER_WASM
        .get_or_init(|| async {
            near_workspaces::compile_project("../guarded_router")
                .await
                .expect("build guarded_router")
        })
        .await
}

pub fn near(n: u128) -> NearToken {
    NearToken::from_near(n)
}

pub async fn account(parent: &Account, name: &str, balance: NearToken) -> anyhow::Result<Account> {
    Ok(parent
        .create_subaccount(name)
        .initial_balance(balance)
        .transact()
        .await?
        .into_result()?)
}

pub struct Env {
    pub worker: Worker<Sandbox>,
    pub root: Account,
    pub oracle: Contract,
    pub owner: Account,
    pub attester: Account,
}

/// Sandbox with the oracle deployed (`owner` owns it, `attester` is its only attester).
pub async fn oracle_env() -> anyhow::Result<Env> {
    let worker = near_workspaces::sandbox().await?;
    let root = worker.root_account()?;
    let owner = account(&root, "owner", near(50)).await?;
    let attester = account(&root, "attester", near(10)).await?;
    let oracle_acc = account(&root, "oracle", near(20)).await?;
    let oracle = oracle_acc
        .deploy(oracle_wasm().await)
        .await?
        .into_result()?;
    oracle
        .call("new")
        .args_json(json!({ "owner_id": owner.id(), "attesters": [attester.id()] }))
        .transact()
        .await?
        .into_result()?;
    Ok(Env {
        worker,
        root,
        oracle,
        owner,
        attester,
    })
}

pub async fn now_ns(worker: &Worker<Sandbox>) -> anyhow::Result<u64> {
    Ok(worker.view_block().await?.timestamp())
}

pub async fn submit_verdict(
    env: &Env,
    target: &AccountId,
    verdict: &str,
    expires_at_ns: u64,
) -> anyhow::Result<ExecutionFinalResult> {
    Ok(env
        .attester
        .call(env.oracle.id(), "submit_verdict")
        .args_json(json!({
            "account_id": target, "code_hash": "11111111111111111111111111111111", "verdict": verdict,
            "score_bps": 1200, "reasons_hash": REASONS_HASH, "expires_at_ns": expires_at_ns.to_string(),
        }))
        .transact()
        .await?)
}

pub async fn allow_for_an_hour(env: &Env, target: &AccountId) -> anyhow::Result<()> {
    let expires = now_ns(&env.worker).await? + ONE_HOUR_NS;
    submit_verdict(env, target, "allow", expires)
        .await?
        .into_result()?;
    Ok(())
}

pub async fn view(contract: &Contract, method: &str, args: Value) -> anyhow::Result<Value> {
    Ok(contract.view(method).args_json(args).await?.json()?)
}

/// A failed transaction whose failure text contains `needle`.
pub fn assert_fails_with(res: &ExecutionFinalResult, needle: &str) {
    assert!(
        res.is_failure(),
        "expected failure containing {needle:?}, got success: {res:?}"
    );
    let text = format!("{:?}", res.failures());
    assert!(
        text.contains(needle),
        "expected failure containing {needle:?}, got: {text}"
    );
}

pub struct RouterEnv {
    pub env: Env,
    pub router: Contract,
    /// The human: full-access key, owns `agent`.
    pub human: Account,
    /// The agent signing with its only key: a function-call key restricted to router/`pay`.
    pub agent: Account,
    pub shop: Account,
}

pub const DAILY_LIMIT_NEAR: u128 = 5;

/// Oracle + router; `human` registered `agent` with a 10 NEAR deposit and a 5 NEAR daily limit,
/// and the agent's full-access key was replaced by a function-call key for router/`pay`.
pub async fn router_env() -> anyhow::Result<RouterEnv> {
    let env = oracle_env().await?;
    let router_acc = account(&env.root, "router", near(20)).await?;
    let router = router_acc
        .deploy(router_wasm().await)
        .await?
        .into_result()?;
    router
        .call("new")
        .args_json(json!({ "oracle_id": env.oracle.id() }))
        .transact()
        .await?
        .into_result()?;

    let human = account(&env.root, "human", near(100)).await?;
    let agent_full = account(&human, "agent", near(5)).await?;
    let shop = account(&env.root, "shop", near(5)).await?;

    human
        .call(router.id(), "deposit")
        .args_json(json!({ "agent_id": agent_full.id(), "daily_limit": near(DAILY_LIMIT_NEAR).as_yoctonear().to_string() }))
        .deposit(near(10))
        .transact()
        .await?
        .into_result()?;

    let fc_key = SecretKey::from_random(KeyType::ED25519);
    agent_full
        .batch(agent_full.id())
        .add_key(
            fc_key.public_key(),
            AccessKey::function_call_access(router.id(), &["pay"], Some(near(1))),
        )
        .delete_key(agent_full.secret_key().public_key())
        .transact()
        .await?
        .into_result()?;
    let agent = Account::from_secret_key(agent_full.id().clone(), fc_key, &env.worker);
    Ok(RouterEnv {
        env,
        router,
        human,
        agent,
        shop,
    })
}

pub async fn pay(
    agent: &Account,
    router: &Contract,
    receiver: &AccountId,
    amount: NearToken,
) -> anyhow::Result<ExecutionFinalResult> {
    Ok(agent
        .call(router.id(), "pay")
        .args_json(json!({ "receiver_id": receiver, "amount": amount.as_yoctonear().to_string() }))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)
}

pub async fn agent_state(r: &RouterEnv) -> anyhow::Result<Value> {
    view(&r.router, "get_agent", json!({ "agent_id": r.agent.id() })).await
}

pub fn yocto(v: &Value) -> u128 {
    v.as_str()
        .expect("yocto string")
        .parse()
        .expect("yocto number")
}

pub fn has_log(res: &ExecutionFinalResult, needles: &[&str]) -> bool {
    res.logs()
        .iter()
        .any(|l| needles.iter().all(|n| l.contains(n)))
}
