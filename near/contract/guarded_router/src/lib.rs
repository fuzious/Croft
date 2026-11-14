//! Optional enforcement of operator-attested account verdicts for future router payments.
//!
//! A human funds a balance for an agent account (a direct sub-account of the human). The agent
//! holds only a function-call key restricted to this contract's `pay` method, so it cannot move
//! NEAR on its own. `pay` debits the agent's balance and daily allowance up front, asks the security
//! oracle about the receiver, and transfers in a private callback only when the verdict is `allow`,
//! unexpired and the receiver is not blocked. Every other outcome restores the debit and logs a
//! NEP-297 `payment_refused` event with the reason.
//! An optional signed pre-approval authorizes one exact payment without an allow verdict; the oracle
//! checks its signature, expiry and blocks, and the router consumes its nonce before the async call.
//! Receipt-rule findings do not call this router automatically. It cannot revert a historical
//! transaction, pause another protocol, or restrict payments made outside this contract.
use near_sdk::json_types::{Base64VecU8, U128, U64};
use near_sdk::serde::Deserialize;
use near_sdk::serde_json::{self, json};
use near_sdk::store::LookupMap;
use near_sdk::{
    assert_one_yocto, env, near, require, AccountId, BorshStorageKey, Gas, NearToken,
    PanicOnDefault, Promise, PromiseError, PromiseOrValue,
};

const NS_PER_DAY: u64 = 86_400 * 1_000_000_000;
const GAS_GET_VERDICT: Gas = Gas::from_tgas(10);
const GAS_IS_BLOCKED: Gas = Gas::from_tgas(5);
const GAS_ON_VERDICT: Gas = Gas::from_tgas(25);
const GAS_ON_TRANSFER: Gas = Gas::from_tgas(10);
const GAS_ON_WITHDRAW: Gas = Gas::from_tgas(10);
/// Prepaid gas `withdraw` requires: its own work plus the callback's static gas.
const GAS_WITHDRAW_TOTAL: Gas = Gas::from_tgas(20);
/// Gas `pay` needs on top of the receipts it schedules (oracle views + callbacks).
const GAS_PAY_SELF: Gas = Gas::from_tgas(10);
const MAX_ORACLE_RESULT_LEN: usize = 4_096;

#[near(serializers = [json])]
pub struct Preapproval {
    pub nonce: U64,
    pub key_generation: U64,
    pub issued_at_ns: U64,
    pub expires_at_ns: U64,
    pub signature: Base64VecU8,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Agent {
    pub owner_id: AccountId,
    pub balance: NearToken,
    pub daily_limit: NearToken,
    pub spent_today: NearToken,
    /// Day index (block timestamp / 1 day) that `spent_today` refers to.
    pub day: u64,
}

/// The fields of the oracle's `Verdict` the router relies on.
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct OracleVerdict {
    verdict: String,
    expires_at_ns: U64,
}

#[near(event_json(standard = "guarded_router"))]
pub enum Event {
    #[event_version("1.0.0")]
    AgentFunded {
        agent_id: AccountId,
        owner_id: AccountId,
        amount: U128,
    },
    #[event_version("1.0.0")]
    LimitSet {
        agent_id: AccountId,
        daily_limit: U128,
    },
    #[event_version("1.0.0")]
    PaymentSent {
        agent_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
    },
    #[event_version("1.0.0")]
    PaymentRefused {
        agent_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        reason: String,
    },
    #[event_version("1.0.0")]
    PaymentFailed {
        agent_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
    },
    #[event_version("1.0.0")]
    Withdrawn {
        agent_id: AccountId,
        owner_id: AccountId,
        amount: U128,
    },
    #[event_version("1.0.0")]
    WithdrawFailed {
        agent_id: AccountId,
        owner_id: AccountId,
        amount: U128,
    },
}

#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    Agents,
    PreapprovalNonces,
}

#[near(
    contract_state,
    contract_metadata(
        link = "https://github.com/fuzious/security_oracle",
        standard(standard = "nep297", version = "1.0.0"),
    )
)]
#[derive(PanicOnDefault)]
pub struct GuardedRouter {
    oracle_id: AccountId,
    agents: LookupMap<AccountId, Agent>,
    preapproval_nonces: LookupMap<AccountId, u64>,
}

#[near]
impl GuardedRouter {
    #[init]
    pub fn new(oracle_id: AccountId) -> Self {
        Self {
            oracle_id,
            agents: LookupMap::new(StorageKey::Agents),
            preapproval_nonces: LookupMap::new(StorageKey::PreapprovalNonces),
        }
    }

    /// Fund `agent_id`. The first deposit registers the agent: the caller becomes its owner (the
    /// agent must be a direct sub-account of the caller, so nobody can squat someone else's agent),
    /// `daily_limit` is required, and the record's storage cost is taken from the deposit.
    #[payable]
    pub fn deposit(&mut self, agent_id: AccountId, daily_limit: Option<U128>) {
        let caller = env::predecessor_account_id();
        let attached = env::attached_deposit();
        require!(!attached.is_zero(), "attach the NEAR to deposit");
        let credited = match self.agents.get_mut(&agent_id) {
            Some(agent) => {
                require!(
                    agent.owner_id == caller,
                    "only the agent's owner can deposit"
                );
                require!(
                    daily_limit.is_none(),
                    "use set_limit to change the daily limit"
                );
                agent.balance = checked_add(agent.balance, attached);
                attached
            }
            None => {
                require!(
                    agent_id.is_sub_account_of(&caller),
                    "agent must be a direct sub-account of its owner"
                );
                let limit = daily_limit
                    .unwrap_or_else(|| env::panic_str("daily_limit is required on first deposit"));
                let before = env::storage_usage();
                self.agents.insert(
                    agent_id.clone(),
                    Agent {
                        owner_id: caller.clone(),
                        balance: NearToken::from_yoctonear(0),
                        daily_limit: NearToken::from_yoctonear(limit.0),
                        spent_today: NearToken::from_yoctonear(0),
                        day: today(),
                    },
                );
                self.agents.flush();
                let used = env::storage_usage().saturating_sub(before) as u128;
                let cost = env::storage_byte_cost()
                    .checked_mul(used)
                    .unwrap_or_else(|| env::panic_str("storage cost overflow"));
                require!(
                    attached > cost,
                    format!(
                        "deposit must exceed the storage cost of {} yoctoNEAR",
                        cost.as_yoctonear()
                    )
                );
                let credited = attached.saturating_sub(cost);
                self.agents.get_mut(&agent_id).unwrap().balance = credited;
                credited
            }
        };
        Event::AgentFunded {
            agent_id,
            owner_id: caller,
            amount: U128(credited.as_yoctonear()),
        }
        .emit();
    }

    #[payable]
    pub fn set_limit(&mut self, agent_id: AccountId, daily_limit: U128) {
        let agent = self.owned_agent_mut(&agent_id);
        agent.daily_limit = NearToken::from_yoctonear(daily_limit.0);
        Event::LimitSet {
            agent_id,
            daily_limit,
        }
        .emit();
    }

    /// Owner takes `amount` back from the agent's balance.
    #[payable]
    pub fn withdraw(&mut self, agent_id: AccountId, amount: U128) -> Promise {
        let amount = NearToken::from_yoctonear(amount.0);
        require!(!amount.is_zero(), "amount must be positive");
        require!(
            env::prepaid_gas() >= GAS_WITHDRAW_TOTAL,
            format!("attach at least {} Tgas", GAS_WITHDRAW_TOTAL.as_tgas())
        );
        let agent = self.owned_agent_mut(&agent_id);
        agent.balance = agent
            .balance
            .checked_sub(amount)
            .unwrap_or_else(|| env::panic_str("insufficient balance"));
        let owner_id = agent.owner_id.clone();
        Promise::new(owner_id.clone()).transfer(amount).then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_ON_WITHDRAW)
                .on_withdraw(agent_id, owner_id, U128(amount.as_yoctonear())),
        )
    }

    /// Called by the agent itself (its function-call key). Not payable.
    pub fn pay(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        preapproval: Option<Preapproval>,
    ) -> Promise {
        let agent_id = env::predecessor_account_id();
        if let Some(ref proof) = preapproval {
            let nonce = self.get_preapproval_nonce(agent_id.clone()).0;
            require!(
                proof.nonce.0 == nonce,
                "preapproval nonce already used or out of order"
            );
            // Consume before the async check, including refused payments, to prevent concurrent replay.
            self.preapproval_nonces.insert(
                agent_id.clone(),
                nonce.checked_add(1).expect("nonce overflow"),
            );
        }
        let value = NearToken::from_yoctonear(amount.0);
        require!(!value.is_zero(), "amount must be positive");
        require!(
            receiver_id != env::current_account_id(),
            "cannot pay the router itself"
        );
        let needed = GAS_GET_VERDICT
            .checked_add(GAS_IS_BLOCKED)
            .and_then(|g| g.checked_add(GAS_ON_VERDICT))
            .and_then(|g| g.checked_add(GAS_ON_TRANSFER))
            .and_then(|g| g.checked_add(GAS_PAY_SELF))
            .unwrap();
        require!(
            env::prepaid_gas() >= needed,
            format!("attach at least {} Tgas", needed.as_tgas())
        );

        let agent = self
            .agents
            .get_mut(&agent_id)
            .unwrap_or_else(|| env::panic_str("caller is not a registered agent"));
        let day = today();
        if agent.day != day {
            agent.day = day;
            agent.spent_today = NearToken::from_yoctonear(0);
        }
        let spent = checked_add(agent.spent_today, value);
        require!(spent <= agent.daily_limit, "daily limit exceeded");
        agent.balance = agent
            .balance
            .checked_sub(value)
            .unwrap_or_else(|| env::panic_str("insufficient balance"));
        agent.spent_today = spent;

        if let Some(proof) = preapproval {
            let expires_at_ns = proof.expires_at_ns;
            return Promise::new(self.oracle_id.clone())
                .function_call(
                    "verify_preapproval".to_string(),
                    json!({"consumer_id": env::current_account_id(), "agent_id": agent_id,
                    "receiver_id": receiver_id, "amount": amount, "preapproval": proof})
                    .to_string()
                    .into_bytes(),
                    NearToken::from_yoctonear(0),
                    GAS_GET_VERDICT,
                )
                .then(
                    Self::ext(env::current_account_id())
                        .with_static_gas(GAS_ON_VERDICT)
                        .on_preapproval(agent_id, receiver_id, amount, U64(day), expires_at_ns),
                );
        }

        let args = json!({ "account_id": receiver_id })
            .to_string()
            .into_bytes();
        let zero = NearToken::from_yoctonear(0);
        Promise::new(self.oracle_id.clone())
            .function_call(
                "get_verdict".to_string(),
                args.clone(),
                zero,
                GAS_GET_VERDICT,
            )
            .and(Promise::new(self.oracle_id.clone()).function_call(
                "is_blocked".to_string(),
                args,
                zero,
                GAS_IS_BLOCKED,
            ))
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_ON_VERDICT)
                    .on_verdict(agent_id, receiver_id, amount, U64(day)),
            )
    }

    #[private]
    pub fn on_preapproval(
        &mut self,
        agent_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        day: U64,
        expires_at_ns: U64,
    ) -> PromiseOrValue<bool> {
        let approved = env::promise_results_count() == 1
            && env::promise_result_checked(0, MAX_ORACLE_RESULT_LEN)
                .ok()
                .and_then(|raw| serde_json::from_slice::<bool>(&raw).ok())
                == Some(true)
            && env::block_timestamp() < expires_at_ns.0;
        if !approved {
            self.restore(&agent_id, amount, day.0);
            Event::PaymentRefused {
                agent_id,
                receiver_id,
                amount,
                reason: "preapproval_invalid".into(),
            }
            .emit();
            return PromiseOrValue::Value(false);
        }
        Promise::new(receiver_id.clone())
            .transfer(NearToken::from_yoctonear(amount.0))
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_ON_TRANSFER)
                    .on_transfer(agent_id, receiver_id, amount, day),
            )
            .into()
    }

    pub fn get_preapproval_nonce(&self, agent_id: AccountId) -> U64 {
        U64(self.preapproval_nonces.get(&agent_id).copied().unwrap_or(0))
    }

    #[private]
    pub fn on_verdict(
        &mut self,
        agent_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        day: U64,
    ) -> PromiseOrValue<bool> {
        if let Err(reason) = check_oracle_answer(env::block_timestamp()) {
            self.restore(&agent_id, amount, day.0);
            Event::PaymentRefused {
                agent_id,
                receiver_id,
                amount,
                reason: reason.to_string(),
            }
            .emit();
            return PromiseOrValue::Value(false);
        }
        Promise::new(receiver_id.clone())
            .transfer(NearToken::from_yoctonear(amount.0))
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_ON_TRANSFER)
                    .on_transfer(agent_id, receiver_id, amount, day),
            )
            .into()
    }

    /// Restores the debit when the transfer failed (e.g. the receiver account does not exist; the
    /// NEAR comes back to the router as a refund).
    #[private]
    pub fn on_transfer(
        &mut self,
        agent_id: AccountId,
        receiver_id: AccountId,
        amount: U128,
        day: U64,
    ) -> bool {
        if previous_promise_succeeded() {
            Event::PaymentSent {
                agent_id,
                receiver_id,
                amount,
            }
            .emit();
            return true;
        }
        self.restore(&agent_id, amount, day.0);
        Event::PaymentFailed {
            agent_id,
            receiver_id,
            amount,
        }
        .emit();
        false
    }

    #[private]
    pub fn on_withdraw(&mut self, agent_id: AccountId, owner_id: AccountId, amount: U128) -> bool {
        if previous_promise_succeeded() {
            Event::Withdrawn {
                agent_id,
                owner_id,
                amount,
            }
            .emit();
            return true;
        }
        if let Some(agent) = self.agents.get_mut(&agent_id) {
            agent.balance = checked_add(agent.balance, NearToken::from_yoctonear(amount.0));
        }
        Event::WithdrawFailed {
            agent_id,
            owner_id,
            amount,
        }
        .emit();
        false
    }

    pub fn get_agent(&self, agent_id: AccountId) -> Option<Agent> {
        self.agents.get(&agent_id).cloned()
    }

    pub fn get_oracle(&self) -> AccountId {
        self.oracle_id.clone()
    }
}

impl GuardedRouter {
    /// The caller's agent record; requires one yoctoNEAR (full-access key) and ownership.
    fn owned_agent_mut(&mut self, agent_id: &AccountId) -> &mut Agent {
        assert_one_yocto();
        let caller = env::predecessor_account_id();
        let agent = self
            .agents
            .get_mut(agent_id)
            .unwrap_or_else(|| env::panic_str("unknown agent"));
        require!(
            agent.owner_id == caller,
            "only the agent's owner can call this method"
        );
        agent
    }

    /// Give a reserved payment back: balance always, today's allowance only if still the same day.
    fn restore(&mut self, agent_id: &AccountId, amount: U128, day: u64) {
        let value = NearToken::from_yoctonear(amount.0);
        let Some(agent) = self.agents.get_mut(agent_id) else {
            return;
        };
        agent.balance = checked_add(agent.balance, value);
        if agent.day == day {
            agent.spent_today = agent.spent_today.saturating_sub(value);
        }
    }
}

/// Reads the two oracle results (0: get_verdict, 1: is_blocked) and says why the payment must be
/// refused, if it must. Failed, oversized or malformed results refuse.
fn check_oracle_answer(now_ns: u64) -> Result<(), &'static str> {
    if env::promise_results_count() != 2 {
        return Err("oracle_call_failed");
    }
    let verdict =
        env::promise_result_checked(0, MAX_ORACLE_RESULT_LEN).map_err(|_| "oracle_call_failed")?;
    let blocked =
        env::promise_result_checked(1, MAX_ORACLE_RESULT_LEN).map_err(|_| "oracle_call_failed")?;
    let blocked: bool = serde_json::from_slice(&blocked).map_err(|_| "oracle_bad_response")?;
    if blocked {
        return Err("receiver_blocked");
    }
    let verdict: Option<OracleVerdict> =
        serde_json::from_slice(&verdict).map_err(|_| "oracle_bad_response")?;
    let verdict = verdict.ok_or("no_verdict")?;
    match verdict.verdict.as_str() {
        "allow" => {}
        "warn" => return Err("verdict_warn"),
        "block" => return Err("verdict_block"),
        _ => return Err("oracle_bad_response"),
    }
    if now_ns >= verdict.expires_at_ns.0 {
        return Err("verdict_expired");
    }
    Ok(())
}

/// True unless the single promise this callback waits on failed (a transfer returns no data).
fn previous_promise_succeeded() -> bool {
    !matches!(env::promise_result_checked(0, 0), Err(PromiseError::Failed))
}

fn today() -> u64 {
    env::block_timestamp() / NS_PER_DAY
}

fn checked_add(a: NearToken, b: NearToken) -> NearToken {
    a.checked_add(b)
        .unwrap_or_else(|| env::panic_str("amount overflow"))
}
