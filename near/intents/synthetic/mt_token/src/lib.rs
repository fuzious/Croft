//! Lean NEP-245 multi-token used as the bridged-token contract in the sandbox.
//!
//! It behaves like a bridge MT token (HOT Omni style) on the transfer-call path:
//! `mt_batch_transfer_call` moves balances, calls `mt_on_transfer` on the receiver and resolves in
//! `mt_resolve_transfer`, refunding `min(requested, amount)` per entry, or every amount when the receiver's
//! promise failed. Its resolve gas reservation is small and flat, so that a deposit with ~100 token entries fits
//! the sandbox's 300 TGas transaction limit (mainnet allowed 1 PGas when the exploit happened).
use near_sdk::json_types::U128;
use near_sdk::serde_json::{self, json};
use near_sdk::store::LookupMap;
use near_sdk::{env, near, require, AccountId, Gas, NearToken, PanicOnDefault, Promise, PromiseResult};

const RESOLVE_GAS: Gas = Gas::from_tgas(15);
const RESERVE_AFTER_CALL: Gas = Gas::from_tgas(25);

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    balances: LookupMap<String, u128>,
}

fn key(owner: &AccountId, token_id: &str) -> String {
    format!("{owner}\u{0}{token_id}")
}

fn emit_transfer(old: &AccountId, new: &AccountId, token_ids: &[String], amounts: &[U128], memo: Option<&str>) {
    let mut data = json!({"old_owner_id": old, "new_owner_id": new, "token_ids": token_ids, "amounts": amounts});
    if let Some(m) = memo {
        data["memo"] = json!(m);
    }
    let ev = json!({"standard": "nep245", "version": "1.0.0", "event": "mt_transfer", "data": [data]});
    env::log_str(&format!("EVENT_JSON:{ev}"));
}

#[near]
impl Contract {
    #[init]
    pub fn new() -> Self {
        Self { balances: LookupMap::new(b"b") }
    }

    fn sub(&mut self, owner: &AccountId, token_id: &str, amount: u128) {
        let k = key(owner, token_id);
        let bal = self.balances.get(&k).copied().unwrap_or(0);
        require!(bal >= amount, "insufficient balance");
        self.balances.insert(k, bal - amount);
    }

    fn add(&mut self, owner: &AccountId, token_id: &str, amount: u128) {
        let k = key(owner, token_id);
        let bal = self.balances.get(&k).copied().unwrap_or(0);
        self.balances.insert(k, bal.checked_add(amount).expect("overflow"));
    }

    fn move_all(&mut self, from: &AccountId, to: &AccountId, token_ids: &[String], amounts: &[U128]) {
        require!(!token_ids.is_empty() && token_ids.len() == amounts.len(), "invalid args");
        for (t, a) in token_ids.iter().zip(amounts) {
            self.sub(from, t, a.0);
            self.add(to, t, a.0);
        }
    }

    /// Bridge mint: credits `owner_id`. Open to anyone; this is a sandbox token.
    pub fn mint(&mut self, owner_id: AccountId, token_ids: Vec<String>, amounts: Vec<U128>) {
        for (t, a) in token_ids.iter().zip(&amounts) {
            self.add(&owner_id, t, a.0);
        }
        let ev = json!({"standard": "nep245", "version": "1.0.0", "event": "mt_mint",
                        "data": [{"owner_id": owner_id, "token_ids": token_ids, "amounts": amounts}]});
        env::log_str(&format!("EVENT_JSON:{ev}"));
    }

    #[payable]
    pub fn mt_transfer(&mut self, receiver_id: AccountId, token_id: String, amount: U128,
                       approval: Option<(AccountId, u64)>, memo: Option<String>) {
        let _ = approval;
        self.mt_batch_transfer(receiver_id, vec![token_id], vec![amount], None, memo);
    }

    #[payable]
    pub fn mt_batch_transfer(&mut self, receiver_id: AccountId, token_ids: Vec<String>, amounts: Vec<U128>,
                             approvals: Option<Vec<Option<(AccountId, u64)>>>, memo: Option<String>) {
        let _ = approvals;
        require!(env::attached_deposit() == NearToken::from_yoctonear(1), "requires 1 yoctoNEAR");
        let sender = env::predecessor_account_id();
        self.move_all(&sender, &receiver_id, &token_ids, &amounts);
        emit_transfer(&sender, &receiver_id, &token_ids, &amounts, memo.as_deref());
    }

    #[payable]
    pub fn mt_transfer_call(&mut self, receiver_id: AccountId, token_id: String, amount: U128,
                            approval: Option<(AccountId, u64)>, memo: Option<String>, msg: String) -> Promise {
        let _ = approval;
        self.mt_batch_transfer_call(receiver_id, vec![token_id], vec![amount], None, memo, msg)
    }

    #[payable]
    pub fn mt_batch_transfer_call(&mut self, receiver_id: AccountId, token_ids: Vec<String>, amounts: Vec<U128>,
                                  approvals: Option<Vec<Option<(AccountId, u64)>>>, memo: Option<String>,
                                  msg: String) -> Promise {
        let _ = approvals;
        require!(env::attached_deposit() == NearToken::from_yoctonear(1), "requires 1 yoctoNEAR");
        let sender = env::predecessor_account_id();
        self.move_all(&sender, &receiver_id, &token_ids, &amounts);
        emit_transfer(&sender, &receiver_id, &token_ids, &amounts, memo.as_deref());

        let call_gas = env::prepaid_gas()
            .saturating_sub(env::used_gas())
            .saturating_sub(RESOLVE_GAS)
            .saturating_sub(RESERVE_AFTER_CALL);
        let previous_owner_ids = vec![sender.clone(); token_ids.len()];
        let on_transfer_args = json!({"sender_id": sender, "previous_owner_ids": previous_owner_ids,
                                      "token_ids": token_ids, "amounts": amounts, "msg": msg});
        let resolve_args = json!({"previous_owner_ids": previous_owner_ids, "receiver_id": receiver_id,
                                  "token_ids": token_ids, "amounts": amounts});
        Promise::new(receiver_id)
            .function_call("mt_on_transfer".to_string(), on_transfer_args.to_string().into_bytes(),
                           NearToken::from_yoctonear(0), call_gas)
            .then(Promise::new(env::current_account_id()).function_call(
                "mt_resolve_transfer".to_string(), resolve_args.to_string().into_bytes(),
                NearToken::from_yoctonear(0), RESOLVE_GAS))
    }

    #[private]
    pub fn mt_resolve_transfer(&mut self, previous_owner_ids: Vec<AccountId>, receiver_id: AccountId,
                               token_ids: Vec<String>, amounts: Vec<U128>) -> Vec<U128> {
        let sender = previous_owner_ids[0].clone();
        #[allow(deprecated)] // the result is bounded by the receiver; this token is sandbox-only
        let refunds: Vec<u128> = match env::promise_result(0) {
            PromiseResult::Successful(v) => serde_json::from_slice::<Vec<U128>>(&v)
                .ok()
                .filter(|r| r.len() == amounts.len())
                .map(|r| r.into_iter().map(|x| x.0).collect())
                .unwrap_or_else(|| amounts.iter().map(|a| a.0).collect()),
            PromiseResult::Failed => amounts.iter().map(|a| a.0).collect(),
        };
        let mut used = Vec::with_capacity(amounts.len());
        let mut refunded_ids = Vec::new();
        let mut refunded_amounts = Vec::new();
        for ((t, a), r) in token_ids.iter().zip(&amounts).zip(refunds) {
            let held = self.balances.get(&key(&receiver_id, t)).copied().unwrap_or(0);
            let refund = r.min(a.0).min(held);
            if refund > 0 {
                self.sub(&receiver_id, t, refund);
                self.add(&sender, t, refund);
                refunded_ids.push(t.clone());
                refunded_amounts.push(U128(refund));
            }
            used.push(U128(a.0 - refund));
        }
        if !refunded_ids.is_empty() {
            emit_transfer(&receiver_id, &sender, &refunded_ids, &refunded_amounts, Some("refund"));
        }
        used
    }

    pub fn mt_balance_of(&self, account_id: AccountId, token_id: String) -> U128 {
        U128(self.balances.get(&key(&account_id, &token_id)).copied().unwrap_or(0))
    }

    pub fn mt_batch_balance_of(&self, account_id: AccountId, token_ids: Vec<String>) -> Vec<U128> {
        token_ids.iter().map(|t| self.mt_balance_of(account_id.clone(), t.clone())).collect()
    }
}
