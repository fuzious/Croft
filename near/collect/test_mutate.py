"""Mutation operator tests: each operator removes its protection from a small safe fixture, keeps the result parseable,
and leaves functions without that protection alone."""
import tempfile
import unittest
from pathlib import Path

from near.analyzer import extract_functions
from near.collect.mutate import OPERATORS, clean_parse, contract_files, mutate, normalized, select


def fn_of(body: str, name: str | None = None) -> dict:
    src = f"#[near_bindgen]\nimpl Contract {{\n{body}\n}}\n"
    fns = extract_functions(src, "src/lib.rs")
    return next(f for f in fns if name is None or f["fn"] == name)


def run(op: str, body: str, name: str | None = None) -> str | None:
    return OPERATORS[op](fn_of(body, name))


class NonPrivateCallbackTest(unittest.TestCase):
    def test_removes_private_attr(self):
        out = run("non_private_callback", """
    #[private]
    pub fn on_withdraw(&mut self, amount: U128) {
        self.total -= amount.0;
    }""")
        self.assertNotIn("#[private]", out)
        self.assertIn("pub fn on_withdraw", out)
        self.assertTrue(clean_parse(out))

    def test_removes_self_check(self):
        out = run("non_private_callback", """
    pub fn resolve_transfer(&mut self, amount: U128) {
        // only the contract itself
        assert_eq!(env::predecessor_account_id(), env::current_account_id(), "private");
        self.total -= amount.0;
    }""")
        self.assertNotIn("predecessor_account_id", out)
        self.assertNotIn("only the contract itself", out)
        self.assertIn("self.total -= amount.0;", out)

    def test_skips_non_callback_and_unprotected(self):
        self.assertIsNone(run("non_private_callback", """
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self { env::state_read().unwrap() }"""))
        self.assertIsNone(run("non_private_callback", """
    pub fn on_withdraw(&mut self) { self.total = 0; }"""))


class UnhandledPromiseResultTest(unittest.TestCase):
    def test_guts_failed_arm_that_restores_state(self):
        out = run("unhandled_promise_result", """
    #[private]
    pub fn on_withdraw(&mut self, account_id: AccountId, amount: U128) -> bool {
        match env::promise_result(0) {
            PromiseResult::Successful(_) => true,
            PromiseResult::Failed => {
                self.balances.insert(&account_id, &amount.0);
                false
            }
        }
    }""")
        self.assertNotIn("self.balances.insert", out)
        self.assertIn("PromiseResult::Failed", out)
        self.assertIn("false", out)
        self.assertTrue(clean_parse(out))

    def test_drops_success_assert(self):
        out = run("unhandled_promise_result", """
    #[private]
    pub fn on_claim(&mut self, id: u64) {
        require!(env::is_promise_success(), "claim failed");
        self.claims.remove(&id);
    }""")
        self.assertNotIn("is_promise_success", out)
        self.assertIn("self.claims.remove(&id);", out)

    def test_negated_if_rollback_removed(self):
        out = run("unhandled_promise_result", """
    #[private]
    pub fn after_transfer(&mut self, who: AccountId, amount: u128) {
        if !is_promise_success() {
            self.internal_deposit(&who, amount);
        }
    }""")
        self.assertNotIn("internal_deposit", out)
        self.assertTrue(clean_parse(out))

    def test_negated_if_with_else_flips(self):
        out = run("unhandled_promise_result", """
    #[private]
    pub fn after_transfer(&mut self, who: AccountId, amount: u128) {
        let ok = is_promise_success();
        if !ok {
            self.internal_deposit(&who, amount);
        } else {
            log!("done");
        }
    }""")
        self.assertIn("if ok {", out)
        self.assertNotIn("internal_deposit", out)
        self.assertNotIn("else", out)

    def test_callback_result_err_arm(self):
        out = run("unhandled_promise_result", """
    #[private]
    pub fn on_stake(&mut self, #[callback_result] r: Result<(), PromiseError>, amount: u128) {
        match r {
            Ok(_) => log!("ok"),
            Err(_) => { self.staked -= amount; }
        }
    }""")
        self.assertNotIn("self.staked -= amount", out)

    def test_no_promise_handling(self):
        self.assertIsNone(run("unhandled_promise_result", """
    pub fn f(&mut self) -> u8 { match self.x { Some(v) => v, None => { self.y = 1; 0 } } }"""))


class AsyncReentrancyTest(unittest.TestCase):
    def test_deletes_deduction_before_call(self):
        out = run("async_reentrancy", """
    pub fn withdraw(&mut self, amount: U128) -> Promise {
        let account_id = env::predecessor_account_id();
        let balance = self.balances.get(&account_id).unwrap_or(0);
        assert!(balance >= amount.0, "not enough");
        self.internal_withdraw(&account_id, amount.0);
        ext_ft::ext(self.token.clone())
            .with_attached_deposit(1)
            .ft_transfer(account_id.clone(), amount, None)
            .then(Self::ext(env::current_account_id()).on_withdraw(account_id, amount))
    }""")
        self.assertNotIn("internal_withdraw", out)
        self.assertIn('assert!(balance >= amount.0, "not enough");', out)
        self.assertTrue(clean_parse(out))

    def test_local_counter_is_not_state(self):
        self.assertIsNone(run("async_reentrancy", """
    pub fn vaa_transfer(&mut self, mut deposit: u128) -> Promise {
        deposit -= 1;
        ext_ft::ext(self.token.clone()).ft_transfer(self.to.clone(), U128(deposit), None)
            .then(Self::ext(env::current_account_id()).on_transfer())
    }"""))

    def test_no_callback_no_mutant(self):
        self.assertIsNone(run("async_reentrancy", """
    pub fn withdraw(&mut self, amount: u128) -> Promise {
        self.balance -= amount;
        Promise::new(env::predecessor_account_id()).transfer(amount)
    }"""))


class MissingAccessControlTest(unittest.TestCase):
    def test_deletes_owner_checks(self):
        out = run("missing_access_control", """
    pub fn set_fee(&mut self, fee: u32) {
        self.assert_owner();
        require!(env::predecessor_account_id() == self.owner_id, "owner only");
        self.fee = fee;
    }""")
        self.assertNotIn("assert_owner", out)
        self.assertNotIn("owner_id", out)
        self.assertIn("self.fee = fee;", out)
        self.assertTrue(clean_parse(out))

    def test_deletes_plugin_attr_and_dead_caller(self):
        out = run("missing_access_control", """
    #[only(Role::DAO)]
    pub fn pause_all(&mut self) {
        let caller = env::predecessor_account_id();
        assert_eq!(caller, self.owner_id);
        self.paused = true;
    }""")
        self.assertNotIn("#[only", out)
        self.assertNotIn("let caller", out)
        self.assertIn("self.paused = true;", out)

    def test_deletes_resource_owner_check(self):
        out = run("missing_access_control", """
    pub fn cancel_order(&mut self, order_id: u64) {
        let order = self.orders.get(&order_id).expect("no order");
        assert_eq!(env::predecessor_account_id(), order.maker, "not your order");
        self.orders.remove(&order_id);
    }""")
        self.assertNotIn("not your order", out)
        self.assertIn("self.orders.remove(&order_id);", out)

    def test_skips_auth_helper_itself(self):
        self.assertIsNone(run("missing_access_control", """
    fn assert_owner(&self) { assert_eq!(env::predecessor_account_id(), self.owner_id); }"""))


class MissingOneYoctoTest(unittest.TestCase):
    def test_deletes_assert_one_yocto(self):
        out = run("missing_one_yocto", """
    #[payable]
    pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128) {
        assert_one_yocto();
        self.token.internal_transfer(&env::predecessor_account_id(), &receiver_id, amount.0, None);
    }""")
        self.assertNotIn("assert_one_yocto", out)
        self.assertIn("internal_transfer", out)

    def test_absent(self):
        self.assertIsNone(run("missing_one_yocto", "pub fn f(&mut self) { self.x = 1; }"))


class SignerAuthTest(unittest.TestCase):
    def test_swaps_predecessor_in_check(self):
        out = run("signer_auth", """
    pub fn set_owner(&mut self, owner_id: AccountId) {
        assert_eq!(env::predecessor_account_id(), self.owner_id, "owner");
        self.owner_id = owner_id;
    }""")
        self.assertIn("assert_eq!(env::signer_account_id(), self.owner_id", out)

    def test_swaps_let_used_in_check(self):
        out = run("signer_auth", """
    pub fn remove_guardian(&mut self, g: AccountId) {
        let caller = env::predecessor_account_id();
        require!(self.guardians.contains(&caller), "no");
        self.guardians.remove(&g);
    }""")
        self.assertIn("let caller = env::signer_account_id();", out)

    def test_swaps_caller_identity_in_mutating_public_fn(self):
        out = run("signer_auth", """
    pub fn withdraw(&mut self, amount: U128) {
        let account_id = env::predecessor_account_id();
        self.internal_withdraw(&account_id, amount.0);
    }""")
        self.assertIn("let account_id = env::signer_account_id();", out)
        out = run("signer_auth", """
    pub fn verify(&mut self, request: Request) {
        log!("predecessor={:?}", env::predecessor_account_id());
        self.pending.insert(&env::predecessor_account_id(), &request);
    }""")
        self.assertIn('log!("predecessor={:?}", env::predecessor_account_id());', out)
        self.assertIn("self.pending.insert(&env::signer_account_id(), &request);", out)
        self.assertIsNone(run("signer_auth", """
    pub fn get_mine(&self) -> u128 { self.balances.get(&env::predecessor_account_id()).unwrap_or(0) }"""))

    def test_ignores_self_check(self):
        self.assertIsNone(run("signer_auth", """
    pub fn on_cb(&mut self) { assert_eq!(env::predecessor_account_id(), env::current_account_id()); }"""))


class UnguardedUpgradeTest(unittest.TestCase):
    def test_deletes_auth_in_deploy(self):
        out = run("unguarded_upgrade", """
    pub fn upgrade(&self) -> Promise {
        self.assert_owner();
        let code = env::input().expect("no input");
        Promise::new(env::current_account_id()).deploy_contract(code)
    }""")
        self.assertNotIn("assert_owner", out)
        self.assertIn("deploy_contract", out)

    def test_migrate_private(self):
        out = run("unguarded_upgrade", """
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self { env::state_read().unwrap() }""")
        self.assertNotIn("#[private]", out)
        self.assertIn("#[init(ignore_state)]", out)


class UnsafeArithmeticTest(unittest.TestCase):
    def test_checked_add_unwrap(self):
        out = run("unsafe_arithmetic", """
    pub fn deposit(&mut self, amount: u128) {
        self.total_supply = self.total_supply.checked_add(amount).expect("overflow");
    }""")
        self.assertIn("self.total_supply = self.total_supply + amount;", out)

    def test_checked_mul_parenthesized(self):
        out = run("unsafe_arithmetic", """
    pub fn f(&self, amount: u128, rate: u128) -> u128 {
        amount.checked_mul(rate + 1).unwrap() / 10
    }""")
        self.assertIn("(amount * (rate + 1)) / 10", out)
        self.assertTrue(clean_parse(out))

    def test_saturating_and_widening(self):
        out = run("unsafe_arithmetic", """
    pub fn f(&mut self, amount: u128) { self.balance = self.balance.saturating_sub(amount); }""")
        self.assertIn("self.balance = self.balance - amount;", out)
        out = run("unsafe_arithmetic", """
    pub fn reward(&self, amount: u64, rate: u64) -> u64 {
        (amount as u128 * rate as u128 / DENOM) as u64
    }""")
        self.assertIn("(amount * rate / DENOM) as u64", out)

    def test_saturating_needs_amount(self):
        self.assertIsNone(run("unsafe_arithmetic", """
    pub fn cutoff(&self, height: u64) -> u64 { height.saturating_sub(EXPIRY_BLOCKS) }"""))

    def test_absent(self):
        self.assertIsNone(run("unsafe_arithmetic", "pub fn f(&self, a: u8) -> u8 { a + 1 }"))


class PrecisionRoundingTest(unittest.TestCase):
    def test_reorders_mul_div(self):
        out = run("precision_rounding", """
    pub fn shares(&self, amount: u128) -> u128 {
        amount * self.total_shares / self.total_balance
    }""")
        self.assertIn("amount / self.total_balance * self.total_shares", out)

    def test_checked_chain(self):
        out = run("precision_rounding", """
    pub fn fee(&self, amount: u128) -> u128 {
        amount.checked_mul(self.fee_bps).unwrap().checked_div(10_000).unwrap()
    }""")
        self.assertIn("amount.checked_div(10_000).unwrap().checked_mul(self.fee_bps).unwrap()", out)
        out = run("precision_rounding", """
    pub fn fee(&self, amount: u128) -> u128 {
        amount
            .checked_mul(self.fee_bps)
            .unwrap()
            .checked_div(10_000)
            .unwrap()
    }""")
        self.assertIn("amount\n        .checked_div(10_000)\n        .unwrap()\n        .checked_mul(self.fee_bps)\n", out)

    def test_ceil_to_floor(self):
        out = run("precision_rounding", """
    pub fn debt_shares(&self, amount: u128) -> u128 {
        (amount * self.shares + self.debt - 1) / self.debt
    }""")
        self.assertIn("(amount * self.shares) / self.debt", out)
        out = run("precision_rounding", """
    pub fn owed(&self, amount: u128) -> u128 { amount.div_ceil(self.rate) }""")
        self.assertIn("amount / self.rate", out)


class StorageStakingTest(unittest.TestCase):
    def test_deletes_storage_check_and_dead_let(self):
        out = run("storage_staking", """
    #[payable]
    pub fn add_message(&mut self, text: String) {
        let initial_storage = env::storage_usage();
        self.messages.push(&text);
        let used = env::storage_usage() - initial_storage;
        require!(env::attached_deposit() >= env::storage_byte_cost() * used as u128, "deposit");
    }""")
        self.assertNotIn("storage_byte_cost", out)
        self.assertNotIn("initial_storage", out)
        self.assertIn("self.messages.push(&text);", out)
        self.assertTrue(clean_parse(out))

    def test_deletes_refund_deposit(self):
        out = run("storage_staking", """
    #[payable]
    pub fn nft_mint(&mut self, token_id: String) {
        let initial = env::storage_usage();
        self.tokens.insert(&token_id, &env::predecessor_account_id());
        refund_deposit(env::storage_usage() - initial);
    }""")
        self.assertNotIn("refund_deposit", out)
        self.assertNotIn("let initial", out)


class FtReceiverTrustTest(unittest.TestCase):
    def test_deletes_token_check(self):
        out = run("ft_receiver_trust", """
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128> {
        let token_id = env::predecessor_account_id();
        require!(token_id == self.token_account_id, "wrong token");
        self.internal_deposit(&sender_id, &token_id, amount.0);
        PromiseOrValue::Value(U128(0))
    }""")
        self.assertNotIn("wrong token", out)
        self.assertIn("self.internal_deposit(&sender_id, &token_id, amount.0);", out)

    def test_only_receivers(self):
        self.assertIsNone(run("ft_receiver_trust", """
    pub fn deposit(&mut self) { require!(env::predecessor_account_id() == self.token_account_id); }"""))


class UncheckedReceiverTest(unittest.TestCase):
    def test_deletes_registration_check(self):
        out = run("unchecked_receiver", """
    pub fn transfer(&mut self, receiver_id: AccountId, amount: u128) {
        assert!(self.accounts.contains_key(&receiver_id), "receiver not registered");
        self.internal_transfer(&env::predecessor_account_id(), &receiver_id, amount);
    }""")
        self.assertNotIn("contains_key", out)

    def test_keeps_side_effecting_condition(self):
        self.assertIsNone(run("unchecked_receiver", """
    pub fn internal_register_account(&mut self, account_id: &AccountId) {
        if self.accounts.insert(account_id, &0).is_some() {
            env::panic_str("The account is already registered");
        }
    }"""))

    def test_ignores_unrelated_registration_words(self):
        self.assertIsNone(run("unchecked_receiver", """
    fn hook(&mut self, account_id: AccountId) {
        self.burn(&account_id).unwrap_or_else(|e| env::panic_str("burn failed during forced unregistration"));
    }"""))

    def test_ignores_caller_registration(self):
        self.assertIsNone(run("unchecked_receiver", """
    pub fn liquidate(&mut self) {
        let account_id = env::predecessor_account_id();
        assert!(self.is_registered(account_id.clone()), "not registered");
        self.x = 1;
    }"""))

    def test_ignores_allowlist_and_already_exists(self):
        self.assertIsNone(run("unchecked_receiver", """
    pub fn add_allowed_account(&mut self, account_id: AccountId) {
        require!(!self.allowed_accounts.contains(&account_id), "ERR_ACCOUNT_ALREADY_EXIST");
        self.allowed_accounts.push(account_id)
    }"""))
        self.assertIsNone(run("unchecked_receiver", """
    fn assert_registered(&self, account_id: &AccountId) {
        require!(self.accounts.contains_key(account_id), "not registered");
    }"""))

    def test_expect_registered_to_default(self):
        out = run("unchecked_receiver", """
    fn internal_deposit(&mut self, receiver_id: &AccountId, amount: u128) {
        let balance = self.accounts.get(receiver_id).expect("The account is not registered");
        self.accounts.insert(receiver_id, &(balance + amount));
    }""")
        self.assertIn("self.accounts.get(receiver_id).unwrap_or_default();", out)


class GasDosTest(unittest.TestCase):
    def test_deletes_prepaid_gas_check(self):
        out = run("gas_dos", """
    pub fn ft_transfer_call(&mut self, receiver_id: AccountId, amount: U128, msg: String) -> Promise {
        require!(env::prepaid_gas() > GAS_FOR_FT_TRANSFER_CALL, "More gas is required");
        self.internal_transfer(&receiver_id, amount.0);
        ext_receiver::ext(receiver_id).ft_on_transfer(amount, msg)
    }""")
        self.assertNotIn("prepaid_gas", out)

    def test_removes_pagination(self):
        out = run("gas_dos", """
    pub fn get_accounts(&self, from_index: Option<u64>, limit: Option<u64>) -> Vec<AccountId> {
        let start = from_index.unwrap_or(0);
        self.accounts
            .keys()
            .skip(start as usize)
            .take(limit.unwrap_or(50) as usize)
            .collect()
    }""")
        self.assertNotIn("from_index", out)
        self.assertNotIn("limit", out)
        self.assertNotIn(".skip(", out)
        self.assertIn("pub fn get_accounts(&self) -> Vec<AccountId>", out)
        self.assertTrue(clean_parse(out))


class OraclePriceTest(unittest.TestCase):
    def test_deletes_freshness_check(self):
        out = run("oracle_price", """
    pub fn oracle_on_call(&mut self, sender_id: AccountId, data: PriceData, msg: String) {
        assert!(data.timestamp + self.max_price_age >= env::block_timestamp(), "stale price");
        self.internal_execute(sender_id, data);
    }""")
        self.assertNotIn("max_price_age", out)

    def test_needs_freshness_comparison(self):
        self.assertIsNone(run("oracle_price", """
    pub fn collateralize(&mut self, price_pair: PricePair) {
        require!(!self.position.status(price_pair, env::block_timestamp_ms()).is_liquidation(), "liquidatable");
    }"""))
        self.assertIsNone(run("oracle_price", """
    pub fn funding_index(m: &Market, now: u64) -> i128 {
        if m.timestamp > now { return m.funding_index.0; }
        m.oracle_price.0
    }"""))

    def test_order_expiry_is_not_price_staleness(self):
        self.assertIsNone(run("oracle_price", """
    pub fn add_limit_order(&mut self, expiry: u64) {
        assert!(expiry > env::block_timestamp_ms(), "Limit order already expired");
        self.orders.push(self.mark_price());
    }"""))

    def test_needs_price_context(self):
        self.assertIsNone(run("oracle_price", """
    pub fn claim(&mut self) { assert!(env::block_timestamp() > self.unlock_timestamp); self.x = 1; }"""))


class PipelineTest(unittest.TestCase):
    def test_mutate_returns_valid_distinct_mutants(self):
        f = fn_of("""
    #[payable]
    pub fn set_fee(&mut self, fee: u32) {
        assert_one_yocto();
        self.assert_owner();
        self.fee = fee;
    }""")
        muts, failed = mutate(f)
        self.assertEqual(set(muts), {"missing_one_yocto", "missing_access_control"})
        self.assertEqual(failed, [])
        for code in muts.values():
            self.assertNotEqual(normalized(code), normalized(f["code"]))

    def test_mutate_rejects_broken_or_identical_output(self):
        f = fn_of("pub fn f(&mut self) { assert_one_yocto(); self.x = 1; }")
        saved = dict(OPERATORS)
        try:
            OPERATORS.clear()
            OPERATORS.update({"broken": lambda g: g["code"].replace("{", "", 1),
                              "same": lambda g: g["code"] + "  // c", "boom": lambda g: 1 / 0})
            muts, failed = mutate(f)
        finally:
            OPERATORS.clear()
            OPERATORS.update(saved)
        self.assertEqual(muts, {})
        self.assertEqual(sorted(failed), ["boom", "broken", "same"])

    def test_select_caps(self):
        cands = [{"id": f"o{i}", "mutants": {"a": "x", "b": "y", "c": "z"}} for i in range(50)]
        picked = select(cands, per_op=30, per_fn=2, rank={"a": 0, "b": 1, "c": 2}, seed="r")
        ops = [op for _, op in picked]
        self.assertTrue(all(ops.count(o) <= 30 for o in "abc"))
        per_fn = {}
        for oid, _ in picked:
            per_fn[oid] = per_fn.get(oid, 0) + 1
        self.assertTrue(all(v <= 2 for v in per_fn.values()))
        self.assertEqual(len(picked), 90)


class ContractFilesTest(unittest.TestCase):
    def test_only_crates_with_contract_markers(self):
        with tempfile.TemporaryDirectory() as d:
            files = {"Cargo.toml": "[workspace]\n[workspace.dependencies]\nnear-sdk = \"5\"\n",
                     "contract/Cargo.toml": "[package]\nname='c'\n", "contract/src/lib.rs": "#[near(contract_state)]\n",
                     "contract/src/math.rs": "pub fn f() {}\n",
                     "node/Cargo.toml": "[package]\nname='n'\n", "node/src/main.rs": "use near_sdk::AccountId;\n",
                     "contract/target/x.rs": "#[near_bindgen]\n"}
            for rel, txt in files.items():
                (Path(d) / rel).parent.mkdir(parents=True, exist_ok=True)
                (Path(d) / rel).write_text(txt)
            got = sorted(rel for rel, _ in contract_files(Path(d)))
            self.assertEqual(got, ["contract/src/lib.rs", "contract/src/math.rs"])


if __name__ == "__main__":
    unittest.main()
