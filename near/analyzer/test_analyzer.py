"""Analyzer tests. Detector cases are vulnerable/fixed pairs adapted from BlockSec Rustle's detector docs
(github.com/blocksecteam/rustle/tree/main/docs/detectors) and NEAR docs' security pages."""
import unittest

from near.analyzer import detect, extract_functions, features
from near.analyzer.features import FEATURE_KEYS


def contract(body: str, impl: str = "#[near_bindgen]\nimpl Contract {") -> str:
    return f"{impl}\n{body}\n}}\n"


def fn_of(src: str, name: str) -> dict:
    return next(f for f in extract_functions(src, "src/lib.rs") if f["fn"] == name)


def classes(src: str, name: str, file_src: str | None = None) -> set[str]:
    return {h["vuln_class"] for h in detect(fn_of(src, name), file_src)}


class ExtractTest(unittest.TestCase):
    SRC = '''
use near_sdk::{near_bindgen, env};

/// The contract
#[near_bindgen]
impl Contract {
    /// Sets the owner.
    #[payable]
    pub fn set_owner(&mut self, owner_id: AccountId) {
        assert_one_yocto();
        self.owner_id = owner_id;
    }

    #[private]
    pub fn on_done(&mut self, #[callback_result] r: Result<U128, PromiseError>) {}

    fn helper(&self) -> u8 { 1 }
}

#[near]
impl FungibleTokenReceiver for Contract {
    fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128> {
        PromiseOrValue::Value(U128(0))
    }
}

impl Contract {
    pub(crate) fn internal(&mut self) {}
}

mod upgrade {
    #[no_mangle]
    pub extern "C" fn upgrade() {}
}

pub fn free() {}
'''

    def test_extracts_all_fns_with_context(self):
        fns = {f["fn"]: f for f in extract_functions(self.SRC, "src/lib.rs")}
        self.assertEqual(set(fns), {"set_owner", "on_done", "helper", "ft_on_transfer", "internal", "upgrade", "free"})
        so = fns["set_owner"]
        self.assertTrue(so["code"].startswith("/// Sets the owner.\n#[payable]\npub fn set_owner"))
        self.assertEqual((so["impl"], so["is_near_bindgen"], so["is_public"], so["is_payable"]),
                         ("Contract", True, True, True))
        self.assertEqual(so["attrs"], ["payable"])
        self.assertEqual(so["start_line"], 7)
        self.assertEqual(so["end_line"], 12)
        self.assertEqual(fns["on_done"]["attrs"], ["private", "callback_result"])
        self.assertFalse(fns["helper"]["is_public"])
        ft = fns["ft_on_transfer"]
        self.assertEqual((ft["impl"], ft["trait"], ft["is_near_bindgen"], ft["is_public"]),
                         ("Contract", "FungibleTokenReceiver", True, True))
        self.assertFalse(fns["internal"]["is_near_bindgen"])
        self.assertFalse(fns["internal"]["is_public"])
        self.assertEqual(fns["upgrade"]["attrs"], ["no_mangle"])
        self.assertIsNone(fns["free"]["impl"])

    def test_bad_input_never_raises(self):
        self.assertEqual(extract_functions("", "x.rs"), [])
        broken = "impl X { pub fn ok(&self) -> u8 { 1 } pub fn bad(&self { let x = ; }\n macro_rules! m { () => {} }"
        names = [f["fn"] for f in extract_functions(broken, "x.rs")]
        self.assertIn("ok", names)
        self.assertEqual(extract_functions("\x00\xff garbage {{{", "x.rs"), [])


class DetectorTest(unittest.TestCase):
    def assertFires(self, src, name, cls, file_src=None):
        self.assertIn(cls, classes(src, name, file_src))

    def assertQuiet(self, src, name, cls, file_src=None):
        self.assertNotIn(cls, classes(src, name, file_src))

    def test_hit_shape(self):
        src = contract("pub fn callback_stake(&mut self) { self.staked = true; }")
        hit = next(h for h in detect(fn_of(src, "callback_stake")) if h["vuln_class"] == "non_private_callback")
        self.assertEqual(set(hit), {"detector", "vuln_class", "line", "message", "severity"})
        self.assertIn(hit["severity"], {"high", "medium", "low", "info"})
        self.assertEqual(hit["line"], 3)

    def test_non_private_callback(self):
        bad = contract("pub fn callback_stake(&mut self) { self.staked = true; }")
        good = contract("#[private]\npub fn callback_stake(&mut self) { self.staked = true; }")
        guarded = contract("pub fn callback_stake(&mut self) {\n"
                           "  assert_eq!(env::predecessor_account_id(), env::current_account_id());\n"
                           "  self.staked = true; }")
        self.assertFires(bad, "callback_stake", "non_private_callback")
        self.assertQuiet(good, "callback_stake", "non_private_callback")
        self.assertQuiet(guarded, "callback_stake", "non_private_callback")
        # referenced as a .then() target elsewhere in the file
        file_src = contract("pub fn stake(&mut self) -> Promise { ext_pool::ext(p).deposit()"
                            ".then(Self::ext(env::current_account_id()).with_static_gas(G).after_stake(a)) }\n"
                            "pub fn after_stake(&mut self, a: U128) { self.total += a.0; }")
        self.assertFires(file_src, "after_stake", "non_private_callback", file_src)
        self.assertQuiet(file_src, "after_stake", "non_private_callback", None)
        # NEP receivers are public by design
        recv = contract("pub fn ft_on_transfer(&mut self, s: AccountId, a: U128, m: String) -> U128 {"
                        " let t = env::predecessor_account_id(); U128(0) }")
        self.assertQuiet(recv, "ft_on_transfer", "non_private_callback")

    def test_unhandled_promise_result(self):
        bad = contract("#[private]\npub fn on_withdraw(&mut self, amount: U128) { self.pending -= amount.0; }")
        good = contract("#[private]\npub fn on_withdraw(&mut self, amount: U128) {\n"
                        "  if !is_promise_success() { self.balance += amount.0; } }")
        good2 = contract("#[private]\npub fn on_withdraw(&mut self, #[callback_result] r: Result<(), PromiseError>,"
                         " amount: U128) { if r.is_err() { self.balance += amount.0; } }")
        self.assertFires(bad, "on_withdraw", "unhandled_promise_result")
        self.assertQuiet(good, "on_withdraw", "unhandled_promise_result")
        self.assertQuiet(good2, "on_withdraw", "unhandled_promise_result")
        # value-moving call with no callback (Rustle unhandled-promise)
        bad2 = contract("pub fn withdraw(&mut self, amount: U128) {\n"
                        "  self.balances.insert(&env::predecessor_account_id(), &0);\n"
                        "  ext_ft::ext(self.token.clone()).with_attached_deposit(1)"
                        ".ft_transfer(env::predecessor_account_id(), amount, None); }")
        good3 = contract("pub fn withdraw(&mut self, amount: U128) -> Promise {\n"
                         "  self.balances.insert(&env::predecessor_account_id(), &0);\n"
                         "  ext_ft::ext(self.token.clone()).with_attached_deposit(1)"
                         ".ft_transfer(env::predecessor_account_id(), amount, None)"
                         ".then(Self::ext(env::current_account_id()).on_withdraw(amount)) }")
        self.assertFires(bad2, "withdraw", "unhandled_promise_result")
        self.assertQuiet(good3, "withdraw", "unhandled_promise_result")

    def test_async_reentrancy(self):
        victim_bad = contract("""
pub fn withdraw(&mut self, amount: u128) -> Promise {
    assert!(self.attacker_balance >= amount);
    ext_ft_token::ft_transfer_call(amount.into(), &FT_TOKEN, 0, GAS)
        .then(ext_self::ft_resolve_transfer(amount.into(), &env::current_account_id(), 0, GAS))
}
#[private]
pub fn ft_resolve_transfer(&mut self, amount: u128) {
    match env::promise_result(0) {
        PromiseResult::NotReady => unreachable!(),
        PromiseResult::Successful(_) => {
            self.attacker_balance -= amount;
        }
        PromiseResult::Failed => {}
    };
}""")
        victim_good = contract("""
pub fn withdraw(&mut self, amount: u128) -> Promise {
    assert!(self.attacker_balance >= amount);
    self.attacker_balance -= amount;
    ext_ft_token::ft_transfer_call(amount.into(), &FT_TOKEN, 0, GAS)
        .then(ext_self::ft_resolve_transfer(amount.into(), &env::current_account_id(), 0, GAS))
}
#[private]
pub fn ft_resolve_transfer(&mut self, amount: u128) {
    match env::promise_result(0) {
        PromiseResult::NotReady => unreachable!(),
        PromiseResult::Successful(_) => {}
        PromiseResult::Failed => {
            self.attacker_balance += amount;
        }
    };
}""")
        self.assertFires(victim_bad, "withdraw", "async_reentrancy")
        self.assertFires(victim_bad, "ft_resolve_transfer", "async_reentrancy")
        self.assertQuiet(victim_good, "withdraw", "async_reentrancy")
        self.assertQuiet(victim_good, "ft_resolve_transfer", "async_reentrancy")

    def test_missing_access_control(self):
        bad = contract("pub fn set_fee(&mut self, fee: u32) { self.fee = fee; }")
        good = contract("pub fn set_fee(&mut self, fee: u32) { self.assert_owner(); self.fee = fee; }")
        good2 = contract("#[only(Role::DAO)]\npub fn set_fee(&mut self, fee: u32) { self.fee = fee; }")
        good3 = contract("pub fn set_fee(&mut self, fee: u32) {\n"
                         "  require!(env::predecessor_account_id() == self.owner_id, \"no\"); self.fee = fee; }")
        self.assertFires(bad, "set_fee", "missing_access_control")
        self.assertQuiet(good, "set_fee", "missing_access_control")
        self.assertQuiet(good2, "set_fee", "missing_access_control")
        self.assertQuiet(good3, "set_fee", "missing_access_control")
        user = contract("pub fn add_liquidity(&mut self, amounts: Vec<U128>) { self.pool.add(amounts); }")
        self.assertQuiet(user, "add_liquidity", "missing_access_control")
        view = contract("pub fn set_fee(&self) -> u32 { self.fee }")
        self.assertQuiet(view, "set_fee", "missing_access_control")

    def test_missing_one_yocto(self):
        bad = contract("#[payable]\npub fn set_owner(&mut self, owner_id: AccountId) {\n"
                       "  self.assert_owner(); self.owner_id = owner_id; }")
        good = contract("#[payable]\npub fn set_owner(&mut self, owner_id: AccountId) {\n"
                        "  assert_one_yocto(); self.assert_owner(); self.owner_id = owner_id; }")
        self.assertFires(bad, "set_owner", "missing_one_yocto")
        self.assertQuiet(good, "set_owner", "missing_one_yocto")
        ft_bad = contract("pub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {\n"
                          "  let sender = env::predecessor_account_id();\n"
                          "  self.internal_withdraw(&sender, amount.0); self.internal_deposit(&receiver_id, amount.0); }")
        ft_delegate = contract("#[payable]\npub fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, "
                               "memo: Option<String>) { self.token.ft_transfer(receiver_id, amount, memo) }")
        self.assertFires(ft_bad, "ft_transfer", "missing_one_yocto")
        self.assertQuiet(ft_delegate, "ft_transfer", "missing_one_yocto")

    def test_signer_auth(self):
        bad = contract("pub fn withdraw_all(&mut self) {\n"
                       "  assert_eq!(env::signer_account_id(), self.owner_id); self.drain(); }")
        bad2 = contract("pub fn pause(&mut self) {\n  let caller = env::signer_account_id();\n"
                        "  require!(caller == self.owner_id); self.paused = true; }")
        good = contract("pub fn withdraw_all(&mut self) {\n"
                        "  assert_eq!(env::predecessor_account_id(), self.owner_id); self.drain(); }")
        self.assertFires(bad, "withdraw_all", "signer_auth")
        self.assertFires(bad2, "pause", "signer_auth")
        self.assertQuiet(good, "withdraw_all", "signer_auth")
        logging = contract("pub fn ping(&mut self) { log!(\"{}\", env::signer_account_id()); }")
        self.assertQuiet(logging, "ping", "signer_auth")

    def test_unguarded_upgrade(self):
        bad = contract("pub fn upgrade(&self, code: Vec<u8>) -> Promise {\n"
                       "  Promise::new(env::current_account_id()).deploy_contract(code) }")
        good = contract("pub fn upgrade(&self, code: Vec<u8>) -> Promise {\n  self.assert_owner();\n"
                        "  Promise::new(env::current_account_id()).deploy_contract(code) }")
        factory = contract("pub fn create(&mut self, name: String) -> Promise {\n"
                           "  Promise::new(sub).create_account().transfer(D).deploy_contract(CODE.to_vec()) }")
        bad_migrate = contract("#[init(ignore_state)]\npub fn migrate() -> Self {\n"
                               "  let old: Old = env::state_read().unwrap(); Self { a: old.a } }")
        good_migrate = contract("#[private]\n#[init(ignore_state)]\npub fn migrate() -> Self {\n"
                                "  let old: Old = env::state_read().unwrap(); Self { a: old.a } }")
        self.assertFires(bad, "upgrade", "unguarded_upgrade")
        self.assertQuiet(good, "upgrade", "unguarded_upgrade")
        self.assertQuiet(factory, "create", "unguarded_upgrade")
        self.assertFires(bad_migrate, "migrate", "unguarded_upgrade")
        self.assertQuiet(good_migrate, "migrate", "unguarded_upgrade")

    def test_unsafe_arithmetic(self):
        bad = contract("pub fn shares(&self, amount: U128) -> u64 { (amount.0 * self.rate) as u64 }")
        bad2 = contract("pub fn add(&mut self, amount: u128) { self.total_supply = self.total_supply.wrapping_add(amount); }")
        good = contract("pub fn shares(&self, amount: U128) -> u128 { amount.0.checked_mul(self.rate).unwrap() }")
        self.assertFires(bad, "shares", "unsafe_arithmetic")
        self.assertFires(bad2, "add", "unsafe_arithmetic")
        self.assertQuiet(good, "shares", "unsafe_arithmetic")
        small = contract("pub fn idx(&self, i: u32) -> usize { i as usize }")
        self.assertQuiet(small, "idx", "unsafe_arithmetic")

    def test_precision_rounding(self):
        bad = contract("fn reward(&self, farm: &Farm) -> u128 {\n  let reward_per_session =\n"
                       "    farm.amount / (farm.end_date - farm.start_date) as u128 * SESSION_INTERVAL as u128;\n"
                       "  reward_per_session }")
        good = contract("fn reward(&self, farm: &Farm) -> u128 {\n  let reward_per_session =\n"
                        "    farm.amount * SESSION_INTERVAL as u128 / (farm.end_date - farm.start_date) as u128;\n"
                        "  reward_per_session }")
        floor = contract("fn epoch_start(&self, ts: u64) -> u64 { ts / INTERVAL * INTERVAL }")
        rnd = contract("fn fee(&self, amount: f64) -> f64 { (amount * self.fee_rate).round() }")
        self.assertFires(bad, "reward", "precision_rounding")
        self.assertQuiet(good, "reward", "precision_rounding")
        self.assertQuiet(floor, "epoch_start", "precision_rounding")
        self.assertFires(rnd, "fee", "precision_rounding")
        deref = contract("fn f(&self, a: &u128) -> u128 { let x = a / 2; *a + x }")
        self.assertQuiet(deref, "f", "precision_rounding")

    def test_storage_staking(self):
        bad = contract("pub fn register(&mut self, name: String) {\n"
                       "  self.names.insert(&env::predecessor_account_id(), &name); }")
        good = contract("#[payable]\npub fn register(&mut self, name: String) {\n"
                        "  let before = env::storage_usage();\n"
                        "  self.names.insert(&env::predecessor_account_id(), &name);\n"
                        "  let cost = (env::storage_usage() - before) as u128 * env::storage_byte_cost();\n"
                        "  assert!(env::attached_deposit() >= cost); }")
        self.assertFires(bad, "register", "storage_staking")
        self.assertQuiet(good, "register", "storage_staking")
        unreg_bad = contract("""
fn storage_unregister(&mut self, force: Option<bool>) -> bool {
    assert_one_yocto();
    let account_id = env::predecessor_account_id();
    if let Some(balance) = self.accounts.get(&account_id) {
        self.accounts.remove(&account_id);
        self.total_supply -= balance;
        Promise::new(account_id.clone()).transfer(self.storage_balance_bounds().min.0 + 1);
        return true;
    }
    false
}""", impl="#[near_bindgen]\nimpl StorageManagement for Contract {")
        unreg_good = contract("""
fn storage_unregister(&mut self, force: Option<bool>) -> bool {
    assert_one_yocto();
    let account_id = env::predecessor_account_id();
    let force = force.unwrap_or(false);
    if let Some(balance) = self.accounts.get(&account_id) {
        if balance == 0 || force {
            self.accounts.remove(&account_id);
            self.total_supply -= balance;
            Promise::new(account_id.clone()).transfer(self.storage_balance_bounds().min.0 + 1);
            true
        } else { env::panic_str("positive balance") }
    } else { false }
}""", impl="#[near_bindgen]\nimpl StorageManagement for Contract {")
        self.assertFires(unreg_bad, "storage_unregister", "storage_staking")
        self.assertQuiet(unreg_good, "storage_unregister", "storage_staking")

    def test_ft_receiver_trust(self):
        bad = contract("pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String)"
                       " -> PromiseOrValue<U128> {\n  let d = self.deposits.get(&sender_id).unwrap_or(0);\n"
                       "  self.deposits.insert(&sender_id, &(d + amount.0)); PromiseOrValue::Value(U128(0)) }")
        good = contract("pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String)"
                        " -> PromiseOrValue<U128> {\n"
                        "  require!(env::predecessor_account_id() == self.token_id, \"wrong token\");\n"
                        "  let d = self.deposits.get(&sender_id).unwrap_or(0);\n"
                        "  self.deposits.insert(&sender_id, &(d + amount.0)); PromiseOrValue::Value(U128(0)) }")
        self.assertFires(bad, "ft_on_transfer", "ft_receiver_trust")
        self.assertQuiet(good, "ft_on_transfer", "ft_receiver_trust")

    def test_unchecked_receiver(self):
        bad = contract("pub fn internal_unwrap_balance_unsafe(&mut self, account_id: &AccountId, amount: u128) {\n"
                       "  let b = self.accounts.get(account_id).unwrap_or(0);\n"
                       "  self.accounts.insert(account_id, &(b + amount)); }", impl="impl Contract {")
        good = contract("pub fn internal_unwrap_balance_safe(&mut self, account_id: &AccountId, amount: u128) {\n"
                        "  let b = self.accounts.get(account_id)"
                        ".unwrap_or_else(|| env::panic_str(\"Account is not registered\"));\n"
                        "  self.accounts.insert(account_id, &(b + amount)); }", impl="impl Contract {")
        self.assertFires(bad, "internal_unwrap_balance_unsafe", "unchecked_receiver")
        self.assertQuiet(good, "internal_unwrap_balance_safe", "unchecked_receiver")
        self_bad = contract("pub fn internal_transfer(&mut self, sender_id: &AccountId, receiver_id: &AccountId,"
                            " amount: u128) {\n  self.internal_withdraw(sender_id, amount);\n"
                            "  self.internal_deposit(receiver_id, amount); }", impl="impl Contract {")
        self_good = contract("pub fn internal_transfer(&mut self, sender_id: &AccountId, receiver_id: &AccountId,"
                             " amount: u128) {\n  require!(sender_id != receiver_id, \"same\");\n"
                             "  self.internal_withdraw(sender_id, amount);\n"
                             "  self.internal_deposit(receiver_id, amount); }", impl="impl Contract {")
        self.assertFires(self_bad, "internal_transfer", "unchecked_receiver")
        self.assertQuiet(self_good, "internal_transfer", "unchecked_receiver")

    def test_gas_dos(self):
        bad = contract("pub fn update_all_users(&mut self) {\n"
                       "  for user in self.users.iter_mut() { user.complex_calc(); } }")
        good = contract("pub fn update_users(&mut self, from: u64, limit: u64) {\n"
                        "  for user in self.users.iter_mut().skip(from as usize).take(limit as usize) {"
                        " user.complex_calc(); } }")
        self.assertFires(bad, "update_all_users", "gas_dos")
        self.assertQuiet(good, "update_users", "gas_dos")
        gas_bad = contract("pub fn ft_transfer_call(&mut self, r: AccountId, a: U128, msg: String) -> Promise {\n"
                           "  ext_recv::ext(r).ft_on_transfer(a, msg)"
                           ".then(Self::ext(env::current_account_id()).ft_resolve_transfer(a)) }")
        gas_good = contract("pub fn ft_transfer_call(&mut self, r: AccountId, a: U128, msg: String) -> Promise {\n"
                            "  require!(env::prepaid_gas() > GAS_FOR_FT_TRANSFER_CALL, \"More gas is required\");\n"
                            "  ext_recv::ext(r).ft_on_transfer(a, msg)"
                            ".then(Self::ext(env::current_account_id()).ft_resolve_transfer(a)) }")
        self.assertFires(gas_bad, "ft_transfer_call", "gas_dos")
        self.assertQuiet(gas_good, "ft_transfer_call", "gas_dos")

    def test_oracle_price(self):
        bad = contract("pub fn liquidate(&mut self, account_id: AccountId, price: U128) {\n"
                       "  let value = self.collateral(&account_id) * price.0 / ONE; self.seize(value); }")
        stale = contract("#[private]\npub fn oracle_on_call(&mut self, data: PriceData) {\n"
                         "  let p = data.prices[0].price; self.value = self.amount * p.multiplier / p.decimals; }")
        fresh = contract("#[private]\npub fn oracle_on_call(&mut self, data: PriceData) {\n"
                         "  assert!(data.timestamp + self.max_age >= env::block_timestamp());\n"
                         "  let p = data.prices[0].price; self.value = self.amount * p.multiplier / p.decimals; }")
        self.assertFires(bad, "liquidate", "oracle_price")
        self.assertFires(stale, "oracle_on_call", "oracle_price")
        self.assertQuiet(fresh, "oracle_on_call", "oracle_price")
        owner = contract("pub fn set_price(&mut self, price: U128) { self.assert_owner(); self.p = price.0 * 2; }")
        self.assertQuiet(owner, "set_price", "oracle_price")

    def test_timestamp_randomness(self):
        bad = contract("pub fn draw(&mut self) { let w = env::block_timestamp() % self.players.len() as u64;"
                       " Promise::new(self.players[w as usize].clone()).transfer(self.pot); }")
        ok = contract("pub fn started(&self) -> bool { env::block_timestamp() > self.start }")
        self.assertFires(bad, "draw", "logic_error")
        self.assertQuiet(ok, "started", "logic_error")

    def test_smoke_false_positives_stay_quiet(self):
        """Patterns seen on audited repos (near-sdk-rs, LiNEAR, rNEAR, Burrow) that must not fire."""
        assoc = contract("pub fn with_hasher(&mut self, h: H) -> Self { let s = Self::with_hasher(h); self.x = 1; s }")
        self.assertEqual(detect(fn_of(assoc, "with_hasher"), assoc), [])
        delegate = contract("#[private]\npub fn ft_resolve_transfer(&mut self, sender_id: AccountId, "
                            "receiver_id: AccountId, amount: U128) -> U128 {\n"
                            "  self.token.internal_ft_resolve_transfer(&sender_id, receiver_id, amount).0.into() }")
        self.assertEqual(detect(fn_of(delegate, "ft_resolve_transfer")), [])
        success_hook = contract("#[private]\npub fn validator_withdraw_callback(&mut self, v: AccountId, a: U128) {\n"
                                "  let mut val = self.pool.get_validator(&v).unwrap();\n"
                                "  if is_promise_success() { val.on_withdraw_success(&mut self.pool); }\n"
                                "  else { val.on_withdraw_failed(&mut self.pool, a.0); } }")
        self.assertQuiet(success_hook, "validator_withdraw_callback", "async_reentrancy")
        nft = contract("fn internal_transfer(&mut self, sender_id: &AccountId, receiver_id: &AccountId, t: &str) {\n"
                       "  self.tokens_per_owner.remove(sender_id); self.owner_by_id.insert(t, receiver_id);\n"
                       "  self.tokens_per_owner.insert(receiver_id, t); }", impl="impl Contract {")
        self.assertQuiet(nft, "internal_transfer", "unchecked_receiver")
        nested = contract("#[payable]\nfn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, "
                          "memo: Option<String>) { self.data_mut().token.ft_transfer(receiver_id, amount, memo) }",
                          impl="#[near]\nimpl FungibleTokenCore for Contract {")
        self.assertQuiet(nested, "ft_transfer", "missing_one_yocto")
        panics = contract("#[payable]\nfn storage_unregister(&mut self, force: Option<bool>) -> bool {"
                          " env::panic_str(\"can't\"); }", impl="#[near]\nimpl StorageManagement for Contract {")
        self.assertEqual(detect(fn_of(panics, "storage_unregister")), [])
        owner_map = contract("pub fn set_beneficiary(&mut self, a: AccountId, bps: u32) {\n  self.assert_owner();\n"
                             "  let old = self.beneficiaries.get(&a).unwrap_or_default();\n"
                             "  self.beneficiaries.insert(&a, &bps); }")
        self.assertQuiet(owner_map, "set_beneficiary", "unchecked_receiver")
        stub = contract("pub fn some_callback(&mut self) { log_str(\"called\"); }")
        self.assertQuiet(stub, "some_callback", "non_private_callback")
        decimals = contract("pub fn scale(&self, amount: U128, cfg: Cfg) -> u128 {"
                            " amount.0 * 10u128.pow(cfg.extra_decimals as u32) }")
        self.assertQuiet(decimals, "scale", "unsafe_arithmetic")
        weighted = contract("pub fn ft_transfer_call(&mut self, r: AccountId, a: U128, msg: String) -> Promise {\n"
                            "  ext_recv::ext(r).ft_on_transfer(a, msg).then(Self::ext(env::current_account_id())"
                            ".with_static_gas(GAS_FOR_RESOLVE).ft_resolve_transfer(a)) }")
        self.assertQuiet(weighted, "ft_transfer_call", "gas_dos")
        recv = contract("pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> U128 {\n"
                        "  assert_eq!(env::predecessor_account_id(), self.token_id); self.total += amount.0; U128(0) }")
        self.assertEqual(detect(fn_of(recv, "ft_on_transfer")), [])
        deposit = contract("#[payable]\npub fn near_deposit(&mut self) {\n  let amount = env::attached_deposit();\n"
                           "  let a = env::predecessor_account_id();\n  if !self.accounts.contains_key(&a) {"
                           " self.register(&a); }\n  self.deposit(&a, amount); }")
        self.assertQuiet(deposit, "near_deposit", "missing_one_yocto")
        refund = contract("fn internal_refund(&mut self, receiver_id: AccountId, unused: u128) {\n"
                          "  let receiver_balance = self.accounts.get(&receiver_id).unwrap_or(0);\n"
                          "  if receiver_balance > 0 {"
                          " self.accounts.insert(&receiver_id, &(receiver_balance - unused)); } }",
                          impl="impl Contract {")
        self.assertQuiet(refund, "internal_refund", "unchecked_receiver")

    def test_rustle_examples(self):
        """Shapes from Rustle's examples/ directory."""
        dbm = contract("pub fn calculate_reward(&self, id: u16) -> U128 {\n  let stake = self.stakes.get(&id).unwrap();\n"
                       "  let per_unit = stake.amount / (stake.end_date - stake.start_date) as u128;\n"
                       "  let reward = per_unit * REWARD_RATE as u128;\n  U128::from(reward) }")
        self.assertFires(dbm, "calculate_reward", "precision_rounding")
        unreg = contract("fn storage_unregister(&mut self, force: Option<bool>) -> bool {\n  assert_one_yocto();\n"
                         "  let account_id = env::predecessor_account_id();\n  let force = force.unwrap_or(false);\n"
                         "  if let Some(balance) = self.accounts.get(&account_id) {\n"
                         "    self.accounts.remove(&account_id); return true; }\n  false }",
                         impl="impl StorageManagement for Contract {")
        self.assertFires(unreg, "storage_unregister", "storage_staking")
        dropped = contract("fn transfer_without_promise(&mut self, amount: U128) {\n"
                           "  ext_ft_core::ext(self.token_id.clone()).with_attached_deposit(1)\n"
                           "    .ft_transfer(self.depositor.clone(), amount, None); }\n"
                           "fn transfer_with_promise(&mut self, amount: U128) -> Promise {\n"
                           "  ext_ft_core::ext(self.token_id.clone()).with_attached_deposit(1)\n"
                           "    .ft_transfer(self.depositor.clone(), amount, None) }", impl="impl Contract {")
        self.assertFires(dropped, "transfer_without_promise", "unhandled_promise_result")
        self.assertQuiet(dropped, "transfer_with_promise", "unhandled_promise_result")
        helpers = contract("pub fn internal_unwrap_balance_unsafe(&self, a: &AccountId) -> Balance {"
                           " self.accounts.get(a).unwrap_or(0) }\n"
                           "pub fn internal_unwrap_balance_safe(&self, a: &AccountId) -> Balance {"
                           " self.accounts.get(a).unwrap_or_else(|| env::panic_str(\"not registered\")) }\n"
                           "pub fn internal_deposit_unsafe(&mut self, a: &AccountId, amount: Balance) {\n"
                           "  let balance = self.internal_unwrap_balance_unsafe(a);\n"
                           "  self.accounts.insert(a, &(balance + amount)); }\n"
                           "pub fn internal_deposit_safe(&mut self, a: &AccountId, amount: Balance) {\n"
                           "  let balance = self.internal_unwrap_balance_safe(a);\n"
                           "  self.accounts.insert(a, &(balance + amount)); }", impl="impl Contract {")
        self.assertFires(helpers, "internal_deposit_unsafe", "unchecked_receiver", helpers)
        self.assertQuiet(helpers, "internal_deposit_safe", "unchecked_receiver", helpers)
        unsaved = contract("pub fn modify_unsafe(&mut self, change: I128) {\n"
                           "  let mut balance = self.accounts.get(&env::predecessor_account_id()).unwrap();\n"
                           "  balance = balance.checked_add(change.0).unwrap(); }\n"
                           "pub fn modify_safe(&mut self, change: I128) {\n"
                           "  let mut balance = self.accounts.get(&env::predecessor_account_id()).unwrap();\n"
                           "  balance = balance.checked_add(change.0).unwrap();\n"
                           "  self.accounts.insert(&env::predecessor_account_id(), &balance); }", impl="impl Contract {")
        self.assertFires(unsaved, "modify_unsafe", "logic_error")
        self.assertQuiet(unsaved, "modify_safe", "logic_error")
        gas = contract("fn ft_transfer_call(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>,"
                       " msg: String) -> PromiseOrValue<U128> {\n  assert_one_yocto();\n"
                       "  ext_ft_receiver::ext(receiver_id.clone())"
                       ".with_static_gas(env::prepaid_gas() - GAS_FOR_FT_TRANSFER_CALL)\n"
                       "    .ft_on_transfer(sender_id.clone(), amount.into(), msg)\n"
                       "    .then(ext_ft_resolver::ext(env::current_account_id()).with_static_gas(G)"
                       ".ft_resolve_transfer(sender_id, receiver_id, amount.into())).into() }",
                       impl="#[near_bindgen]\nimpl FungibleTokenCore for Contract {")
        self.assertFires(gas, "ft_transfer_call", "gas_dos")
        revoke = contract("fn nft_revoke_all(&mut self, token_id: TokenId) {\n  assert_one_yocto();\n"
                          "  let predecessor_account_id = env::predecessor_account_id();\n"
                          "  if let Some(ids) = &mut self.approvals.get(&token_id) {\n"
                          "    refund_approved_account_ids(predecessor_account_id, ids);"
                          " self.approvals.remove(&token_id); } }",
                          impl="impl NonFungibleTokenApproval for Contract {")
        self.assertFires(revoke, "nft_revoke_all", "missing_access_control")
        idx = contract("fn generate_winner(&self, time: u64) -> AccountId {\n"
                       "  self.users[((time as u128) % (self.users.len() as u128)) as usize].clone() }")
        self.assertQuiet(idx, "generate_winner", "unsafe_arithmetic")
        remainder = contract("fn split(&self, x: u128) -> (u128, u128) {\n  let a = x / U384::from(D);\n"
                             "  let b = x - a * U384::from(D);\n  (a, b) }")
        self.assertQuiet(remainder, "split", "precision_rounding")
        other_coll = contract("fn count(&self, k: Pk) -> u32 { self.num_requests.get(&k).unwrap_or(0) }\n"
                              "fn confirm(&mut self, id: u32) {\n  let n = self.count(pk());\n"
                              "  self.confirmations.insert(&id, &n); }", impl="impl Contract {")
        self.assertQuiet(other_coll, "confirm", "unchecked_receiver", other_coll)

    def test_tests_are_marked_and_skipped(self):
        src = ("#[cfg(test)]\nmod tests {\n  #[test]\n  fn t() { assert_eq!(env::signer_account_id(), owner()); }\n"
               "  fn helper(&mut self) { self.fee = 1; }\n}\n"
               "#[test]\nfn top() {}\npub fn real() {}\n")
        fns = {f["fn"]: f for f in extract_functions(src, "src/lib.rs")}
        self.assertEqual({k: f["is_test"] for k, f in fns.items()}, {"t": True, "helper": True, "top": True,
                                                                     "real": False})
        self.assertEqual(detect(fns["t"]), [])

    def test_comments_and_strings_ignored(self):
        src = contract("pub fn set_fee(&mut self, fee: u32) {\n  // self.assert_owner();\n"
                       "  log!(\"assert_owner\"); self.fee = fee; }")
        self.assertFires(src, "set_fee", "missing_access_control")

    def test_audited_fns_quiet(self):
        """Typical correct near-sdk code fires nothing."""
        src = contract('''
#[init]
pub fn new(owner_id: AccountId) -> Self { Self { owner_id, fee: 0 } }

pub fn get_fee(&self) -> u32 { self.fee }

#[payable]
pub fn set_fee(&mut self, fee: u32) {
    assert_one_yocto();
    self.assert_owner();
    self.fee = fee;
}

#[private]
pub fn on_withdraw(&mut self, account_id: AccountId, amount: U128, #[callback_result] r: Result<(), PromiseError>) {
    if r.is_err() {
        self.deposits.insert(&account_id, &amount.0);
    }
}''')
        for f in extract_functions(src, "src/lib.rs"):
            self.assertEqual(detect(f, src), [], f["fn"])


class CargoTest(unittest.TestCase):
    def test_overflow_checks(self):
        from near.analyzer.detectors import overflow_checks_enabled
        self.assertTrue(overflow_checks_enabled('[package]\nname="x"\n[profile.release]\nopt-level = "z"\n'
                                                'overflow-checks = true\n'))
        self.assertFalse(overflow_checks_enabled('[profile.release]\nopt-level = "z"\n[dependencies]\n'
                                                 'overflow-checks = "true"\n'))
        self.assertFalse(overflow_checks_enabled('[profile.release]\noverflow-checks = false\n'))
        self.assertFalse(overflow_checks_enabled('[package]\nname = "x"\n'))


class FeaturesTest(unittest.TestCase):
    def test_stable_keys_and_values(self):
        src = contract('''
#[payable]
pub fn withdraw(&mut self, amount: U128) -> Promise {
    let a = env::predecessor_account_id();
    assert_one_yocto();
    let b = self.balances.get(&a).unwrap();
    self.balances.insert(&a, &b.checked_sub(amount.0).unwrap());
    Promise::new(a).transfer(amount.0)
}
pub fn get(&self) -> u8 { 1 }''')
        fw, fg = (features(f, src) for f in extract_functions(src, "src/lib.rs"))
        self.assertEqual(list(fw), list(FEATURE_KEYS))
        self.assertEqual(list(fg), list(FEATURE_KEYS))
        self.assertTrue(all(isinstance(v, float) for v in fw.values()))
        self.assertEqual(fw["is_payable"], 1.0)
        self.assertEqual(fw["uses_predecessor"], 1.0)
        self.assertEqual(fw["uses_assert_one_yocto"], 1.0)
        self.assertEqual(fw["uses_checked_math"], 1.0)
        self.assertEqual(fw["transfers"], 1.0)
        self.assertEqual(fw["n_collection_inserts"], 1.0)
        self.assertEqual(fg["is_view"], 1.0)
        self.assertEqual(fg["n_hits"], 0.0)


if __name__ == "__main__":
    unittest.main()
