use near_sdk::{env, near, require, AccountId, Promise, PromiseError, NearToken, assert_one_yocto};

#[near(contract_state)]
pub struct Vault { owner: AccountId, balances: near_sdk::store::LookupMap<AccountId, u128> }

#[near]
impl Vault {
    #[payable]
    pub fn withdraw(&mut self, amount: u128) -> Promise {
        assert_one_yocto();
        let who = env::predecessor_account_id();
        let bal = *self.balances.get(&who).unwrap_or(&0);
        let left = bal.checked_sub(amount).expect("not enough");
        self.balances.insert(who.clone(), left);
        Promise::new(who.clone()).transfer(NearToken::from_yoctonear(amount))
            .then(Self::ext(env::current_account_id()).on_withdraw(who, amount))
    }

    #[private]
    pub fn on_withdraw(&mut self, who: AccountId, amount: u128, #[callback_result] r: Result<(), PromiseError>) {
        if r.is_err() {
            let bal = *self.balances.get(&who).unwrap_or(&0);
            self.balances.insert(who, bal.checked_add(amount).expect("overflow"));
        }
    }

    #[payable]
    pub fn set_owner(&mut self, owner: AccountId) {
        assert_one_yocto();
        require!(env::predecessor_account_id() == self.owner, "owner only");
        self.owner = owner;
    }
}
