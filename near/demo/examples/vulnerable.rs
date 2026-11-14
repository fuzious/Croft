use near_sdk::{env, near, AccountId, Promise, PromiseResult, NearToken};

#[near(contract_state)]
pub struct Vault { owner: AccountId, balances: near_sdk::store::LookupMap<AccountId, u128> }

#[near]
impl Vault {
    pub fn withdraw(&mut self, amount: u128) -> Promise {
        let who = env::predecessor_account_id();
        let bal = *self.balances.get(&who).unwrap_or(&0);
        assert!(bal >= amount, "not enough");
        Promise::new(who.clone()).transfer(NearToken::from_yoctonear(amount))
            .then(Self::ext(env::current_account_id()).on_withdraw(who, amount))
    }

    // anyone can call this and reduce (or skip reducing) any balance
    pub fn on_withdraw(&mut self, who: AccountId, amount: u128) {
        let bal = *self.balances.get(&who).unwrap_or(&0);
        self.balances.insert(who, bal - amount);
    }

    pub fn set_owner(&mut self, owner: AccountId) {
        self.owner = owner;
    }
}
