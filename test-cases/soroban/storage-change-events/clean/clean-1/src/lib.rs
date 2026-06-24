#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Balance(Address),
}

#[contract]
pub struct StorageChangeEvents;

#[contractimpl]
impl StorageChangeEvents {
    /// Public entrypoint that mutates storage. It does not emit the event
    /// inline; instead it delegates emission to the `emit_balance_changed`
    /// helper. The detector builds a (now method-aware) call graph, so the
    /// helper's event reaches this entrypoint and the detector stays silent.
    pub fn set_balance(env: Env, account: Address, amount: i128) {
        env.storage()
            .instance()
            .set(&DataKey::Balance(account.clone()), &amount);
        Self::emit_balance_changed(&env, &account, amount);
    }

    fn emit_balance_changed(env: &Env, account: &Address, amount: i128) {
        env.events()
            .publish((symbol_short!("balance"),), (account.clone(), amount));
    }
}
