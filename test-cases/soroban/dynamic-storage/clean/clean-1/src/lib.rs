#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Balance(Address),
    TotalSupply,
}

#[contract]
pub struct FixedSizeStorage;

#[contractimpl]
impl FixedSizeStorage {
    /// Stores only fixed-size primitive values (`i128`) keyed by `Address`.
    /// No dynamic collections (`Vec`, `Map`, `String`, slices) ever reach storage,
    /// so the dynamic-storage detector must stay silent.
    pub fn set_balance(e: Env, account: Address, amount: i128) {
        e.storage()
            .persistent()
            .set(&DataKey::Balance(account), &amount);
    }

    pub fn set_total_supply(e: Env, total: i128) {
        e.storage().instance().set(&DataKey::TotalSupply, &total);
    }

    pub fn get_balance(e: Env, account: Address) -> i128 {
        e.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }
}
