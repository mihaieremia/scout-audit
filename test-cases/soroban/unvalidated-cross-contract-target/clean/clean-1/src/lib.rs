#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

#[contracttype]
pub enum DataKey {
    Pool,
}

/// Internal wrapper that calls into `pool`. The address is read from storage by
/// the caller and forwarded here, so it is configured, not attacker-controlled.
fn pool_balance(env: &Env, pool: &Address, asset: &Address) -> i128 {
    token::Client::new(env, pool).balance(asset)
}

#[contract]
pub struct UnvalidatedCrossContractTarget;

#[contractimpl]
impl UnvalidatedCrossContractTarget {
    /// The pool address comes from storage, and `asset` (the only caller-supplied
    /// address) is not used as a cross-contract *target*, so nothing is flagged.
    pub fn read(env: Env, asset: Address) -> i128 {
        let pool: Address = env.storage().instance().get(&DataKey::Pool).unwrap();
        pool_balance(&env, &pool, &asset)
    }
}
