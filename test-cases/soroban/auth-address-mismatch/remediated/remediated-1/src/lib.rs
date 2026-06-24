#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Balance(Address),
}

#[contract]
pub struct AuthAddressMismatch;

#[contractimpl]
impl AuthAddressMismatch {
    /// Authorizes `caller` and writes the balance of `caller`: the authorized
    /// address is the one being mutated, so there is no mismatch.
    pub fn set_balance(env: Env, caller: Address, amount: i128) {
        caller.require_auth();
        let storage = env.storage().persistent();
        storage.set(&DataKey::Balance(caller), &amount);
    }
}
