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
    /// Authorizes `caller` but writes the balance of `victim`: an authorized
    /// caller can overwrite any other account's balance.
    pub fn set_balance(env: Env, caller: Address, victim: Address, amount: i128) {
        caller.require_auth();
        let storage = env.storage().persistent();
        storage.set(&DataKey::Balance(victim), &amount);
    }
}
