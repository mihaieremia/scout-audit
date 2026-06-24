#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
}

#[contract]
pub struct MissingInitializationGuard;

#[contractimpl]
impl MissingInitializationGuard {
    pub fn initialize(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }
}
