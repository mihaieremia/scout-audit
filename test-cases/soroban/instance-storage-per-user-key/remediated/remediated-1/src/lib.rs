#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

#[contract]
pub struct InstanceStoragePerUserKey;

#[contractimpl]
impl InstanceStoragePerUserKey {
    pub fn set_balance(e: Env, user: Address, amount: i128) {
        e.storage()
            .persistent()
            .set(&DataKey::Balance(user), &amount);
    }
}
