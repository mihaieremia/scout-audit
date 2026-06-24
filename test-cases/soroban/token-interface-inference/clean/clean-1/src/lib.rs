#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Env};

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Counter,
}

#[contract]
pub struct Counter;

#[contractimpl]
impl Counter {
    /// A plain counter contract. None of its functions resemble the SEP-41
    /// canonical token functions, so the token-interface-inference detector
    /// must not infer a token and must stay silent.
    pub fn increment(env: Env) -> u32 {
        let count: u32 = env.storage().instance().get(&DataKey::Counter).unwrap_or(0);
        let next = count + 1;
        env.storage().instance().set(&DataKey::Counter, &next);
        next
    }

    pub fn decrement(env: Env) -> u32 {
        let count: u32 = env.storage().instance().get(&DataKey::Counter).unwrap_or(0);
        let next = count.saturating_sub(1);
        env.storage().instance().set(&DataKey::Counter, &next);
        next
    }

    pub fn reset(env: Env) {
        env.storage().instance().set(&DataKey::Counter, &0u32);
    }

    pub fn current(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::Counter).unwrap_or(0)
    }
}
