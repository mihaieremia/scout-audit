#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Env};

#[contracttype]
pub enum DataKey {
    Counter,
}

#[contract]
pub struct NonTerminatingLoop;

#[contractimpl]
impl NonTerminatingLoop {
    pub fn run(e: Env) {
        let mut counter: u64 = 0;
        loop {
            counter += 1;
            e.storage().persistent().set(&DataKey::Counter, &counter);
        }
    }
}
