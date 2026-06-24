#![no_std]

use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct RawSymbolStorageKey;

#[contractimpl]
impl RawSymbolStorageKey {
    pub fn set_balance(e: Env, _user: Address, amount: i128) {
        let storage = e.storage().persistent();
        storage.set(&symbol_short!("bal"), &amount);
    }
}
