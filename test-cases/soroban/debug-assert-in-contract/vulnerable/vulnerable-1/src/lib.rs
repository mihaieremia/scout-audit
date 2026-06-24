#![no_std]

use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct DebugAssertInContract;

#[contractimpl]
impl DebugAssertInContract {
    pub fn safe_div(_env: Env, amount: u128, divisor: u128) -> u128 {
        debug_assert!(divisor > 0, "divisor must be non-zero");
        amount / divisor
    }
}
