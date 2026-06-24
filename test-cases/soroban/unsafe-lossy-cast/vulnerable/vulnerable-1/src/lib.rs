#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct UnsafeLossyCast;

#[contractimpl]
impl UnsafeLossyCast {
    // `amount` is an unconstrained parameter; truncating it to `u64` silently
    // drops the high bits when it does not fit.
    pub fn narrow(amount: i128) -> u64 {
        amount as u64
    }

    // Unsigned-to-signed reinterpretation of an unconstrained parameter:
    // large `u128` values become negative `i128` values.
    pub fn reinterpret(value: u128) -> i128 {
        value as i128
    }
}
