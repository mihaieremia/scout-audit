#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct DivisionByZero;

#[contractimpl]
impl DivisionByZero {
    // `divisor` is an unconstrained parameter with no zero check, so this
    // division panics when it is called with `0`.
    pub fn divide(numerator: u64, divisor: u64) -> u64 {
        numerator / divisor
    }

    // The remainder operation panics on a zero divisor in the same way.
    pub fn modulo(numerator: u64, divisor: u64) -> u64 {
        numerator % divisor
    }
}
