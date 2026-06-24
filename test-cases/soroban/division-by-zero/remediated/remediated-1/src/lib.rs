#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct DivisionByZero;

#[contractimpl]
impl DivisionByZero {
    // Guard the divisor with an explicit non-zero check before dividing.
    pub fn divide(numerator: u64, divisor: u64) -> u64 {
        if divisor == 0 {
            return 0;
        }
        numerator / divisor
    }

    // `checked_rem` returns `None` instead of panicking on a zero divisor.
    pub fn modulo(numerator: u64, divisor: u64) -> u64 {
        numerator.checked_rem(divisor).unwrap_or(0)
    }
}
