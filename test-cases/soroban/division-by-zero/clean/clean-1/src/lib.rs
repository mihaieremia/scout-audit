#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct DivisionByZero;

#[contractimpl]
impl DivisionByZero {
    // Dividing by a non-zero literal can never panic.
    pub fn halve(value: u64) -> u64 {
        value / 2
    }

    // A non-zero constant divisor is provably safe.
    pub fn scale_down(value: u64) -> u64 {
        const DIVISOR: u64 = 1000;
        value / DIVISOR
    }

    // Remainder by a non-zero literal is also safe.
    pub fn last_digit(value: u64) -> u64 {
        value % 10
    }
}
