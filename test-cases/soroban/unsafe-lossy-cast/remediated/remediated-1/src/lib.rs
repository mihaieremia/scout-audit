#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct UnsafeLossyCast;

#[contractimpl]
impl UnsafeLossyCast {
    // Use a fallible conversion and surface the error instead of truncating.
    pub fn narrow(amount: i128) -> u64 {
        u64::try_from(amount).unwrap_or(0)
    }

    // Fallible conversion preserves correctness for out-of-range values.
    pub fn reinterpret(value: u128) -> i128 {
        i128::try_from(value).unwrap_or(0)
    }
}
