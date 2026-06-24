#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct UnsafeLossyCast;

#[contractimpl]
impl UnsafeLossyCast {
    // Widening an unsigned value never loses information.
    pub fn widen_unsigned(amount: u32) -> u64 {
        amount as u64
    }

    // Unsigned-to-signed where the target is strictly wider always fits.
    pub fn widen_to_signed(amount: u32) -> i128 {
        amount as i128
    }

    // Widening a signed value preserves it.
    pub fn widen_signed(amount: i32) -> i64 {
        amount as i64
    }
}
