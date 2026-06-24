#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct DivisionByZero;

#[contractimpl]
impl DivisionByZero {
    // The zero check happens *after* the division, so the division itself is
    // still reachable with `divisor == 0`. A body-wide guard scan is fooled by
    // the later comparison; a flow-aware analysis flags the unguarded `/`.
    pub fn divide_then_check(numerator: u64, divisor: u64) -> u64 {
        let result = numerator / divisor;
        if divisor == 0 {
            return 0;
        }
        result
    }

    // `divisor` is only checked inside an unrelated branch (`flag`), so the
    // remainder on the fall-through path runs without any zero guard.
    pub fn modulo_unrelated_guard(numerator: u64, divisor: u64, flag: bool) -> u64 {
        if flag && divisor != 0 {
            return numerator + 1;
        }
        numerator % divisor
    }
}
