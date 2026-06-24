#![no_std]
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct DivisionByZero;

#[contractimpl]
impl DivisionByZero {
    // `assert!(divisor != 0)` aborts the transaction before the division when
    // the divisor is zero, so the division below can never panic.
    pub fn divide(numerator: u64, divisor: u64) -> u64 {
        assert!(divisor != 0);
        numerator / divisor
    }

    // The same assertion guards the remainder operation.
    pub fn modulo(numerator: u64, divisor: u64) -> u64 {
        assert!(divisor != 0);
        numerator % divisor
    }

    // A guard written as `if divisor == 0 { panic!(...) }` is also recognized:
    // the diverging branch proves `divisor` non-zero on the way out.
    pub fn divide_or_panic(numerator: u64, divisor: u64) -> u64 {
        if divisor == 0 {
            panic!("divisor must be non-zero");
        }
        numerator / divisor
    }

    // The division lives inside the positive `divisor != 0` branch, where the
    // divisor is proven non-zero.
    pub fn divide_in_branch(numerator: u64, divisor: u64) -> u64 {
        if divisor != 0 {
            numerator / divisor
        } else {
            0
        }
    }

    // A compound `&&` guard still proves the divisor non-zero on the true path.
    pub fn divide_compound_guard(numerator: u64, divisor: u64, enabled: bool) -> u64 {
        if enabled && divisor != 0 {
            return numerator / divisor;
        }
        0
    }
}
