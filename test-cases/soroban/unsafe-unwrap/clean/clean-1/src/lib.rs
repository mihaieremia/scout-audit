#![no_std]
// The `if let Ok(_)`/`if let Some(_)` guards are intentionally non-idiomatic
// (clippy would prefer `is_ok()`/`is_some()`); they exist to exercise the
// detector's recognition of `if let` guards before an `unwrap`.
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::unnecessary_literal_unwrap)]

use soroban_sdk::{contract, contracterror, contractimpl};

#[contract]
pub struct UnsafeUnwrap;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    CustomError = 1,
}

#[contractimpl]
impl UnsafeUnwrap {
    // `if let Ok(..)` proves the result is present inside the then-branch.
    pub fn if_let_ok(n: u64) -> u64 {
        let result = Self::non_zero_or_error(n);
        if let Ok(_) = result {
            return result.unwrap();
        }
        0
    }

    // `if let Some(..)` proves the option is present inside the then-branch.
    pub fn if_let_some(n: u64) -> u64 {
        let opt = Self::maybe_value(n);
        if let Some(_) = opt {
            return opt.unwrap();
        }
        0
    }

    fn non_zero_or_error(n: u64) -> Result<u64, Error> {
        if n == 0 {
            return Err(Error::CustomError);
        }
        Ok(n)
    }

    fn maybe_value(n: u64) -> Option<u64> {
        if n == 0 {
            return None;
        }
        Some(n)
    }
}

#[cfg(test)]
mod tests {
    use crate::UnsafeUnwrap;

    #[test]
    fn test_if_let_ok() {
        assert_eq!(UnsafeUnwrap::if_let_ok(0), 0);
        assert_eq!(UnsafeUnwrap::if_let_ok(5), 5);
    }

    #[test]
    fn test_if_let_some() {
        assert_eq!(UnsafeUnwrap::if_let_some(0), 0);
        assert_eq!(UnsafeUnwrap::if_let_some(5), 5);
    }
}
