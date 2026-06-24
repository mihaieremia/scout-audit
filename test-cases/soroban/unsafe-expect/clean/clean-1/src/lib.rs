#![no_std]
// The `if let Ok(_)`/`if let Some(_)` guards are intentionally non-idiomatic
// (clippy would prefer `is_ok()`/`is_some()`); they exist to exercise the
// detector's recognition of `if let` guards before an `expect`.
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::unnecessary_literal_unwrap)]

use soroban_sdk::{contract, contracterror, contractimpl};

#[contract]
pub struct UnsafeExpect;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    CustomError = 1,
}

#[contractimpl]
impl UnsafeExpect {
    // `if let Ok(..)` proves the result is present before `expect`.
    pub fn if_let_ok(n: u64) -> Result<u64, Error> {
        let result = Self::non_zero_or_error(n);
        if let Ok(_) = result {
            return Ok(result.expect("checked above"));
        }
        Ok(0)
    }

    // `if let Some(..)` proves the option is present before `expect`.
    pub fn if_let_some(n: u64) -> Option<u64> {
        let opt = Self::maybe_value(n);
        if let Some(_) = opt {
            return Some(opt.expect("checked above"));
        }
        Some(0)
    }

    // `is_ok` guard followed by `expect` is already recognized as safe.
    pub fn is_ok_guard(n: u64) -> Result<u64, Error> {
        let result = Self::non_zero_or_error(n);
        if result.is_err() {
            return Ok(0);
        }
        Ok(result.expect("checked above"))
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
    use crate::UnsafeExpect;

    #[test]
    fn test_if_let_ok() {
        assert_eq!(UnsafeExpect::if_let_ok(0), Ok(0));
        assert_eq!(UnsafeExpect::if_let_ok(5), Ok(5));
    }

    #[test]
    fn test_if_let_some() {
        assert_eq!(UnsafeExpect::if_let_some(0), Some(0));
        assert_eq!(UnsafeExpect::if_let_some(5), Some(5));
    }

    #[test]
    fn test_is_ok_guard() {
        assert_eq!(UnsafeExpect::is_ok_guard(0), Ok(0));
        assert_eq!(UnsafeExpect::is_ok_guard(5), Ok(5));
    }
}
