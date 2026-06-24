#![no_std]

use soroban_sdk::{contract, contracterror, contractimpl, Env};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum DAError {
    DivisionByZero = 1,
}

#[contract]
pub struct DebugAssertInContract;

#[contractimpl]
impl DebugAssertInContract {
    pub fn safe_div(_env: Env, amount: u128, divisor: u128) -> Result<u128, DAError> {
        if divisor == 0 {
            return Err(DAError::DivisionByZero);
        }
        Ok(amount / divisor)
    }
}
