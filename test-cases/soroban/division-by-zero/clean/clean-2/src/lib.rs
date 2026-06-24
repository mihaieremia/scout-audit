#![no_std]
use soroban_sdk::{contract, contractimpl, Vec};

const BPS: i128 = 10_000;

#[contract]
pub struct DivisionByZero;

#[contractimpl]
impl DivisionByZero {
    // The `is_empty` guard diverges, so `history.len()` is at least 1 on the
    // fall-through path. The `.len() as i128` divisor can never be zero.
    pub fn average(history: Vec<i128>) -> i128 {
        if history.is_empty() {
            return 0;
        }
        let mut sum: i128 = 0;
        for value in history.iter() {
            sum += value;
        }
        sum / history.len() as i128
    }

    // A `len() < N` guard with a non-zero bound likewise proves the collection
    // non-empty afterwards, so the remainder is safe.
    pub fn fold_mod(history: Vec<i128>) -> i128 {
        if history.len() < 3 {
            return 0;
        }
        let mut sum: i128 = 0;
        for value in history.iter() {
            sum += value;
        }
        sum % history.len() as i128
    }

    // `clamp(1, BPS)` floors the divisor at 1, so the inline division is safe
    // without any explicit zero check.
    pub fn scale_inline(numerator: i128, raw_bps: i128) -> i128 {
        numerator / raw_bps.clamp(1, BPS)
    }

    // The clamped value bound to a local is recognized through its initializer,
    // so dividing by `eff_thr_bps` later is safe.
    pub fn scale_let(numerator: i128, raw_bps: i128) -> i128 {
        let eff_thr_bps = raw_bps.clamp(1, BPS);
        numerator / eff_thr_bps
    }

    // `.max(1)` floors the divisor at 1, so this division cannot panic.
    pub fn scale_max(numerator: u64, raw: u64) -> u64 {
        numerator / raw.max(1)
    }
}
