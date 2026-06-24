#![no_std]
use soroban_sdk::{contract, contractimpl};

// Single-field newtype wrapping a primitive integer. Its value is a bounded
// domain (basis points, validated to `0..=10000` at construction), so reading
// the inner integer and narrowing it is lossless in practice.
pub struct Bps(i128);

impl Bps {
    // Construction enforces the domain invariant.
    pub fn new(raw: i128) -> Self {
        Bps(raw.clamp(0, 10_000))
    }

    pub fn raw(self) -> i128 {
        self.0
    }
}

#[contract]
pub struct UnsafeLossyCast;

#[contractimpl]
impl UnsafeLossyCast {
    // Narrowing the inner value of a bounded-domain newtype read through an
    // accessor is in range by the type's invariant.
    pub fn from_accessor(raw: i128) -> u32 {
        let cfg = Bps::new(raw);
        cfg.raw() as u32
    }

    // Same pattern through a tuple-field access.
    pub fn from_field(raw: i128) -> u32 {
        let cfg = Bps::new(raw);
        cfg.0 as u32
    }
}
