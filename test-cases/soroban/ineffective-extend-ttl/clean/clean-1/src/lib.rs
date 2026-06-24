#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Env};

const BUMP_THRESHOLD: u32 = 100;
const BUMP_EXTEND_TO: u32 = 1000;

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Counter,
}

#[contract]
pub struct EffectiveTtl;

#[contractimpl]
impl EffectiveTtl {
    /// Idiomatic TTL bump: `extend_to` (1000) is strictly greater than the
    /// `threshold` (100), so each call genuinely extends the entry's lifetime.
    /// The ineffective-extend-ttl detector must stay silent.
    pub fn bump_instance(e: Env) {
        e.storage().instance().set(&DataKey::Counter, &0u32);
        e.storage()
            .instance()
            .extend_ttl(BUMP_THRESHOLD, BUMP_EXTEND_TO);
    }

    pub fn bump_persistent(e: Env) {
        e.storage().persistent().set(&DataKey::Counter, &0u32);
        e.storage()
            .persistent()
            .extend_ttl(&DataKey::Counter, BUMP_THRESHOLD, BUMP_EXTEND_TO);
    }
}
