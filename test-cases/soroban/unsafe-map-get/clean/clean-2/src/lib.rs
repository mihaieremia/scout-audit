#![no_std]
// FP-regression fixtures: real lending-protocol patterns where `Map::get`
// already handles the missing-key `None`. None of these may be flagged, since
// `get` returns `Option<V>` and never panics on an absent key.

use soroban_sdk::{contract, contractimpl, map, Env, Map};

// Helper that consumes the `Option<V>` produced by `get`.
fn expect_invariant(value: Option<i32>) -> i32 {
    match value {
        Some(v) => v,
        None => 0,
    }
}

#[contract]
pub struct UnsafeMapGet;

#[contractimpl]
impl UnsafeMapGet {
    // (a) `let Some(..) = m.get(..) else { .. }` handles the missing key.
    pub fn with_let_else(env: Env, key: i32) -> i32 {
        let m: Map<i32, i32> = map![&env, (1, 2)];
        let Some(value) = m.get(key) else {
            return 0;
        };
        value
    }

    // (b) `m.get(..)` as the tail expression of a fn returning `Option<V>`.
    pub fn read(env: Env, key: i32) -> Option<i32> {
        let m: Map<i32, i32> = map![&env, (1, 2)];
        m.get(key)
    }

    // (c) `m.get(..)` passed as an argument to a helper taking `Option<V>`.
    pub fn with_helper_arg(env: Env, key: i32) -> i32 {
        let m: Map<i32, i32> = map![&env, (1, 2)];
        expect_invariant(m.get(key))
    }
}
