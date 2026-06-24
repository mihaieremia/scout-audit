#![no_std]
// These fixtures deliberately use explicit `match`/`if let` over the more
// idiomatic combinators so the detector's safe-consumer recognition is
// exercised directly.
#![allow(clippy::manual_unwrap_or_default)]
#![allow(clippy::manual_unwrap_or)]
#![allow(clippy::manual_map)]

use soroban_sdk::{contract, contractimpl, map, Env, Map};

#[contract]
pub struct UnsafeMapGet;

#[contractimpl]
impl UnsafeMapGet {
    // `match` on the returned `Option` handles the missing-key case.
    pub fn with_match(env: Env, key: i32) -> i32 {
        let m: Map<i32, i32> = map![&env, (1, 2), (3, 4)];
        match m.get(key) {
            Some(value) => value,
            None => 0,
        }
    }

    // `if let Some(..)` handles the missing-key case.
    pub fn with_if_let(env: Env, key: i32) -> i32 {
        let m: Map<i32, i32> = map![&env, (1, 2)];
        if let Some(value) = m.get(key) {
            value
        } else {
            0
        }
    }

    // `unwrap_or_default` provides a fallback.
    pub fn with_unwrap_or_default(env: Env, key: i32) -> i32 {
        let m: Map<i32, i32> = map![&env, (1, 2)];
        m.get(key).unwrap_or_default()
    }

    // `unwrap_or` provides a fallback.
    pub fn with_unwrap_or(env: Env, key: i32) -> i32 {
        let m: Map<i32, i32> = map![&env, (1, 2)];
        m.get(key).unwrap_or(7)
    }

    // `map` transforms the present value without panicking.
    pub fn with_map(env: Env, key: i32) -> Option<i32> {
        let m: Map<i32, i32> = map![&env, (1, 2)];
        m.get(key).map(|value| value + 1)
    }

    // `and_then` chains without panicking.
    pub fn with_and_then(env: Env, key: i32) -> Option<i32> {
        let m: Map<i32, i32> = map![&env, (1, 2)];
        m.get(key).and_then(|value| value.checked_add(1))
    }

    // `is_some` only inspects presence.
    pub fn with_is_some(env: Env, key: i32) -> bool {
        let m: Map<i32, i32> = map![&env, (1, 2)];
        m.get(key).is_some()
    }
}
