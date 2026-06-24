#![no_std]

use soroban_sdk::{contract, contractimpl, token, Address, Env};

/// Internal helper that builds a client from `pool` and calls into it. The
/// address is forwarded unvalidated from a public entry point, so the target is
/// attacker-controlled even though the sink lives one call frame down.
fn call_pool(env: &Env, pool: &Address, asset: &Address) -> i128 {
    token::Client::new(env, pool).balance(asset)
}

#[contract]
pub struct UnvalidatedCrossContractTarget;

#[contractimpl]
impl UnvalidatedCrossContractTarget {
    /// `pool` is an untrusted parameter forwarded, without any allowlist,
    /// equality, or `require_auth` guard, into `call_pool`, which calls into it.
    pub fn read(env: Env, pool: Address, asset: Address) -> i128 {
        call_pool(&env, &pool, &asset)
    }
}
