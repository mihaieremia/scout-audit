#![no_std]

use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct UnvalidatedCrossContractTarget;

#[contractimpl]
impl UnvalidatedCrossContractTarget {
    /// `oracle` is an untrusted parameter: an attacker can pass any contract
    /// address and have this contract call into it. No allowlist, equality, or
    /// `require_auth` guards the target before the cross-contract call.
    pub fn read(env: Env, oracle: Address, asset: Address) -> i128 {
        let client = token::Client::new(&env, &oracle);
        client.balance(&asset)
    }
}
