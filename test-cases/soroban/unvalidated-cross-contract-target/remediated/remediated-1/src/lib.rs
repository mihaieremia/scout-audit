#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env, Vec};

#[contracttype]
pub enum DataKey {
    Oracles,
}

#[contract]
pub struct UnvalidatedCrossContractTarget;

#[contractimpl]
impl UnvalidatedCrossContractTarget {
    /// The target is validated against an on-chain allowlist read from storage
    /// before any cross-contract call is made, so a malicious `oracle` is rejected.
    pub fn read(env: Env, oracle: Address, asset: Address) -> i128 {
        let allowed: Vec<Address> = env.storage().instance().get(&DataKey::Oracles).unwrap();
        if !allowed.contains(&oracle) {
            panic!("oracle not in allowlist");
        }
        let client = token::Client::new(&env, &oracle);
        client.balance(&asset)
    }
}
