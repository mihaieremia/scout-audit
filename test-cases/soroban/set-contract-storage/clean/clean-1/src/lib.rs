#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SetContractStorage;

#[contractimpl]
impl SetContractStorage {
    // Authorization is delegated to a helper and the storage write to another.
    // Auth is reachable through the call graph, so this must NOT be reported as
    // an unprotected storage write.
    pub fn increment(env: Env, user: Address) -> u32 {
        Self::ensure_authorized(&user);
        Self::bump(env, user)
    }

    fn ensure_authorized(user: &Address) {
        user.require_auth();
    }

    fn bump(env: Env, user: Address) -> u32 {
        let storage = env.storage().instance();
        let mut count: u32 = storage.get(&user).unwrap_or_default();
        count += 1;
        storage.set(&user, &count);
        storage.extend_ttl(100, 100);
        count
    }
}
