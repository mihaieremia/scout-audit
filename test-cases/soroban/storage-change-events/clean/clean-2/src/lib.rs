#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    LendingAccount(Address),
}

#[contract]
pub struct StorageChangeEvents;

#[contractimpl]
impl StorageChangeEvents {
    /// Read-only getter. It delegates to `reconcile`, which contains a storage
    /// `remove` on a branch this caller never takes (`clear_if_gone = false`).
    /// The detector must stay silent: the getter returns a concrete value and
    /// never writes storage in its own body.
    pub fn lending_account_id(env: Env, vault: Address) -> u64 {
        Self::reconcile(&env, &vault, false).unwrap_or(0)
    }

    /// Read-only getter mirroring the same delegation.
    pub fn has_lending_account(env: Env, vault: Address) -> bool {
        Self::reconcile(&env, &vault, false).is_some()
    }

    /// Helper that only reads on the getter path. The `remove` lives behind a
    /// branch that read callers disable, so storage is never mutated here when
    /// reached from a getter.
    fn reconcile(env: &Env, vault: &Address, clear_if_gone: bool) -> Option<u64> {
        let key = DataKey::LendingAccount(vault.clone());
        let current: Option<u64> = env.storage().persistent().get(&key);

        if current.is_none() && clear_if_gone {
            env.storage().persistent().remove(&key);
        }

        current
    }
}
