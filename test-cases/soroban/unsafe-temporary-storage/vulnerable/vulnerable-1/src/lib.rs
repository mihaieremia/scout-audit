#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Admin,
}

#[contract]
pub struct UnsafeTemporaryStorage;

#[contractimpl]
impl UnsafeTemporaryStorage {
    /// Stores the contract administrator in temporary storage. When the entry's
    /// TTL expires the admin is auto-deleted and cannot be restored, locking the
    /// contract permanently.
    pub fn set_admin(e: Env, admin: Address) {
        e.storage().temporary().set(&DataKey::Admin, &admin);
    }
}
