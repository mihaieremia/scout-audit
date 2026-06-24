#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Balance(Address),
}

#[contract]
pub struct CachedStorage;

#[contractimpl]
impl CachedStorage {
    /// Reads the balance, modifies the local copy, and writes it back to
    /// storage before the value is read again. The intervening `set` acts as a
    /// write barrier, so the re-read is fresh and the
    /// uncached-storage-modification detector must stay silent.
    pub fn deposit(e: Env, account: Address, amount: i128) -> i128 {
        let key = DataKey::Balance(account);

        let mut balance: i128 = e.storage().persistent().get(&key).unwrap_or(0);
        balance += amount;

        // Write the modified value back before re-reading.
        e.storage().persistent().set(&key, &balance);

        e.storage().persistent().get(&key).unwrap_or(0)
    }
}
