#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

/// Ephemeral single-flight guard. Temporary storage is the correct home for
/// this flag: it is meant to vanish on TTL expiry, and its variant name is on
/// the detector's ephemeral allow-list (`ongoing`).
#[derive(Clone)]
#[contracttype]
pub enum SessionKey {
    FlashLoanOngoing,
}

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Balance(Address),
}

#[contract]
pub struct CleanTemporaryStorage;

#[contractimpl]
impl CleanTemporaryStorage {
    /// Sets an ephemeral reentrancy guard in temporary storage. Auto-deletion on
    /// TTL expiry is desired here, so the detector must stay silent.
    pub fn begin_flash_loan(e: Env) {
        e.storage()
            .temporary()
            .set(&SessionKey::FlashLoanOngoing, &true);
    }

    /// Critical balance state lives in persistent storage, where it survives
    /// archival and can be restored. The detector only flags temporary storage,
    /// so this must stay silent.
    pub fn set_balance(e: Env, account: Address, amount: i128) {
        e.storage()
            .persistent()
            .set(&DataKey::Balance(account), &amount);
    }
}
