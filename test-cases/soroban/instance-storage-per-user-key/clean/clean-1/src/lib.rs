#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Env,
};

/// Hard cap on the admin-curated allowlist kept in instance storage.
const MAX_APPROVED: u32 = 16;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    TooManyApproved = 1,
}

#[contracttype]
pub enum DataKey {
    ApprovedCount,
    ApprovedToken(Address),
}

/// Read accessor: only calls `.get()`. The cap lives in the sibling setter, so a
/// function-scoped exemption would miss it; the crate-wide capped-variant set
/// recognizes `ApprovedToken` as bounded and suppresses the finding here.
fn is_token_approved(env: &Env, token: Address) -> bool {
    env.storage()
        .instance()
        .get(&DataKey::ApprovedToken(token))
        .unwrap_or(false)
}

/// Setter: caps the allowlist with `assert_with_error!(count < MAX_APPROVED, ..)`
/// before writing `ApprovedToken(token)`, marking the variant bounded crate-wide.
/// The key is bound to a local (`let key = ..`) and reused, mirroring real
/// setters — the exemption pass must resolve the variant through that binding.
fn set_token_approved(env: &Env, token: Address) {
    let key = DataKey::ApprovedToken(token);
    let count: u32 = approved_count(env);
    soroban_sdk::assert_with_error!(env, count < MAX_APPROVED, Error::TooManyApproved);
    env.storage().instance().set(&key, &true);
    env.storage()
        .instance()
        .set(&DataKey::ApprovedCount, &(count + 1));
}

/// Count read through a sibling helper, as in real contracts: the capping body
/// never references the `ApprovedToken` variant inline.
fn approved_count(env: &Env) -> u32 {
    env.storage()
        .instance()
        .get(&DataKey::ApprovedCount)
        .unwrap_or(0)
}

#[contract]
pub struct InstanceStoragePerUserKey;

#[contractimpl]
impl InstanceStoragePerUserKey {
    pub fn approve_token(env: Env, token: Address) {
        set_token_approved(&env, token);
    }

    pub fn is_approved(env: Env, token: Address) -> bool {
        is_token_approved(&env, token)
    }
}
