#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
enum DataKey {
    Owner,
}

// Stands in for `stellar_access::ownable::enforce_owner_auth`, the helper the
// OpenZeppelin `stellar-macros` `#[only_owner]` macro injects at the top of a
// guarded function. The macro expands `#[only_owner] pub fn f(env: Env)` into a
// body beginning with `enforce_owner_auth(&env);`.
//
// In production this enforcer lives in the external `stellar-access` crate, so
// its body (which reads the owner `Address` and calls `owner.require_auth()`) is
// never analyzed by the detector: it is neither an inline `addr.require_auth()`
// at the call site nor a local function the call graph can credit. The only
// signal available to the detector is the enforcer's name at the call site. This
// stub is deliberately opaque to model that invisibility; the real owner check is
// performed by the external crate.
fn enforce_owner_auth(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&DataKey::Owner)
        .unwrap_or_else(|| panic!("owner not set"))
}

#[contract]
pub struct SetContractStorage;

#[contractimpl]
impl SetContractStorage {
    pub fn init(env: Env, owner: Address) {
        env.storage().instance().set(&DataKey::Owner, &owner);
    }

    // Post-expansion shape of an `#[only_owner]`-guarded entry point: the body
    // starts with the injected `enforce_owner_auth(&env)` call, then performs a
    // storage write keyed by an `Address`. The write must NOT be reported because
    // authorization is enforced by the injected owner check.
    pub fn set_balance(env: Env, account: Address, amount: i128) {
        enforce_owner_auth(&env);

        env.storage().persistent().set(&account, &amount);
    }
}
