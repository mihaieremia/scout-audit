#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env};

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
}

#[contract]
pub struct UpgradeableContract;

#[contractimpl]
impl UpgradeableContract {
    pub fn init(e: Env, admin: Address) {
        e.storage().instance().set(&DataKey::Admin, &admin);
    }

    // Authorization is delegated to a helper before the upgrade is performed.
    // Auth is reachable through the call graph, so this must NOT be reported.
    pub fn upgrade(e: Env, new_wasm_hash: BytesN<32>) {
        Self::require_admin(&e);
        Self::do_upgrade(e, new_wasm_hash);
    }

    fn require_admin(e: &Env) {
        let admin: Address = e
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("admin not set");
        admin.require_auth();
    }

    fn do_upgrade(e: Env, new_wasm_hash: BytesN<32>) {
        e.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}
