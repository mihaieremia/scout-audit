#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
}

/// Centralized authorization helper. `require` is invoked as a method call, so
/// authorization on the new admin is delegated one frame down through a method.
pub struct Authorizer;

impl Authorizer {
    pub fn require(&self, who: &Address) {
        who.require_auth();
    }
}

#[contract]
pub struct MissingNewAdminAuth;

#[contractimpl]
impl MissingNewAdminAuth {
    pub fn initialize(e: Env, admin: Address) {
        e.storage().instance().set(&DataKey::Admin, &admin);
    }

    // Both the current admin and the new admin authorize the change. The new
    // admin's `require_auth` is delegated to a method helper, so this must NOT be
    // flagged as missing new-admin authorization.
    pub fn set_admin(e: Env, new_admin: Address) {
        let current: Address = e.storage().instance().get(&DataKey::Admin).unwrap();
        current.require_auth();

        let authorizer = Authorizer;
        authorizer.require(&new_admin);

        e.storage().instance().set(&DataKey::Admin, &new_admin);
    }
}

#[cfg(test)]
mod tests {
    use crate::{MissingNewAdminAuth, MissingNewAdminAuthClient};
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn set_admin_authorizes_both() {
        // Given
        let env = Env::default();
        let contract_id = env.register_contract(None, MissingNewAdminAuth);
        let client = MissingNewAdminAuthClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let new_admin = Address::generate(&env);

        // When
        client.initialize(&admin);
        client.mock_all_auths().set_admin(&new_admin);

        // Then
        let stored: Address = env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .get(&crate::DataKey::Admin)
                .unwrap()
        });
        assert_eq!(stored, new_admin);
    }
}
