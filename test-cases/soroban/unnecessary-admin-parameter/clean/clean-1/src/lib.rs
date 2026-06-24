#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
}

#[contract]
pub struct UnnecessaryAdminParameter;

#[contractimpl]
impl UnnecessaryAdminParameter {
    pub fn initialize(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    // The admin parameter is authorized through a centralized helper rather than
    // inline. Authorization is reachable through the call graph, so the admin
    // parameter is genuinely used for access control and must NOT be flagged.
    pub fn set_config(env: Env, admin: Address, value: i128) {
        Self::ensure_admin(&admin);
        env.storage().instance().set(&Self::config_key(), &value);
    }

    fn ensure_admin(admin: &Address) {
        admin.require_auth();
    }

    fn config_key() -> soroban_sdk::Symbol {
        soroban_sdk::symbol_short!("CONFIG")
    }
}

#[cfg(test)]
mod tests {
    use crate::{UnnecessaryAdminParameter, UnnecessaryAdminParameterClient};
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn set_config_requires_admin_auth() {
        // Given
        let env = Env::default();
        let contract_id = env.register_contract(None, UnnecessaryAdminParameter);
        let client = UnnecessaryAdminParameterClient::new(&env, &contract_id);
        let admin = Address::generate(&env);

        // When
        client.initialize(&admin);
        client.mock_all_auths().set_config(&admin, &42);

        // Then
        let stored: i128 = env.as_contract(&contract_id, || {
            env.storage()
                .instance()
                .get(&soroban_sdk::symbol_short!("CONFIG"))
                .unwrap()
        });
        assert_eq!(stored, 42);
    }
}
