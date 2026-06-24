#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, Map, Symbol};

const STORAGE_KEY: Symbol = symbol_short!("DATA");

#[contract]
pub struct UserKeyedStorage;

#[contractimpl]
impl UserKeyedStorage {
    // The entry point authorizes the caller through a helper before the
    // per-user-keyed map write. Authorization is reachable through the call
    // graph, so this must NOT be reported as an unprotected storage operation.
    pub fn save_user_data(env: Env, user: Address, data: u64) {
        Self::ensure_authorized(&user);
        Self::write(env, user, data);
    }

    fn ensure_authorized(user: &Address) {
        user.require_auth();
    }

    fn write(env: Env, user: Address, data: u64) {
        let mut map: Map<Address, u64> = env
            .storage()
            .instance()
            .get(&STORAGE_KEY)
            .unwrap_or(Map::new(&env));
        map.set(user, data);
        env.storage().instance().set(&STORAGE_KEY, &map);
    }
}

#[cfg(test)]
mod tests {
    use soroban_sdk::{testutils::Address as _, Address, Env};

    use crate::{UserKeyedStorage, UserKeyedStorageClient};

    #[test]
    fn test_save_user_data() {
        // Given
        let env = Env::default();
        let contract_id = env.register_contract(None, UserKeyedStorage);
        let client = UserKeyedStorageClient::new(&env, &contract_id);
        let user = Address::generate(&env);

        // When
        client.mock_all_auths().save_user_data(&user, &42);

        // Then: no panic; write succeeded under the caller's own key.
    }
}
