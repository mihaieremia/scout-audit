#![no_std]

use soroban_sdk::{contract, contractimpl, map, Env, Map};

#[contract]
pub struct UnsafeMapGet;

#[contractimpl]
impl UnsafeMapGet {
    // `get_unchecked` panics (traps) when the key is absent.
    pub fn get_from_map(env: Env, key: i32) -> i32 {
        let map: Map<i32, i32> = map![&env, (1, 2)];
        map.get_unchecked(key)
    }
}

#[cfg(test)]
mod tests {
    use soroban_sdk::Env;

    use crate::{UnsafeMapGet, UnsafeMapGetClient};

    #[test]
    fn get_present_key() {
        // Given
        let env = Env::default();
        let contract_id = env.register(UnsafeMapGet, ());
        let client = UnsafeMapGetClient::new(&env, &contract_id);

        // When
        let value = client.get_from_map(&1);

        // Then
        assert_eq!(value, 2);
    }

    #[test]
    #[should_panic]
    fn get_missing_key_panics() {
        // Given
        let env = Env::default();
        let contract_id = env.register(UnsafeMapGet, ());
        let client = UnsafeMapGetClient::new(&env, &contract_id);

        // When
        let _value = client.get_from_map(&42);

        // Then

        // Test should panic: `get_unchecked` traps on the absent key.
    }
}
