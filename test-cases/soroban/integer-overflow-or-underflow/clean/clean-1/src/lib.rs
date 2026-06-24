#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env, Symbol};

#[contract]
pub struct IntegerOverflowUnderflow;

#[contractimpl]
impl IntegerOverflowUnderflow {
    const VALUE: Symbol = symbol_short!("VALUE");

    pub fn initialize(env: Env, value: i128) {
        env.storage().temporary().set(&Self::VALUE, &value);
    }

    pub fn add(env: Env, a: i128, b: i128) -> i128 {
        let result = a + b;
        env.storage().temporary().set(&Self::VALUE, &result);
        result
    }

    pub fn get(env: Env) -> i128 {
        env.storage().temporary().get(&Self::VALUE).unwrap_or(0)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn test_add() {
        // Given
        let env = Env::default();
        let contract_id = env.register(IntegerOverflowUnderflow, ());
        let client = IntegerOverflowUnderflowClient::new(&env, &contract_id);

        // When
        let result = client.add(&2, &3);

        // Then
        assert_eq!(result, 5);
    }
}
