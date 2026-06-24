#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Map, Symbol};

#[contract]
pub struct UnprotectedMappingOperation;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    balances: Map<Address, i128>,
}
const STATE: Symbol = symbol_short!("STATE");

#[contractimpl]
impl UnprotectedMappingOperation {
    // The entry point delegates authorization to one helper and the mapping
    // write to another. Authorization is reachable through the call graph, so
    // this must NOT be reported as an unprotected mapping operation.
    pub fn set_balance(env: Env, address: Address, balance: i128) -> State {
        Self::ensure_authorized(&address);
        Self::write_balance(env, address, balance)
    }

    fn ensure_authorized(address: &Address) {
        address.require_auth();
    }

    fn write_balance(env: Env, address: Address, balance: i128) -> State {
        let mut state = Self::get_state(env.clone());
        state.balances.set(address, balance);
        env.storage().persistent().set(&STATE, &state);
        state
    }

    /// Return the current state.
    pub fn get_state(env: Env) -> State {
        env.storage().persistent().get(&STATE).unwrap_or(State {
            balances: Map::new(&env),
        })
    }
}

#[cfg(test)]
const TOTAL_SUPPLY: i128 = 200;

#[cfg(test)]
mod tests {

    use soroban_sdk::Env;

    use crate::{UnprotectedMappingOperation, UnprotectedMappingOperationClient, TOTAL_SUPPLY};

    #[test]
    fn balance_of_works() {
        // Given
        let env = Env::default();
        let contract_id = env.register_contract(None, UnprotectedMappingOperation);
        let client = UnprotectedMappingOperationClient::new(&env, &contract_id);

        // When
        let state = client
            .mock_all_auths()
            .set_balance(&contract_id, &TOTAL_SUPPLY);

        // Then
        let balance = state
            .balances
            .get(contract_id)
            .expect("Contract should have a balance");
        assert_eq!(TOTAL_SUPPLY, balance);
    }
}
