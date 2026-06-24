#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

#[contracttype]
pub struct Transfer {
    pub to: Address,
    pub amount: i128,
}

#[contract]
pub struct AvoidVecMapInputClean;

#[contractimpl]
impl AvoidVecMapInputClean {
    // The detector targets raw `soroban_sdk::Vec`/`Map` parameters. Functions
    // that accept individually-typed inputs (scalars, addresses, or a
    // contract-defined `#[contracttype]` struct) are the recommended shape and
    // must NOT be flagged.
    pub fn record(env: Env, key: Symbol, transfer: Transfer) {
        env.storage().persistent().set(&key, &transfer);
    }
}

#[cfg(test)]
mod tests {
    use soroban_sdk::{symbol_short, testutils::Address as _, Address, Env};

    use crate::{AvoidVecMapInputClean, AvoidVecMapInputCleanClient, Transfer};

    #[test]
    fn test_record() {
        // Given
        let env = Env::default();
        let contract_id = env.register_contract(None, AvoidVecMapInputClean);
        let client = AvoidVecMapInputCleanClient::new(&env, &contract_id);

        // When
        let transfer = Transfer {
            to: Address::generate(&env),
            amount: 100,
        };
        client.record(&symbol_short!("k"), &transfer);

        // Then: no panic; typed input stored as-is.
    }
}
