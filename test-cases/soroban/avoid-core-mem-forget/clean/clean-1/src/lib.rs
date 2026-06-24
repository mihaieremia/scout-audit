#![no_std]

use soroban_sdk::{contract, contractimpl, Env, Vec};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    // Drops an owned value via the idiomatic `let _ = ...` pattern instead of
    // `core::mem::forget`, so the destructor still runs and the detector stays
    // silent.
    pub fn sum_and_discard(env: Env, values: Vec<u32>) -> u32 {
        let total: u32 = values.iter().sum();
        let _ = values;
        total
    }

    // Explicitly drops a value with `drop`, which is the recommended
    // alternative to forgetting it.
    pub fn build_and_drop(env: Env) {
        let scratch = Vec::<u32>::new(&env);
        drop(scratch);
    }
}

#[cfg(test)]
mod test {
    use crate::{Contract, ContractClient};
    use soroban_sdk::{Env, Vec};

    #[test]
    fn sum_and_discard_returns_total() {
        let env = Env::default();
        let contract_id = env.register_contract(None, Contract);
        let client = ContractClient::new(&env, &contract_id);

        let mut values = Vec::new(&env);
        values.push_back(2);
        values.push_back(3);

        assert_eq!(client.sum_and_discard(&values), 5);
    }
}
