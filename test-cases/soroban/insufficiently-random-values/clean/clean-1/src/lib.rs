#![no_std]

use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    // Uses the secure PRNG for randomness; no ledger value is used as entropy.
    pub fn random_in_range(env: Env, max_val: u64) -> u64 {
        env.prng().gen_range(0..max_val)
    }

    // Reads the ledger timestamp for a legitimate, non-random purpose (time
    // bucketing). The value is not combined with a modulo to derive entropy,
    // so the detector must stay silent.
    pub fn current_epoch_day(env: Env) -> u64 {
        let timestamp = env.ledger().timestamp();
        timestamp / 86_400
    }

    // Reads the ledger sequence and returns it directly without using it as a
    // random source.
    pub fn current_sequence(env: Env) -> u32 {
        env.ledger().sequence()
    }
}

#[cfg(test)]
mod test {
    use crate::{Contract, ContractClient};
    use soroban_sdk::Env;

    #[test]
    fn random_in_range_is_bounded() {
        let env = Env::default();
        let contract_id = env.register(Contract, ());
        let client = ContractClient::new(&env, &contract_id);

        let value = client.random_in_range(&100);
        assert!(value < 100);
    }
}
