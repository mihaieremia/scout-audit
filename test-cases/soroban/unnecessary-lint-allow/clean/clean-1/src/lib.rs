#![no_std]

use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct Contract;

// No `#[scout_allow(...)]` attributes are present anywhere in this crate, so
// the detector must stay silent. A plain `#[allow(...)]` is unrelated and must
// not be flagged either.
#[contractimpl]
impl Contract {
    #[allow(clippy::needless_pass_by_value)]
    pub fn add(env: Env, a: u32, b: u32) -> u32 {
        a.saturating_add(b)
    }
}

#[cfg(test)]
mod test {
    use crate::{Contract, ContractClient};
    use soroban_sdk::Env;

    #[test]
    fn add_saturates() {
        let env = Env::default();
        let contract_id = env.register_contract(None, Contract);
        let client = ContractClient::new(&env, &contract_id);

        assert_eq!(client.add(&2, &3), 5);
    }
}
