#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
}

#[contract]
pub struct Contract;

// A self-contained contract that does not use the `contractimport!` macro at
// all, so there is no untracked WASM dependency for the detector to flag.
#[contractimpl]
impl Contract {
    pub fn init(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }
}

#[cfg(test)]
mod test {
    use crate::{Contract, ContractClient};
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn admin_roundtrips() {
        let env = Env::default();
        let contract_id = env.register_contract(None, Contract);
        let client = ContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.init(&admin);

        assert_eq!(client.admin(), admin);
    }
}
