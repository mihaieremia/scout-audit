#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype,
    token::{StellarAssetClient, TokenClient},
    Address, Env,
};

#[contracttype]
pub enum DataKey {
    Token,
}

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn init(e: Env, contract: Address) {
        e.storage().persistent().set(&DataKey::Token, &contract);
    }

    pub fn get_token(e: Env) -> Address {
        get_token(&e)
    }

    pub fn mint(e: Env, to: Address, amount: i128) {
        StellarAssetClient::new(&e, &get_token(&e)).mint(&to, &amount);
    }

    // Guards the parameter-derived transfer amount against a caller-supplied
    // minimum before transferring. Because the amount is checked, the detector
    // must stay silent.
    pub fn transfer(e: Env, from: Address, to: Address, amount: i128, min_amount: i128) {
        let transfer_amount = get_conversion_price(amount);
        if transfer_amount < min_amount {
            panic!("insufficient output amount");
        }
        TokenClient::new(&e, &get_token(&e)).transfer(&from, &to, &transfer_amount);
    }
}

fn get_token(e: &Env) -> Address {
    e.storage().persistent().get(&DataKey::Token).unwrap()
}

fn get_conversion_price(amount: i128) -> i128 {
    100 * amount
}

#[cfg(test)]
mod test {
    extern crate std;

    use crate::{Contract, ContractClient};
    use soroban_sdk::{testutils::Address as _, token::TokenClient, Address, Env};

    #[test]
    fn transfer_with_sufficient_output_succeeds() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let asset_contract = env.register_stellar_asset_contract_v2(admin);

        let contract_id = env.register_contract(None, Contract);
        let client = ContractClient::new(&env, &contract_id);
        client.init(&asset_contract.address());

        let from = Address::generate(&env);
        let to = Address::generate(&env);

        client
            .mock_all_auths_allowing_non_root_auth()
            .mint(&from, &10_000);

        client
            .mock_all_auths_allowing_non_root_auth()
            .transfer(&from, &to, &1, &50);

        let token_client = TokenClient::new(&env, &client.get_token());
        assert_eq!(token_client.balance(&to), 100);
    }
}
