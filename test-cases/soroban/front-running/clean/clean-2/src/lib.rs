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

    pub fn refund_excess(e: Env, refund_to: Address, spent: i128) {
        refund(&e, &refund_to, spent);
    }
}

// Free helper taking `env: &Env` — the common idiom. The transfer's `from` is
// `env.current_contract_address()` where `env` is a `&Env`, so the receiver type
// is `&soroban_sdk::Env`. The detector must peel the reference and stay silent:
// a self-funded refund cannot be front-run for slippage.
fn refund(env: &Env, refund_to: &Address, spent: i128) {
    let token = TokenClient::new(env, &get_token(env));
    let excess = token.balance(&env.current_contract_address()) - spent;
    if excess > 0 {
        token.transfer(&env.current_contract_address(), refund_to, &excess);
    }
}

fn get_token(e: &Env) -> Address {
    e.storage().persistent().get(&DataKey::Token).unwrap()
}

#[cfg(test)]
mod test {
    extern crate std;

    use crate::{Contract, ContractClient};
    use soroban_sdk::{testutils::Address as _, token::TokenClient, Address, Env};

    #[test]
    fn refund_returns_excess_to_user() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let asset_contract = env.register_stellar_asset_contract_v2(admin);

        let contract_id = env.register(Contract, ());
        let client = ContractClient::new(&env, &contract_id);
        client.init(&asset_contract.address());

        let refund_to = Address::generate(&env);

        client
            .mock_all_auths_allowing_non_root_auth()
            .mint(&contract_id, &1_000);

        client
            .mock_all_auths_allowing_non_root_auth()
            .refund_excess(&refund_to, &600);

        let token_client = TokenClient::new(&env, &client.get_token());
        assert_eq!(token_client.balance(&refund_to), 400);
    }
}
