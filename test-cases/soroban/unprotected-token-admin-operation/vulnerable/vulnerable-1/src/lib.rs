#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, token::StellarAssetClient, Address, Env};

#[contracttype]
pub enum DataKey {
    Token,
}

#[contract]
pub struct UnprotectedTokenAdmin;

#[contractimpl]
impl UnprotectedTokenAdmin {
    pub fn init(e: Env, token: Address) {
        e.storage().persistent().set(&DataKey::Token, &token);
    }

    pub fn mint(e: Env, to: Address, amount: i128) {
        let token = get_token(&e);
        StellarAssetClient::new(&e, &token).mint(&to, &amount);
    }
}

fn get_token(e: &Env) -> Address {
    e.storage().persistent().get(&DataKey::Token).unwrap()
}
