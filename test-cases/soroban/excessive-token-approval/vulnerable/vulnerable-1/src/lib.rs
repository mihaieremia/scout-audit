#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, token::TokenClient, Address, Env};

#[contracttype]
pub enum DataKey {
    Token,
}

#[contract]
pub struct ExcessiveTokenApproval;

#[contractimpl]
impl ExcessiveTokenApproval {
    pub fn init(e: Env, token: Address) {
        e.storage().persistent().set(&DataKey::Token, &token);
    }

    pub fn approve(e: Env, from: Address, spender: Address) {
        let token = get_token(&e);
        TokenClient::new(&e, &token).approve(&from, &spender, &i128::MAX, &u32::MAX);
    }
}

fn get_token(e: &Env) -> Address {
    e.storage().persistent().get(&DataKey::Token).unwrap()
}
