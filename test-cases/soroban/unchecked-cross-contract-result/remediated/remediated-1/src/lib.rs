#![no_std]

use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct UncheckedCrossContractResult;

#[contractimpl]
impl UncheckedCrossContractResult {
    pub fn pay(env: Env, token: Address, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let client = token::Client::new(&env, &token);
        match client.try_transfer(&from, &to, &amount) {
            Ok(Ok(())) => {}
            _ => panic!("cross-contract transfer failed"),
        }
    }
}
