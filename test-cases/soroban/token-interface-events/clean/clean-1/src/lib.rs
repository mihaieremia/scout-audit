#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token::TokenInterface, Address, Env,
    MuxedAddress, String,
};

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Balance(Address),
    Allowance(Address, Address),
}

#[contract]
pub struct TokenWithHelperEvents;

impl TokenWithHelperEvents {
    /// All token events are emitted through this single helper. Because the
    /// call graph is method-aware, each `TokenInterface` method that calls a
    /// helper reaching `events()` is considered to emit its event, so the
    /// token-interface-events detector must stay silent.
    fn emit_event(env: &Env, amount: i128) {
        env.events().publish((symbol_short!("token"),), amount);
    }

    fn read_balance(env: &Env, account: &Address) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::Balance(account.clone()))
            .unwrap_or(0)
    }

    fn write_balance(env: &Env, account: &Address, amount: i128) {
        env.storage()
            .instance()
            .set(&DataKey::Balance(account.clone()), &amount);
    }
}

#[contractimpl]
impl TokenInterface for TokenWithHelperEvents {
    fn allowance(env: Env, from: Address, spender: Address) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::Allowance(from, spender))
            .unwrap_or(0)
    }

    fn approve(env: Env, from: Address, spender: Address, amount: i128, _expiration_ledger: u32) {
        from.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::Allowance(from, spender), &amount);
        Self::emit_event(&env, amount);
    }

    fn balance(env: Env, id: Address) -> i128 {
        Self::read_balance(&env, &id)
    }

    fn transfer(env: Env, from: Address, to: MuxedAddress, amount: i128) {
        let to = to.address();
        from.require_auth();
        let from_balance = Self::read_balance(&env, &from);
        let to_balance = Self::read_balance(&env, &to);
        Self::write_balance(&env, &from, from_balance - amount);
        Self::write_balance(&env, &to, to_balance + amount);
        Self::emit_event(&env, amount);
    }

    fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        let from_balance = Self::read_balance(&env, &from);
        let to_balance = Self::read_balance(&env, &to);
        Self::write_balance(&env, &from, from_balance - amount);
        Self::write_balance(&env, &to, to_balance + amount);
        Self::emit_event(&env, amount);
    }

    fn burn(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let from_balance = Self::read_balance(&env, &from);
        Self::write_balance(&env, &from, from_balance - amount);
        Self::emit_event(&env, amount);
    }

    fn burn_from(env: Env, spender: Address, from: Address, amount: i128) {
        spender.require_auth();
        let from_balance = Self::read_balance(&env, &from);
        Self::write_balance(&env, &from, from_balance - amount);
        Self::emit_event(&env, amount);
    }

    fn decimals(_env: Env) -> u32 {
        7
    }

    fn name(env: Env) -> String {
        String::from_str(&env, "Clean Token")
    }

    fn symbol(env: Env) -> String {
        String::from_str(&env, "CLN")
    }
}
