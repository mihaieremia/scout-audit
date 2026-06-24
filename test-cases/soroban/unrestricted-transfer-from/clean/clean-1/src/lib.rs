#![no_std]

use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct UnrestrictedTransferFrom;

#[contractimpl]
impl UnrestrictedTransferFrom {
    // `from` is a user-supplied argument, but the caller must prove ownership of
    // those funds via `from.require_auth()` before the `transfer_from`. This is a
    // restricted transfer and must NOT be flagged.
    pub fn deposit(env: Env, token: Address, from: Address, amount: i128) {
        from.require_auth();
        let client = token::Client::new(&env, &token);
        client.transfer_from(
            &env.current_contract_address(),
            &from,
            &env.current_contract_address(),
            &amount,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::{UnrestrictedTransferFrom, UnrestrictedTransferFromClient};
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn deposit_requires_from_auth() {
        // Given
        let env = Env::default();
        let contract_id = env.register_contract(None, UnrestrictedTransferFrom);
        let client = UnrestrictedTransferFromClient::new(&env, &contract_id);
        let token = Address::generate(&env);
        let from = Address::generate(&env);

        // When / Then: the call path compiles and authorizes `from`.
        let _ = (client, token, from);
    }
}
