#![no_std]

use soroban_sdk::{
    auth::{ContractContext, InvokerContractAuthEntry, SubContractInvocation},
    contract, contractimpl, vec, Address, Env, IntoVal, Symbol, Vec,
};

#[contract]
pub struct UnscopedAuthorizeAsCurrentContract;

#[contractimpl]
impl UnscopedAuthorizeAsCurrentContract {
    pub fn run(env: Env, token: Address, spender: Address, amount: i128) {
        // REMEDIATED: `sub_invocations` is a statically-empty vector, so this is
        // a one-shot, non-delegating authorization (the safe protocol idiom).
        let entries = vec![
            &env,
            InvokerContractAuthEntry::Contract(SubContractInvocation {
                context: ContractContext {
                    contract: token.clone(),
                    fn_name: Symbol::new(&env, "transfer"),
                    args: (spender, amount).into_val(&env),
                },
                sub_invocations: Vec::new(&env),
            }),
        ];

        env.authorize_as_current_contract(entries);
    }
}
