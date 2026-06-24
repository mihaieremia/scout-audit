#![no_std]

use soroban_sdk::{
    auth::{ContractContext, InvokerContractAuthEntry, SubContractInvocation},
    contract, contractimpl, vec, Address, Env, IntoVal, Symbol,
};

#[contract]
pub struct UnscopedAuthorizeAsCurrentContract;

#[contractimpl]
impl UnscopedAuthorizeAsCurrentContract {
    pub fn run(env: Env, token: Address, spender: Address, amount: i128) {
        // VULNERABLE: the `sub_invocations` vector is non-empty, so this entry
        // delegates onward authority on behalf of the current contract.
        let entries = vec![
            &env,
            InvokerContractAuthEntry::Contract(SubContractInvocation {
                context: ContractContext {
                    contract: token.clone(),
                    fn_name: Symbol::new(&env, "transfer"),
                    args: (spender.clone(), amount).into_val(&env),
                },
                sub_invocations: vec![
                    &env,
                    InvokerContractAuthEntry::Contract(SubContractInvocation {
                        context: ContractContext {
                            contract: token.clone(),
                            fn_name: Symbol::new(&env, "approve"),
                            args: (spender, amount).into_val(&env),
                        },
                        sub_invocations: vec![&env],
                    }),
                ],
            }),
        ];

        env.authorize_as_current_contract(entries);
    }
}
