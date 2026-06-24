#![no_std]

use soroban_sdk::{contract, contracterror, contractimpl};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    DivByZero = 1,
}

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    // Returns a `Result` whose `Ok` and `Err` variants are both constructed,
    // so the detector must stay silent: there is no unused variant.
    pub fn safe_div(a: u64, b: u64) -> Result<u64, Error> {
        if b == 0 {
            Err(Error::DivByZero)
        } else {
            Ok(a / b)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{Contract, ContractClient, Error};
    use soroban_sdk::Env;

    #[test]
    fn safe_div_handles_both_variants() {
        let env = Env::default();
        let contract_id = env.register(Contract, ());
        let client = ContractClient::new(&env, &contract_id);

        assert_eq!(client.safe_div(&10, &2), 5);
        assert_eq!(client.try_safe_div(&10, &0), Err(Ok(Error::DivByZero)));
    }
}
