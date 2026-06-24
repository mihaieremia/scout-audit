#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Vec};

#[contract]
pub struct LinearScanInLoop;

#[contractimpl]
impl LinearScanInLoop {
    /// Deduplicates `extra` into a growing `Vec`. Each `contains` is an O(n)
    /// scan run once per iteration, so building `out` is O(n^2).
    pub fn dedup(env: Env, extra: Vec<Address>) -> Vec<Address> {
        let mut out: Vec<Address> = Vec::new(&env);
        for a in extra.iter() {
            if !out.contains(&a) {
                out.push_back(a);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{vec, Address, Env};

    use crate::{LinearScanInLoop, LinearScanInLoopClient};

    #[test]
    fn test_dedup() {
        let env = Env::default();
        let contract_id = env.register(LinearScanInLoop, ());
        let client = LinearScanInLoopClient::new(&env, &contract_id);

        let a = Address::generate(&env);
        let b = Address::generate(&env);
        let input = vec![&env, a.clone(), a.clone(), b.clone()];

        let out = client.dedup(&input);

        assert_eq!(out.len(), 2);
    }
}
