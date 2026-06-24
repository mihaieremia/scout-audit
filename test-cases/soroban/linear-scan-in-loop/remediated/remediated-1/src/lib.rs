#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Map, Vec};

#[contract]
pub struct LinearScanInLoop;

#[contractimpl]
impl LinearScanInLoop {
    /// Deduplicates `extra` using a `Map` for membership. Each `contains_key`
    /// is O(1), so building `out` is O(n) overall.
    pub fn dedup(env: Env, extra: Vec<Address>) -> Vec<Address> {
        let mut seen: Map<Address, ()> = Map::new(&env);
        let mut out: Vec<Address> = Vec::new(&env);
        for a in extra.iter() {
            if !seen.contains_key(a.clone()) {
                seen.set(a.clone(), ());
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
