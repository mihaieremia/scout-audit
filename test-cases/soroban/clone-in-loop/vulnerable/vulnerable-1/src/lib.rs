#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Vec};

#[contract]
pub struct CloneInLoop;

#[contractimpl]
impl CloneInLoop {
    pub fn sum_repeatedly(env: Env, n: u32) -> u32 {
        let items: Vec<u32> = Vec::from_array(&env, [1u32, 2, 3, 4]);
        let mut total: u32 = 0;
        for _ in 0..n {
            let snapshot = items.clone();
            total += snapshot.len();
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use crate::{CloneInLoop, CloneInLoopClient};
    use soroban_sdk::Env;

    #[test]
    fn test_sum_repeatedly() {
        let env = Env::default();
        let contract_id = env.register(CloneInLoop, ());
        let client = CloneInLoopClient::new(&env, &contract_id);

        let total = client.sum_repeatedly(&3u32);

        assert_eq!(total, 12);
    }
}
