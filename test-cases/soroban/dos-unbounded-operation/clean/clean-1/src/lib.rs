#![no_std]
use soroban_sdk::{contract, contractimpl, Vec};

#[contract]
pub struct DosUnboundedOperation;

#[contractimpl]
impl DosUnboundedOperation {
    // The loop is bounded by the length of a Soroban `Vec`, which is itself
    // bounded by how much data fits in a transaction. This is not an unbounded
    // operation and must NOT be flagged.
    pub fn sum_over_vec(items: Vec<u64>) -> u64 {
        let mut total = 0u64;
        for i in 0..items.len() {
            total += items.get(i).unwrap_or(0);
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use soroban_sdk::{vec, Env};

    use crate::{DosUnboundedOperation, DosUnboundedOperationClient};

    #[test]
    fn test_sum_over_vec() {
        // Given
        let env = Env::default();
        let contract_id = env.register(DosUnboundedOperation, ());
        let client = DosUnboundedOperationClient::new(&env, &contract_id);

        // When
        let items = vec![&env, 1u64, 2u64, 3u64, 4u64];
        let total = client.sum_over_vec(&items);

        // Then
        assert_eq!(total, 10);
    }
}
