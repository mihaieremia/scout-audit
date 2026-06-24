# Unsafe lossy cast

## Description

- Category: `Arithmetic`
- Severity: `Medium`
- Detector: [`unsafe-lossy-cast`](https://github.com/CoinFabrik/scout-audit/tree/main/nightly/2025-08-07/detectors/soroban/unsafe-lossy-cast)
- Test Cases: [`unsafe-lossy-cast-1`](https://github.com/CoinFabrik/scout-audit/tree/main/test-cases/soroban/unsafe-lossy-cast/vulnerable/vulnerable-1)

Casting an integer to a narrower type, or between signed and unsigned types, with the `as` operator silently truncates or reinterprets the value when it does not fit in the target type.

## Why is this bad?

The `as` operator never fails. When the source value does not fit in the target type, the high bits are dropped (truncation) or the bit pattern is reinterpreted (sign change). The contract keeps running with a wrong number, which can corrupt balances, indices, or accounting and is hard to detect because no error is raised.

## Issue example

In the following example, a `i128` parameter is truncated to `u64`. Any value that does not fit in 64 bits, or that is negative, is silently turned into a different number.

```rust
pub fn narrow(amount: i128) -> u64 {
    amount as u64
}
```

## Remediated example

Use a fallible conversion (`TryFrom`/`TryInto`) and handle the out-of-range case explicitly instead of dropping bits.

```rust
pub fn narrow(amount: i128) -> u64 {
    u64::try_from(amount).unwrap_or(0)
}
```

## How is it detected?

The detector inspects `as` casts whose source and target are both integers. It reports a cast when the target is narrower than the source, when a signed value is cast to an unsigned type, or when an unsigned value is cast to a signed type that cannot hold its full range. Casts whose source is a constant that the compiler can fully evaluate, and pointer-sized types (`usize`/`isize`), are skipped to avoid false positives.
