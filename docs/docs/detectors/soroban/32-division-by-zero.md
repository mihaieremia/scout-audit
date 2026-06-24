# Division by zero

## Description

- Category: `Arithmetic`
- Severity: `Medium`
- Detector: [`division-by-zero`](https://github.com/CoinFabrik/scout-audit/tree/main/nightly/2025-08-07/detectors/soroban/division-by-zero)
- Test Cases: [`division-by-zero-1`](https://github.com/CoinFabrik/scout-audit/tree/main/test-cases/soroban/division-by-zero/vulnerable/vulnerable-1)

Integer division or remainder where the divisor is not proven to be non-zero can panic at runtime and abort the transaction.

## Why is this bad?

In Soroban, an integer division or remainder by zero panics, which aborts the whole transaction. When the divisor comes from a parameter or a computed value that is never checked, an attacker (or an honest caller) can trigger the panic by passing `0`, turning a normal operation into a denial of service.

## Issue example

In the following example, `divisor` is an unconstrained parameter and is used directly as a divisor. Calling the function with `0` panics.

```rust
pub fn divide(numerator: u64, divisor: u64) -> u64 {
    numerator / divisor
}
```

## Remediated example

Guard the divisor with an explicit non-zero check, or use the checked arithmetic methods and handle the `None` case.

```rust
pub fn divide(numerator: u64, divisor: u64) -> u64 {
    if divisor == 0 {
        return 0;
    }
    numerator / divisor
}
```

## How is it detected?

The detector reports integer `/` and `%` operations whose divisor may be zero. A divisor is considered safe when it is a non-zero constant, or when the local variable used as the divisor is compared against `0` somewhere in the same function (an explicit guard). Literal `0` divisors are always reported.
