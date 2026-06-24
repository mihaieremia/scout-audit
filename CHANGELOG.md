# Changelog

XOXNO's fork of CoinFabrik's [scout-audit](https://github.com/CoinFabrik/scout-audit),
narrowed to Soroban, modernized, and tuned for accuracy on production lending-protocol
code. This is the delta of the `soroban` branch against upstream `main`.

## Scope

- Soroban only: removed all ink! and Substrate detectors, test cases, and code paths.
- Builds for the `wasm32v1-none` target.

## Toolchain

- Detector toolchain `nightly-2026-05-28` (rustc 1.98), `clippy_utils` 0.1.98, `dylint` 6.0.1, orchestrator `cargo` 0.97.
- Test corpus on `soroban-sdk` 27. The previous nightly could not compile soroban-sdk 26/27, so the fork is what makes analysis of current Soroban contracts possible.

## Detector accuracy

- Interprocedural, method-aware call graph: authorization is recognized when delegated to a helper or injected by a macro (`#[only_owner]`/`#[only_admin]`), not only when written inline.
- Arithmetic checks respect `overflow-checks` and `panic = "abort"`, so math that already traps on-chain is not flagged.
- Storage checks model per-user keys instead of treating every storage write as a global denial-of-service risk.
- False-positive pass across seven detectors: cross-contract-target taint fires only at public entrypoints, and map access, lossy casts, division, self-funded refunds, read-only getters, and bounded admin allowlists no longer misfire. On a production lending protocol this cut findings from 50 to 1.
- Test harness asserts an exact per-detector finding count via `expected.json`; over-firing fails CI.

## New detectors

Detectors with no upstream equivalent.

**Critical**

- `unvalidated-cross-contract-target` — client built from an unvalidated address parameter.
- `unprotected-token-admin-operation` — token mint/burn/clawback/admin ops without reachable auth.
- `unscoped-authorize-as-current-contract` — over-delegated `authorize_as_current_contract`.
- `missing-initialization-guard` — initializer writes admin state with no guard.
- `auth-address-mismatch` — auth checked on one address, storage written for another.

**Medium**

- `division-by-zero` — divisor not proven non-zero.
- `unsafe-lossy-cast` — narrowing or sign-changing `as` cast.
- `excessive-token-approval` — unlimited or never-expiring approval.
- `unsafe-temporary-storage` — critical state kept in temporary storage.
- `unchecked-cross-contract-result` — ignored `try_*` result from a client.
- `debug-assert-in-contract` — `debug_assert!` is dead code under the release profile.
- `non-terminating-loop` — loop with no reachable exit.

**Enhancement**

- `clone-in-loop` — host collection cloned each iteration.
- `linear-scan-in-loop` — O(n²) `Vec` membership scan inside a loop.
- `instance-storage-per-user-key` — per-user data in always-loaded instance storage.
- `raw-symbol-storage-key` — raw symbol/string key instead of a typed `DataKey` enum.

Design notes for all detectors live in [`docs/new-detectors-catalog.md`](docs/new-detectors-catalog.md).

## Tooling

- The runner builds the driver and loads detectors from a local checkout instead of fetching them at run time.
- GitHub Action: per-contract scan, configurable severity gate, report upload, and a Markdown summary on the run page.
- Local IDE scanning: a script runs the same analysis on demand and emits SARIF for inline review.
- Every detector and test case is documented inline.

## Inherited from upstream

The Dylint-based lint model, output formats (md/html/json/sarif), and the existing Soroban
detector families come from CoinFabrik's scout-audit.
