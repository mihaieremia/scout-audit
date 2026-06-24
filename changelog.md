# Changelog — XOXNO fork vs. upstream `main`

This fork of CoinFabrik's [`scout-audit`](https://github.com/CoinFabrik/scout-audit)
modernizes the tool, narrows it to **Soroban only**, sharpens detector accuracy on real
lending-protocol code, and adds new detectors. Everything below is the delta on
`soroban` relative to upstream `main`.

## Scope — Soroban only

- **Removed all ink! and Substrate support** — detectors, test-cases, orchestrator
  `BlockChain` variants, and the ink/substrate paths in every script. The tool now
  targets Stellar/Soroban exclusively. (`154cebf3`, `1b134ddd`, `19e5e02b`)
- Builds for the **`wasm32v1-none`** target throughout. (`1def0dd8`)

## Toolchain & dependency modernization

Migrated the entire detector + driver + orchestrator stack to current versions
(`154cebf3`, `1b134ddd`, `19e5e02b`, `aed1197a`):

| Component | Before (`main`) | After (this fork) |
|---|---|---|
| Detector toolchain | `nightly-2025-08-07` (rustc 1.91) | **`nightly-2026-05-28`** (rustc 1.98) |
| `clippy_utils` | pinned git rev | **crates.io `0.1.98`** |
| `dylint_linting` / `dylint` | 3.1.2 / 4.1.0 | **6.0.1** |
| `cargo` (orchestrator) | 0.80 | **0.97.1** |
| `soroban-sdk` (test corpus) | 21.7.6 | **27.0.0-rc.1** |

- The full `rustc_private` API surface of `common/*`, all detectors, and the driver was
  ported to rustc 1.98 (removed `QPath::LangItem`, `Rvalue::Len`,
  `clippy_utils::path_to_local`; reshaped `DefKind`, `TyKind::Alias`, `Res::SelfTyAlias`,
  `Rvalue::Use`, `AttrItem`, the dataflow `Analysis` trait; etc.).
- The `nightly/2025-08-07` tree was renamed to **`nightly/2026-05-28`**.
- Orchestrator/driver ported to dylint 6 / cargo 0.97 (async `Source::query`,
  `Verbosity` moved to `cargo_util_terminal`).

> Why it matters: the old pinned nightly could not compile `soroban-sdk` 26/27, so the
> tool could not analyze modern contracts. The new stack runs the full detector suite on
> **Soroban v27 contracts** with no toolchain skew (verified end-to-end).

## Detector accuracy overhaul

The upstream detectors flooded real protocols with false positives; this fork attacks the
three structural causes (`6565e6a9`):

- **Method-aware, interprocedural call graph** — the call-graph visitor now records
  `ExprKind::MethodCall` (resolved via `type_dependent_def_id`), not just path calls, and a
  new `is_auth_reachable` helper credits authorization that is delegated to a helper one or
  more frames down. Macro-injected auth (OZ `#[only_owner]`/`#[only_admin]`) is recognized.
- **Profile-aware arithmetic** — `integer-overflow-or-underflow` respects
  `[profile.release] overflow-checks` / `panic = "abort"`, so on-chain-trapping arithmetic
  is no longer flagged.
- **Per-user-key storage modeling** — `dos-unexpected-revert-with-storage` understands
  per-account-keyed writes instead of treating every storage op as global DoS.
- **Manifest test harness** — optional `expected.json` per test-case asserts the EXACT
  finding count (and lines) per detector; a `clean`/`remediated` case pins the target
  detector at `count: 0`, turning over-firing into a CI failure.

## New detectors

Sixteen detectors that do not exist upstream:

**Accuracy phase** (`6565e6a9`):
- `division-by-zero` — `/`/`%` by a divisor not proven non-zero.
- `unsafe-lossy-cast` — narrowing / sign-changing `as` casts.

**Detector-expansion phase, waves 1–2** (`0d0d62b1`, `2d10fd7f`):
- `unprotected-token-admin-operation` (Critical) — `mint`/`burn`/`clawback`/
  `set_authorized`/`set_admin` on a token client with no reachable `require_auth`.
- `unscoped-authorize-as-current-contract` (Critical) — `authorize_as_current_contract`
  entry with a non-empty `sub_invocations` (over-delegated authority).
- `unvalidated-cross-contract-target` (Critical) — a `Client` built from an untrusted
  `Address` parameter and called without an allowlist/equality/auth guard.
- `missing-initialization-guard` (Critical) — public `initialize`/`init` writes admin
  state with no `has()`/owner-setter/`is_initialized` guard.
- `excessive-token-approval` (Medium) — `approve` with an `i128::MAX`/near-max amount or a
  `u32::MAX`/far-future constant expiration.
- `unsafe-temporary-storage` (Medium) — admin/balance/critical keys stored in
  `temporary()` storage (unrecoverable after archival).
- `unchecked-cross-contract-result` (Medium) — an ignored `try_*` `Result` from a client
  swallows a failed cross-contract/token call.
- `debug-assert-in-contract` (Medium) — `debug_assert!*` is dead code under the Soroban
  release profile, so the check never runs on-chain.

**Detector-expansion phase, wave 3** (`d16d1a77`):
- `auth-address-mismatch` (Critical) — `require_auth` on address A but per-user storage
  written for a distinct address B; same-address and admin/owner auth are credited.
- `non-terminating-loop` (Medium) — a bare `loop {}` with no reachable break/return/panic.
- `clone-in-loop` (Enhancement) — `.clone()` of an outside-the-loop host collection (Vec/
  Map/Bytes/String) inside a loop.
- `linear-scan-in-loop` (Enhancement) — `Vec::contains`/`contains_key` inside a loop (O(n²)).
- `instance-storage-per-user-key` (Enhancement) — per-user data keyed in always-loaded
  `instance()` storage (bounded-set exempt).
- `raw-symbol-storage-key` (Enhancement) — a raw `Symbol`/string storage key instead of a
  typed `DataKey` enum.

See [`docs/new-detectors-catalog.md`](docs/new-detectors-catalog.md) for the full design
rationale, detection strategies, and additional candidates.

## Orchestrator & tooling

- `BlockChain` reduced to Soroban; `make test` runs only the Soroban harness; scripts no
  longer reference ink/substrate. (`19e5e02b`)
- The harness builds the driver and loads detectors from the local checkout
  (`--scout-source` + `--local-detectors`) instead of fetching them at run time.
- Every detector + test-case crate is documented inline; this changelog and a rewritten
  README accompany the fork.

## Inherited from upstream

Core architecture, the Dylint-based lint model, output formats (md/html/json/sarif), and
the existing Soroban detector families remain from CoinFabrik's `scout-audit` — see
Acknowledgements in the README.
