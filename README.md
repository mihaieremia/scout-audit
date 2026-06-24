# Scout Audit — Soroban (XOXNO fork)

![license: MIT](https://img.shields.io/badge/license-MIT-green)

A static analyzer that helps [Soroban](https://stellar.org/soroban) (Stellar) smart-contract
developers and auditors catch common security issues and deviations from best practice. It
runs a suite of [Dylint](https://github.com/trailofbits/dylint)-based detectors over your
contract's HIR/MIR and reports findings by severity.

This is the **XOXNO fork** of CoinFabrik's [`scout-audit`](https://github.com/CoinFabrik/scout-audit).
Relative to upstream it is **Soroban-only**, modernized to a current toolchain
(`nightly-2026-05-28` / rustc 1.98, Dylint 6, `clippy_utils` 0.1.98, `soroban-sdk` 27),
tuned to drastically reduce false positives on real lending-protocol code, and extended
with new detectors. The full delta is in **[`changelog.md`](changelog.md)**.

> Upstream targets ink!, Soroban and Substrate. This fork drops ink! and Substrate and
> focuses entirely on Soroban so it can keep pace with the latest Stellar protocol and run
> as advisory CI against production contracts.

## Requirements

- A Rust toolchain (install via [rustup](https://www.rust-lang.org/tools/install)).
- The pinned detector toolchain with the components the Dylint driver needs:
  ```bash
  rustup toolchain install nightly-2026-05-28 \
    --component rustc-dev --component llvm-tools-preview --component rust-src \
    --target wasm32v1-none
  ```
- Your contracts must compile (Scout won't run if there are compilation errors).

## Quick start

Install the orchestrator from a pinned revision of this fork:

```bash
cargo install --git https://github.com/mihaieremia/scout-audit.git \
  --rev <commit> cargo-scout-audit --locked
```

Then run it against a contract, pointing the driver and detectors at a local checkout of
this repo (the detectors are not published to crates.io):

```bash
git clone https://github.com/mihaieremia/scout-audit.git
cargo scout-audit \
  --manifest-path path/to/contract/Cargo.toml \
  --scout-source   /path/to/scout-audit \
  --local-detectors /path/to/scout-audit/nightly
```

- `--scout-source` builds the analysis driver from the local checkout.
- `--local-detectors` loads the detectors from `nightly/2026-05-28/detectors/` instead of
  fetching them over the network.

Scout supports [Cargo workspaces](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html);
run with `--manifest-path` per contract or at the workspace root.

## Output formats

```bash
cargo scout-audit ... --output-format [md|html|json|sarif] --output-path report.json
```

`json`/`sarif` are convenient for CI gating; `md`/`html` for human review.

## GitHub Action

A container entrypoint ([`entrypoint.sh`](entrypoint.sh)) runs Scout against the target
project using the detectors and driver baked into the image, so nothing is fetched at
analysis time. Set `INPUT_TARGET` to the project directory and `INPUT_SCOUT_ARGS` to any
extra flags (e.g. `--output-format sarif`).

## Detectors

This fork ships **52 detectors** — 41 Soroban-specific (`nightly/2026-05-28/detectors/soroban/`)
and 11 shared Rust detectors that also apply to Soroban contracts
(`nightly/2026-05-28/detectors/rust/`). **16 of them are new in this fork**, with a strong
focus on authorization and cross-contract permission leakage.

Every detector's `src/lib.rs` carries a module-level doc comment describing what it does,
what it flags, why it matters, and the remediation — start there, or read
**[`docs/new-detectors-catalog.md`](docs/new-detectors-catalog.md)** for the design
rationale behind the new detectors and additional candidates.

Highlights of the new detectors:

| Detector | Severity | Flags |
|---|---|---|
| `unprotected-token-admin-operation` | Critical | `mint`/`burn`/`clawback`/`set_authorized`/`set_admin` with no reachable `require_auth` |
| `unscoped-authorize-as-current-contract` | Critical | `authorize_as_current_contract` entry with non-empty `sub_invocations` |
| `unvalidated-cross-contract-target` | Critical | a client built from an untrusted `Address` param and called without validation |
| `missing-initialization-guard` | Critical | `initialize`/`init` writing admin state with no re-init guard |
| `excessive-token-approval` | Medium | `approve` with a max/never-expiring allowance |
| `unsafe-temporary-storage` | Medium | critical keys stored in `temporary()` (unrecoverable after archival) |
| `unchecked-cross-contract-result` | Medium | an ignored `try_*` `Result` from a client |
| `debug-assert-in-contract` | Medium | `debug_assert!*` (dead code under the release profile) |
| `auth-address-mismatch` | Critical | `require_auth` on one address but per-user state written for a different address |
| `division-by-zero` | Medium | division by a divisor not proven non-zero |
| `non-terminating-loop` | Medium | a bare `loop {}` with no reachable exit |
| `unsafe-lossy-cast` | Medium | narrowing / sign-changing `as` casts |
| `linear-scan-in-loop` | Enhancement | `Vec::contains` inside a loop (O(n²)) |
| `clone-in-loop` | Enhancement | cloning a host collection on each loop iteration |
| `instance-storage-per-user-key` | Enhancement | per-user data in always-loaded `instance()` storage |
| `raw-symbol-storage-key` | Enhancement | a raw `Symbol`/string storage key instead of a typed `DataKey` enum |

## Repository layout

```
nightly/2026-05-28/
  common/                 shared analysis crates (call graph, soroban/const helpers)
  detectors/soroban/      Soroban detectors (one Dylint crate each)
  detectors/rust/         shared Rust detectors
apps/cargo-scout-audit/   the orchestrator + dylint driver (cargo-scout-audit binary)
test-cases/soroban/       vulnerable + remediated fixtures, with expected.json manifests
scripts/                  fmt / clippy / test-discovery / validation helpers
docs/                     detector catalog and design notes
```

## Tests

Validate detector structure and run the integration harness:

```bash
python3 scripts/validate-detectors.py          # structure + 1:1 detector<->test-case mapping
make test                                       # run the Soroban harness over every test-case
python3 scripts/run-tests.py --detector soroban/<name>   # a single detector
```

Each test-case asserts its expected findings via `expected.json` (exact count, and lines
where given); a `remediated` case pins the detector at `count: 0` so over-firing fails CI.

> Note: if `RUSTC_WRAPPER=sccache` is set in your environment, run the harness with
> `env -u RUSTC_WRAPPER ...` — sccache caches rustc output and would otherwise skip the lint
> pass on cache hits, silently producing stale (zero) findings. `make test` does this for you.

## Acknowledgements

Scout was created by [CoinFabrik](https://www.coinfabrik.com/)'s R&D team with support from
the [Web3 Foundation Grants Program](https://github.com/w3f/Grants-Program), the
[Aleph Zero Ecosystem Funding Program](https://alephzero.org/ecosystem-funding-program), the
[Stellar Community Fund](https://communityfund.stellar.org), and the
[Polkadot Assurance Legion](https://polkadotassurance.com/). This fork builds on their work;
the upstream project remains at [CoinFabrik/scout-audit](https://github.com/CoinFabrik/scout-audit).

## License

MIT. See the upstream project for the original terms.
