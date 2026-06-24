# Contributing to Scout (Soroban detectors)

This guide covers how to work on the Soroban detectors in this fork: the
toolchain, the repository layout, adding a detector, adding test cases, and
the validation and linting bar that CI enforces.

Scout's detectors are [Dylint](https://github.com/trailofbits/dylint) lints
compiled as `cdylib` plugins. Each detector is its own crate. The Soroban
detectors are built for the `wasm32v1-none` target under a pinned nightly
toolchain.

## Toolchain

Detectors compile against rustc internals, so the toolchain is pinned and
must include the `rustc-dev` and `llvm-tools-preview` components. The pin
lives in `nightly/2026-05-28/.../rust-toolchain` files, e.g.
`nightly/2026-05-28/common/rust-toolchain`:

```toml
[toolchain]
channel = "nightly-2026-05-28"
components = ["llvm-tools-preview", "rustc-dev"]
```

Install the toolchain, components, and the Soroban contract target:

```bash
rustup toolchain install nightly-2026-05-28 \
  --component rustc-dev --component llvm-tools-preview
rustup target add wasm32v1-none --toolchain nightly-2026-05-28
```

Install the Dylint tooling and `cargo-scout-audit` (the integration test
harness invokes `cargo +nightly-2026-05-28 scout-audit`):

```bash
cargo +nightly install cargo-dylint dylint-link
cargo install --path apps/cargo-scout-audit/crates/cargo-scout-audit
```

## Repository layout

```
nightly/2026-05-28/
  common/                         shared crates used by every detector
    src/lib.rs                    re-exports: analysis, declarations, macros
    declarations/                 Severity, VulnerabilityClass, LintInfo
    macros/                       #[expose_lint_info] proc-macro
    analysis/                     shared analysis helpers (auth, soroban, ...)
    detectors/                    common-detectors crate
  detectors/soroban/<name>/       one crate per detector
    Cargo.toml                    name == hyphenated detector id
    src/lib.rs                    the lint implementation
test-cases/soroban/<name>/        test cases for detector <name>
  vulnerable/vulnerable-N/        contracts that MUST trigger the detector
  remediated/remediated-N/        the fixed versions that MUST NOT trigger
  clean/clean-N/                  idiomatic-but-safe false-positive regressions
doc/templates/detector/           copy-from templates (early-lint, late-lint)
scripts/                          validation and test harness (Python)
```

The detector crate directory name, its `Cargo.toml` `name`, and the
test-case directory name must all be the same hyphenated id (e.g.
`avoid-core-mem-forget`). `validate-detectors.py` enforces this 1:1 pairing.

The Soroban detectors form a Cargo workspace
(`nightly/2026-05-28/detectors/soroban/Cargo.toml`, `members = ["*"]`) whose
`[workspace.dependencies]` provide the shared `clippy_utils`, `common`,
`common_detectors`, `dylint_linting`, `dylint_internal`, and `if_chain`
deps. Detector `Cargo.toml`s reference them with `{ workspace = true }`.

## Adding a new detector

1. Copy a template from `doc/templates/detector/` into
   `nightly/2026-05-28/detectors/soroban/<name>/`. Use `late-lint` for lints
   that need types or the HIR (a `LateLintPass`), or `early-lint` for lints
   that work on the AST before type-checking (an `EarlyLintPass`). An existing
   simple detector to model is `avoid-core-mem-forget` (early) or
   `dos-unbounded-operation` (late).

2. Set the crate `name` in `Cargo.toml` to the hyphenated `<name>`. The
   `LintInfo.name` field reads it back via `env!("CARGO_PKG_NAME")`, so they
   stay in sync.

3. Fill in the `#[expose_lint_info]` metadata block. This static is read by
   `cargo-scout-audit` to produce the detector list and reports:

   ```rust
   #[expose_lint_info]
   pub static AVOID_CORE_MEM_FORGET_INFO: LintInfo = LintInfo {
       name: env!("CARGO_PKG_NAME"),
       short_message: LINT_MESSAGE,
       long_message: "The core::mem::forget function ... could lead to memory leaks and logic errors.",
       severity: Severity::Enhancement,
       help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/avoid-core-mem-forget",
       vulnerability_class: VulnerabilityClass::BestPractices,
   };
   ```

   `Severity` is one of `Critical`, `Medium`, `Minor`, `Enhancement`.
   `VulnerabilityClass` is one of `Arithmetic`, `Authorization`,
   `BestPractices`, `BlockAttributes`, `DoS`, `ErrorHandling`, `GasUsage`,
   `KnownBugs`, `MEV`, `Panic`, `Reentrancy`, `ResourceManagement`,
   `Upgradability` (see `common/declarations/src/lib.rs`).

4. Declare the lint with the macro matching the pass type:
   - `dylint_linting::declare_late_lint!` — a `LateLintPass` (HIR/types).
   - `dylint_linting::impl_late_lint!` — declare + provide a stateful struct.
   - `dylint_linting::declare_early_lint!` — an `EarlyLintPass` (AST).
   - `dylint_linting::impl_pre_expansion_lint!` — runs before macro
     expansion; used by `avoid-core-mem-forget` to see source pre-expansion.

5. Implement the pass and emit findings with
   `clippy_utils::diagnostics::span_lint_and_help(cx, LINT, span, msg, None, help)`.
   Reuse shared logic from `common::analysis` (authorization, Soroban-specific
   helpers, etc.) rather than re-deriving it per detector.

Required imports for a current detector:

```rust
use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
```

> Note: older detectors imported `scout-audit-clippy-utils`. Current
> detectors use `clippy_utils` (from the pinned `rust-clippy` rev in the
> workspace) and the `common` crate. Do not reintroduce the old crate.

## Adding a test case

Test cases live under `test-cases/soroban/<name>/` and follow a fixed layout.
Each leaf is a standalone Soroban contract crate (`Cargo.toml` + `src/lib.rs`):

```
test-cases/soroban/<name>/
  vulnerable/vulnerable-1/    MUST trigger <name>
  vulnerable/vulnerable-2/    (numbered sequentially from 1)
  remediated/remediated-1/    fixed version, MUST NOT trigger <name>
  clean/clean-1/              idiomatic-but-safe, MUST NOT trigger <name>
```

Rules enforced by `scripts/validate-detectors.py`:

- `vulnerable/` and `remediated/` are required; `clean/` is optional.
- Subdirectories must be named `<category>-N`, numbered sequentially from 1
  (`vulnerable-1`, `vulnerable-2`, ...). No gaps, no extra files.
- Each leaf crate may contain only `Cargo.toml`, `Cargo.lock`, `src/`,
  `target`, `.cargo`, and `expected.json`. Anything else is a validation
  error.
- To skip validation for a generated/imported case, drop a `Cargo.toml.skip`
  marker in the test-case root.

## The `expected.json` test manifest

A test-case leaf crate may carry an `expected.json` manifest that asserts
exactly which findings Scout must report for that crate. The integration
harness (`scripts/test_utils.py`) loads it and compares against the raw JSON
findings produced by `cargo scout-audit`.

Schema:

```json
{
  "findings": [
    { "detector": "<hyphen-id>", "count": <int>, "lines": [<int>, ...] }
  ]
}
```

Semantics:

- **Targeted, exact counts.** Each entry asserts the *exact* finding count
  for that one detector. Detectors not listed are ignored, so always-on
  detectors (e.g. `soroban-version`) do not make the assertion brittle.
- `detector` is the hyphenated id (e.g. `set-contract-storage`). The harness
  normalizes the underscores in Scout's raw output to hyphens before matching.
- `count` is the required number of findings for that detector in this crate.
- `lines` is optional. When present, the listed line numbers must all appear
  among the actual finding lines (subset check), pinning *where* the detector
  fires.

A **`clean/clean-N` false-positive regression** case pins the target detector
at zero — proving an idiomatic, safe contract produces no finding:

```json
{
  "findings": [
    { "detector": "set-contract-storage", "count": 0 }
  ]
}
```

When a leaf has no `expected.json`, the harness falls back to the legacy
binary rule: the detector must fire if and only if the path contains
`vulnerable`. Prefer `expected.json` for new cases — it is precise about both
count and location.

## Validating and running tests

Validate the detector/test-case structure (the 1:1 pairing, naming, and
allowed files described above):

```bash
python3 scripts/validate-detectors.py
```

Run the unit and integration tests for one detector. This compiles the
test-case crates, runs `cargo scout-audit` against them under
`nightly-2026-05-28`, and checks the results against each `expected.json`:

```bash
python3 scripts/run-tests.py --detector soroban/<name>
```

To run every Soroban detector's tests (as CI does), use the Makefile target,
which enumerates cases via `find-test-cases.py`:

```bash
make test-soroban
```

## Linting and formatting bar

CI (`.github/workflows/general-rust.yml`) runs the same two scripts; both must
pass before a change merges. They format and lint the app plus every
`nightly/<date>/detectors/<chain>` workspace.

```bash
python3 scripts/run-fmt.py      # cargo fmt --all --check across all workspaces
python3 scripts/run-clippy.py   # cargo clippy --all-targets --all-features -- -D warnings
```

When iterating on a single detector you can run the checks directly in its
workspace:

```bash
cd nightly/2026-05-28/detectors/soroban
cargo +nightly-2026-05-28 fmt --all --check
cargo +nightly-2026-05-28 clippy --all-targets --all-features -- -D warnings
```

Clippy is run with `-D warnings`: a warning fails the build. Do not silence it
with blanket `#[allow(...)]`; fix the underlying issue.
