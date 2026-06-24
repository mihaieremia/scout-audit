#![feature(rustc_private)]

extern crate rustc_ast;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use rustc_ast::{Expr, ExprKind};
use rustc_lint::{EarlyContext, EarlyLintPass};

// PLACEHOLDER: one-line message shown on the flagged span.
const LINT_MESSAGE: &str = "Short description of what is wrong";

// PLACEHOLDER: rename `YOUR_DETECTOR_NAME` (UPPER_SNAKE_CASE) throughout this file.
// `name` is read from the crate name via `env!("CARGO_PKG_NAME")`, so the crate
// directory and `Cargo.toml` `name` must be the hyphenated detector id.
#[expose_lint_info]
pub static YOUR_DETECTOR_NAME_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "A longer explanation of the issue, why it is dangerous, and the impact.",
    // Severity: Critical | Medium | Minor | Enhancement
    severity: Severity::Medium,
    // PLACEHOLDER: update the slug to match the detector id and its docs page.
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/your-detector-name",
    // VulnerabilityClass: Arithmetic | Authorization | BestPractices | BlockAttributes
    //   | DoS | ErrorHandling | GasUsage | KnownBugs | MEV | Panic | Reentrancy
    //   | ResourceManagement | Upgradability
    vulnerability_class: VulnerabilityClass::BestPractices,
};

// `declare_early_lint!` runs after macro expansion. To inspect source before
// macros expand (e.g. to catch a macro-generated call), swap this for
// `dylint_linting::impl_pre_expansion_lint!` and carry state in the struct.
dylint_linting::declare_early_lint!(
    pub YOUR_DETECTOR_NAME,
    Warn,
    LINT_MESSAGE
);

impl EarlyLintPass for YourDetectorName {
    fn check_expr(&mut self, cx: &EarlyContext, expr: &Expr) {
        // PLACEHOLDER: match on `expr.kind` and emit a diagnostic when it fits.
        if let ExprKind::Call(_callee, _args) = &expr.kind {
            span_lint_and_help(
                cx,
                YOUR_DETECTOR_NAME,
                expr.span,
                LINT_MESSAGE,
                None,
                "How to fix the issue.",
            );
        }
    }
}
