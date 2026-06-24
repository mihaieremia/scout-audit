#![feature(rustc_private)]

extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use rustc_hir::{
    intravisit::{walk_expr, FnKind, Visitor},
    Body, Expr, FnDecl,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{def_id::LocalDefId, Span};

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

dylint_linting::declare_late_lint!(
    pub YOUR_DETECTOR_NAME,
    Warn,
    LINT_MESSAGE
);

struct YourVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
}

impl<'a, 'tcx> Visitor<'tcx> for YourVisitor<'a, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        // PLACEHOLDER: inspect `expr` and emit a diagnostic when the pattern matches.
        // span_lint_and_help(
        //     self.cx,
        //     YOUR_DETECTOR_NAME,
        //     expr.span,
        //     LINT_MESSAGE,
        //     None,
        //     "How to fix the issue.",
        // );

        walk_expr(self, expr);
    }
}

impl<'tcx> LateLintPass<'tcx> for YourDetectorName {
    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        _: FnKind<'tcx>,
        _: &'tcx FnDecl<'tcx>,
        body: &'tcx Body<'tcx>,
        _: Span,
        _: LocalDefId,
    ) {
        let mut visitor = YourVisitor { cx };
        visitor.visit_body(body);
    }
}
