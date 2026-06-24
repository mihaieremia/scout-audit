#![feature(rustc_private)]

//! # unsafe-unwrap
//!
//! A late lint that flags `.unwrap()` calls that can panic, after ruling out
//! provably-safe receivers.
//!
//! ## What it detects
//! In non-macro functions, it runs a `ConstantAnalyzer` to identify values
//! known to be safe, then reports the remaining `unwrap` calls via the shared
//! `UnsafeChecks` visitor.
//!
//! ## Why it matters
//! `unwrap` retrieves the inner value of a `Result`/`Option` and panics on the
//! error/`None` case. An unchecked `unwrap` on attacker- or state-controlled
//! data lets callers force the contract to panic instead of returning an error.
//!
//! ## Remediation
//! Handle the `Option`/`Result` explicitly with pattern matching or the `?`
//! operator and return a proper error instead of unwrapping.
//!
//! Severity: Medium · Class: ErrorHandling.

extern crate rustc_hir;
extern crate rustc_span;

use common::{
    analysis::ConstantAnalyzer,
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use common_detectors::unsafe_checks::UnsafeChecks;
use rustc_hir::{
    def_id::LocalDefId,
    intravisit::{walk_expr, FnKind, Visitor},
    Body, FnDecl,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{sym, Span};

const LINT_MESSAGE: &str = "Unsafe usage of `unwrap`";

#[expose_lint_info]
pub static UNSAFE_UNWRAP_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "This vulnerability class pertains to the inappropriate usage of the unwrap method in Rust, which is commonly employed for error handling. The unwrap method retrieves the inner value of an Option or Result, but if an error or None occurs, it triggers a panic and crashes the program.    ",
    severity: Severity::Medium,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/rust/unsafe-unwrap",
    vulnerability_class: VulnerabilityClass::ErrorHandling,
};

dylint_linting::declare_late_lint! {
    pub UNSAFE_UNWRAP,
    Warn,
    LINT_MESSAGE
}

impl<'tcx> LateLintPass<'tcx> for UnsafeUnwrap {
    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        _: FnKind<'tcx>,
        _: &'tcx FnDecl<'tcx>,
        body: &'tcx Body<'tcx>,
        span: Span,
        _: LocalDefId,
    ) {
        // If the function comes from a macro expansion we don't want to analyze it.
        if span.from_expansion() {
            return;
        }

        let mut constant_analyzer = ConstantAnalyzer::new(cx);
        constant_analyzer.visit_body(body);

        let mut visitor = UnsafeChecks::new(cx, UNSAFE_UNWRAP, constant_analyzer, sym::unwrap);

        walk_expr(&mut visitor, body.value);
    }
}
