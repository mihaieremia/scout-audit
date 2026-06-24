#![feature(rustc_private)]
//! # insufficiently-random-values
//!
//! Flags use of the ledger timestamp or sequence number as a source of
//! randomness.
//!
//! ## What it detects
//! A remainder expression `<expr> % <_>` whose left side is a method call to
//! `timestamp()` or `sequence()` (i.e. `env.ledger().timestamp() % n` or
//! `env.ledger().sequence() % n`), the typical "pick a value modulo N" pattern.
//!
//! ## Why it matters
//! Ledger timestamp and sequence are controlled by validators and are
//! predictable, so deriving randomness from them lets a validator or observer
//! influence or foresee the outcome, breaking lotteries, selections, or any
//! security decision that depends on unpredictability.
//!
//! ## Remediation
//! Use `env.prng()` for randomness, while remembering that on-chain randomness is
//! still ultimately under validator control for high-value decisions.
//!
//! Severity: Critical · Class: BlockAttributes.

extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use if_chain::if_chain;
use rustc_hir::{BinOpKind, Expr, ExprKind};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::Symbol;

const LINT_MESSAGE: &str = "Use env.prng() to generate random numbers, and remember that all random numbers are under the control of validators";

#[expose_lint_info]
pub static INSUFFICIENTLY_RANDOM_VALUES_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: LINT_MESSAGE,
    severity: Severity::Critical,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/insufficiently-random-values",
    vulnerability_class: VulnerabilityClass::BlockAttributes,
};

dylint_linting::declare_late_lint! {
    pub INSUFFICIENTLY_RANDOM_VALUES,
    Warn,
    LINT_MESSAGE
}

impl<'tcx> LateLintPass<'tcx> for InsufficientlyRandomValues {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'_>) {
        if_chain! {
            if let ExprKind::Binary(op, lexp, _rexp) = expr.kind;
            if op.node == BinOpKind::Rem;
            if let ExprKind::MethodCall(path, _, _, _) = lexp.kind;
            if path.ident.name == Symbol::intern("timestamp") ||
                path.ident.name == Symbol::intern("sequence");
            then {
                span_lint_and_help(
                    cx,
                    INSUFFICIENTLY_RANDOM_VALUES,
                    expr.span,
                    LINT_MESSAGE,
                    None,
                    format!("This expression seems to use ledger().{}() as a pseudo random number",path.ident.as_str()),
                );
            }
        }
    }
}
