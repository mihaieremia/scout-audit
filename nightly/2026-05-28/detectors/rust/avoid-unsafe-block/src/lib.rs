#![feature(rustc_private)]

//! # avoid-unsafe-block
//!
//! A pre-expansion early lint that flags user-written `unsafe` blocks.
//!
//! ## What it detects
//! Block expressions whose check mode is `unsafe` and whose source is
//! user-provided (i.e. an explicit `unsafe { .. }`, not compiler-generated).
//!
//! ## Why it matters
//! `unsafe` blocks bypass Rust's safety guarantees and can introduce undefined
//! behavior, memory corruption, and security vulnerabilities. Contract code
//! rarely needs them and should not weaken its safety baseline.
//!
//! ## Remediation
//! Remove the `unsafe` block and use safe alternatives instead.
//!
//! Severity: Enhancement · Class: BestPractices.

extern crate rustc_ast;

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use rustc_ast::{BlockCheckMode, Expr, ExprKind, UnsafeSource};
use rustc_lint::{EarlyContext, EarlyLintPass};

const LINT_MESSAGE: &str = "Avoid using unsafe blocks as it may lead to undefined behavior";
const HELP_MESSAGE: &str = "Remove this unsafe block and use safe alternatives instead";

#[expose_lint_info]
pub static AVOID_UNSAFE_BLOCK_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "The unsafe block is used to bypass Rust's safety checks. This is dangerous \
                  and should be avoided. Unsafe blocks can lead to undefined behavior, memory \
                  corruption, and security vulnerabilities.",
    severity: Severity::Enhancement,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/rust/avoid-unsafe-block",
    vulnerability_class: VulnerabilityClass::BestPractices,
};

dylint_linting::declare_pre_expansion_lint! {
    pub AVOID_UNSAFE_BLOCK,
    Warn,
    LINT_MESSAGE
}

impl EarlyLintPass for AvoidUnsafeBlock {
    fn check_expr(&mut self, cx: &EarlyContext, expr: &Expr) {
        if let ExprKind::Block(block, ..) = &expr.kind
            && block.rules == BlockCheckMode::Unsafe(UnsafeSource::UserProvided)
        {
            span_lint_and_help(
                cx,
                AVOID_UNSAFE_BLOCK,
                expr.span,
                LINT_MESSAGE,
                Some(expr.span),
                HELP_MESSAGE,
            );
        }
    }
}
