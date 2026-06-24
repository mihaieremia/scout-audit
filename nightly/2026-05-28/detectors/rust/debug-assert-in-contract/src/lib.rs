#![feature(rustc_private)]

//! # debug-assert-in-contract
//!
//! A pre-expansion early lint that flags `debug_assert!`-family macros in
//! contract code (outside of tests).
//!
//! ## What it detects
//! Calls to `debug_assert!`, `debug_assert_eq!`, or `debug_assert_ne!` anywhere
//! that is not inside a `#[test]` / `#[cfg(test)]` item.
//!
//! ## Why it matters
//! Soroban contracts are compiled with `debug-assertions = false` and
//! `panic = "abort"`, so `debug_assert!` macros lower to dead code and are
//! stripped from the on-chain Wasm. A security check written as a debug
//! assertion therefore never runs in production.
//!
//! ## Remediation
//! Use `assert!`, `panic_with_error!`, or `return Err(..)` for on-chain
//! invariants that must be enforced in the release build.
//!
//! Severity: Medium · Class: ErrorHandling.

extern crate rustc_ast;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint;
use common::{
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use common_utils::clippy_sym;
use rustc_ast::{tokenstream::TokenTree, AttrArgs, AttrKind, Item, MacCall};
use rustc_lint::{EarlyContext, EarlyLintPass};
use rustc_span::{sym, Span};

const LINT_MESSAGE: &str = "`debug_assert!` compiles to nothing under the Soroban release profile \
                            (debug-assertions=false); this check does not run on-chain.";

#[expose_lint_info]
pub static DEBUG_ASSERT_IN_CONTRACT_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "Soroban contracts are compiled with `debug-assertions = false` and \
                    `panic = \"abort\"`, so `debug_assert!`, `debug_assert_eq!`, and \
                    `debug_assert_ne!` lower to dead code and are stripped from the on-chain \
                    Wasm. A security check written as a debug assertion therefore never \
                    executes in production. Use `assert!`, `panic_with_error!`, or \
                    `return Err(..)` for on-chain invariants.",
    severity: Severity::Medium,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/rust/debug-assert-in-contract",
    vulnerability_class: VulnerabilityClass::ErrorHandling,
};

dylint_linting::impl_pre_expansion_lint! {
    pub DEBUG_ASSERT_IN_CONTRACT,
    Warn,
    LINT_MESSAGE,
    DebugAssertInContract::default()
}

#[derive(Default)]
pub struct DebugAssertInContract {
    test_spans: Vec<Span>,
}

impl DebugAssertInContract {
    fn is_within_test(&self, span: Span) -> bool {
        self.test_spans
            .iter()
            .any(|test_span| test_span.contains(span))
    }

    fn is_test_token_present(args: &AttrArgs) -> bool {
        matches!(args, AttrArgs::Delimited(delim_args) if delim_args
            .tokens
            .iter()
            .any(|tree| matches!(tree, TokenTree::Token(token, _) if token.is_ident_named(sym::test))))
    }

    fn is_test_item(item: &Item) -> bool {
        item.attrs.iter().any(|attr| {
            attr.has_name(sym::test)
                || (attr.has_name(sym::cfg)
                    && attr
                        .meta_item_list()
                        .is_some_and(|list| list.iter().any(|item| item.has_name(sym::test))))
                || matches!(
                    &attr.kind,
                    AttrKind::Normal(normal) if normal
                        .item
                        .args
                        .unparsed_ref()
                        .is_some_and(Self::is_test_token_present)
                )
        })
    }

    fn is_debug_assert_macro(mac: &MacCall) -> bool {
        mac.path == clippy_sym!(debug_assert)
            || mac.path == clippy_sym!(debug_assert_eq)
            || mac.path == clippy_sym!(debug_assert_ne)
    }
}

impl EarlyLintPass for DebugAssertInContract {
    fn check_item(&mut self, _: &EarlyContext<'_>, item: &rustc_ast::Item) {
        if Self::is_test_item(item) {
            self.test_spans.push(item.span);
        }
    }

    fn check_mac(&mut self, cx: &EarlyContext<'_>, mac: &MacCall) {
        if !Self::is_debug_assert_macro(mac) {
            return;
        }

        // Early return if within a test function
        if self.is_within_test(mac.span()) {
            return;
        }

        span_lint(cx, DEBUG_ASSERT_IN_CONTRACT, mac.span(), LINT_MESSAGE);
    }
}
