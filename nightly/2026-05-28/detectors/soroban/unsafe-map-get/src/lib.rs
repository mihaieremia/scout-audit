#![feature(rustc_private)]
//! # unsafe-map-get
//!
//! Flags panic-prone reads on a Soroban `Map` that trap when the key is absent.
//!
//! ## What it detects
//! A `get_unchecked` or `try_get_unchecked` call on a `soroban_sdk::Map`. These
//! accessors assume the key exists. The safe `get`/`try_get` accessors return an
//! `Option`/`Result` for the missing key and are not flagged.
//!
//! ## Why it matters
//! `get_unchecked`/`try_get_unchecked` panic (trap) when the key is absent,
//! aborting the contract invocation and potentially making functionality
//! unreachable or enabling a denial-of-service on a missing or attacker-chosen
//! key.
//!
//! ## Remediation
//! Use `map.get(key)` (returns `Option<V>`) or `map.try_get(key)` (returns
//! `Result<Option<V>, _>`) and handle the missing key explicitly.
//!
//! Severity: Medium · Class: Authorization.

extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    analysis::is_soroban_map,
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use if_chain::if_chain;
use rustc_hir::{
    intravisit::{walk_expr, FnKind, Visitor},
    Body, Expr, ExprKind, FnDecl,
};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_span::{def_id::LocalDefId, Span};
use std::collections::HashSet;

const LINT_MESSAGE: &str = "Unchecked access on Map, method panics on a missing key.";
const UNSAFE_GET_METHODS: [&str; 2] = ["get_unchecked", "try_get_unchecked"];

/// Methods that, when called directly on the `Option` returned by a `Map::get`,
/// constitute safe handling of the missing-key case and therefore should not be
/// flagged. `unwrap`/`expect` are intentionally absent: those re-introduce the
/// panic and are covered by the `unsafe-unwrap`/`unsafe-expect` detectors.
const SAFE_OPTION_CONSUMERS: [&str; 18] = [
    "unwrap_or",
    "unwrap_or_else",
    "unwrap_or_default",
    "map",
    "map_or",
    "map_or_else",
    "and_then",
    "and",
    "or",
    "or_else",
    "ok_or",
    "ok_or_else",
    "filter",
    "inspect",
    "is_some",
    "is_none",
    "is_some_and",
    "iter",
];

#[expose_lint_info]
pub static UNSAFE_MAP_GET_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "This vulnerability class pertains to the use of the unchecked Map accessors (`get_unchecked`/`try_get_unchecked`) in soroban, which panic when the key is absent",
    severity: Severity::Medium,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/unsafe-map-get",
    vulnerability_class: VulnerabilityClass::Authorization,
};

dylint_linting::declare_late_lint! {
    pub UNSAFE_MAP_GET,
    Warn,
    LINT_MESSAGE
}

struct UnsafeMapGetVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    /// HirIds of `Map::get` expressions whose returned `Option` is safely
    /// consumed by an enclosing expression and must therefore not be flagged.
    handled_gets: HashSet<rustc_hir::HirId>,
}

impl<'a, 'tcx> UnsafeMapGetVisitor<'a, 'tcx> {
    fn get_receiver_ident_name(&self, receiver: &'tcx Expr<'tcx>) -> String {
        self.cx
            .sess()
            .source_map()
            .span_to_snippet(receiver.span)
            .unwrap_or_default()
    }

    /// Returns `true` if `expr` is an unchecked `Map::get_unchecked`/
    /// `try_get_unchecked` call on a Soroban `Map`.
    fn is_unsafe_map_get(&self, expr: &Expr<'tcx>) -> bool {
        if_chain! {
            if let ExprKind::MethodCall(path_segment, receiver, _, _) = &expr.kind;
            if UNSAFE_GET_METHODS.contains(&path_segment.ident.as_str());
            if is_soroban_map(self.cx, self.cx.typeck_results().node_type(receiver.hir_id));
            then {
                return true;
            }
        }
        false
    }

    fn mark_safe_consumers(&mut self, expr: &Expr<'tcx>) {
        match &expr.kind {
            ExprKind::Match(scrutinee, _, source) => {
                // The `get?` try-operator desugars to a `Match` whose scrutinee
                // is `Try::branch(get)`; the get itself is the first argument.
                if let rustc_hir::MatchSource::TryDesugar(_) = source {
                    if let ExprKind::Call(_, args) = &scrutinee.kind {
                        if let Some(inner) = args.first() {
                            if self.is_unsafe_map_get(inner) {
                                self.handled_gets.insert(inner.hir_id);
                            }
                        }
                    }
                } else if self.is_unsafe_map_get(scrutinee) {
                    // `match get { .. }` and `if let Some(v) = get { .. }`.
                    self.handled_gets.insert(scrutinee.hir_id);
                }
            }
            // `if let Some(v) = get` condition form.
            ExprKind::Let(let_expr) => {
                if self.is_unsafe_map_get(let_expr.init) {
                    self.handled_gets.insert(let_expr.init.hir_id);
                }
            }
            // `get.unwrap_or(..)`, `get.map(..)`, `get.ok_or(..)`, etc.
            ExprKind::MethodCall(path_segment, receiver, _, _)
                if SAFE_OPTION_CONSUMERS.contains(&path_segment.ident.as_str())
                    && self.is_unsafe_map_get(receiver) =>
            {
                self.handled_gets.insert(receiver.hir_id);
            }
            _ => {}
        }
    }
}

impl<'a, 'tcx> Visitor<'tcx> for UnsafeMapGetVisitor<'a, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'_>) {
        // Pre-order: record safely-consumed gets before reaching them below.
        self.mark_safe_consumers(expr);

        if_chain! {
            if let ExprKind::MethodCall(path_segment, receiver, args, _) = &expr.kind;
            if UNSAFE_GET_METHODS.contains(&path_segment.ident.as_str());
            if is_soroban_map(self.cx, self.cx.typeck_results().node_type(receiver.hir_id));
            if !self.handled_gets.contains(&expr.hir_id);
            then {
                let receiver_ident_name = self.get_receiver_ident_name(receiver);
                let first_arg_str = self.get_receiver_ident_name(&args[0]);
                span_lint_and_help(
                    self.cx,
                    UNSAFE_MAP_GET,
                    expr.span,
                    LINT_MESSAGE,
                    None,
                    format!(
                        "`{method}` panics when the key is absent; use `{recv}.get({key})` (returns `Option`) or `{recv}.try_get({key})` (returns `Result<Option, _>`) and handle the missing key",
                        method = path_segment.ident,
                        recv = receiver_ident_name,
                        key = first_arg_str,
                    ),
                );
            }
        }
        walk_expr(self, expr);
    }
}

impl<'tcx> LateLintPass<'tcx> for UnsafeMapGet {
    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        _: FnKind<'tcx>,
        _: &'tcx FnDecl<'tcx>,
        body: &'tcx Body<'tcx>,
        span: Span,
        _: LocalDefId,
    ) {
        // If the function comes from a macro expansion, we don't want to analyze it.
        if span.from_expansion() {
            return;
        }

        let mut visitor = UnsafeMapGetVisitor {
            cx,
            handled_gets: HashSet::new(),
        };

        walk_expr(&mut visitor, body.value);
    }
}
