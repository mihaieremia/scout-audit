#![feature(rustc_private)]

//! # unchecked-cross-contract-result
//!
//! Detects Soroban `Client::try_<m>` cross-contract calls whose `Result` is
//! discarded, silently swallowing a failed call.
//!
//! ## What it detects
//! A method call whose name starts with `try_` (excluding std/container
//! `try_*` methods), with a receiver typed as a Soroban contract `Client`,
//! returning `core::result::Result`, where the result is ignored either as a
//! bare statement (`client.try_x(..);`) or bound to a wildcard (`let _ = ..`).
//!
//! ## Why it matters
//! Unlike the non-`try_` variant, a `try_<m>` call does not panic on failure;
//! it returns `Result<Result<T, _>, _>`. Dropping that result lets the contract
//! continue as though the cross-contract or token call had succeeded, which can
//! corrupt state or skip a required transfer.
//!
//! ## Remediation
//! Inspect the returned `Result` and handle the failed case explicitly: match on
//! `Ok(Ok(..))`, or return/propagate an error when the inner call fails.
//!
//! Severity: Medium · Class: ErrorHandling.

extern crate rustc_hir;
extern crate rustc_span;

use common::{
    analysis::{get_node_type_opt, match_type_to_str},
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use if_chain::if_chain;
use rustc_hir::{
    Body, Expr, ExprKind, FnDecl, LetStmt, Node, PatKind, StmtKind,
    intravisit::{FnKind, Visitor, walk_expr},
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{Span, def_id::LocalDefId};

const LINT_MESSAGE: &str = "The result of this cross-contract `try_` call is ignored; a failed call is silently swallowed.";

/// `try_` methods from std/core and common containers that look like a Soroban
/// `try_<m>` codegen call but are not. The receiver-`Client` gate already
/// excludes most of these, but keeping the denylist makes the intent explicit
/// and guards against a user type whose name happens to end in `Client`.
const TRY_DENYLIST: [&str; 8] = [
    "try_into",
    "try_from",
    "try_borrow",
    "try_borrow_mut",
    "try_lock",
    "try_reserve",
    "try_recv",
    "try_send",
];

#[expose_lint_info]
pub static UNCHECKED_CROSS_CONTRACT_RESULT_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "A Soroban `Client::try_<m>` call returns `Result<Result<T, _>, _>` and, unlike the non-`try_` variant, does not panic when the cross-contract or token call fails. Discarding that result (via `let _ = ...` or a bare statement) swallows the failure, so the contract proceeds as if the call had succeeded. Inspect the returned `Result` and handle the failed case explicitly (match on `Ok(Ok(..))`, return an error, or panic).",
    severity: Severity::Medium,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/unchecked-cross-contract-result",
    vulnerability_class: VulnerabilityClass::ErrorHandling,
};

dylint_linting::declare_late_lint! {
    pub UNCHECKED_CROSS_CONTRACT_RESULT,
    Warn,
    LINT_MESSAGE
}

struct UncheckedCrossContractResultVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
}

impl<'a, 'tcx> UncheckedCrossContractResultVisitor<'a, 'tcx> {
    /// `true` when the receiver of the method call is a Soroban contract client,
    /// i.e. a codegen type whose name ends in `Client`.
    fn is_client_receiver(&self, receiver: &Expr<'tcx>) -> bool {
        match get_node_type_opt(self.cx, &receiver.hir_id) {
            Some(ty) => match_type_to_str(self.cx, ty, "Client"),
            None => false,
        }
    }

    /// `true` when the call's result type is `core::result::Result`, the shape
    /// of every Soroban `try_<m>` return.
    fn returns_result(&self, expr: &Expr<'tcx>) -> bool {
        match get_node_type_opt(self.cx, &expr.hir_id) {
            Some(ty) => match_type_to_str(self.cx, ty, "core::result::Result"),
            None => false,
        }
    }

    /// `true` when the result of `expr` is discarded: either a bare expression
    /// statement (`client.try_x(..);`) or bound to a wildcard (`let _ = ..`).
    fn result_is_ignored(&self, expr: &Expr<'tcx>) -> bool {
        match self.cx.tcx.parent_hir_node(expr.hir_id) {
            Node::Stmt(stmt) => matches!(stmt.kind, StmtKind::Semi(_)),
            Node::LetStmt(LetStmt { pat, .. }) => matches!(pat.kind, PatKind::Wild),
            _ => false,
        }
    }
}

impl<'a, 'tcx> Visitor<'tcx> for UncheckedCrossContractResultVisitor<'a, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if_chain! {
            if let ExprKind::MethodCall(segment, receiver, _, _) = &expr.kind;
            let method_name = segment.ident.name.as_str();
            if method_name.starts_with("try_");
            if !TRY_DENYLIST.contains(&method_name);
            if self.is_client_receiver(receiver);
            if self.returns_result(expr);
            if self.result_is_ignored(expr);
            then {
                clippy_utils::diagnostics::span_lint_and_help(
                    self.cx,
                    UNCHECKED_CROSS_CONTRACT_RESULT,
                    expr.span,
                    LINT_MESSAGE,
                    None,
                    "inspect the returned `Result` and handle a failed cross-contract call explicitly (e.g. `match client.try_x(..) { Ok(Ok(v)) => .., _ => return Err(..) }`)",
                );
            }
        }
        walk_expr(self, expr);
    }
}

impl<'tcx> LateLintPass<'tcx> for UncheckedCrossContractResult {
    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        _: FnKind<'tcx>,
        _: &'tcx FnDecl<'tcx>,
        body: &'tcx Body<'tcx>,
        span: Span,
        _: LocalDefId,
    ) {
        if span.from_expansion() {
            return;
        }

        let mut visitor = UncheckedCrossContractResultVisitor { cx };
        walk_expr(&mut visitor, body.value);
    }
}
