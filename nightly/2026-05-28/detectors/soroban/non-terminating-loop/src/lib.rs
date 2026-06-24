#![feature(rustc_private)]
#![recursion_limit = "256"]
//! # non-terminating-loop
//!
//! Flags a bare `loop { .. }` that has no reachable way to terminate.
//!
//! ## What it detects
//! An `ExprKind::Loop` written as a `loop { .. }` (not a `while`/`for` desugar)
//! whose body contains no escape: no `break` targeting this loop or an enclosing
//! loop, no `return`, and no diverging call such as `panic!`, `panic_with_error!`,
//! `unreachable!`, or `process::abort`. A `break`/`continue` that targets a loop
//! nested *inside* the body does not count, since it never leaves the outer loop.
//!
//! ## Why it matters
//! A Soroban contract runs inside a single transaction with a finite resource
//! budget; there are no servers or event loops. A `loop` with no escape therefore
//! never returns control, exhausts the instruction budget, and aborts the
//! transaction, making the entry point permanently uncallable (a denial of
//! service).
//!
//! ## Remediation
//! Give the loop a reachable exit: `break` on a termination condition, `return`
//! the result, or convert it to a bounded `for`/`while` with a decreasing
//! measure.
//!
//! Severity: Medium · Class: DoS.

extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    analysis::decomposers::expr_to_loop,
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use rustc_hir::{
    intravisit::{walk_body, walk_expr, FnKind, Visitor},
    Block, Body, Expr, ExprKind, FnDecl, HirId, LoopSource,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{def_id::LocalDefId, Span};

const LINT_MESSAGE: &str =
    "This `loop` has no reachable `break`, `return`, or panic, so it never terminates on-chain";

#[expose_lint_info]
pub static NON_TERMINATING_LOOP_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "A Soroban contract executes within a single transaction bounded by a finite resource budget; there are no servers or background event loops. A `loop` with no reachable `break`, `return`, or panic never yields control, exhausts the instruction budget, and aborts the transaction, leaving the entry point permanently uncallable.",
    severity: Severity::Medium,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/non-terminating-loop",
    vulnerability_class: VulnerabilityClass::DoS,
};

dylint_linting::declare_late_lint!(
    pub NON_TERMINATING_LOOP,
    Warn,
    LINT_MESSAGE
);

/// Walks a single `loop` body and records whether any escape is reachable.
///
/// An escape is a `return`, a `break` that targets the analyzed loop or an
/// enclosing loop, or a diverging call (`panic!`, `panic_with_error!`,
/// `unreachable!`, `process::abort`, …). A `break`/`continue` targeting a loop
/// nested inside the body is not an escape, since control stays within the outer
/// loop; such inner loops are tracked in `inner_loops` and analyzed on their own.
struct EscapeVisitor<'tcx, 'tcx_ref> {
    cx: &'tcx_ref LateContext<'tcx>,
    inner_loops: Vec<HirId>,
    has_escape: bool,
}

impl<'tcx> Visitor<'tcx> for EscapeVisitor<'tcx, '_> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if self.has_escape {
            return;
        }

        match expr.kind {
            // A `return` always leaves the function, and therefore the loop.
            ExprKind::Ret(_) => {
                self.has_escape = true;
                return;
            }
            // A `break` escapes unless it targets a loop nested inside this body.
            ExprKind::Break(dest, _) => {
                let targets_inner = dest
                    .target_id
                    .ok()
                    .is_some_and(|id| self.inner_loops.contains(&id));
                if !targets_inner {
                    self.has_escape = true;
                    return;
                }
            }
            // A diverging call (`panic!`, `panic_with_error!`, `unreachable!`,
            // `abort`, …) lowers to a never-typed call; a nested `loop {}` is an
            // `ExprKind::Loop`, not a call, so it is not mistaken for an escape.
            ExprKind::Call(..) | ExprKind::MethodCall(..) => {
                if self.cx.typeck_results().expr_ty(expr).is_never() {
                    self.has_escape = true;
                    return;
                }
            }
            // Descending into a nested loop: record it so that breaks/continues
            // bound to it are not treated as escapes from the outer loop.
            ExprKind::Loop(_, _, _, _) => {
                self.inner_loops.push(expr.hir_id);
            }
            _ => {}
        }

        walk_expr(self, expr);
    }
}

/// Returns `true` if `body` (the body of a `loop`) has no reachable escape.
fn loop_body_has_no_escape<'tcx>(cx: &LateContext<'tcx>, body: &'tcx Block<'tcx>) -> bool {
    let mut visitor = EscapeVisitor {
        cx,
        inner_loops: Vec::new(),
        has_escape: false,
    };
    for stmt in body.stmts {
        visitor.visit_stmt(stmt);
    }
    if let Some(tail) = body.expr {
        visitor.visit_expr(tail);
    }
    !visitor.has_escape
}

/// Finds every bare `loop` in the function body and flags those without an escape.
struct LoopVisitor<'tcx, 'tcx_ref> {
    cx: &'tcx_ref LateContext<'tcx>,
    findings: Vec<Span>,
}

impl<'tcx> Visitor<'tcx> for LoopVisitor<'tcx, '_> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if let Some((block, _, source, span)) = expr_to_loop(&expr.kind) {
            // Only a bare `loop { .. }`; `while`/`for` desugar to other sources
            // and have their own termination conditions.
            if source == LoopSource::Loop
                && !span.from_expansion()
                && loop_body_has_no_escape(self.cx, block)
            {
                self.findings.push(*span);
            }
        }
        walk_expr(self, expr);
    }
}

impl<'tcx> LateLintPass<'tcx> for NonTerminatingLoop {
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

        let mut visitor = LoopVisitor {
            cx,
            findings: Vec::new(),
        };
        walk_body(&mut visitor, body);

        for span in visitor.findings {
            span_lint_and_help(
                cx,
                NON_TERMINATING_LOOP,
                span,
                LINT_MESSAGE,
                None,
                "Add a reachable `break`/`return`, or use a bounded `for`/`while` loop.",
            );
        }
    }
}
