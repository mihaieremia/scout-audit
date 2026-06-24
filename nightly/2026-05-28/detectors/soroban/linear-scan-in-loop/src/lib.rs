#![feature(rustc_private)]
#![recursion_limit = "256"]
//! # linear-scan-in-loop
//!
//! Flags a `Vec::contains` / `Vec::contains_key` membership scan performed
//! inside a loop body.
//!
//! ## What it detects
//! A `contains` or `contains_key` method call whose receiver is a
//! `soroban_sdk::Vec` and which executes inside a `for`, `while`, or `loop`
//! body, where the scanned vector is a local declared *outside* the loop (a
//! collection that grows across iterations). Each membership check is O(n), so
//! running it once per iteration is O(n²).
//!
//! ## Why it matters
//! Quadratic work scales the contract's gas cost with the square of the
//! collection size, making the operation progressively more expensive and an
//! easy denial-of-service vector as the data set grows.
//!
//! ## Remediation
//! Track membership with a `soroban_sdk::Map` keyed by the element, which gives
//! O(1) `contains_key` lookups and turns the overall loop back into O(n).
//!
//! Severity: Enhancement · Class: GasUsage.

extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    analysis::{get_node_type_opt, is_soroban_vec},
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use if_chain::if_chain;
use rustc_hir::{
    def::Res,
    intravisit::{walk_body, walk_expr, walk_local, FnKind, Visitor},
    Body, Expr, ExprKind, FnDecl, HirId, LetStmt, PatKind, QPath,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{def_id::LocalDefId, Span};

const LINT_MESSAGE: &str =
    "This `Vec` membership scan runs inside a loop, making the operation O(n^2). Consider using a `Map` for O(1) lookups.";

#[expose_lint_info]
pub static LINEAR_SCAN_IN_LOOP_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "Calling `contains` or `contains_key` on a `soroban_sdk::Vec` inside a loop performs a linear scan on every iteration, so the overall cost grows quadratically with the collection size. Replacing the vector with a `soroban_sdk::Map` keyed by the element makes each membership check constant-time.",
    severity: Severity::Enhancement,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/linear-scan-in-loop",
    vulnerability_class: VulnerabilityClass::GasUsage,
};

dylint_linting::declare_late_lint!(
    pub LINEAR_SCAN_IN_LOOP,
    Warn,
    LINT_MESSAGE
);

struct LinearScanVisitor<'tcx, 'tcx_ref> {
    cx: &'tcx_ref LateContext<'tcx>,
    /// Current loop nesting depth. While greater than zero we are inside a loop
    /// body and a membership scan is candidate for flagging.
    loop_depth: u32,
    /// Locals bound while inside a loop body. A receiver resolving to one of
    /// these is loop-local (re-created each iteration), so a scan over it does
    /// not represent a growing collection and is exempt.
    locals_in_loop: Vec<HirId>,
    spans: Vec<Span>,
}

impl<'tcx> LinearScanVisitor<'tcx, '_> {
    /// Resolves `receiver` to the `HirId` of the local it refers to, if any.
    fn receiver_local(&self, receiver: &Expr<'_>) -> Option<HirId> {
        if let ExprKind::Path(QPath::Resolved(_, path)) = receiver.kind {
            if let Res::Local(hir_id) = path.res {
                return Some(hir_id);
            }
        }
        None
    }

    fn is_membership_scan_on_vec(&self, expr: &Expr<'tcx>) -> Option<Span> {
        if_chain! {
            if let ExprKind::MethodCall(segment, receiver, _, _) = expr.kind;
            if matches!(segment.ident.name.as_str(), "contains" | "contains_key");
            // Gate strictly on the receiver being a Soroban `Vec`. This excludes
            // `Range::contains`, `Map::contains_key`, slice/std `contains`, etc.
            if let Some(receiver_ty) = get_node_type_opt(self.cx, &receiver.hir_id);
            if is_soroban_vec(self.cx, receiver_ty);
            // Only flag scans over a collection declared outside the loop; a
            // loop-local vector is not the growing-collection case this targets.
            if self
                .receiver_local(receiver)
                .is_none_or(|hir_id| !self.locals_in_loop.contains(&hir_id));
            then {
                Some(expr.span)
            } else {
                None
            }
        }
    }
}

impl<'tcx> Visitor<'tcx> for LinearScanVisitor<'tcx, '_> {
    fn visit_local(&mut self, local: &'tcx LetStmt<'tcx>) {
        // Record `let` bindings introduced inside a loop body so a scan over a
        // loop-local collection (re-created each iteration) is not flagged.
        if self.loop_depth > 0 {
            if let PatKind::Binding(_, hir_id, _, _) = local.pat.kind {
                self.locals_in_loop.push(hir_id);
            }
        }
        walk_local(self, local);
    }

    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if let ExprKind::Loop(..) = expr.kind {
            self.loop_depth += 1;
            walk_expr(self, expr);
            self.loop_depth -= 1;
            return;
        }

        if self.loop_depth > 0 {
            if let Some(span) = self.is_membership_scan_on_vec(expr) {
                self.spans.push(span);
            }
        }

        walk_expr(self, expr);
    }
}

impl<'tcx> LateLintPass<'tcx> for LinearScanInLoop {
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

        let mut visitor = LinearScanVisitor {
            cx,
            loop_depth: 0,
            locals_in_loop: Vec::new(),
            spans: Vec::new(),
        };

        walk_body(&mut visitor, body);

        for span in visitor.spans {
            span_lint_and_help(
                cx,
                LINEAR_SCAN_IN_LOOP,
                span,
                LINT_MESSAGE,
                None,
                "Use a `Map` keyed by the element for O(1) membership checks instead of scanning a `Vec` each iteration",
            );
        }
    }
}
