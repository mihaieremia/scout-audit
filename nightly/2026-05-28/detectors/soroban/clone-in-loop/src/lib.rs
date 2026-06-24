#![feature(rustc_private)]
#![recursion_limit = "256"]
//! # clone-in-loop
//!
//! Flags `.clone()` on a Soroban host collection inside a loop body.
//!
//! ## What it detects
//! A call to `.clone()` whose receiver is a Soroban host collection
//! (`Vec`, `Map`, `Bytes`, or `String`) that appears inside a `for`, `while`,
//! or `loop` body, where the cloned value is a local declared *outside* the
//! loop. Cloning the loop's current element (a local bound inside the loop) is
//! not flagged, since that copy is usually required.
//!
//! ## Why it matters
//! Soroban host collections live in host memory; each `.clone()` performs a
//! deep copy across the host boundary and is charged to the contract's host
//! budget. Re-cloning a value that does not change between iterations wastes
//! CPU and host budget on every pass and can push a contract over its limit.
//!
//! ## Remediation
//! Hoist the clone above the loop (`let snapshot = items.clone();`) and reuse
//! the snapshot, or iterate by reference, so the deep copy happens once.
//!
//! Severity: Enhancement · Class: Gas Usage.

extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    analysis::{get_node_type_opt, is_soroban_map, is_soroban_vec, match_type_to_str},
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use if_chain::if_chain;
use rustc_hir::{
    def::Res,
    intravisit::{walk_body, walk_expr, FnKind, Visitor},
    Body, Expr, ExprKind, FnDecl, HirId, PatKind, QPath, StmtKind,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{def_id::LocalDefId, Span};

const SOROBAN_BYTES: &str = "soroban_sdk::Bytes";
const SOROBAN_STRING: &str = "soroban_sdk::String";

const LINT_MESSAGE: &str = "Cloning a Soroban collection inside a loop deep-copies it to the host on every iteration; hoist the clone above the loop or iterate by reference";

#[expose_lint_info]
pub static CLONE_IN_LOOP_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "Soroban host collections (Vec, Map, Bytes, String) live in host memory, so each .clone() performs a deep copy across the host boundary that is charged to the contract's host budget. Cloning a value that does not change between iterations repeats that cost on every pass and can exhaust the host budget. Hoist the clone above the loop and reuse the snapshot, or iterate by reference.",
    severity: Severity::Enhancement,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/clone-in-loop",
    vulnerability_class: VulnerabilityClass::GasUsage,
};

dylint_linting::declare_late_lint!(
    pub CLONE_IN_LOOP,
    Warn,
    LINT_MESSAGE
);

struct CloneInLoopVisitor<'tcx, 'tcx_ref> {
    cx: &'tcx_ref LateContext<'tcx>,
    /// Number of loops currently enclosing the visited expression.
    loop_depth: u32,
    /// Locals bound while outside any loop; cloning one of these inside a loop
    /// is what we flag. Locals bound inside a loop (e.g. the iteration element)
    /// are intentionally absent so they are never flagged.
    outer_locals: Vec<HirId>,
    findings: Vec<Span>,
}

impl<'tcx, 'tcx_ref> CloneInLoopVisitor<'tcx, 'tcx_ref> {
    /// Records every binding introduced by a `let` pattern so the receiver of a
    /// later `.clone()` can be matched back to its declaration site.
    fn collect_let_bindings(&mut self, expr: &Expr<'tcx>) {
        if let ExprKind::Block(block, _) = expr.kind {
            for stmt in block.stmts {
                if let StmtKind::Let(local) = stmt.kind {
                    local.pat.walk(|pat| {
                        if let PatKind::Binding(_, hir_id, _, _) = pat.kind {
                            if self.loop_depth == 0 {
                                self.outer_locals.push(hir_id);
                            }
                        }
                        true
                    });
                }
            }
        }
    }

    /// True when the receiver resolves to a local declared outside every
    /// enclosing loop. Element bindings and temporaries created inside the loop
    /// resolve to locals absent from `outer_locals` and are therefore exempt.
    fn receiver_is_outer_local(&self, receiver: &Expr<'_>) -> bool {
        if let ExprKind::Path(QPath::Resolved(_, path)) = receiver.kind {
            if let Res::Local(hir_id) = path.res {
                return self.outer_locals.contains(&hir_id);
            }
        }
        false
    }

    /// True for `Vec`, `Map`, `Bytes`, and `String`: the host collections whose
    /// `.clone()` triggers a host-side deep copy. Scalars such as `Address`,
    /// `i128`, or `u32` are deliberately excluded.
    fn is_soroban_host_collection(&self, receiver: &Expr<'_>) -> bool {
        if let Some(receiver_ty) = get_node_type_opt(self.cx, &receiver.hir_id) {
            is_soroban_vec(self.cx, receiver_ty)
                || is_soroban_map(self.cx, receiver_ty)
                || match_type_to_str(self.cx, receiver_ty, SOROBAN_BYTES)
                || match_type_to_str(self.cx, receiver_ty, SOROBAN_STRING)
        } else {
            false
        }
    }
}

impl<'tcx> Visitor<'tcx> for CloneInLoopVisitor<'tcx, '_> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        self.collect_let_bindings(expr);

        // `for`, `while`, and bare `loop` all lower to `ExprKind::Loop`, so a
        // single depth counter around it covers every loop form.
        if let ExprKind::Loop(..) = expr.kind {
            self.loop_depth += 1;
            walk_expr(self, expr);
            self.loop_depth -= 1;
            return;
        }

        if_chain! {
            if self.loop_depth > 0;
            if let ExprKind::MethodCall(segment, receiver, args, _) = expr.kind;
            if segment.ident.name.as_str() == "clone";
            if args.is_empty();
            if self.is_soroban_host_collection(receiver);
            if self.receiver_is_outer_local(receiver);
            then {
                self.findings.push(expr.span);
            }
        }

        walk_expr(self, expr);
    }
}

impl<'tcx> LateLintPass<'tcx> for CloneInLoop {
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

        let mut visitor = CloneInLoopVisitor {
            cx,
            loop_depth: 0,
            outer_locals: Vec::new(),
            findings: Vec::new(),
        };

        walk_body(&mut visitor, body);

        for span in visitor.findings {
            span_lint_and_help(
                cx,
                CLONE_IN_LOOP,
                span,
                LINT_MESSAGE,
                None,
                "Hoist the clone above the loop and reuse the snapshot, or iterate by reference",
            );
        }
    }
}
