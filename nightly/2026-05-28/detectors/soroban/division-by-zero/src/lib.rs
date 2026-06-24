#![feature(rustc_private)]
//! # division-by-zero
//!
//! Flags integer `/` and `%` operations whose divisor is not proven non-zero on
//! the current control-flow path.
//!
//! ## What it detects
//! An integer division or remainder where the divisor is a literal `0`, or a
//! local/value not shown to be non-zero. Compile-time constants and several
//! syntactic guards suppress the finding: `if d == 0 { return/panic }`,
//! `assert!(d != 0)`, `if d != 0 { .. } else { return/panic }`, and the positive
//! branch of `if [.. &&] d != 0 { .. }`. Guards are tracked per-path, so they
//! only protect the divisions they dominate.
//!
//! ## Why it matters
//! Integer division or remainder by zero panics at runtime in Soroban, aborting
//! the whole transaction. When the divisor derives from a parameter or computed
//! value, an attacker can force the panic as a denial-of-service.
//!
//! ## Remediation
//! Guard the divisor with an explicit non-zero check, or use `checked_div` /
//! `checked_rem` and handle the `None` case.
//!
//! Severity: Medium · Class: Arithmetic.

extern crate rustc_ast;
extern crate rustc_hir;
extern crate rustc_span;

use std::collections::HashSet;

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    analysis::ConstantAnalyzer,
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use if_chain::if_chain;
use rustc_hir::{
    def::Res,
    intravisit::{walk_expr, FnKind, Visitor},
    BinOpKind, Block, Body, Expr, ExprKind, FnDecl, HirId, Path, QPath, StmtKind, UnOp,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{def_id::LocalDefId, Span};

/// If `expr` is a bare path to a local binding, returns that local's `HirId`.
///
/// Mirrors the canonical-binding resolution used to key the guard set: only a
/// direct local reference (`x`) resolves; projections such as `x.field` do not.
fn path_to_local(expr: &Expr<'_>) -> Option<HirId> {
    if let ExprKind::Path(QPath::Resolved(
        _,
        Path {
            res: Res::Local(local),
            ..
        },
    )) = expr.kind
    {
        Some(*local)
    } else {
        None
    }
}

const LINT_MESSAGE: &str = "This division or remainder may panic because the divisor can be zero.";

#[expose_lint_info]
pub static DIVISION_BY_ZERO_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "Integer division or remainder by zero panics at runtime in Soroban contracts, aborting the transaction. When the divisor comes from a parameter or computed value that is not proven to be non-zero, the contract can be made to panic. Guard the divisor with an explicit zero check or use `checked_div`/`checked_rem`.",
    severity: Severity::Medium,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/division-by-zero",
    vulnerability_class: VulnerabilityClass::Arithmetic,
};

dylint_linting::declare_late_lint! {
    pub DIVISION_BY_ZERO,
    Warn,
    LINT_MESSAGE
}

/// If one side of a comparison is a local variable and the other is the
/// literal `0`, returns the local's `HirId`.
fn local_compared_to_zero(lhs: &Expr<'_>, rhs: &Expr<'_>) -> Option<HirId> {
    if is_zero_literal(rhs) {
        return path_to_local(lhs);
    }
    if is_zero_literal(lhs) {
        return path_to_local(rhs);
    }
    None
}

fn is_zero_literal(expr: &Expr<'_>) -> bool {
    if_chain! {
        if let ExprKind::Lit(lit) = &expr.kind;
        if let rustc_ast::LitKind::Int(value, _) = lit.node;
        then {
            value.get() == 0
        } else {
            false
        }
    }
}

/// Returns `true` if evaluating `expr` always diverges (never falls through to
/// the code after it), which is what an early-return / panic guard relies on.
/// Recognized forms: `return`, `break`, `continue`, and any expression whose
/// type is the never type `!` (covers `panic!`, `unreachable!`, `todo!`,
/// `assert!(false)`, `core::panic::*`, and Soroban's `panic_with_error!`, all of
/// which lower to a diverging call).
fn expr_diverges(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    if matches!(
        expr.kind,
        ExprKind::Ret(_) | ExprKind::Break(..) | ExprKind::Continue(_)
    ) {
        return true;
    }
    cx.typeck_results().expr_ty(expr).is_never()
}

/// Returns `true` if `block` is a guard body that always diverges: every path
/// out of it returns or panics. Conservatively, this requires the block's tail
/// expression (or, for a statement-only block, its last statement) to diverge.
fn block_diverges(cx: &LateContext<'_>, block: &Block<'_>) -> bool {
    if let Some(tail) = block.expr {
        return expr_diverges(cx, tail);
    }
    match block.stmts.last().map(|stmt| &stmt.kind) {
        Some(StmtKind::Semi(expr)) | Some(StmtKind::Expr(expr)) => expr_diverges(cx, expr),
        _ => false,
    }
}

/// If `cond` is a zero comparison of a local, returns `(local, guarded_on_eq)`.
///
/// `guarded_on_eq` is `true` when the condition is `local == 0` (so the local is
/// proven non-zero on the *false*/else path), and `false` when the condition is
/// `local != 0` (proven non-zero on the *true*/then path). This lets the caller
/// pick which branch the guard protects.
fn zero_comparison(cond: &Expr<'_>) -> Option<(HirId, bool)> {
    if let ExprKind::Binary(op, lhs, rhs) = &cond.kind {
        match op.node {
            BinOpKind::Eq => return local_compared_to_zero(lhs, rhs).map(|id| (id, true)),
            BinOpKind::Ne => return local_compared_to_zero(lhs, rhs).map(|id| (id, false)),
            _ => {}
        }
    }
    // `!(local == 0)` behaves like `local != 0`, and vice versa.
    if let ExprKind::Unary(UnOp::Not, inner) = &cond.kind {
        return zero_comparison(inner).map(|(id, on_eq)| (id, !on_eq));
    }
    None
}

/// Removes a `DropTemps` wrapper if present. `if`/`while` conditions are lowered
/// with such a wrapper; peeling it lets the same matcher handle both wrapped and
/// already-unwrapped expressions.
fn peel_drop_temps<'a, 'tcx>(expr: &'a Expr<'tcx>) -> &'a Expr<'tcx> {
    if let ExprKind::DropTemps(inner) = &expr.kind {
        inner
    } else {
        expr
    }
}

/// Collects every local proven non-zero when `cond` evaluates to `true`.
///
/// Besides a bare `local != 0`, this understands the `&&` short-circuit form,
/// which HIR lowers to `if <lhs> { <rhs> } else { false }`. Each conjunct that
/// is a `local != 0` therefore also proves that local non-zero on the true path,
/// so a divisor guarded by `if a && divisor != 0 { .. / divisor }` is still
/// recognized and not falsely flagged. `||` lowers to `if <lhs> { true } else
/// { <rhs> }`; its `true` arm proves nothing, so it is intentionally ignored.
fn locals_nonzero_on_true(cond: &Expr<'_>, out: &mut Vec<HirId>) {
    let cond = peel_drop_temps(cond);

    // A single-expression block (the `&&` lowering wraps each operand in one)
    // contributes whatever its tail expression proves.
    if let ExprKind::Block(block, _) = &cond.kind {
        if block.stmts.is_empty() {
            if let Some(tail) = block.expr {
                locals_nonzero_on_true(tail, out);
            }
        }
        return;
    }

    if let Some((local, on_eq)) = zero_comparison(cond) {
        if !on_eq {
            out.push(local);
        }
        return;
    }
    // `lhs && rhs` kept as a `Binary(And)` node: both conjuncts hold on the true
    // path, so a `divisor != 0` in either operand proves the divisor non-zero.
    if let ExprKind::Binary(op, lhs, rhs) = &cond.kind {
        if matches!(op.node, BinOpKind::And) {
            locals_nonzero_on_true(lhs, out);
            locals_nonzero_on_true(rhs, out);
            return;
        }
    }
    // `lhs && rhs` lowered to `if lhs { rhs } else { false }`. Both conjuncts hold
    // on the true path, so recurse into the condition and the (then) `rhs` arm.
    if_chain! {
        if let ExprKind::If(inner_cond, then, Some(els)) = &cond.kind;
        if is_false_literal(els);
        then {
            locals_nonzero_on_true(inner_cond, out);
            locals_nonzero_on_true(then, out);
        }
    }
}

fn is_false_literal(expr: &Expr<'_>) -> bool {
    // The `&&` lowering may wrap the `else { false }` arm in a trivial block, so
    // peel a single-expression block (and drop-temps) before matching the literal.
    let mut expr = peel_drop_temps(expr);
    if let ExprKind::Block(block, _) = &expr.kind {
        if block.stmts.is_empty() {
            if let Some(tail) = block.expr {
                expr = peel_drop_temps(tail);
            }
        }
    }
    matches!(
        expr.kind,
        ExprKind::Lit(ref lit) if matches!(lit.node, rustc_ast::LitKind::Bool(false))
    )
}

/// Returns `true` if the branch expression (a block, or anything diverging)
/// never falls through.
fn branch_diverges(cx: &LateContext<'_>, branch: &Expr<'_>) -> bool {
    match &branch.kind {
        ExprKind::Block(block, _) => block_diverges(cx, block),
        _ => expr_diverges(cx, branch),
    }
}

/// Recognizes an `if` whose comparison of `local` against zero, combined with a
/// diverging branch, proves `local` non-zero on the *fall-through* path, and
/// returns that `local`.
///
/// Covered shapes:
/// * `if d == 0 { return ... }` / `{ panic_with_error!(...) }` (no/any else):
///   the `d == 0` branch diverges, so reaching past it means `d != 0`.
/// * `assert!(d != 0)`, which `assert!` lowers to `if !(d != 0) { panic!(...) }`;
///   `zero_comparison` folds `!(d != 0)` back into the `d == 0` case.
/// * `if d != 0 { .. } else { return ... }`: the `else` (the `d == 0` side)
///   diverges, so the fall-through path again has `d != 0`.
///
/// `assert_ne!(d, 0)` lowers to a `match` rather than this `if`/negation shape
/// and is therefore not recognized (see the precision note on the visitor).
fn diverging_zero_guard<'tcx>(cx: &LateContext<'tcx>, expr: &Expr<'tcx>) -> Option<HirId> {
    if_chain! {
        if let ExprKind::If(cond, then, els) = &expr.kind;
        if let Some((local, on_eq)) = zero_comparison(peel_drop_temps(cond));
        then {
            // The branch taken when `local == 0` is the `then` when the
            // condition is `local == 0`, or the `else` when it is `local != 0`.
            // If that branch diverges, the value is non-zero afterwards.
            let zero_branch = if on_eq { Some(*then) } else { *els };
            if let Some(zero_branch) = zero_branch {
                if branch_diverges(cx, zero_branch) {
                    return Some(local);
                }
            }
        }
    }
    None
}

/// Walks a function body and flags integer `/` and `%` whose divisor is not
/// proven non-zero on the current path.
///
/// Precision notes (intentionally conservative to avoid false positives):
/// * Guard recognition is local and syntactic. It understands the diverging
///   forms `if d == 0 { return/panic }`, `assert!(d != 0)`, and
///   `if d != 0 { .. } else { return/panic }`, plus the positive branch of
///   `if [.. &&] d != 0 { .. }`. It does **not** model `assert_ne!(d, 0)` (which
///   lowers to a `match`), `||` conditions, loops, reassignment, or guards that
///   live in a different function. Such cases simply fall back to flagging,
///   which is safe but may over-report.
/// * Non-literal arithmetic that is nonetheless always non-zero (e.g.
///   `d.max(1)`, `1 << k`) is not recognized as safe and may be flagged. Only
///   compile-time constants (via `ConstantAnalyzer`) and explicit guards
///   suppress a finding.
struct DivisionByZeroVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    constant_analyzer: ConstantAnalyzer<'a, 'tcx>,
    /// Locals proven non-zero on the current control-flow path. A divisor backed
    /// by one of these is treated as guarded. The set grows as guards are seen
    /// earlier in a block and shrinks again when their scope ends, so a guard
    /// only protects the divisions it actually dominates (unlike a body-wide
    /// scan, which also silenced divisions that precede or sit outside the
    /// guard).
    guarded: HashSet<HirId>,
    findings: Vec<Span>,
}

impl<'tcx> DivisionByZeroVisitor<'_, 'tcx> {
    /// Decides whether the given divisor expression is unsafe (may be zero).
    fn divisor_is_unsafe(&mut self, divisor: &Expr<'tcx>) -> bool {
        // A literal `0` divisor is always unsafe.
        if is_zero_literal(divisor) {
            return true;
        }

        // Any other constant divisor is provably non-zero (a constant `0`
        // would have been caught above), so it is safe.
        if self.constant_analyzer.is_constant(divisor) {
            return false;
        }

        // A divisor backed by a local proven non-zero on this path is safe.
        if let Some(local) = path_to_local(divisor) {
            if self.guarded.contains(&local) {
                return false;
            }
        }

        true
    }

    /// Walks a block, accumulating guards that apply to the statements that
    /// follow them within the same block (early-return / `assert!` forms).
    fn walk_guarded_block(&mut self, block: &'tcx Block<'tcx>) {
        // Guards introduced inside this block must not leak to sibling blocks,
        // so remember what was already active and restore it on exit.
        let entry_guards: Vec<HirId> = self.guarded.iter().copied().collect();

        for stmt in block.stmts {
            match &stmt.kind {
                StmtKind::Expr(expr) | StmtKind::Semi(expr) => {
                    if let Some(local) = diverging_zero_guard(self.cx, expr) {
                        // `if d == 0 { return/panic }` and `assert!(d != 0)`
                        // protect every statement that follows them in this
                        // block. We still descend into the guard itself so that
                        // any division *inside* its diverging branch (where the
                        // value is not yet proven non-zero) is still examined.
                        self.visit_expr(expr);
                        self.guarded.insert(local);
                        continue;
                    }
                    self.visit_expr(expr);
                }
                StmtKind::Let(let_stmt) => {
                    if let Some(init) = let_stmt.init {
                        self.visit_expr(init);
                    }
                    if let Some(els) = let_stmt.els {
                        self.walk_guarded_block(els);
                    }
                }
                StmtKind::Item(_) => {}
            }
        }

        if let Some(tail) = block.expr {
            self.visit_expr(tail);
        }

        self.guarded.retain(|id| entry_guards.contains(id));
    }
}

impl<'tcx> Visitor<'tcx> for DivisionByZeroVisitor<'_, 'tcx> {
    fn visit_block(&mut self, block: &'tcx Block<'tcx>) {
        self.walk_guarded_block(block);
    }

    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        // Recognize `if .. divisor != 0 .. { <then> }`: divisions in the then
        // branch are guarded, so visit it with those locals added to the active
        // guard set. Handles compound `&&` conditions (e.g. `a && divisor != 0`)
        // so legitimately guarded divisions are not falsely flagged.
        if let ExprKind::If(cond, then, els) = &expr.kind {
            let mut proven = Vec::new();
            locals_nonzero_on_true(cond, &mut proven);
            if !proven.is_empty() {
                let inserted: Vec<HirId> = proven
                    .into_iter()
                    .filter(|local| self.guarded.insert(*local))
                    .collect();
                self.visit_expr(then);
                for local in inserted {
                    self.guarded.remove(&local);
                }
                if let Some(els) = els {
                    self.visit_expr(els);
                }
                return;
            }
        }

        if let ExprKind::Binary(op, dividend, divisor) = &expr.kind {
            if matches!(op.node, BinOpKind::Div | BinOpKind::Rem) {
                let dividend_ty = self.cx.typeck_results().expr_ty(dividend).peel_refs();
                if dividend_ty.is_integral() && self.divisor_is_unsafe(divisor) {
                    self.findings.push(expr.span);
                }
            }
        }
        walk_expr(self, expr);
    }
}

impl<'tcx> LateLintPass<'tcx> for DivisionByZero {
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

        let mut constant_analyzer = ConstantAnalyzer::new(cx);
        constant_analyzer.visit_body(body);

        let mut visitor = DivisionByZeroVisitor {
            cx,
            constant_analyzer,
            guarded: HashSet::new(),
            findings: Vec::new(),
        };
        visitor.visit_body(body);

        for span in visitor.findings {
            span_lint_and_help(
                cx,
                DIVISION_BY_ZERO,
                span,
                LINT_MESSAGE,
                None,
                "Guard the divisor with an explicit non-zero check, or use `checked_div`/`checked_rem` and handle the `None` case.",
            );
        }
    }
}
