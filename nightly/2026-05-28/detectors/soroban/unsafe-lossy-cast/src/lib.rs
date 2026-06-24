#![feature(rustc_private)]
//! # unsafe-lossy-cast
//!
//! Flags integer `as` casts that can silently truncate a value or change its
//! sign.
//!
//! ## What it detects
//! A non-constant integer-to-integer `as` cast that narrows the bit width
//! (e.g. `i64 as i32`) or crosses signedness in a value-changing way
//! (e.g. `i32 as u32`, `u64 as i32`). Casts of compiler-evaluable constants are
//! skipped to avoid noise.
//!
//! ## Why it matters
//! Silent truncation or sign reinterpretation produces incorrect numeric results
//! that are easy to miss and can corrupt balances, indices, or accounting in a
//! contract.
//!
//! ## Remediation
//! Use `TryFrom`/`TryInto` and handle the conversion error explicitly instead of
//! an `as` cast.
//!
//! Severity: Medium · Class: Arithmetic.

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    analysis::ConstantAnalyzer,
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use rustc_hir::{
    intravisit::{walk_expr, FnKind, Visitor},
    Body, Expr, ExprKind, FnDecl,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::ty::{IntTy, Ty, TyKind, UintTy};
use rustc_span::{def_id::LocalDefId, Span};

const LINT_MESSAGE: &str =
    "This `as` cast may truncate or change the sign of the value, silently losing information.";

#[expose_lint_info]
pub static UNSAFE_LOSSY_CAST_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "Casting an integer to a narrower type, or between signed and unsigned types, with the `as` operator silently truncates or reinterprets the value when it does not fit in the target type. This can produce incorrect results that are hard to detect. Prefer `TryFrom`/`TryInto` and handle the error explicitly.",
    severity: Severity::Medium,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/unsafe-lossy-cast",
    vulnerability_class: VulnerabilityClass::Arithmetic,
};

dylint_linting::declare_late_lint! {
    pub UNSAFE_LOSSY_CAST,
    Warn,
    LINT_MESSAGE
}

/// Integer type description used to decide whether a cast is lossy.
#[derive(Clone, Copy, PartialEq, Eq)]
struct IntInfo {
    signed: bool,
    /// Bit width; `None` for pointer-sized types (`usize`/`isize`).
    width: Option<u64>,
}

fn int_info(ty: Ty<'_>) -> Option<IntInfo> {
    match ty.kind() {
        TyKind::Int(int_ty) => Some(IntInfo {
            signed: true,
            width: int_bit_width(*int_ty),
        }),
        TyKind::Uint(uint_ty) => Some(IntInfo {
            signed: false,
            width: uint_bit_width(*uint_ty),
        }),
        _ => None,
    }
}

fn int_bit_width(int_ty: IntTy) -> Option<u64> {
    match int_ty {
        IntTy::I8 => Some(8),
        IntTy::I16 => Some(16),
        IntTy::I32 => Some(32),
        IntTy::I64 => Some(64),
        IntTy::I128 => Some(128),
        IntTy::Isize => None,
    }
}

fn uint_bit_width(uint_ty: UintTy) -> Option<u64> {
    match uint_ty {
        UintTy::U8 => Some(8),
        UintTy::U16 => Some(16),
        UintTy::U32 => Some(32),
        UintTy::U64 => Some(64),
        UintTy::U128 => Some(128),
        UintTy::Usize => None,
    }
}

/// Returns true when casting a value of type `src` to type `dst` can lose
/// information (truncation) or change its sign (reinterpretation).
fn is_lossy_cast(src: IntInfo, dst: IntInfo) -> bool {
    // Pointer-sized types have a target-dependent width; skip them to stay
    // conservative and avoid false positives.
    let (Some(src_width), Some(dst_width)) = (src.width, dst.width) else {
        return false;
    };

    if src.signed == dst.signed {
        // Same signedness: lossy only when narrowing.
        return src_width > dst_width;
    }

    if src.signed && !dst.signed {
        // Signed -> unsigned: negative values become large positives, always lossy.
        return true;
    }

    // Unsigned -> signed: the top bit of the source must fit in the signed
    // target. A `uN as iM` is lossy unless `M > N` (so the source range fits
    // entirely in the positive range of the target).
    dst_width <= src_width
}

struct UnsafeLossyCastVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    constant_analyzer: ConstantAnalyzer<'a, 'tcx>,
    findings: Vec<Span>,
}

impl<'tcx> Visitor<'tcx> for UnsafeLossyCastVisitor<'_, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if let ExprKind::Cast(source, _) = &expr.kind {
            // A constant source that the compiler can fully evaluate provably
            // fits (or would be a hard error), so skip it to avoid noise.
            if !self.constant_analyzer.is_constant(source) {
                let src_ty = self.cx.typeck_results().expr_ty(source).peel_refs();
                let dst_ty = self.cx.typeck_results().expr_ty(expr).peel_refs();
                if let (Some(src), Some(dst)) = (int_info(src_ty), int_info(dst_ty)) {
                    if is_lossy_cast(src, dst) {
                        self.findings.push(expr.span);
                    }
                }
            }
        }
        walk_expr(self, expr);
    }
}

impl<'tcx> LateLintPass<'tcx> for UnsafeLossyCast {
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

        let mut visitor = UnsafeLossyCastVisitor {
            cx,
            constant_analyzer,
            findings: Vec::new(),
        };
        visitor.visit_body(body);

        for span in visitor.findings {
            span_lint_and_help(
                cx,
                UNSAFE_LOSSY_CAST,
                span,
                LINT_MESSAGE,
                None,
                "Use `TryFrom`/`TryInto` and handle the conversion error instead of an `as` cast.",
            );
        }
    }
}
