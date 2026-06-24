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
//! ## Suppressed patterns
//! Two cases are not flagged, because the source value is provably (or
//! by-convention) in range of the target:
//! 1. The operand is a compiler-evaluable constant.
//! 2. The operand reads the inner integer of a *bounded-domain newtype* via an
//!    accessor (`.raw()`, `.value()`, `.get()`, `.to_bits()`) or a tuple field
//!    (`.0`). A bounded-domain newtype is a single-field tuple/struct that wraps
//!    one primitive integer (fixed-point / ratio types such as `Bps`, `Wad`,
//!    `Ray`). Such types carry a domain invariant enforced at construction
//!    (e.g. basis points are validated to `0..=10000`), so narrowing their inner
//!    value is lossless in practice. Tradeoff: a newtype that wraps an unbounded
//!    `i128` with no real invariant would also be suppressed; this is accepted
//!    because the pattern overwhelmingly denotes domain ratio types, and the
//!    local cast site never carries the proof anyway.
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

/// Accessor method names that conventionally expose the inner value of a
/// single-field newtype.
const NEWTYPE_ACCESSORS: [&str; 4] = ["raw", "value", "get", "to_bits"];

/// Returns true when `ty` is a single-field tuple/struct that wraps exactly one
/// primitive integer (a "bounded-domain newtype" such as `Bps`, `Wad`, `Ray`).
fn is_domain_newtype<'tcx>(cx: &LateContext<'tcx>, ty: Ty<'tcx>) -> bool {
    let TyKind::Adt(adt_def, args) = ty.kind() else {
        return false;
    };
    if !adt_def.is_struct() {
        return false;
    }
    let variant = adt_def.non_enum_variant();
    let [field] = variant.fields.raw.as_slice() else {
        return false;
    };
    // `FieldDef::ty` returns an unnormalized type; the inner type of a domain
    // newtype is a concrete primitive integer, so normalization is a no-op and
    // skipping it is sound here.
    int_info(field.ty(cx.tcx, args).skip_norm_wip()).is_some()
}

/// Returns true when `source` reads the inner integer of a bounded-domain
/// newtype, either through a zero-argument accessor method (`.raw()`,
/// `.value()`, `.get()`, `.to_bits()`) or a tuple-field access (`.0`).
///
/// The newtype invariant lives in the type, not at the cast site, so we resolve
/// the receiver/base type via typeck and treat any single-integer-field struct
/// as carrying a bounded domain. See the crate-level docs for the tradeoff.
fn reads_bounded_domain_newtype<'tcx>(cx: &LateContext<'tcx>, source: &Expr<'tcx>) -> bool {
    let base = match &source.kind {
        ExprKind::MethodCall(segment, receiver, args, _)
            if args.is_empty() && NEWTYPE_ACCESSORS.contains(&segment.ident.as_str()) =>
        {
            receiver
        }
        ExprKind::Field(base, _) => base,
        _ => return false,
    };
    let base_ty = cx.typeck_results().expr_ty(base).peel_refs();
    is_domain_newtype(cx, base_ty)
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
            // fits (or would be a hard error), so skip it to avoid noise. A read
            // of a bounded-domain newtype's inner integer is in range by the
            // type's construction invariant, so skip it too.
            if !self.constant_analyzer.is_constant(source)
                && !reads_bounded_domain_newtype(self.cx, source)
            {
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
