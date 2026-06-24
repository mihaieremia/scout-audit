#![feature(rustc_private)]
//! # instance-storage-per-user-key
//!
//! Flags Soroban instance storage keyed by an `Address`-bearing enum variant,
//! a pattern that grows the always-loaded instance map per user.
//!
//! ## What it detects
//! A `set`/`get`/`has` call on `env.storage().instance()` whose key argument is
//! a `#[contracttype]` enum variant constructor carrying at least one
//! `soroban_sdk::Address` field (e.g. `DataKey::Balance(user)`). Such a key is
//! distinct per address, so the entry count is bounded only by the number of
//! users.
//!
//! ## Why it matters
//! Instance storage is loaded in its entirety into memory on every contract
//! invocation, and its single TTL is shared across all entries. Per-user keys
//! let it grow without bound, inflating read cost and rent for every call and
//! eventually risking entry-size limits.
//!
//! ## Remediation
//! Store per-user data in `persistent()` (or `temporary()`) storage keyed by the
//! same variant; reserve `instance()` for a bounded set of global keys.
//!
//! ## False-positive scope
//! A bounded set keyed in instance storage is acceptable. The lint suppresses a
//! finding when the enclosing function caps the set with an `assert!` /
//! `assert_with_error!` / `panic_with_error!` gated on a `<` / `<=` comparison,
//! or when the same variant is also written through `persistent()` storage
//! (an intentional mixed-tier layout). Macro-expanded and `#[cfg(test)]` code is
//! skipped.
//!
//! Severity: Enhancement · Class: ResourceManagement.

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::{diagnostics::span_lint_and_help, macros::macro_backtrace};
use common::{
    analysis::{get_node_type_opt, is_soroban_address, is_soroban_storage, SorobanStorageType},
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use if_chain::if_chain;
use rustc_hir::{
    def::{CtorOf, DefKind, Res},
    intravisit::{walk_expr, FnKind, Visitor},
    BinOpKind, Body, Expr, ExprKind, FnDecl,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{def_id::LocalDefId, Span};

const LINT_MESSAGE: &str =
    "Instance storage keyed per user grows the always-loaded instance map without bound.";

/// Names of the assertion/panic macros whose `<`/`<=` guard caps a set and so
/// exempts an instance-storage key from this lint.
const BOUNDING_MACROS: [&str; 5] = [
    "assert",
    "assert_eq",
    "assert_with_error",
    "panic_with_error",
    "debug_assert",
];

#[expose_lint_info]
pub static INSTANCE_STORAGE_PER_USER_KEY_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "Soroban instance storage is loaded in full into memory on every invocation and shares a single TTL. Keying it by an `Address`-bearing enum variant makes the entry count grow per user, inflating read cost and rent for every call. Store per-user data in persistent or temporary storage and reserve instance storage for a bounded set of global keys.",
    severity: Severity::Enhancement,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/instance-storage-per-user-key",
    vulnerability_class: VulnerabilityClass::ResourceManagement,
};

dylint_linting::impl_late_lint! {
    pub INSTANCE_STORAGE_PER_USER_KEY,
    Warn,
    LINT_MESSAGE,
    InstanceStoragePerUserKey
}

#[derive(Default)]
struct InstanceStoragePerUserKey;

impl<'tcx> LateLintPass<'tcx> for InstanceStoragePerUserKey {
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

        // Pre-pass: collect the bounded-set exemptions that apply to the whole
        // function body — a `<`/`<=` guard reported through a bounding macro, and
        // every variant also written through persistent storage.
        let mut context = ExemptionVisitor {
            cx,
            saw_bounding_macro: false,
            saw_lt_compare: false,
            persistent_variants: Vec::new(),
        };
        context.visit_body(body);

        let mut visitor = InstanceStoragePerUserKeyVisitor {
            cx,
            has_bounding_guard: context.saw_bounding_macro && context.saw_lt_compare,
            persistent_variants: context.persistent_variants,
        };
        visitor.visit_body(body);
    }
}

/// Pre-pass that records the function-wide exemptions.
struct ExemptionVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    saw_bounding_macro: bool,
    saw_lt_compare: bool,
    persistent_variants: Vec<String>,
}

impl<'tcx> Visitor<'tcx> for ExemptionVisitor<'_, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        // A `<`/`<=` comparison anywhere in the body, paired with a bounding
        // macro, caps a set. The two signals are tracked independently because
        // `assert!(x < MAX)` preserves the condition's original span, so the
        // comparison itself does not carry the macro context.
        if let ExprKind::Binary(op, _, _) = &expr.kind {
            if matches!(op.node, BinOpKind::Lt | BinOpKind::Le) {
                self.saw_lt_compare = true;
            }
        }
        if spans_bounding_macro(self.cx, expr.span) {
            self.saw_bounding_macro = true;
        }

        // A persistent write of a variant marks it as intentionally mixed-tier.
        if_chain! {
            if let ExprKind::MethodCall(path, receiver, args, _) = &expr.kind;
            if matches!(path.ident.name.as_str(), "set" | "get" | "has");
            if let Some(receiver_ty) = get_node_type_opt(self.cx, &receiver.hir_id);
            if is_soroban_storage(self.cx, receiver_ty, SorobanStorageType::Persistent);
            if let Some(key_arg) = args.first();
            if let Some(variant) = variant_ident(self.cx, key_arg);
            then {
                self.persistent_variants.push(variant);
            }
        }

        walk_expr(self, expr);
    }
}

struct InstanceStoragePerUserKeyVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    has_bounding_guard: bool,
    persistent_variants: Vec<String>,
}

impl<'tcx> Visitor<'tcx> for InstanceStoragePerUserKeyVisitor<'_, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if_chain! {
            if !expr.span.from_expansion();
            if let ExprKind::MethodCall(path, receiver, args, _) = &expr.kind;
            if matches!(path.ident.name.as_str(), "set" | "get" | "has");
            if let Some(receiver_ty) = get_node_type_opt(self.cx, &receiver.hir_id);
            if is_soroban_storage(self.cx, receiver_ty, SorobanStorageType::Instance);
            if let Some(key_arg) = args.first();
            if let Some(variant) = self.address_bearing_variant(key_arg);
            // Bounded-set exemptions: a `< MAX` guard caps the set, or the same
            // variant is also written through persistent storage (mixed-tier).
            if !self.has_bounding_guard;
            if !self.persistent_variants.contains(&variant);
            then {
                span_lint_and_help(
                    self.cx,
                    INSTANCE_STORAGE_PER_USER_KEY,
                    expr.span,
                    LINT_MESSAGE,
                    None,
                    format!(
                        "key `{variant}` carries an Address; store per-user data in persistent storage instead of instance storage"
                    ),
                );
            }
        }

        walk_expr(self, expr);
    }
}

impl<'tcx> InstanceStoragePerUserKeyVisitor<'_, 'tcx> {
    /// Returns the variant identifier of `expr` when it constructs a tuple
    /// enum variant carrying at least one `soroban_sdk::Address` field.
    fn address_bearing_variant(&self, expr: &Expr<'tcx>) -> Option<String> {
        let inner = peel_borrow(expr);

        // Only tuple variants carry positional fields; a unit variant (bare
        // path) never holds an Address, so it is ignored here.
        let ExprKind::Call(callee, ctor_args) = &inner.kind else {
            return None;
        };
        let ExprKind::Path(qpath) = &callee.kind else {
            return None;
        };
        if !matches!(
            self.cx.qpath_res(qpath, callee.hir_id),
            Res::Def(DefKind::Ctor(CtorOf::Variant, _), _)
        ) {
            return None;
        }

        // Any constructor argument whose type is a Soroban `Address` marks the
        // key as per-user.
        let carries_address = ctor_args.iter().any(|arg| {
            get_node_type_opt(self.cx, &arg.hir_id)
                .is_some_and(|ty| is_soroban_address(self.cx, ty.peel_refs()))
        });
        if !carries_address {
            return None;
        }

        variant_ident(self.cx, inner)
    }
}

/// Removes a single leading `&`/`&mut` borrow.
fn peel_borrow<'a, 'tcx>(expr: &'a Expr<'tcx>) -> &'a Expr<'tcx> {
    match &expr.kind {
        ExprKind::AddrOf(_, _, inner) => inner,
        _ => expr,
    }
}

/// Extracts the enum-variant identifier from a storage-key expression, handling
/// unit variants (`DataKey::Admin`) and tuple variants (`DataKey::Balance(a)`),
/// with an optional leading `&`.
fn variant_ident<'tcx>(cx: &LateContext<'tcx>, expr: &Expr<'tcx>) -> Option<String> {
    let inner = peel_borrow(expr);

    let (qpath, hir_id) = match &inner.kind {
        ExprKind::Call(callee, _) => match &callee.kind {
            ExprKind::Path(qpath) => (qpath, callee.hir_id),
            _ => return None,
        },
        ExprKind::Path(qpath) => (qpath, inner.hir_id),
        _ => return None,
    };

    if let Res::Def(DefKind::Ctor(CtorOf::Variant, _), ctor_def_id) = cx.qpath_res(qpath, hir_id) {
        let variant_def_id = cx.tcx.parent(ctor_def_id);
        return Some(cx.tcx.item_name(variant_def_id).to_string());
    }
    None
}

/// Returns `true` if `span` was expanded from one of the bounding macros.
fn spans_bounding_macro(cx: &LateContext<'_>, span: Span) -> bool {
    macro_backtrace(span)
        .any(|call| BOUNDING_MACROS.contains(&cx.tcx.item_name(call.def_id).as_str()))
}
