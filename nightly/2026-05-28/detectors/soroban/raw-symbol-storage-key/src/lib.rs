#![feature(rustc_private)]
//! # raw-symbol-storage-key
//!
//! Flags Soroban storage keyed by a raw `Symbol`/string literal instead of a
//! typed `#[contracttype]` enum.
//!
//! ## What it detects
//! A `set`/`get`/`has`/`remove`/`extend_ttl` call on any Soroban storage
//! (`instance`/`persistent`/`temporary`) whose key argument is a raw symbol: a
//! string literal, a `symbol_short!` / `Symbol::new` construction, or any value
//! of type `soroban_sdk::Symbol` that is not an enum-variant constructor.
//!
//! ## Why it matters
//! Raw symbol keys are unchecked by the type system: two unrelated entries can
//! collide on the same short symbol, a typo silently reads a different slot, and
//! the storage layout is undocumented. A `#[contracttype]` enum makes every key
//! distinct, exhaustive, and self-describing.
//!
//! ## Remediation
//! Define a `#[contracttype] enum DataKey { ... }` and key all storage on its
//! variants instead of raw symbols.
//!
//! ## False-positive scope
//! Only the key position (`args[0]`) of a storage call is inspected. The
//! `is_soroban_storage` receiver gate already excludes the legitimate
//! Symbol-as-value uses — event topics, cross-contract function names, and RBAC
//! role identifiers — which are correct. Macro-expanded and `#[cfg(test)]` code
//! is skipped.
//!
//! Severity: Enhancement · Class: BestPractices.

extern crate rustc_ast;
extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    analysis::{get_node_type_opt, is_soroban_storage, match_type_to_str, SorobanStorageType},
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use if_chain::if_chain;
use rustc_ast::LitKind;
use rustc_hir::{
    def::{CtorOf, DefKind, Res},
    intravisit::{walk_expr, FnKind, Visitor},
    Body, Expr, ExprKind, FnDecl,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{def_id::LocalDefId, Span};

const LINT_MESSAGE: &str =
    "Storage keyed by a raw Symbol or string literal is collision-prone; use a typed `#[contracttype]` enum key.";

/// Fully-qualified type of a Soroban symbol. A storage key of this type that is
/// not built from an enum variant is a raw key.
const SOROBAN_SYMBOL: &str = "soroban_sdk::Symbol";

#[expose_lint_info]
pub static RAW_SYMBOL_STORAGE_KEY_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "Keying Soroban storage on a raw `Symbol` or string literal bypasses the type system: unrelated entries can collide on the same short symbol, a mistyped key silently reads a different slot, and the storage layout stays undocumented. Define a `#[contracttype]` enum and key every storage entry on its variants so keys are distinct, exhaustive, and self-describing.",
    severity: Severity::Enhancement,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/raw-symbol-storage-key",
    vulnerability_class: VulnerabilityClass::BestPractices,
};

dylint_linting::impl_late_lint! {
    pub RAW_SYMBOL_STORAGE_KEY,
    Warn,
    LINT_MESSAGE,
    RawSymbolStorageKey
}

#[derive(Default)]
struct RawSymbolStorageKey;

impl<'tcx> LateLintPass<'tcx> for RawSymbolStorageKey {
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

        let mut visitor = RawSymbolStorageKeyVisitor { cx };
        visitor.visit_body(body);
    }
}

struct RawSymbolStorageKeyVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
}

impl<'tcx> Visitor<'tcx> for RawSymbolStorageKeyVisitor<'_, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if_chain! {
            if !expr.span.from_expansion();
            // A storage access whose key we can inspect.
            if let ExprKind::MethodCall(path, receiver, args, _) = &expr.kind;
            if matches!(
                path.ident.name.as_str(),
                "set" | "get" | "has" | "remove" | "extend_ttl"
            );
            if let Some(receiver_ty) = get_node_type_opt(self.cx, &receiver.hir_id);
            if is_soroban_storage(self.cx, receiver_ty, SorobanStorageType::Any);
            // Only the key position (`args[0]`) is inspected.
            if let Some(key_arg) = args.first();
            if self.is_raw_symbol_key(key_arg);
            then {
                span_lint_and_help(
                    self.cx,
                    RAW_SYMBOL_STORAGE_KEY,
                    expr.span,
                    LINT_MESSAGE,
                    None,
                    "define a `#[contracttype]` enum (e.g. `DataKey`) and key storage on its variants instead of a raw symbol",
                );
            }
        }

        walk_expr(self, expr);
    }
}

impl<'tcx> RawSymbolStorageKeyVisitor<'_, 'tcx> {
    /// Returns `true` if the key expression is a raw symbol: a string literal,
    /// or a value of type `soroban_sdk::Symbol` that is not an enum-variant
    /// constructor (which would be a typed `#[contracttype]` key).
    fn is_raw_symbol_key(&self, key: &Expr<'tcx>) -> bool {
        let inner = peel_borrow(key);

        // A bare string literal key.
        if let ExprKind::Lit(lit) = &inner.kind {
            if matches!(lit.node, LitKind::Str(..)) {
                return true;
            }
        }

        // A typed `#[contracttype]` enum-variant key is the correct form; never
        // flag it even though its construction may carry a `Symbol` somewhere.
        if is_enum_variant_ctor(self.cx, inner) {
            return false;
        }

        // Any remaining key whose type is `soroban_sdk::Symbol` — a
        // `symbol_short!`, `Symbol::new`, or a `const Symbol` reference.
        get_node_type_opt(self.cx, &inner.hir_id)
            .is_some_and(|ty| match_type_to_str(self.cx, ty.peel_refs(), SOROBAN_SYMBOL))
    }
}

/// Removes a single leading `&`/`&mut` borrow.
fn peel_borrow<'a, 'tcx>(expr: &'a Expr<'tcx>) -> &'a Expr<'tcx> {
    match &expr.kind {
        ExprKind::AddrOf(_, _, inner) => inner,
        _ => expr,
    }
}

/// Returns `true` if `expr` constructs a `#[contracttype]` enum variant, either
/// a unit variant (`DataKey::Admin`) or a tuple variant (`DataKey::Balance(a)`).
fn is_enum_variant_ctor<'tcx>(cx: &LateContext<'tcx>, expr: &Expr<'tcx>) -> bool {
    let (qpath, hir_id) = match &expr.kind {
        ExprKind::Call(callee, _) => match &callee.kind {
            ExprKind::Path(qpath) => (qpath, callee.hir_id),
            _ => return false,
        },
        ExprKind::Path(qpath) => (qpath, expr.hir_id),
        _ => return false,
    };

    matches!(
        cx.qpath_res(qpath, hir_id),
        Res::Def(DefKind::Ctor(CtorOf::Variant, _), _)
    )
}
