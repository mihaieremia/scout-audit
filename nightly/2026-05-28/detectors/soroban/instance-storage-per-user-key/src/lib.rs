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
//! finding for any key variant that is capped *anywhere in the crate*: a setter
//! that gates the entry count with an `assert!` / `assert_with_error!` /
//! `panic_with_error!` on a `<` / `<=` comparison while writing the variant marks
//! that variant as bounded, so a sibling read accessor that only calls `.get()`
//! is exempt too. A variant also written through `persistent()` storage (an
//! intentional mixed-tier layout) is likewise suppressed. Macro-expanded and
//! `#[cfg(test)]` code is skipped.
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
    intravisit::{walk_expr, walk_local, FnKind, Visitor},
    BinOpKind, Body, Expr, ExprKind, FnDecl, HirId, LetStmt, PatKind, Path, QPath,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{def_id::LocalDefId, Span};
use std::collections::{HashMap, HashSet};

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
    InstanceStoragePerUserKey::default()
}

/// One flagged instance-storage access, deferred until the whole crate has been
/// scanned so it can be checked against the crate-wide exemption sets.
struct Candidate {
    variant: String,
    span: Span,
}

#[derive(Default)]
struct InstanceStoragePerUserKey {
    /// Address-bearing instance-storage accesses, emitted in `check_crate_post`.
    candidates: Vec<Candidate>,
    /// Variants whose entry count is capped by a `<`/`<=` bounding guard in some
    /// function that also writes them (typically the setter).
    capped_variants: HashSet<String>,
    /// Variants also written through persistent storage (intentional mixed-tier).
    persistent_variants: HashSet<String>,
}

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

        // Pre-pass: record the per-function exemption signals. A `<`/`<=` guard
        // reported through a bounding macro caps the entry count; every variant
        // also written through persistent storage is mixed-tier. These two
        // signals are tracked independently because `assert!(x < MAX)` preserves
        // the condition's original span, so the comparison itself does not carry
        // the macro context.
        let mut exemptions = ExemptionVisitor {
            cx,
            saw_bounding_macro: false,
            saw_lt_compare: false,
            instance_variants: Vec::new(),
            persistent_variants: Vec::new(),
            key_bindings: HashMap::new(),
        };
        exemptions.visit_body(body);

        // A capping guard binds the function's instance-storage variants: a
        // setter that caps the count and writes `ApprovedToken(addr)` marks that
        // variant as bounded crate-wide, so a read accessor in another function
        // is exempt too.
        if exemptions.saw_bounding_macro && exemptions.saw_lt_compare {
            self.capped_variants.extend(exemptions.instance_variants);
        }
        self.persistent_variants
            .extend(exemptions.persistent_variants);

        // Collect candidate accesses; emission is deferred to `check_crate_post`.
        let mut visitor = CandidateVisitor {
            cx,
            candidates: Vec::new(),
        };
        visitor.visit_body(body);
        self.candidates.extend(visitor.candidates);
    }

    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        for candidate in &self.candidates {
            if self.capped_variants.contains(&candidate.variant)
                || self.persistent_variants.contains(&candidate.variant)
            {
                continue;
            }
            span_lint_and_help(
                cx,
                INSTANCE_STORAGE_PER_USER_KEY,
                candidate.span,
                LINT_MESSAGE,
                None,
                format!(
                    "key `{}` carries an Address; store per-user data in persistent storage instead of instance storage",
                    candidate.variant
                ),
            );
        }
    }
}

/// Pre-pass that records the per-function exemption signals.
struct ExemptionVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    saw_bounding_macro: bool,
    saw_lt_compare: bool,
    /// Instance-storage key variants accessed in this body.
    instance_variants: Vec<String>,
    /// Persistent-storage key variants accessed in this body.
    persistent_variants: Vec<String>,
    /// `let key = SomeKey::Variant(..)` bindings, so a storage call that reuses
    /// the local (`.get(&key)`) still resolves to its variant. Setters commonly
    /// bind the key once and read/write/remove it several times.
    key_bindings: HashMap<HirId, String>,
}

impl<'tcx> ExemptionVisitor<'_, 'tcx> {
    /// Resolves a storage-key argument to its enum-variant name, via an inline
    /// constructor (`&SomeKey::Variant(..)`) or a previously `let`-bound local.
    fn resolve_key_variant(&self, key_arg: &Expr<'tcx>) -> Option<String> {
        if let Some(variant) = variant_ident(self.cx, key_arg) {
            return Some(variant);
        }
        if let ExprKind::Path(QPath::Resolved(
            _,
            Path {
                res: Res::Local(hir_id),
                ..
            },
        )) = &peel_borrow(key_arg).kind
        {
            return self.key_bindings.get(hir_id).cloned();
        }
        None
    }
}

impl<'tcx> Visitor<'tcx> for ExemptionVisitor<'_, 'tcx> {
    fn visit_local(&mut self, local: &'tcx LetStmt<'tcx>) {
        if_chain! {
            if let PatKind::Binding(_, hir_id, _, _) = local.pat.kind;
            if let Some(init) = local.init;
            if let Some(variant) = variant_ident(self.cx, init);
            then {
                self.key_bindings.insert(hir_id, variant);
            }
        }
        walk_local(self, local);
    }

    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if let ExprKind::Binary(op, _, _) = &expr.kind {
            if matches!(op.node, BinOpKind::Lt | BinOpKind::Le) {
                self.saw_lt_compare = true;
            }
        }
        if spans_bounding_macro(self.cx, expr.span) {
            self.saw_bounding_macro = true;
        }

        if_chain! {
            if let ExprKind::MethodCall(path, receiver, args, _) = &expr.kind;
            if matches!(path.ident.name.as_str(), "set" | "get" | "has" | "remove" | "update");
            if let Some(receiver_ty) = get_node_type_opt(self.cx, &receiver.hir_id);
            if let Some(key_arg) = args.first();
            if let Some(variant) = self.resolve_key_variant(key_arg);
            then {
                if is_soroban_storage(self.cx, receiver_ty, SorobanStorageType::Instance) {
                    self.instance_variants.push(variant);
                } else if is_soroban_storage(self.cx, receiver_ty, SorobanStorageType::Persistent) {
                    self.persistent_variants.push(variant);
                }
            }
        }

        walk_expr(self, expr);
    }
}

/// Collects address-bearing instance-storage accesses for later emission.
struct CandidateVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    candidates: Vec<Candidate>,
}

impl<'tcx> Visitor<'tcx> for CandidateVisitor<'_, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if_chain! {
            if !expr.span.from_expansion();
            if let ExprKind::MethodCall(path, receiver, args, _) = &expr.kind;
            if matches!(path.ident.name.as_str(), "set" | "get" | "has");
            if let Some(receiver_ty) = get_node_type_opt(self.cx, &receiver.hir_id);
            if is_soroban_storage(self.cx, receiver_ty, SorobanStorageType::Instance);
            if let Some(key_arg) = args.first();
            if let Some(variant) = self.address_bearing_variant(key_arg);
            then {
                self.candidates.push(Candidate { variant, span: expr.span });
            }
        }

        walk_expr(self, expr);
    }
}

impl<'tcx> CandidateVisitor<'_, 'tcx> {
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
