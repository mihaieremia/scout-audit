#![feature(rustc_private)]
//! # unsafe-temporary-storage
//!
//! Flags critical, long-lived contract state stored under Soroban temporary
//! storage.
//!
//! ## What it detects
//! A `set`/`get`/`has` call on temporary storage whose key is a `#[contracttype]`
//! enum variant whose name looks critical (matches a lexicon such as `admin`,
//! `owner`, `balance`, `supply`, `config`, `vault`, `nonce`, ...) and is not on
//! the ephemeral allow-list (`pending`, `session`, `cache`, ...).
//!
//! ## Why it matters
//! Temporary storage entries are auto-deleted when their TTL expires and cannot
//! be restored after archival, so keeping critical state there risks
//! irrecoverable loss of admin rights, balances, or configuration.
//!
//! ## Remediation
//! Store critical, long-lived keys in persistent or instance storage; reserve
//! temporary storage for genuinely ephemeral data.
//!
//! Severity: Medium · Class: ResourceManagement.

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    analysis::{get_node_type_opt, is_soroban_storage, SorobanStorageType},
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use if_chain::if_chain;
use rustc_hir::{
    def::{CtorOf, DefKind, Res},
    intravisit::{walk_expr, FnKind, Visitor},
    Body, Expr, ExprKind, FnDecl, QPath,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{def_id::LocalDefId, Span};

const LINT_MESSAGE: &str =
    "Critical state stored under temporary storage can be irrecoverably lost when its TTL expires.";

/// Substrings that mark a storage key as holding critical, long-lived state.
/// A temporary-storage entry keyed on any of these is auto-deleted on TTL
/// expiry and cannot be restored after archival, causing permanent loss.
const CRITICAL_KEY_LEXICON: [&str; 14] = [
    "admin",
    "owner",
    "balance",
    "total",
    "supply",
    "config",
    "position",
    "debt",
    "collateral",
    "vault",
    "treasury",
    "allowance",
    "nonce",
    "stake",
];

/// Substrings that mark a storage key as genuinely ephemeral. Temporary
/// storage is the correct home for these, so they are never flagged even when
/// they happen to share a substring with the critical lexicon (e.g. a
/// `PendingAdmin` hand-off flag).
const EPHEMERAL_KEY_ALLOWLIST: [&str; 9] = [
    "pending", "session", "flash", "lock", "guard", "temp", "cache", "ongoing", "snapshot",
];

#[expose_lint_info]
pub static UNSAFE_TEMPORARY_STORAGE_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "Soroban temporary storage is automatically deleted once its TTL expires and cannot be restored after archival. Storing critical, long-lived state (admin, balances, configuration, positions, ...) there risks irrecoverable loss. Use persistent or instance storage for such keys and reserve temporary storage for ephemeral data.",
    severity: Severity::Medium,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/unsafe-temporary-storage",
    vulnerability_class: VulnerabilityClass::ResourceManagement,
};

dylint_linting::impl_late_lint! {
    pub UNSAFE_TEMPORARY_STORAGE,
    Warn,
    LINT_MESSAGE,
    UnsafeTemporaryStorage
}

#[derive(Default)]
struct UnsafeTemporaryStorage;

impl<'tcx> LateLintPass<'tcx> for UnsafeTemporaryStorage {
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

        let mut visitor = UnsafeTemporaryStorageVisitor { cx };
        visitor.visit_body(body);
    }
}

struct UnsafeTemporaryStorageVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
}

impl<'a, 'tcx> Visitor<'tcx> for UnsafeTemporaryStorageVisitor<'a, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if_chain! {
            if !expr.span.from_expansion();
            // Match a `set`/`get`/`has` call (never `remove`) on temporary storage.
            if let ExprKind::MethodCall(path, receiver, args, _) = &expr.kind;
            if matches!(path.ident.name.as_str(), "set" | "get" | "has");
            if let Some(receiver_ty) = get_node_type_opt(self.cx, &receiver.hir_id);
            if is_soroban_storage(self.cx, receiver_ty, SorobanStorageType::Temporary);
            // Inspect the key argument (peeling a leading `&`).
            if let Some(key_arg) = args.first();
            if let Some(variant) = self.critical_key_variant(key_arg);
            then {
                span_lint_and_help(
                    self.cx,
                    UNSAFE_TEMPORARY_STORAGE,
                    expr.span,
                    LINT_MESSAGE,
                    None,
                    format!(
                        "key `{variant}` looks like critical state; move it to persistent or instance storage"
                    ),
                );
            }
        }

        walk_expr(self, expr)
    }
}

impl<'a, 'tcx> UnsafeTemporaryStorageVisitor<'a, 'tcx> {
    /// Returns the variant identifier of `expr` when it constructs a
    /// `#[contracttype]` enum variant whose name looks critical and is not on
    /// the ephemeral allow-list.
    fn critical_key_variant(&self, expr: &Expr<'tcx>) -> Option<String> {
        let variant = self.enum_variant_ident(expr)?;
        let lowered = variant.to_lowercase();

        if EPHEMERAL_KEY_ALLOWLIST
            .iter()
            .any(|allowed| lowered.contains(allowed))
        {
            return None;
        }

        CRITICAL_KEY_LEXICON
            .iter()
            .any(|critical| lowered.contains(critical))
            .then_some(variant)
    }

    /// Extracts the enum-variant identifier from a storage-key expression,
    /// handling both unit variants (`DataKey::Admin`) and tuple variants
    /// (`DataKey::Balance(addr)`), with an optional leading `&`.
    fn enum_variant_ident(&self, expr: &Expr<'tcx>) -> Option<String> {
        let inner = match &expr.kind {
            ExprKind::AddrOf(_, _, inner) => inner,
            _ => expr,
        };

        // Tuple variant: `DataKey::Balance(addr)` is a call to the variant ctor.
        let qpath = match &inner.kind {
            ExprKind::Call(callee, _) => match &callee.kind {
                ExprKind::Path(qpath) => Some((qpath, callee.hir_id)),
                _ => None,
            },
            // Unit variant: `DataKey::Admin` is a bare path to the const ctor.
            ExprKind::Path(qpath) => Some((qpath, inner.hir_id)),
            _ => None,
        };

        let (qpath, hir_id) = qpath?;
        let res = self.cx.qpath_res(qpath, hir_id);
        if let Res::Def(DefKind::Ctor(CtorOf::Variant, _), ctor_def_id) = res {
            // The ctor's parent is the variant definition; its name is the ident.
            let variant_def_id = self.cx.tcx.parent(ctor_def_id);
            return Some(self.cx.tcx.item_name(variant_def_id).to_string());
        }

        // Fall back to the last path segment for non-resolved or aliased keys.
        if let QPath::Resolved(_, p) = qpath {
            if let Res::Def(DefKind::Variant, variant_def_id) = p.res {
                return Some(self.cx.tcx.item_name(variant_def_id).to_string());
            }
        }
        None
    }
}
