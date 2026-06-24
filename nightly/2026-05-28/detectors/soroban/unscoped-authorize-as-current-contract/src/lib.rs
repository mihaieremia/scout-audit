#![feature(rustc_private)]

extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::expr_or_init;
use common::{
    analysis::{get_node_type_opt, is_soroban_env, is_soroban_vec, match_type_to_str},
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use if_chain::if_chain;
use rustc_hir::{
    Body, Expr, ExprField, ExprKind, FnDecl, QPath,
    intravisit::{FnKind, Visitor, walk_expr},
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{Span, def_id::LocalDefId};

const LINT_MESSAGE: &str = "This `authorize_as_current_contract` entry delegates the current contract's authority too broadly: its `sub_invocations` is non-empty.";

/// Fully-qualified type name used to recognise the auth entry shape.
const SUB_CONTRACT_INVOCATION: &str = "soroban_sdk::auth::SubContractInvocation";

/// The field of `SubContractInvocation` that, when non-empty, delegates onward
/// authority on behalf of the current contract.
const SUB_INVOCATIONS_FIELD: &str = "sub_invocations";

#[expose_lint_info]
pub static UNSCOPED_AUTHORIZE_AS_CURRENT_CONTRACT_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "`env.authorize_as_current_contract(entries)` pre-authorizes calls on behalf of the current contract. When an `InvokerContractAuthEntry::Contract(SubContractInvocation { .. })` entry carries a non-empty `sub_invocations` tree, the current contract's authority is delegated onward to every nested call, not just the one it intends to make. This is the Soroban analog of an unlimited ERC-20 approval. Authorize a single, one-shot invocation by leaving `sub_invocations` empty (`Vec::new(&env)`), and add nested entries only when each deeper call is itself intended and bounded.",
    severity: Severity::Critical,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/unscoped-authorize-as-current-contract",
    vulnerability_class: VulnerabilityClass::Authorization,
};

dylint_linting::declare_late_lint! {
    pub UNSCOPED_AUTHORIZE_AS_CURRENT_CONTRACT,
    Warn,
    LINT_MESSAGE
}

/// Whether the `sub_invocations` initializer can be statically proven empty,
/// proven non-empty, or is opaque (cannot be determined here).
enum SubInvocations {
    /// Statically empty: the safe, one-shot, non-delegating form.
    Empty,
    /// Statically non-empty: delegates onward authority.
    NonEmpty,
    /// Cannot be determined statically; conservatively treated as not-a-finding.
    Unknown,
}

struct UnscopedAuthorizeVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
}

impl<'a, 'tcx> UnscopedAuthorizeVisitor<'a, 'tcx> {
    /// `true` when the receiver of the method call is the Soroban environment
    /// (`soroban_sdk::Env`).
    fn is_env_receiver(&self, receiver: &Expr<'tcx>) -> bool {
        get_node_type_opt(self.cx, &receiver.hir_id).is_some_and(|ty| is_soroban_env(self.cx, ty))
    }

    /// `true` when the struct literal `expr` is a `SubContractInvocation`.
    fn is_sub_contract_invocation(&self, expr: &Expr<'tcx>) -> bool {
        get_node_type_opt(self.cx, &expr.hir_id)
            .is_some_and(|ty| match_type_to_str(self.cx, ty, SUB_CONTRACT_INVOCATION))
    }

    /// `true` when `expr`'s type is a Soroban `Vec`.
    fn is_soroban_vec_ty(&self, expr: &Expr<'tcx>) -> bool {
        get_node_type_opt(self.cx, &expr.hir_id).is_some_and(|ty| is_soroban_vec(self.cx, ty))
    }

    /// Classify a `sub_invocations` field initializer.
    ///
    /// The `soroban_sdk::vec!` macro lowers to `Vec::new(env)` (empty) or
    /// `Vec::from_array(env, [elems])` (one element per `vec!` entry), so the
    /// element count of the array literal is the authoritative emptiness signal.
    /// A direct `Vec::new(env)` is likewise empty. Anything else is opaque.
    fn classify_sub_invocations(&self, field_init: &Expr<'tcx>) -> SubInvocations {
        let init = expr_or_init(self.cx, field_init);

        // Only reason about Soroban `Vec` constructors; bail out otherwise.
        if !self.is_soroban_vec_ty(init) {
            return SubInvocations::Unknown;
        }

        if_chain! {
            if let ExprKind::Call(callee, args) = &init.kind;
            if let ExprKind::Path(qpath) = &callee.kind;
            if let Some(method) = type_relative_method(qpath);
            then {
                return match method {
                    // `Vec::new(env)` => statically empty.
                    "new" => SubInvocations::Empty,
                    // `Vec::from_array(env, [..])` => emptiness == array len 0.
                    "from_array" => match args.last().map(|a| &a.kind) {
                        Some(ExprKind::Array([])) => SubInvocations::Empty,
                        Some(ExprKind::Array(_)) => SubInvocations::NonEmpty,
                        _ => SubInvocations::Unknown,
                    },
                    _ => SubInvocations::Unknown,
                };
            }
        }

        SubInvocations::Unknown
    }

    /// Find the `sub_invocations` field initializer of a `SubContractInvocation`
    /// struct literal, if present.
    fn sub_invocations_field<'f>(fields: &'f [ExprField<'tcx>]) -> Option<&'f Expr<'tcx>> {
        fields
            .iter()
            .find(|f| f.ident.name.as_str() == SUB_INVOCATIONS_FIELD)
            .map(|f| f.expr)
    }
}

/// Extract the final path segment name of a type-relative call path
/// (e.g. `Vec::from_array` -> `"from_array"`).
fn type_relative_method<'hir>(qpath: &'hir QPath<'hir>) -> Option<&'hir str> {
    match qpath {
        QPath::TypeRelative(_, segment) => Some(segment.ident.as_str()),
        QPath::Resolved(_, path) => path.segments.last().map(|s| s.ident.as_str()),
    }
}

/// Walks the entries argument subtree, recording whether any
/// `SubContractInvocation` literal carries a provably non-empty
/// `sub_invocations` tree.
struct EntriesScan<'a, 'b, 'tcx> {
    outer: &'a UnscopedAuthorizeVisitor<'b, 'tcx>,
    found_unscoped: bool,
}

impl<'a, 'b, 'tcx> Visitor<'tcx> for EntriesScan<'a, 'b, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if_chain! {
            if let ExprKind::Struct(_, fields, _) = &expr.kind;
            if self.outer.is_sub_contract_invocation(expr);
            if let Some(field_init) = UnscopedAuthorizeVisitor::sub_invocations_field(fields);
            if matches!(
                self.outer.classify_sub_invocations(field_init),
                SubInvocations::NonEmpty
            );
            then {
                self.found_unscoped = true;
            }
        }
        walk_expr(self, expr);
    }
}

impl<'a, 'tcx> Visitor<'tcx> for UnscopedAuthorizeVisitor<'a, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if_chain! {
            if let ExprKind::MethodCall(segment, receiver, args, _) = &expr.kind;
            if segment.ident.name.as_str() == "authorize_as_current_contract";
            if self.is_env_receiver(receiver);
            if let Some(entries_arg) = args.first();
            then {
                // Resolve a `let entries = ...` binding to its initializer, then
                // scan the whole entries tree for an unscoped delegation.
                let entries = expr_or_init(self.cx, entries_arg);
                let mut scan = EntriesScan {
                    outer: self,
                    found_unscoped: false,
                };
                scan.visit_expr(entries);
                if scan.found_unscoped {
                    clippy_utils::diagnostics::span_lint_and_help(
                        self.cx,
                        UNSCOPED_AUTHORIZE_AS_CURRENT_CONTRACT,
                        expr.span,
                        LINT_MESSAGE,
                        None,
                        "authorize a single, one-shot invocation by leaving `sub_invocations` empty (`Vec::new(&env)`); add nested entries only when each deeper call is itself intended and bounded",
                    );
                }
            }
        }
        walk_expr(self, expr);
    }
}

impl<'tcx> LateLintPass<'tcx> for UnscopedAuthorizeAsCurrentContract {
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

        let mut visitor = UnscopedAuthorizeVisitor { cx };
        walk_expr(&mut visitor, body.value);
    }
}
