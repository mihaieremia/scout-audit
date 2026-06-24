#![feature(rustc_private)]

//! # unnecessary-admin-parameter
//!
//! Detects Soroban entry points that take an admin `Address` as a parameter
//! instead of reading the admin from storage.
//!
//! ## What it detects
//! A public Soroban function (other than `initialize`) with a parameter named
//! like `admin` (edit distance <= 1) of Soroban `Address` type, where the
//! parameter is not used as access control through a reachable `require_auth`.
//! Parameters forwarded to a helper that does perform `require_auth` (recognized
//! via the call graph) are not flagged.
//!
//! ## Why it matters
//! Accepting the admin as a caller-supplied argument lets the caller pass any
//! address, which either bypasses access control entirely or invites confusion
//! about who the real admin is. The trusted admin should come from contract
//! storage, not from the caller.
//!
//! ## Remediation
//! Retrieve the admin from storage and call `require_auth` on it, removing the
//! caller-supplied admin parameter.
//!
//! Severity: Medium · Class: Authorization.

extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    analysis::{
        get_node_type_opt, is_auth_reachable, is_soroban_address, is_soroban_function,
        FunctionCallVisitor,
    },
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use edit_distance::edit_distance;
use if_chain::if_chain;
use rustc_hir::{
    def::Res,
    intravisit::{walk_expr, FnKind, Visitor},
    Body, Expr, ExprKind, FnDecl, HirId, Param, PatKind, QPath,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{
    def_id::{DefId, LocalDefId},
    Span, Symbol,
};
use std::collections::{HashMap, HashSet};

const LINT_MESSAGE: &str = "Usage of admin parameter might be unnecessary";

#[expose_lint_info]
pub static UNNECESSARY_ADMIN_PARAMETER_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "This function has an admin parameter that might be unnecessary. Consider retrieving the admin from storage instead.",
    severity: Severity::Medium,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/unnecessary-admin-parameter",
    vulnerability_class: VulnerabilityClass::Authorization,
};

dylint_linting::impl_late_lint! {
    pub UNNECESSARY_ADMIN_PARAMETER,
    Warn,
    LINT_MESSAGE,
    UnnecessaryAdminParameter::default()
}

struct AdminInfo {
    param_span: Span,
    usage_span: Option<Span>,
    /// `true` when the admin parameter is forwarded to a called helper, i.e. its
    /// authorization may be delegated rather than performed inline.
    admin_forwarded: bool,
}

#[derive(Default)]
struct UnnecessaryAdminParameter {
    checked_functions: HashSet<String>,
    admin_params: HashMap<DefId, AdminInfo>,
    function_call_graph: HashMap<DefId, HashSet<DefId>>,
    authorized_functions: HashSet<DefId>,
}

impl<'tcx> LateLintPass<'tcx> for UnnecessaryAdminParameter {
    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        for (function_def_id, admin_info) in &self.admin_params {
            if is_soroban_function(cx, &self.checked_functions, function_def_id) {
                // If the admin parameter is forwarded to a helper and authorization is
                // reachable through the call graph, the access control is centralized in
                // that helper rather than missing. Don't flag helper-delegated auth.
                if admin_info.admin_forwarded
                    && is_auth_reachable(
                        *function_def_id,
                        &self.function_call_graph,
                        &self.authorized_functions,
                    )
                {
                    continue;
                }

                let help_message = if admin_info.usage_span.is_some() {
                    "Consider retrieving the admin from storage instead of passing it as a parameter"
                } else {
                    "This admin parameter is not used for access control. Consider removing it or implementing proper access control"
                };

                span_lint_and_help(
                    cx,
                    UNNECESSARY_ADMIN_PARAMETER,
                    admin_info.param_span,
                    LINT_MESSAGE,
                    admin_info.usage_span,
                    help_message,
                )
            }
        }
    }

    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        _: FnKind<'tcx>,
        _: &'tcx FnDecl<'tcx>,
        body: &'tcx Body<'tcx>,
        span: Span,
        local_def_id: LocalDefId,
    ) {
        let def_id = local_def_id.to_def_id();
        self.checked_functions.insert(cx.tcx.def_path_str(def_id));

        if span.from_expansion() {
            return;
        }

        // Build the function call graph so helper-delegated authorization can be
        // recognized interprocedurally.
        let mut function_call_visitor =
            FunctionCallVisitor::new(cx, def_id, &mut self.function_call_graph);
        function_call_visitor.visit_body(body);

        // Record any function that performs authorization (`require_auth`) so that
        // `is_auth_reachable` can credit callers that delegate to it.
        let mut auth_visitor = AuthReachVisitor {
            cx,
            auth_found: false,
        };
        auth_visitor.visit_body(body);
        if auth_visitor.auth_found {
            self.authorized_functions.insert(def_id);
        }

        // Skip analysis for functions named "initialize"
        if let Some(fn_name) = cx.tcx.opt_item_name(def_id) {
            if is_similar_to(&fn_name.as_str().to_lowercase(), "initialize") {
                return;
            }
        }

        // Step 1: Check for admin parameter
        if let Some(admin_param) = find_admin_param(cx, body.params) {
            // Step 2: Check function body for proper use of admin parameter
            let mut visitor = UnnecessaryAdminParameterVisitor {
                admin_param_id: admin_param.pat.hir_id,
                access_control_span: None,
                admin_forwarded: false,
            };
            visitor.visit_body(body);

            // Step 3: Store the information for later analysis
            self.admin_params.insert(
                def_id,
                AdminInfo {
                    param_span: admin_param.span,
                    usage_span: visitor.access_control_span,
                    admin_forwarded: visitor.admin_forwarded,
                },
            );
        }
    }
}

fn find_admin_param<'tcx>(
    cx: &LateContext<'tcx>,
    params: &'tcx [Param<'tcx>],
) -> Option<&'tcx Param<'tcx>> {
    params.iter().find(|param| {
        matches!(param.pat.kind, PatKind::Binding(_, _, ident, _)
            if is_similar_to(&ident.name.as_str().to_lowercase(), "admin"))
            && get_node_type_opt(cx, &param.hir_id)
                .is_some_and(|type_| is_soroban_address(cx, type_))
    })
}

fn is_similar_to(s1: &str, s2: &str) -> bool {
    edit_distance(s1, s2) <= 1
}

struct UnnecessaryAdminParameterVisitor {
    admin_param_id: HirId,
    access_control_span: Option<Span>,
    /// Set when the admin parameter is passed as an argument to another call,
    /// i.e. authorization on it may be delegated to a helper.
    admin_forwarded: bool,
}

impl UnnecessaryAdminParameterVisitor {
    fn is_admin_param(&self, expr: &Expr<'_>) -> bool {
        matches!(
            expr.kind,
            ExprKind::Path(QPath::Resolved(_, path))
                if matches!(path.res, Res::Local(id) if id == self.admin_param_id)
        )
    }
}

impl<'tcx> Visitor<'tcx> for UnnecessaryAdminParameterVisitor {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if_chain! {
            if let ExprKind::MethodCall(path_segment, receiver, ..) = expr.kind;
            if path_segment.ident.name == Symbol::intern("require_auth");
            if self.is_admin_param(receiver);
            then {
                self.access_control_span = Some(expr.span);
            }
        }

        // Track forwarding of the admin parameter into another call (free function,
        // associated function, or method receiver/argument).
        match expr.kind {
            ExprKind::Call(_, args) => {
                if args
                    .iter()
                    .any(|arg| self.is_admin_param(arg.peel_borrows()))
                {
                    self.admin_forwarded = true;
                }
            }
            ExprKind::MethodCall(method_seg, receiver, args, _) => {
                // `admin.require_auth()` is inline access control, not delegation; it is
                // handled above. Only treat the admin parameter flowing into another
                // method (as receiver or argument) as forwarding to a helper.
                let is_auth_call = method_seg.ident.name == Symbol::intern("require_auth")
                    || method_seg.ident.name == Symbol::intern("require_auth_for_args");
                if !is_auth_call
                    && (self.is_admin_param(receiver.peel_borrows())
                        || args
                            .iter()
                            .any(|arg| self.is_admin_param(arg.peel_borrows())))
                {
                    self.admin_forwarded = true;
                }
            }
            _ => {}
        }

        walk_expr(self, expr);
    }
}

/// Detects whether a function performs `require_auth` on any Soroban address,
/// used to populate the authorized-functions set for `is_auth_reachable`.
struct AuthReachVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    auth_found: bool,
}

impl<'a, 'tcx> Visitor<'tcx> for AuthReachVisitor<'a, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if self.auth_found {
            return;
        }
        if let ExprKind::MethodCall(path_segment, receiver, ..) = expr.kind {
            if path_segment.ident.name == Symbol::intern("require_auth") {
                let is_address = get_node_type_opt(self.cx, &receiver.hir_id)
                    .is_some_and(|ty| is_soroban_address(self.cx, ty));
                if is_address {
                    self.auth_found = true;
                    return;
                }
            }
        }
        walk_expr(self, expr);
    }
}
