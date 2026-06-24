#![feature(rustc_private)]

extern crate rustc_hir;
extern crate rustc_span;

use std::collections::{HashMap, HashSet};

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    analysis::{self, is_auth_reachable, match_type_to_str, FunctionCallVisitor},
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use rustc_hir::{
    intravisit::{walk_expr, FnKind, Visitor},
    Body, Expr, ExprKind, FnDecl,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{
    def_id::{DefId, LocalDefId},
    Span, Symbol,
};

const LINT_MESSAGE: &str = "This privileged token operation is reachable without any authorization, so any caller can invoke it";

/// Privileged Stellar Asset Contract / token admin operations. Reaching any of
/// these on a token client without an authorization check lets an arbitrary
/// caller mint, burn, claw back, (de)authorize, or hand over admin rights.
const PRIVILEGED_TOKEN_OPS: [&str; 5] = ["mint", "burn", "clawback", "set_authorized", "set_admin"];

/// Free functions injected by the OpenZeppelin `stellar-macros` access-control
/// attribute macros (`#[only_owner]`, `#[only_admin]`). Their bodies live in the
/// external `stellar-access` crate and internally call `require_auth`, so they are
/// invisible to both the inline `addr.require_auth()` check and the local call-graph
/// reachability analysis. Recognizing them by name credits the injected authorization.
const ACCESS_CONTROL_AUTH_ENFORCERS: [&str; 2] = ["enforce_owner_auth", "enforce_admin_auth"];

/// Authorization methods on a Soroban `Address` that gate a privileged operation.
const AUTH_METHODS: [&str; 2] = ["require_auth", "require_auth_for_args"];

/// Returns `true` if `expr` is a call to an OpenZeppelin access-control auth enforcer
/// (see [`ACCESS_CONTROL_AUTH_ENFORCERS`]).
fn is_access_control_auth_call(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    if let ExprKind::Call(callee, _) = &expr.kind {
        if let ExprKind::Path(qpath) = &callee.kind {
            if let Some(def_id) = cx.qpath_res(qpath, callee.hir_id).opt_def_id() {
                let path = cx.tcx.def_path_str(def_id);
                return ACCESS_CONTROL_AUTH_ENFORCERS
                    .iter()
                    .any(|enforcer| path.ends_with(enforcer));
            }
        }
    }
    false
}

#[expose_lint_info]
pub static UNPROTECTED_TOKEN_ADMIN_OPERATION_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "A contract entry point reaches a privileged token operation (mint, burn, clawback, set_authorized, or set_admin) on a token/SAC client, but no require_auth is reachable from it and it is not guarded by an access-control macro. Any caller could mint tokens, claw back balances, or seize admin rights.",
    severity: Severity::Critical,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/unprotected-token-admin-operation",
    vulnerability_class: VulnerabilityClass::Authorization,
};

dylint_linting::impl_late_lint! {
    pub UNPROTECTED_TOKEN_ADMIN_OPERATION,
    Warn,
    LINT_MESSAGE,
    UnprotectedTokenAdminOperation::default()
}

#[derive(Default)]
struct UnprotectedTokenAdminOperation {
    function_call_graph: HashMap<DefId, HashSet<DefId>>,
    authorized_functions: HashSet<DefId>,
    checked_functions: HashSet<String>,
    unauthorized_privileged_calls: HashMap<DefId, Vec<Span>>,
}

impl<'tcx> LateLintPass<'tcx> for UnprotectedTokenAdminOperation {
    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        for (callee_def_id, op_spans) in &self.unauthorized_privileged_calls {
            // If authorization is reachable from the callee itself (e.g. it delegates
            // `require_auth` to a helper), the privileged operation is protected.
            if is_auth_reachable(
                *callee_def_id,
                &self.function_call_graph,
                &self.authorized_functions,
            ) {
                continue;
            }
            let is_callee_soroban =
                analysis::is_soroban_function(cx, &self.checked_functions, callee_def_id);
            let (is_called_by_soroban, is_soroban_caller_authed) = self
                .function_call_graph
                .iter()
                .fold((false, true), |acc, (caller, callees)| {
                    if callees.contains(callee_def_id) {
                        let is_caller_soroban =
                            analysis::is_soroban_function(cx, &self.checked_functions, caller);
                        // A Soroban caller authorizes the call if `require_auth` is
                        // reachable from it through the call graph, not only inline.
                        (
                            acc.0 || is_caller_soroban,
                            acc.1
                                && (!is_caller_soroban
                                    || is_auth_reachable(
                                        *caller,
                                        &self.function_call_graph,
                                        &self.authorized_functions,
                                    )),
                        )
                    } else {
                        acc
                    }
                });

            // Only fire on exported contract entry points (or privileged calls reached
            // from an unauthorized one), never on internal-only helpers.
            if is_callee_soroban || (is_called_by_soroban && !is_soroban_caller_authed) {
                for span in op_spans {
                    span_lint_and_help(
                        cx,
                        UNPROTECTED_TOKEN_ADMIN_OPERATION,
                        *span,
                        LINT_MESSAGE,
                        None,
                        "",
                    );
                }
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
        // Record the function so `is_soroban_function` can recognize exported entry points.
        let def_id = local_def_id.to_def_id();
        self.checked_functions.insert(cx.tcx.def_path_str(def_id));

        // If this function comes from a macro, don't analyze it.
        if span.from_expansion() {
            return;
        }

        // First visitor: build the function call graph.
        let mut function_call_visitor =
            FunctionCallVisitor::new(cx, def_id, &mut self.function_call_graph);
        function_call_visitor.visit_body(body);

        // Second visitor: collect privileged operations and inline authorization.
        let mut visitor = PrivilegedOpVisitor {
            cx,
            auth_found: false,
            op_spans: Vec::new(),
        };
        visitor.visit_body(body);

        if !visitor.op_spans.is_empty() && !visitor.auth_found {
            self.unauthorized_privileged_calls
                .insert(def_id, visitor.op_spans);
        } else if visitor.auth_found {
            self.authorized_functions.insert(def_id);
        }
    }
}

struct PrivilegedOpVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    auth_found: bool,
    op_spans: Vec<Span>,
}

impl<'a, 'tcx> Visitor<'tcx> for PrivilegedOpVisitor<'a, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        // Recognize authorization injected by OZ `#[only_owner]` / `#[only_admin]`
        // macros, which call an external enforcer instead of `addr.require_auth()`.
        if is_access_control_auth_call(self.cx, expr) {
            self.auth_found = true;
        }

        if let ExprKind::MethodCall(path, object, _, _) = &expr.kind {
            if let Some(object_type) = analysis::get_node_type_opt(self.cx, &object.hir_id) {
                // Inline `require_auth` / `require_auth_for_args` on an Address authorizes
                // the enclosing function.
                if analysis::is_soroban_address(self.cx, object_type)
                    && AUTH_METHODS
                        .iter()
                        .any(|m| path.ident.name == Symbol::intern(m))
                {
                    self.auth_found = true;
                }

                // Privileged token/SAC operation: a method in the privileged set invoked
                // on a token client (receiver type path contains `Client`, e.g.
                // `soroban_sdk::token::StellarAssetClient`). Requiring a `Client` receiver
                // avoids flagging unrelated same-named methods on other types.
                if PRIVILEGED_TOKEN_OPS
                    .iter()
                    .any(|op| path.ident.name == Symbol::intern(op))
                    && match_type_to_str(self.cx, object_type, "Client")
                {
                    self.op_spans.push(expr.span);
                }
            }
        }

        walk_expr(self, expr)
    }
}
