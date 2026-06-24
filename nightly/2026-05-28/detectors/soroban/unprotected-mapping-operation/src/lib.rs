#![feature(rustc_private)]
//! # unprotected-mapping-operation
//!
//! Flags writes to a Soroban `Map` keyed by `Address` that are reachable from a
//! contract entry point without any authorization check.
//!
//! ## What it detects
//! A `Map<Address, _>::set(..)` call inside a contract function (or reachable
//! through the call graph from one) where no `addr.require_auth()` and no
//! OpenZeppelin `#[only_owner]`/`#[only_admin]` enforcer
//! (`enforce_owner_auth`/`enforce_admin_auth`) gates the write.
//!
//! ## Why it matters
//! Without an auth check, any caller can overwrite a mapping entry under an
//! arbitrary key (e.g. another user's balance or role), corrupting per-address
//! state and enabling theft or privilege escalation.
//!
//! ## Remediation
//! Require authorization of the relevant `Address` (`addr.require_auth()`) before
//! mutating the mapping, or gate the function with an access-control macro.
//!
//! Severity: Critical · Class: Authorization.

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    analysis::{
        get_node_type_opt, is_auth_reachable, is_soroban_address, is_soroban_function,
        is_soroban_map, FunctionCallVisitor,
    },
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use if_chain::if_chain;
use rustc_hir::{
    intravisit::{walk_expr, FnKind, Visitor},
    Body, Expr, ExprKind, FnDecl,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::ty::{Ty, TyKind};
use rustc_span::{
    def_id::{DefId, LocalDefId},
    Span, Symbol,
};
use std::collections::{HashMap, HashSet};

const LINT_MESSAGE: &str = "This mapping operation is called without access control on a different key than the caller's address";

/// Free functions injected by the OpenZeppelin `stellar-macros` access-control
/// attribute macros (`#[only_owner]`, `#[only_admin]`). Their bodies live in the
/// external `stellar-access` crate and internally call `require_auth`, so they are
/// invisible to both the inline `addr.require_auth()` check and the local call-graph
/// reachability analysis. Recognizing them by name credits the injected authorization.
const ACCESS_CONTROL_AUTH_ENFORCERS: [&str; 2] = ["enforce_owner_auth", "enforce_admin_auth"];

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
pub static UNPROTECTED_MAPPING_OPERATION_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "This mapping operation is called without access control on a different key than the caller's address",
    severity: Severity::Critical,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/unprotected-mapping-operation",
    vulnerability_class: VulnerabilityClass::Authorization,
};

dylint_linting::impl_late_lint! {
    pub UNPROTECTED_MAPPING_OPERATION,
    Warn,
    LINT_MESSAGE,
    UnprotectedMappingOperation::default()
}

#[derive(Default)]
struct UnprotectedMappingOperation {
    function_call_graph: HashMap<DefId, HashSet<DefId>>,
    authorized_functions: HashSet<DefId>,
    checked_functions: HashSet<String>,
    unauthorized_mapping_calls: HashMap<DefId, Vec<Span>>,
}

impl<'tcx> LateLintPass<'tcx> for UnprotectedMappingOperation {
    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        for (callee_def_id, mapping_spans) in &self.unauthorized_mapping_calls {
            // If authorization is reachable from the callee itself (e.g. it delegates
            // `require_auth` to a helper), the operation is protected.
            if is_auth_reachable(
                *callee_def_id,
                &self.function_call_graph,
                &self.authorized_functions,
            ) {
                continue;
            }
            let is_callee_soroban = is_soroban_function(cx, &self.checked_functions, callee_def_id);
            let (is_called_by_soroban, is_soroban_caller_authed) = self
                .function_call_graph
                .iter()
                .fold((false, true), |acc, (caller, callees)| {
                    if callees.contains(callee_def_id) {
                        let is_caller_soroban =
                            is_soroban_function(cx, &self.checked_functions, caller);
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

            // Determine if a warning should be emitted
            if is_callee_soroban || (is_called_by_soroban && !is_soroban_caller_authed) {
                for span in mapping_spans {
                    span_lint_and_help(
                        cx,
                        UNPROTECTED_MAPPING_OPERATION,
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
        // Fetch the DefId of the current function for future reference on public functions implemented inside the soroban contract
        let def_id = local_def_id.to_def_id();
        self.checked_functions.insert(cx.tcx.def_path_str(def_id));

        // If this function comes from a macro, don't analyze it
        if span.from_expansion() {
            return;
        }

        // First visitor: build the function call graph
        let mut function_call_visitor =
            FunctionCallVisitor::new(cx, def_id, &mut self.function_call_graph);
        function_call_visitor.visit_body(body);

        // Second visitor: check for authed functions and storage calls
        let mut unprotected_mapping_visitor = UnprotectedMappingOperationVisitor {
            cx,
            auth_found: false,
            mapping_spans: Vec::new(),
        };
        unprotected_mapping_visitor.visit_body(body);

        // If the function calls storage without auth, we store the spans
        if !unprotected_mapping_visitor.mapping_spans.is_empty()
            && !unprotected_mapping_visitor.auth_found
        {
            self.unauthorized_mapping_calls
                .insert(def_id, unprotected_mapping_visitor.mapping_spans);
        } else if unprotected_mapping_visitor.auth_found {
            self.authorized_functions.insert(def_id);
        }
    }
}

struct UnprotectedMappingOperationVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    auth_found: bool,
    mapping_spans: Vec<Span>,
}

impl<'tcx> UnprotectedMappingOperationVisitor<'_, 'tcx> {
    fn is_soroban_map_with_address(&self, receiver: &Expr, receiver_type: Ty<'_>) -> bool {
        if_chain! {
            // Check that the receiver expression is a field (e.g., accessing a struct's field).
            if let ExprKind::Field(..) = &receiver.kind;

            // Verify that the type of the receiver is a 'soroban_sdk::Map'.
            if is_soroban_map(self.cx, receiver_type);

            // Retrieve the first generic argument, ensure it exists and is of type Ty.
            if let TyKind::Adt(_, args) = receiver_type.kind();
            if let Some(first_arg) = args.first();
            if let Some(first_type) = first_arg.as_type();

            // Verify that the type of the first argument is 'soroban_sdk::Address'.
            if is_soroban_address(self.cx, first_type);
            then {
                return true;
            }
        }
        false
    }
}

impl<'a, 'tcx> Visitor<'tcx> for UnprotectedMappingOperationVisitor<'a, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if self.auth_found {
            return;
        }

        // Recognize authorization injected by OZ `#[only_owner]` / `#[only_admin]`
        // macros, which call an external enforcer instead of `addr.require_auth()`.
        if is_access_control_auth_call(self.cx, expr) {
            self.auth_found = true;
            return;
        }

        if let ExprKind::MethodCall(path_segment, receiver, _args, _) = &expr.kind {
            // Get the method expression type and check if it's a map with address
            let receiver_type = get_node_type_opt(self.cx, &receiver.hir_id);
            if let Some(type_) = receiver_type {
                // Check if the method call is require_auth() on an address
                if is_soroban_address(self.cx, type_)
                    && path_segment.ident.name == Symbol::intern("require_auth")
                {
                    self.auth_found = true;
                }

                // Look for usage of soroban map with address
                // Anything that looks like `soroban_sdk::Map::<soroban_sdk::Address, _>` is in our interest
                if self.is_soroban_map_with_address(receiver, type_)
                    && path_segment.ident.name == Symbol::intern("set")
                {
                    self.mapping_spans.push(expr.span);
                }
            }
        }

        walk_expr(self, expr);
    }
}
