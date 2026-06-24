#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint;
use common::{
    analysis::{is_auth_reachable, is_soroban_function, FunctionCallVisitor},
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use rustc_hir::{
    intravisit::{walk_expr, FnKind, Visitor},
    Body, Expr, ExprKind, FnDecl,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::ty::Ty;
use rustc_span::{
    def_id::{DefId, LocalDefId},
    Span,
};
use std::collections::{HashMap, HashSet};

const LINT_MESSAGE: &str =
    "This storage (vector or map) operation is called without access control";

#[expose_lint_info]
pub static DOS_UNEXPECTED_REVERT_WITH_STORAGE_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: " It occurs by preventing transactions by other users from being successfully executed forcing the blockchain state to revert to its original state.",
    severity: Severity::Medium,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/dos-unexpected-revert-with-storage",
    vulnerability_class: VulnerabilityClass::DoS,
};

dylint_linting::impl_late_lint! {
    pub DOS_UNEXPECTED_REVERT_WITH_STORAGE,
    Warn,
    "",
    DosUnexpectedRevertWithStorage::default()
}

#[derive(Default)]
pub struct DosUnexpectedRevertWithStorage {
    function_call_graph: HashMap<DefId, HashSet<DefId>>,
    authorized_functions: HashSet<DefId>,
    checked_functions: HashSet<String>,
    unprotected_storage_calls: HashMap<DefId, Vec<Span>>,
}

impl DosUnexpectedRevertWithStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<'tcx> LateLintPass<'tcx> for DosUnexpectedRevertWithStorage {
    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        for (callee_def_id, storage_spans) in &self.unprotected_storage_calls {
            // If authorization is reachable from the callee itself (e.g. it
            // delegates `require_auth` to a helper), the operation is protected.
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
                        // A Soroban caller authorizes the call if `require_auth`
                        // is reachable from it through the call graph, not only
                        // when it appears inline in the same function body.
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

            if is_callee_soroban || (is_called_by_soroban && !is_soroban_caller_authed) {
                for span in storage_spans {
                    span_lint(cx, DOS_UNEXPECTED_REVERT_WITH_STORAGE, *span, LINT_MESSAGE);
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
        let def_id = local_def_id.to_def_id();
        self.checked_functions.insert(cx.tcx.def_path_str(def_id));

        if span.from_expansion() {
            return;
        }

        // First visitor: build the function call graph for interprocedural auth.
        let mut function_call_visitor =
            FunctionCallVisitor::new(cx, def_id, &mut self.function_call_graph);
        function_call_visitor.visit_body(body);

        // Second visitor: collect storage ops and inline auth in this body.
        let mut storage_finder = UnprotectedStorageFinder {
            cx,
            storage_spans: Vec::new(),
            require_auth: false,
        };
        storage_finder.visit_body(body);

        if storage_finder.require_auth {
            self.authorized_functions.insert(def_id);
        } else if !storage_finder.storage_spans.is_empty() {
            self.unprotected_storage_calls
                .insert(def_id, storage_finder.storage_spans);
        }
    }
}

struct UnprotectedStorageFinder<'tcx, 'tcx_ref> {
    cx: &'tcx_ref LateContext<'tcx>,
    storage_spans: Vec<Span>,
    require_auth: bool,
}

impl<'tcx> Visitor<'tcx> for UnprotectedStorageFinder<'tcx, '_> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'_>) {
        if let ExprKind::MethodCall(path, _receiver, ..) = expr.kind {
            if let Some(defid) = self.cx.typeck_results().type_dependent_def_id(expr.hir_id) {
                let ty = Ty::new_foreign(self.cx.tcx, defid);
                let method_name = path.ident.name.to_string();

                if method_name == "require_auth" {
                    self.require_auth = true;
                }
                if ty.to_string().contains("soroban_sdk::Vec")
                    && (method_name == "push_back" || method_name == "push_front")
                {
                    self.storage_spans.push(path.ident.span);
                }
                if ty.to_string().contains("soroban_sdk::Map") && method_name == "set" {
                    self.storage_spans.push(path.ident.span);
                }
            }
        }
        walk_expr(self, expr);
    }
}
