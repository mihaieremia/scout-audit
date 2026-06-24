#![feature(rustc_private)]
//! # front-running
//!
//! Flags token transfers whose amount is not bounded by a caller-supplied
//! minimum, leaving the transfer exposed to front-running.
//!
//! ## What it detects
//! A `transfer` call on a `soroban_sdk::token::TokenClient` where the amount is a
//! local variable that (1) is derived from a function parameter but (2) is never
//! compared against a parameter in a guarding `if` (e.g. `amount >= min` or
//! `if amount < min { panic/return }`). Such comparisons mark the amount checked
//! and suppress the finding.
//!
//! ## Why it matters
//! Without a minimum-amount check, the realized transfer amount can be
//! manipulated by transaction ordering (MEV): an observer can sandwich or
//! front-run the transaction so the user receives less than intended.
//!
//! ## Remediation
//! Validate the transferred amount against a caller-supplied minimum before the
//! transfer, reverting when it is not met (slippage protection).
//!
//! Severity: Medium · Class: MEV.

extern crate rustc_hir;
extern crate rustc_span;

mod conditional_checker;

use clippy_utils::diagnostics::span_lint;
use clippy_utils::higher::If;
use common::{
    analysis::{get_node_type_opt, FunctionCallVisitor},
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use conditional_checker::{get_res_hir_id, is_panic_inducing_call, ConditionalChecker};
use if_chain::if_chain;
use rustc_hir::{
    def::Res::{self},
    intravisit::{walk_expr, FnKind, Visitor},
    Body, Expr, ExprKind, FnDecl, HirId, LetStmt, Path, QPath,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{
    def_id::{DefId, LocalDefId},
    Span, Symbol,
};
use std::{
    collections::{HashMap, HashSet},
    vec,
};

const LINT_MESSAGE: &str =
    "The transferred amount should be checked against a minimum to prevent front-running";

#[expose_lint_info]
pub static FRONT_RUNNING_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "This lint checks for potential front-running vulnerabilities in token transfers",
    severity: Severity::Medium,
    help: "Consider implementing a minimum amount check before the transfer",
    vulnerability_class: VulnerabilityClass::MEV,
};

dylint_linting::impl_late_lint! {
    pub FRONT_RUNNING,
    Warn,
    LINT_MESSAGE,
    FrontRunning::default()
}

#[derive(Default)]
struct FrontRunning {
    function_call_graph: HashMap<DefId, HashSet<DefId>>,
    checked_functions: HashSet<String>,
}

impl<'tcx> LateLintPass<'tcx> for FrontRunning {
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

        let mut function_call_visitor =
            FunctionCallVisitor::new(cx, def_id, &mut self.function_call_graph);
        function_call_visitor.visit_body(body);

        let function_params: HashSet<_> =
            body.params.iter().map(|param| param.pat.hir_id).collect();

        let mut front_running_visitor = FrontRunningVisitor {
            checked_hir_ids: HashSet::new(),
            conditional_checker: Vec::new(),
            cx,
            filtered_local_variables: HashSet::new(),
            function_params,
            transfer_amount_id: Vec::new(),
        };
        front_running_visitor.visit_body(body);

        for (transfer_amount_id, span) in &front_running_visitor.transfer_amount_id {
            if !front_running_visitor
                .checked_hir_ids
                .contains(transfer_amount_id)
                && front_running_visitor
                    .filtered_local_variables
                    .contains(transfer_amount_id)
            {
                span_lint(cx, FRONT_RUNNING, *span, LINT_MESSAGE);
            }
        }
    }
}

struct FrontRunningVisitor<'a, 'tcx> {
    checked_hir_ids: HashSet<HirId>,
    conditional_checker: Vec<ConditionalChecker>,
    cx: &'a LateContext<'tcx>,
    filtered_local_variables: HashSet<HirId>,
    function_params: HashSet<HirId>,
    transfer_amount_id: Vec<(HirId, Span)>,
}

impl FrontRunningVisitor<'_, '_> {
    fn add_to_checked_hir_ids(&mut self, last_conditional_checker: ConditionalChecker) {
        if let (Some(lesser_hir_id), Some(greater_hir_id)) = (
            last_conditional_checker.lesser_expr,
            last_conditional_checker.greater_expr,
        ) {
            // A transfer amount is guarded whether it is compared as the greater
            // side (`amount >= min_param`) or the lesser side (`amount < min_param`
            // / `if amount < min_param { panic }`): in both cases a caller-supplied
            // parameter bounds the amount, so mark the non-parameter operand checked.
            if self.function_params.contains(&lesser_hir_id) {
                self.checked_hir_ids.insert(greater_hir_id);
            }
            if self.function_params.contains(&greater_hir_id) {
                self.checked_hir_ids.insert(lesser_hir_id);
            }
        }
    }

    fn local_uses_parameter(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::MethodCall(_, _, args, _) | ExprKind::Call(_, args) => {
                args.iter().any(|arg| {
                    get_res_hir_id(arg).is_some_and(|hir_id| self.function_params.contains(&hir_id))
                })
            }
            ExprKind::Binary(_, left_expr, right_expr) => {
                self.local_uses_parameter(left_expr) || self.local_uses_parameter(right_expr)
            }
            _ => false,
        }
    }

    /// Returns true when `expr` is the contract spending funds it already holds,
    /// i.e. the transfer's `from` argument resolves to
    /// `env.current_contract_address()` (peeling a leading `&`). A self-funded
    /// refund or sweep cannot be front-run for slippage, so a minimum-amount
    /// check is meaningless and the finding must be suppressed.
    fn is_current_contract_address(&self, expr: &Expr) -> bool {
        let inner = match &expr.kind {
            ExprKind::AddrOf(_, _, inner, ..) => inner,
            _ => expr,
        };
        if_chain! {
            if let ExprKind::MethodCall(path_segment, receiver, ..) = &inner.kind;
            if path_segment.ident.name == Symbol::intern("current_contract_address");
            if let Some(receiver_type) = get_node_type_opt(self.cx, &receiver.hir_id);
            then {
                // Peel references: the receiver is commonly `&Env` (e.g. a
                // `fn(env: &Env, ..)` helper), which renders as `&soroban_sdk::Env`.
                receiver_type.peel_refs().to_string() == "soroban_sdk::Env"
            } else {
                false
            }
        }
    }
}

impl<'a, 'tcx> Visitor<'tcx> for FrontRunningVisitor<'a, 'tcx> {
    fn visit_local(&mut self, local: &'tcx LetStmt<'tcx>) {
        if let Some(init) = &local.init {
            if self.local_uses_parameter(init) {
                self.filtered_local_variables.insert(local.pat.hir_id);
            }
        }
    }

    fn visit_expr(&mut self, expr: &'tcx Expr<'_>) {
        // Check if the expression is a transfer method call, then store the HirId of the amount parameter
        if_chain! {
            if let ExprKind::MethodCall(path_segment, receiver, args, ..) = expr.kind;
            if path_segment.ident.name == Symbol::intern("transfer");
            if let Some(receiver_type) = get_node_type_opt(self.cx, &receiver.hir_id);
            if receiver_type.to_string() == "soroban_sdk::token::TokenClient<'_>";
            // `transfer(from, to, amount)`: a self-funded transfer where `from`
            // is the contract's own address cannot be front-run for slippage.
            if !self.is_current_contract_address(&args[0]);
            if let ExprKind::AddrOf(_, _, amount_expr, ..) = args[2].kind;
            if let ExprKind::Path(QPath::Resolved(_, Path { segments, .. }), ..) = amount_expr.kind;
            if let Some(segment) = segments.first();
            if let Res::Local(hir_id) = segment.res;
            then {
                self.transfer_amount_id.push((hir_id, expr.span));
            }
        }

        // If we are inside an 'if' statement, check if the current expression is a return or a panic inducing call
        if let Some(last_conditional_checker) = self.conditional_checker.last().copied() {
            match &expr.kind {
                ExprKind::Ret(..) => {
                    self.add_to_checked_hir_ids(last_conditional_checker);
                }
                ExprKind::Call(func, _) if is_panic_inducing_call(func) => {
                    self.add_to_checked_hir_ids(last_conditional_checker);
                }
                _ => {}
            }
        }

        // Check if the expression has an 'if' and if it does, check if it meets our condition
        if let Some(If {
            cond,
            then: if_expr,
            r#else: _,
        }) = If::hir(expr)
        {
            let mut conditional_checker = ConditionalChecker {
                greater_expr: None,
                lesser_expr: None,
            };
            if conditional_checker.handle_condition(cond) {
                self.conditional_checker.push(conditional_checker);
                walk_expr(self, if_expr);
                self.conditional_checker.pop();
                return;
            }
        }

        walk_expr(self, expr);
    }
}
