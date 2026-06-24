#![feature(rustc_private)]

extern crate rustc_hir;
extern crate rustc_span;

use std::collections::{HashMap, HashSet};

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    analysis::{
        get_expr_hir_id_opt, get_node_type_opt, is_auth_reachable, is_soroban_address,
        is_soroban_storage, match_type_to_str, FunctionCallVisitor, SorobanStorageType,
    },
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use rustc_hir::{
    intravisit::{walk_expr, walk_local, FnKind, Visitor},
    BinOpKind, Body, Expr, ExprKind, FnDecl, HirId, LetStmt, PatKind, QPath, UnOp,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{
    def_id::{DefId, LocalDefId},
    Span, Symbol,
};

const LINT_MESSAGE: &str =
    "This cross-contract call targets an unvalidated address taken from a function parameter";

#[expose_lint_info]
pub static UNVALIDATED_CROSS_CONTRACT_TARGET_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "A contract client is built from an `Address` that comes directly from an untrusted function parameter, and a method is invoked on it without first validating the address (allowlist membership, equality against a stored/configured value, or `require_auth`). An attacker can pass a malicious token, oracle, or pool contract and have the contract call into it, enabling fund theft, price manipulation, or reentrancy. Validate the target address before calling into it: check it against an on-chain allowlist, compare it to a value read from storage, or require the address to authorize the call.",
    severity: Severity::Critical,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/unvalidated-cross-contract-target",
    vulnerability_class: VulnerabilityClass::Authorization,
};

dylint_linting::impl_late_lint! {
    pub UNVALIDATED_CROSS_CONTRACT_TARGET,
    Warn,
    LINT_MESSAGE,
    UnvalidatedCrossContractTarget::default()
}

/// A cross-contract call whose target client was built from an untrusted address
/// parameter. The finding fires unless a guard on that parameter is reachable
/// through the call graph.
struct Candidate {
    /// Index into the owning function's address-parameter list of the parameter
    /// that flowed into the client target.
    param_index: usize,
    span: Span,
}

#[derive(Default)]
struct UnvalidatedCrossContractTarget {
    function_call_graph: HashMap<DefId, HashSet<DefId>>,
    /// Functions that perform an `addr.require_auth()` on at least one of their
    /// address parameters (used as a call-graph-reachable auth credit).
    authorized_functions: HashSet<DefId>,
    /// Per-function candidate cross-contract calls keyed by the function `DefId`.
    candidates: HashMap<DefId, Vec<Candidate>>,
    /// Per-function set of address-parameter indices that are guarded inline
    /// (allowlist membership, equality vs storage, or `require_auth`).
    guarded_params: HashMap<DefId, HashSet<usize>>,
}

impl<'tcx> LateLintPass<'tcx> for UnvalidatedCrossContractTarget {
    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        for (def_id, candidates) in &self.candidates {
            // A function that delegates `require_auth` to a helper still authorizes
            // its targets; credit auth reachable through the call graph.
            let auth_reachable = is_auth_reachable(
                *def_id,
                &self.function_call_graph,
                &self.authorized_functions,
            );
            let guarded = self.guarded_params.get(def_id);

            for candidate in candidates {
                if auth_reachable {
                    continue;
                }
                if guarded.is_some_and(|set| set.contains(&candidate.param_index)) {
                    continue;
                }
                span_lint_and_help(
                    cx,
                    UNVALIDATED_CROSS_CONTRACT_TARGET,
                    candidate.span,
                    LINT_MESSAGE,
                    None,
                    "validate the target address before calling into it: check it against an on-chain allowlist (`allowed.contains(&addr)`), compare it to a value read from storage, or require `addr.require_auth()`",
                );
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
        if span.from_expansion() {
            return;
        }

        let def_id = local_def_id.to_def_id();

        let mut function_call_visitor =
            FunctionCallVisitor::new(cx, def_id, &mut self.function_call_graph);
        function_call_visitor.visit_body(body);

        let params = collect_address_params(cx, body);
        if params.is_empty() {
            return;
        }

        let mut visitor = TargetVisitor::new(cx, params);
        visitor.visit_body(body);

        if !visitor.authorized_params.is_empty() {
            self.authorized_functions.insert(def_id);
        }
        if !visitor.guarded_params.is_empty() {
            self.guarded_params.insert(def_id, visitor.guarded_params);
        }
        // A `__constructor` receives its addresses from the deployer at deploy time,
        // not from an attacker-controllable call, so its targets are not flagged.
        // Its guards/auth still feed the call graph for functions it reaches.
        if !visitor.candidates.is_empty() && !is_constructor(cx, def_id) {
            self.candidates.insert(def_id, visitor.candidates);
        }
    }
}

/// `true` if `def_id` is the Soroban contract constructor (`__constructor`).
fn is_constructor(cx: &LateContext<'_>, def_id: DefId) -> bool {
    cx.tcx
        .opt_item_name(def_id)
        .is_some_and(|name| name.as_str() == "__constructor")
}

/// Returns the `HirId`s of the function's parameters whose type is a Soroban
/// `Address`, preserving declaration order so indices are stable.
fn collect_address_params<'tcx>(cx: &LateContext<'tcx>, body: &'tcx Body<'tcx>) -> Vec<HirId> {
    body.params
        .iter()
        .filter(|param| {
            get_node_type_opt(cx, &param.hir_id)
                .map(|ty| is_soroban_address(cx, ty))
                .unwrap_or(false)
        })
        .map(|param| param.pat.hir_id)
        .collect()
}

struct TargetVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    /// Maps an address-parameter `HirId` to its declaration index, which is the
    /// `param_index` used throughout.
    param_by_hir: HashMap<HirId, usize>,
    /// `let x = <param>` aliases, so a renamed parameter still resolves.
    aliases: HashMap<HirId, usize>,
    /// `let client = SomeClient::new(&env, &param)` bindings: client local
    /// `HirId` -> address-parameter index it targets.
    client_bindings: HashMap<HirId, usize>,
    /// Cross-contract calls whose target traced to an untrusted address parameter.
    candidates: Vec<Candidate>,
    /// Address-parameter indices on which `require_auth` was called.
    authorized_params: HashSet<usize>,
    /// Address-parameter indices guarded by an allowlist/equality/auth check.
    guarded_params: HashSet<usize>,
}

impl<'a, 'tcx> TargetVisitor<'a, 'tcx> {
    fn new(cx: &'a LateContext<'tcx>, address_params: Vec<HirId>) -> Self {
        let param_by_hir = address_params
            .into_iter()
            .enumerate()
            .map(|(i, hir_id)| (hir_id, i))
            .collect();
        Self {
            cx,
            param_by_hir,
            aliases: HashMap::new(),
            client_bindings: HashMap::new(),
            candidates: Vec::new(),
            authorized_params: HashSet::new(),
            guarded_params: HashSet::new(),
        }
    }

    /// Resolves an expression to the index of the address parameter it refers to,
    /// following `let`-aliases. Returns `None` for anything not rooted in a param.
    fn resolve_to_param(&self, expr: &Expr<'tcx>) -> Option<usize> {
        let hir_id = get_expr_hir_id_opt(strip_refs(expr))?;
        if let Some(idx) = self.param_by_hir.get(&hir_id) {
            return Some(*idx);
        }
        self.aliases.get(&hir_id).copied()
    }

    /// `true` if `expr`'s type is a Soroban contract client (a codegen type whose
    /// name ends in `Client`).
    fn is_client_ty(&self, expr: &Expr<'tcx>) -> bool {
        get_node_type_opt(self.cx, &expr.hir_id)
            .is_some_and(|ty| match_type_to_str(self.cx, ty, "Client"))
    }

    /// If `expr` is `SomeClient::new(&env, &addr)` with `addr` resolving to an
    /// address parameter, returns that parameter index.
    fn client_new_target(&self, expr: &Expr<'tcx>) -> Option<usize> {
        if_chain::if_chain! {
            if let ExprKind::Call(callee, args) = &expr.kind;
            if args.len() >= 2;
            if let ExprKind::Path(QPath::TypeRelative(_, seg)) = &callee.kind;
            if seg.ident.name == Symbol::intern("new");
            if self.is_client_ty(expr);
            then {
                return self.resolve_to_param(&args[1]);
            }
        }
        None
    }
}

/// Strips references, derefs, and identity-preserving conversions so a parameter
/// reached through `&addr`, `addr.clone()`, etc. still resolves to its root.
fn strip_refs<'tcx>(expr: &'tcx Expr<'tcx>) -> &'tcx Expr<'tcx> {
    match expr.kind {
        ExprKind::AddrOf(_, _, inner) => strip_refs(inner),
        ExprKind::Unary(UnOp::Deref, inner) => strip_refs(inner),
        ExprKind::MethodCall(seg, receiver, _, _)
            if matches!(seg.ident.name.as_str(), "clone" | "to_owned" | "into") =>
        {
            strip_refs(receiver)
        }
        _ => expr,
    }
}

impl<'a, 'tcx> Visitor<'tcx> for TargetVisitor<'a, 'tcx> {
    fn visit_local(&mut self, local: &'tcx LetStmt<'tcx>) {
        if_chain::if_chain! {
            if let PatKind::Binding(_, _, _, _) = local.pat.kind;
            if let Some(init) = local.init;
            then {
                // `let client = SomeClient::new(&env, &param)`
                if let Some(param_index) = self.client_new_target(init) {
                    self.client_bindings.insert(local.pat.hir_id, param_index);
                } else if let Some(param_index) = self.resolve_to_param(init) {
                    // `let x = param` (or `&param`, `param.clone()`): track the alias.
                    self.aliases.insert(local.pat.hir_id, param_index);
                }
            }
        }
        walk_local(self, local);
    }

    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if let ExprKind::MethodCall(seg, receiver, args, _) = &expr.kind {
            let method_name = seg.ident.name;

            // `addr.require_auth()` / `addr.require_auth_for_args(..)` on a parameter.
            if matches!(
                method_name.as_str(),
                "require_auth" | "require_auth_for_args"
            ) {
                if let Some(idx) = self.resolve_to_param(receiver) {
                    self.authorized_params.insert(idx);
                    self.guarded_params.insert(idx);
                }
            }

            // Allowlist membership: `allowed.contains(&param)` /
            // `allowed.contains_key(&param)` where the argument is the parameter.
            if matches!(method_name.as_str(), "contains" | "contains_key") {
                if let Some(arg) = args.first() {
                    if let Some(idx) = self.resolve_to_param(arg) {
                        self.guarded_params.insert(idx);
                    }
                }
            }

            // A method call on a client built from an untrusted parameter is the
            // sink. Bare `Client::new(..)` without a call is not flagged.
            if let Some(client_hir) = get_expr_hir_id_opt(strip_refs(receiver)) {
                if let Some(param_index) = self.client_bindings.get(&client_hir).copied() {
                    self.candidates.push(Candidate {
                        param_index,
                        span: expr.span,
                    });
                }
            }

            // Direct, unbound call: `SomeClient::new(&env, &param).method(..)`.
            if let Some(param_index) = self.client_new_target(receiver) {
                self.candidates.push(Candidate {
                    param_index,
                    span: expr.span,
                });
            }
        }

        // Equality against a storage read: `param == storage.get(&Key)` (either side).
        if let ExprKind::Binary(op, lhs, rhs) = &expr.kind {
            if matches!(op.node, BinOpKind::Eq | BinOpKind::Ne) {
                self.record_storage_equality(lhs, rhs);
                self.record_storage_equality(rhs, lhs);
            }
        }

        walk_expr(self, expr);
    }
}

impl<'a, 'tcx> TargetVisitor<'a, 'tcx> {
    /// Marks the address parameter guarded when one side of an equality is the
    /// parameter and the other side reads from storage.
    fn record_storage_equality(&mut self, param_side: &Expr<'tcx>, storage_side: &'tcx Expr<'tcx>) {
        if let Some(idx) = self.resolve_to_param(param_side) {
            if is_storage_read(self.cx, storage_side) {
                self.guarded_params.insert(idx);
            }
        }
    }
}

/// `true` if `expr` is (or unwraps to) a `storage.get(&Key)` read on a Soroban
/// storage receiver.
fn is_storage_read<'tcx>(cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) -> bool {
    let mut expr = strip_refs(expr);
    loop {
        match &expr.kind {
            ExprKind::MethodCall(seg, receiver, _, _) => {
                let name = seg.ident.name.as_str();
                if matches!(
                    name,
                    "unwrap" | "expect" | "unwrap_or" | "unwrap_or_else" | "unwrap_or_default"
                ) {
                    expr = receiver;
                    continue;
                }
                if matches!(name, "get" | "get_unchecked") {
                    return get_node_type_opt(cx, &receiver.hir_id)
                        .is_some_and(|ty| is_soroban_storage(cx, ty, SorobanStorageType::Any));
                }
                return false;
            }
            _ => return false,
        }
    }
}
