#![feature(rustc_private)]
//! # unvalidated-cross-contract-target
//!
//! Flags cross-contract calls whose target contract is an unvalidated `Address`
//! taken directly from a function parameter.
//!
//! ## What it detects
//! A method invoked on a `SomeClient` built (via `Client::new(&env, &addr)`) from
//! an untrusted address parameter, where that parameter is never guarded: no
//! allowlist membership check (`allowed.contains(&addr)`), no equality against a
//! storage-read value, and no reachable `addr.require_auth()`. Constructor
//! (`__constructor`) targets are exempt.
//!
//! ## Why it matters
//! Calling into an attacker-chosen contract (a malicious token, oracle, or pool)
//! enables fund theft, price manipulation, and reentrancy.
//!
//! ## Remediation
//! Validate the target address before calling into it: check it against an
//! on-chain allowlist, compare it to a value read from storage, or require it to
//! authorize the call via `require_auth`.
//!
//! Severity: Critical · Class: Authorization.

extern crate rustc_hir;
extern crate rustc_span;

use std::collections::{HashMap, HashSet};

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    analysis::{
        get_expr_hir_id_opt, get_node_type_opt, is_auth_reachable, is_soroban_address,
        is_soroban_function, is_soroban_storage, match_type_to_str, FunctionCallVisitor,
        SorobanStorageType,
    },
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use rustc_hir::{
    def::DefKind,
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

/// One caller forwards its own address parameter into a callee's address
/// parameter: `caller`'s `caller_index`-th address param flows, as an argument,
/// into `callee`'s `callee_index`-th address param. Used to propagate
/// attacker-controlled taint across the call graph at parameter granularity.
struct TaintEdge {
    caller: DefId,
    caller_index: usize,
    callee: DefId,
    callee_index: usize,
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
    /// Fully-qualified names of every analyzed function, used by
    /// `is_soroban_function` to recognize public contract ABI entry points.
    checked_functions: HashSet<String>,
    /// Number of address parameters per function (used to seed entry-point taint).
    address_param_counts: HashMap<DefId, usize>,
    /// Parameter-granular taint edges: a caller forwarding its address param into
    /// a callee's address param.
    taint_edges: Vec<TaintEdge>,
}

impl<'tcx> LateLintPass<'tcx> for UnvalidatedCrossContractTarget {
    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        // An address is attacker-controlled only if it originates from a *public
        // contract entry point* parameter. Seed the entry points, then propagate
        // that taint downstream through parameter-forwarding edges, stopping at any
        // function that guards or authorizes the forwarded parameter (a validated
        // address is no longer attacker-controlled).
        let attacker_reachable = self.compute_attacker_reachable(cx);

        for (def_id, candidates) in &self.candidates {
            // A function that delegates `require_auth` to a helper still authorizes
            // its targets; credit auth reachable through the call graph.
            let auth_reachable = is_auth_reachable(
                *def_id,
                &self.function_call_graph,
                &self.authorized_functions,
            );
            if auth_reachable {
                continue;
            }
            let guarded = self.guarded_params.get(def_id);

            for candidate in candidates {
                if guarded.is_some_and(|set| set.contains(&candidate.param_index)) {
                    continue;
                }
                // Only fire when the target address is reachable from a public
                // entry-point parameter without validation along the way. Internal
                // wrappers that receive a storage-read or allowlisted address are
                // not attacker-controlled and are not flagged.
                if !attacker_reachable.contains(&(*def_id, candidate.param_index)) {
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
        let def_id = local_def_id.to_def_id();
        // Record every function (including macro-generated ABI siblings) so
        // `is_soroban_function` can recognize public contract entry points.
        self.checked_functions.insert(cx.tcx.def_path_str(def_id));

        if span.from_expansion() {
            return;
        }

        let mut function_call_visitor =
            FunctionCallVisitor::new(cx, def_id, &mut self.function_call_graph);
        function_call_visitor.visit_body(body);

        let params = collect_address_params(cx, body);
        if params.is_empty() {
            return;
        }
        self.address_param_counts.insert(def_id, params.len());

        let mut visitor = TargetVisitor::new(cx, params);
        visitor.visit_body(body);

        if !visitor.authorized_params.is_empty() {
            self.authorized_functions.insert(def_id);
        }
        if !visitor.guarded_params.is_empty() {
            self.guarded_params.insert(def_id, visitor.guarded_params);
        }
        for (caller_index, callee, callee_index) in visitor.taint_edges.drain(..) {
            self.taint_edges.push(TaintEdge {
                caller: def_id,
                caller_index,
                callee,
                callee_index,
            });
        }
        // A `__constructor` receives its addresses from the deployer at deploy time,
        // not from an attacker-controllable call, so its targets are not flagged.
        // Its guards/auth still feed the call graph for functions it reaches.
        if !visitor.candidates.is_empty() && !is_constructor(cx, def_id) {
            self.candidates.insert(def_id, visitor.candidates);
        }
    }
}

impl UnvalidatedCrossContractTarget {
    /// Computes the set of `(function, address-parameter-index)` pairs that an
    /// attacker can control. Seeds public contract entry points, then propagates
    /// taint along parameter-forwarding edges, stopping at any function that
    /// guards or authorizes the forwarded parameter.
    fn compute_attacker_reachable(&self, cx: &LateContext<'_>) -> HashSet<(DefId, usize)> {
        let mut reachable: HashSet<(DefId, usize)> = HashSet::new();
        let mut worklist: Vec<(DefId, usize)> = Vec::new();

        for (def_id, count) in &self.address_param_counts {
            if is_constructor(cx, *def_id) {
                continue;
            }
            if !is_soroban_function(cx, &self.checked_functions, def_id) {
                continue;
            }
            for index in 0..*count {
                if reachable.insert((*def_id, index)) {
                    worklist.push((*def_id, index));
                }
            }
        }

        while let Some((def_id, index)) = worklist.pop() {
            // A validated address forwarded downstream is no longer
            // attacker-controlled, so taint does not propagate past a guard/auth.
            if is_auth_reachable(
                def_id,
                &self.function_call_graph,
                &self.authorized_functions,
            ) {
                continue;
            }
            if self
                .guarded_params
                .get(&def_id)
                .is_some_and(|set| set.contains(&index))
            {
                continue;
            }
            for edge in &self.taint_edges {
                if edge.caller == def_id && edge.caller_index == index {
                    let key = (edge.callee, edge.callee_index);
                    if reachable.insert(key) {
                        worklist.push(key);
                    }
                }
            }
        }

        reachable
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
    /// Parameter-forwarding edges discovered in this body:
    /// `(caller_address_index, callee_def_id, callee_address_index)`.
    taint_edges: Vec<(usize, DefId, usize)>,
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
            taint_edges: Vec::new(),
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
        self.record_taint_edges(expr);

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
    /// Records a taint edge whenever this body forwards one of its own address
    /// parameters into another function's address parameter, so attacker-control
    /// can be propagated across the call graph in `check_crate_post`.
    fn record_taint_edges(&mut self, expr: &'tcx Expr<'tcx>) {
        match &expr.kind {
            // `g(a, b, c)` / `Type::g(a, b)`: arguments map 1:1 onto parameters.
            ExprKind::Call(callee, args) => {
                if let ExprKind::Path(qpath) = &callee.kind {
                    if let Some(callee_def_id) =
                        self.cx.qpath_res(qpath, callee.hir_id).opt_def_id()
                    {
                        for (raw_pos, arg) in args.iter().enumerate() {
                            self.try_taint_edge(callee_def_id, raw_pos, arg);
                        }
                    }
                }
            }
            // `receiver.m(a, b)`: the receiver is parameter 0, args follow.
            ExprKind::MethodCall(_, receiver, args, _) => {
                if let Some(callee_def_id) =
                    self.cx.typeck_results().type_dependent_def_id(expr.hir_id)
                {
                    self.try_taint_edge(callee_def_id, 0, receiver);
                    for (k, arg) in args.iter().enumerate() {
                        self.try_taint_edge(callee_def_id, k + 1, arg);
                    }
                }
            }
            _ => {}
        }
    }

    /// If `arg` resolves to one of this body's address parameters and the callee's
    /// `raw_pos`-th parameter is also an address, record the forwarding edge.
    fn try_taint_edge(&mut self, callee: DefId, raw_pos: usize, arg: &Expr<'tcx>) {
        if let Some(caller_index) = self.resolve_to_param(arg) {
            if let Some(callee_index) = callee_addr_param_index(self.cx, callee, raw_pos) {
                self.taint_edges.push((caller_index, callee, callee_index));
            }
        }
    }

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

/// For a callable `callee`, returns the address-parameter index of its
/// `raw_pos`-th parameter, or `None` if that parameter is not a Soroban
/// `Address`. The index counts only address parameters in declaration order, so
/// it lines up with `collect_address_params` / `Candidate::param_index`.
fn callee_addr_param_index(cx: &LateContext<'_>, callee: DefId, raw_pos: usize) -> Option<usize> {
    if !matches!(cx.tcx.def_kind(callee), DefKind::Fn | DefKind::AssocFn) {
        return None;
    }
    let inputs = cx.tcx.fn_sig(callee).skip_binder().skip_binder().inputs();
    let ty = inputs.get(raw_pos)?;
    if !is_soroban_address(cx, *ty) {
        return None;
    }
    Some(
        inputs[..raw_pos]
            .iter()
            .filter(|ty| is_soroban_address(cx, **ty))
            .count(),
    )
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
