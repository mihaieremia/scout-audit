#![feature(rustc_private)]

//! # auth-address-mismatch
//!
//! Flags a function that authorizes one address but writes per-user storage keyed
//! on a different, clearly-distinct address.
//!
//! ## What it detects
//! Within a single non-macro contract function, the detector collects the set of
//! addresses passed to `require_auth` / `require_auth_for_args` (the AUTHED set)
//! and the addresses carried by the key of each Soroban storage `set` (the MUTATED
//! address). It flags a storage write only when the function authorizes *exactly
//! one* address `A`, the storage key carries an address `B`, and `A` and `B` are
//! provably not structurally equivalent (`are_equivalent`). When the function
//! delegates authorization to a helper (auth reachable through the call graph) or
//! is gated by an OpenZeppelin `#[only_owner]`/`#[only_admin]` enforcer, the write
//! is treated as admin/owner-guarded and never flagged.
//!
//! ## Why it matters
//! Existing auth detectors only check that *some* `require_auth` is present or
//! reachable, not that the *authorized* address is the same one whose balance or
//! position is mutated. `addr_a.require_auth(); storage.set(&Balance(addr_b), ..)`
//! passes those checks yet lets an authorized caller overwrite *someone else's*
//! state — a critical authorization flaw.
//!
//! ## Remediation
//! Key the storage write on the same address you authorized
//! (`caller.require_auth(); storage.set(&Balance(caller), ..)`), or authorize the
//! address being mutated, or gate the write behind an admin/owner access-control
//! check.
//!
//! Severity: Critical · Class: Authorization.

extern crate rustc_hir;
extern crate rustc_span;

use std::collections::{HashMap, HashSet};

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    analysis::{
        collect_locals, get_node_type_opt, is_auth_reachable, is_soroban_address,
        is_soroban_storage, ExprAnalyzer, FunctionCallVisitor, SorobanStorageType,
    },
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use if_chain::if_chain;
use rustc_hir::{
    intravisit::{walk_expr, FnKind, Visitor},
    Body, Expr, ExprKind, FnDecl, HirId,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{
    def_id::{DefId, LocalDefId},
    Span, Symbol,
};

const LINT_MESSAGE: &str =
    "This function authorizes one address but writes storage keyed on a different address, letting an authorized caller mutate another account's state";

/// Free functions injected by the OpenZeppelin `stellar-macros` access-control
/// attribute macros (`#[only_owner]`, `#[only_admin]`). Their bodies live in the
/// external `stellar-access` crate and internally call `require_auth`, so they are
/// invisible to the inline auth check. Recognizing them by name credits the
/// injected admin/owner authorization, which legitimately mutates other users.
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
pub static AUTH_ADDRESS_MISMATCH_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "The function calls `require_auth` on one address but then writes per-user storage keyed on a different, clearly-distinct address. Authorization proves the caller controls address `A`, but the write mutates the state of address `B != A`. Any party who can authorize `A` can therefore overwrite the balance, position, or role of another account `B`. Key the write on the authorized address, authorize the address being mutated, or gate the write behind an admin/owner access-control check.",
    severity: Severity::Critical,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/auth-address-mismatch",
    vulnerability_class: VulnerabilityClass::Authorization,
};

dylint_linting::impl_late_lint! {
    pub AUTH_ADDRESS_MISMATCH,
    Warn,
    LINT_MESSAGE,
    AuthAddressMismatch::default()
}

#[derive(Default)]
struct AuthAddressMismatch {
    /// Call graph used to credit authorization delegated to a helper as a blanket
    /// admin/owner-style guard that suppresses the mismatch.
    function_call_graph: HashMap<DefId, HashSet<DefId>>,
    /// Functions where authorization (`require_auth` or an OZ enforcer) was found
    /// inline; consumed by `is_auth_reachable`.
    authorized_functions: HashSet<DefId>,
    /// Candidate mismatch sites: the per-function storage-write spans whose key
    /// address was never the inline-authorized address.
    mismatch_sites: HashMap<DefId, Vec<Span>>,
}

impl AuthAddressMismatch {
    /// `true` when authorization is reachable from any *callee* of `fn_def_id`
    /// (a delegated/helper auth such as an admin guard), as opposed to the
    /// function's own inline `require_auth`. The inline auth is the address matched
    /// against the storage key and must not blanket-suppress the mismatch.
    fn auth_reachable_via_callee(&self, fn_def_id: DefId) -> bool {
        self.function_call_graph
            .get(&fn_def_id)
            .is_some_and(|callees| {
                callees.iter().any(|callee| {
                    is_auth_reachable(
                        *callee,
                        &self.function_call_graph,
                        &self.authorized_functions,
                    )
                })
            })
    }
}

impl<'tcx> LateLintPass<'tcx> for AuthAddressMismatch {
    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        for (fn_def_id, spans) in &self.mismatch_sites {
            // Suppress when authorization is delegated to a helper: if any callee of
            // this function authorizes (inline `require_auth`/admin enforcer, possibly
            // transitively), treat the write as admin/owner-guarded. We cannot know
            // which address the helper authorizes, so we conservatively credit it.
            // The function's OWN inline single-address auth is deliberately excluded
            // here — that is the address we matched against the key, not a blanket guard.
            if self.auth_reachable_via_callee(*fn_def_id) {
                continue;
            }
            for span in spans {
                span_lint_and_help(
                    cx,
                    AUTH_ADDRESS_MISMATCH,
                    *span,
                    LINT_MESSAGE,
                    None,
                    "key the write on the authorized address, authorize the address being mutated, or gate the write behind an admin/owner access-control check",
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

        // Functions synthesized by macros are not analyzed; their auth/storage
        // shape is the macro author's responsibility.
        if span.from_expansion() {
            return;
        }

        // Build the call graph so delegated authorization can be credited.
        let mut function_call_visitor =
            FunctionCallVisitor::new(cx, def_id, &mut self.function_call_graph);
        function_call_visitor.visit_body(body);

        // Resolve `let` bindings so equivalent addresses bound to different locals
        // (`let x = caller; x.require_auth(); set(&Balance(caller), ..)`) compare equal.
        let mut locals = HashMap::new();
        collect_locals(body, &mut locals);

        let mut collector = AuthMismatchVisitor {
            cx,
            authed_addresses: Vec::new(),
            access_control_auth: false,
            storage_keys: Vec::new(),
        };
        collector.visit_body(body);

        // An OZ access-control enforcer authorizes admin/owner, which legitimately
        // mutates other users' state: record it as a blanket authorization and skip.
        if collector.access_control_auth {
            self.authorized_functions.insert(def_id);
            return;
        }

        if !collector.authed_addresses.is_empty() {
            self.authorized_functions.insert(def_id);
        }

        // Conservative gate: only reason about the unambiguous single-authorizer
        // shape. Zero authed addresses is `set-contract-storage`'s domain; more than
        // one authed address (e.g. `from` and `to` both authorized) is out of scope.
        if collector.authed_addresses.len() != 1 {
            return;
        }
        let authed = collector.authed_addresses[0];

        let analyzer = ExprAnalyzer::new(&locals);
        let authed = strip_clone(authed);
        let mut spans = Vec::new();
        for key in &collector.storage_keys {
            // Flag only when NO authed address is structurally equivalent to the
            // mutated address. `.clone()` is normalized away on both sides so
            // `caller.require_auth(); set(&Balance(caller.clone()))` clears. If we
            // cannot prove `A != B`, we do not flag.
            if !analyzer.are_equivalent(authed, strip_clone(key.address)) {
                spans.push(key.span);
            }
        }

        if !spans.is_empty() {
            self.mismatch_sites.insert(def_id, spans);
        }
    }
}

/// Look through a chain of `.clone()` calls to the underlying address expression,
/// so a cloned address compares equal to its source under structural equivalence.
fn strip_clone<'tcx>(mut expr: &'tcx Expr<'tcx>) -> &'tcx Expr<'tcx> {
    while let ExprKind::MethodCall(path, receiver, [], _) = &expr.kind {
        if path.ident.name != Symbol::intern("clone") {
            break;
        }
        expr = receiver;
    }
    expr
}

/// A per-user storage write: the span of the `set` call and the `Address`
/// expression carried by its key.
struct StorageKeyWrite<'tcx> {
    span: Span,
    address: &'tcx Expr<'tcx>,
}

struct AuthMismatchVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    /// Addresses on which `require_auth`/`require_auth_for_args` was called inline.
    authed_addresses: Vec<&'tcx Expr<'tcx>>,
    /// Whether an OZ `#[only_owner]`/`#[only_admin]` enforcer was called inline.
    access_control_auth: bool,
    /// Per-user storage writes found inline, with their key address.
    storage_keys: Vec<StorageKeyWrite<'tcx>>,
}

impl<'a, 'tcx> AuthMismatchVisitor<'a, 'tcx> {
    /// `true` when `expr`'s type is `soroban_sdk::Address`.
    fn is_address(&self, expr: &Expr<'tcx>) -> bool {
        get_node_type_opt(self.cx, &expr.hir_id).is_some_and(|ty| is_soroban_address(self.cx, ty))
    }

    /// Find the `Address` expression carried by a storage key (the first argument
    /// of a `set` call), e.g. the `addr` in `&DataKey::Balance(addr)`.
    ///
    /// Returns `Some` only when the key carries *exactly one* `Address` sub-expr,
    /// so a key with two addresses (ambiguous which is the per-user slot) is not
    /// flagged. The key itself being an `Address` (`set(&addr, ..)`) also counts.
    fn key_address(&self, key: &'tcx Expr<'tcx>) -> Option<&'tcx Expr<'tcx>> {
        let mut found: Vec<&'tcx Expr<'tcx>> = Vec::new();
        let mut finder = AddressFinder {
            outer: self,
            found: &mut found,
        };
        finder.visit_expr(key);
        match found.as_slice() {
            [single] => Some(single),
            _ => None,
        }
    }
}

impl<'a, 'tcx> Visitor<'tcx> for AuthMismatchVisitor<'a, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        // Recognize authorization injected by OZ `#[only_owner]`/`#[only_admin]`.
        if is_access_control_auth_call(self.cx, expr) {
            self.access_control_auth = true;
        }

        if let ExprKind::MethodCall(path, receiver, args, _) = &expr.kind {
            let method = path.ident.name;

            // `addr.require_auth()` / `addr.require_auth_for_args(..)` on an Address.
            if (method == Symbol::intern("require_auth")
                || method == Symbol::intern("require_auth_for_args"))
                && self.is_address(receiver)
            {
                self.authed_addresses.push(receiver);
            }

            // `storage.set(&key, &value)` on Instance/Persistent/Temporary storage
            // whose key carries an Address: a per-user storage write.
            if_chain! {
                if path.ident.name == Symbol::intern("set");
                if let Some(receiver_ty) = get_node_type_opt(self.cx, &receiver.hir_id);
                if is_soroban_storage(self.cx, receiver_ty, SorobanStorageType::Any);
                if let Some(key_arg) = args.first();
                if let Some(address) = self.key_address(key_arg);
                then {
                    self.storage_keys.push(StorageKeyWrite {
                        span: expr.span,
                        address,
                    });
                }
            }
        }

        walk_expr(self, expr);
    }
}

/// Collects every `Address`-typed sub-expression of a storage key, looking
/// through references and enum-variant constructor calls
/// (`&DataKey::Balance(addr)` -> `addr`).
struct AddressFinder<'a, 'b, 'tcx> {
    outer: &'a AuthMismatchVisitor<'b, 'tcx>,
    found: &'a mut Vec<&'tcx Expr<'tcx>>,
}

impl<'a, 'b, 'tcx> Visitor<'tcx> for AddressFinder<'a, 'b, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if self.outer.is_address(expr) {
            self.found.push(expr);
            // Do not descend into an Address expression: `addr.clone()` and `addr`
            // are the same per-user slot, recorded once.
            return;
        }
        walk_expr(self, expr);
    }

    fn visit_id(&mut self, _: HirId) {}
}
