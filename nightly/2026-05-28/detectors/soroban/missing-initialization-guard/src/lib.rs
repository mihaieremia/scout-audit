#![feature(rustc_private)]

//! # missing-initialization-guard
//!
//! Detects public `initialize`/`init` entry points that write privileged state
//! without first checking whether the contract is already initialized.
//!
//! ## What it detects
//! A public `initialize`/`init` Soroban function that writes a privileged
//! storage key (name containing `admin`, `owner`, `governor`, `manager`, or
//! `authority`) to instance/persistent storage, with no reachable guard: no
//! `storage.has(&key)` check, no `is_initialized`-style check, and no
//! OpenZeppelin `set_owner`/`set_admin` setter that panics if already set. The
//! host-run `__constructor` is intentionally excluded since it cannot be
//! re-invoked.
//!
//! ## Why it matters
//! Without a guard, any caller can re-invoke the initializer after deployment,
//! overwrite the stored admin/owner address, and seize control of the contract.
//! This is a critical takeover vector.
//!
//! ## Remediation
//! Guard the initializer: check `storage.has(&key)` (or an `is_initialized`
//! helper) and abort if already set, or use a setter that panics when the
//! privileged key already exists.
//!
//! Severity: Critical · Class: Authorization.

extern crate rustc_hir;
extern crate rustc_span;

use std::collections::{HashMap, HashSet};

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    analysis::{self, is_auth_reachable, FunctionCallVisitor, SorobanStorageType},
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use if_chain::if_chain;
use rustc_hir::{
    def::Res,
    intravisit::{walk_expr, FnKind, Visitor},
    Body, Expr, ExprKind, FnDecl, QPath,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{
    def_id::{DefId, LocalDefId},
    Span, Symbol,
};

const LINT_MESSAGE: &str =
    "This initialization function writes privileged state without first checking whether the \
     contract is already initialized, so it can be re-invoked to seize admin/owner control";

/// Storage keys whose names denote privileged/critical state. Writing one of these
/// during `initialize`/`init` without a guard lets an attacker re-initialize the
/// contract and take it over.
const PRIVILEGED_KEY_FRAGMENTS: [&str; 5] = ["admin", "owner", "governor", "manager", "authority"];

/// Names of the exported entry points this detector targets. A public
/// `initialize`/`init` can be called again after deployment; the host-run
/// `__constructor` cannot, so it is intentionally excluded.
const INIT_FN_NAMES: [&str; 2] = ["initialize", "init"];

/// Free functions injected by the OpenZeppelin `stellar-access` crate that set the
/// owner/admin and panic if it is already set, i.e. they are themselves a
/// reinitialization guard. Their bodies live in an external crate, so they are
/// recognized by the trailing segment of their fully-qualified path.
const OZ_INIT_GUARD_SETTERS: [&str; 2] = ["set_owner", "set_admin"];

/// Returns `true` if `name` denotes privileged/critical state.
fn is_privileged_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    PRIVILEGED_KEY_FRAGMENTS
        .iter()
        .any(|fragment| lower.contains(fragment))
}

/// Returns `true` if `expr` is a privileged storage key, i.e. an enum variant /
/// path whose last segment matches [`is_privileged_name`] (e.g. `DataKey::Admin`).
fn is_privileged_key(expr: &Expr<'_>) -> bool {
    match expr.kind {
        ExprKind::AddrOf(_, _, inner) => is_privileged_key(inner),
        ExprKind::Path(QPath::Resolved(_, path)) => {
            if_chain! {
                if let Res::Def(_, _) = path.res;
                if let Some(seg) = path.segments.last();
                then {
                    return is_privileged_name(seg.ident.name.as_str());
                }
            }
            false
        }
        _ => false,
    }
}

/// Returns `true` if `expr` is a call to an OpenZeppelin owner/admin setter that
/// panics when already set (see [`OZ_INIT_GUARD_SETTERS`]).
fn is_oz_init_guard_call(cx: &LateContext<'_>, expr: &Expr<'_>) -> bool {
    if let ExprKind::Call(callee, _) = &expr.kind {
        if let ExprKind::Path(qpath) = &callee.kind {
            if let Some(def_id) = cx.qpath_res(qpath, callee.hir_id).opt_def_id() {
                let path = cx.tcx.def_path_str(def_id);
                return OZ_INIT_GUARD_SETTERS
                    .iter()
                    .any(|setter| path.ends_with(setter));
            }
        }
    }
    false
}

/// Returns `true` if `def_id` is a public `initialize`/`init` entry point (and not
/// the host-run `__constructor`).
fn is_init_fn(cx: &LateContext<'_>, def_id: DefId) -> bool {
    cx.tcx
        .opt_item_name(def_id)
        .is_some_and(|name| INIT_FN_NAMES.contains(&name.as_str()))
}

#[expose_lint_info]
pub static MISSING_INITIALIZATION_GUARD_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "A public initialize/init function writes admin/owner/critical state to instance or persistent storage without a preceding guard (a storage `has` check, an `is_initialized` check, or an OpenZeppelin `set_owner`/`set_admin` that panics if already set). Any caller can re-invoke it to overwrite the privileged address and seize control of the contract.",
    severity: Severity::Critical,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/missing-initialization-guard",
    vulnerability_class: VulnerabilityClass::Authorization,
};

dylint_linting::impl_late_lint! {
    pub MISSING_INITIALIZATION_GUARD,
    Warn,
    LINT_MESSAGE,
    MissingInitializationGuard::default()
}

#[derive(Default)]
struct MissingInitializationGuard {
    function_call_graph: HashMap<DefId, HashSet<DefId>>,
    /// Functions that contain a reinitialization guard (`has`, `is_initialized`,
    /// or an OZ `set_owner`/`set_admin`).
    guarded_functions: HashSet<DefId>,
    checked_functions: HashSet<String>,
    /// Init functions that perform a privileged storage write with no inline guard,
    /// mapped to the spans of those writes.
    unguarded_init_sinks: HashMap<DefId, Vec<Span>>,
}

impl<'tcx> LateLintPass<'tcx> for MissingInitializationGuard {
    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        for (def_id, sink_spans) in &self.unguarded_init_sinks {
            // Only public `initialize`/`init` entry points are at risk; `__constructor`
            // is run once by the host and cannot be re-invoked.
            if !is_init_fn(cx, *def_id)
                || !analysis::is_soroban_function(cx, &self.checked_functions, def_id)
            {
                continue;
            }

            // A guard reachable from the init function (inline or in a callee) protects
            // the write, e.g. an `is_initialized` helper or an OZ setter in a delegate.
            if is_auth_reachable(*def_id, &self.function_call_graph, &self.guarded_functions) {
                continue;
            }

            for span in sink_spans {
                span_lint_and_help(
                    cx,
                    MISSING_INITIALIZATION_GUARD,
                    *span,
                    LINT_MESSAGE,
                    None,
                    "",
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
        // Record the function so `is_soroban_function` can recognize exported entry points.
        let def_id = local_def_id.to_def_id();
        self.checked_functions.insert(cx.tcx.def_path_str(def_id));

        // If this function comes from a macro, don't analyze it.
        if span.from_expansion() {
            return;
        }

        // First visitor: build the function call graph for guard reachability.
        let mut function_call_visitor =
            FunctionCallVisitor::new(cx, def_id, &mut self.function_call_graph);
        function_call_visitor.visit_body(body);

        // Second visitor: collect privileged storage writes and reinitialization guards.
        let mut visitor = InitGuardVisitor {
            cx,
            guard_found: false,
            sink_spans: Vec::new(),
        };
        visitor.visit_body(body);

        if visitor.guard_found {
            self.guarded_functions.insert(def_id);
        } else if !visitor.sink_spans.is_empty() {
            self.unguarded_init_sinks.insert(def_id, visitor.sink_spans);
        }
    }
}

struct InitGuardVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    guard_found: bool,
    sink_spans: Vec<Span>,
}

impl<'a, 'tcx> Visitor<'tcx> for InitGuardVisitor<'a, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        // An OZ `set_owner`/`set_admin` panics if already set, so it is a guard.
        if is_oz_init_guard_call(self.cx, expr) {
            self.guard_found = true;
        }

        if let ExprKind::MethodCall(path, object, args, _) = &expr.kind {
            let method_name = path.ident.name;

            if let Some(object_type) = analysis::get_node_type_opt(self.cx, &object.hir_id) {
                let is_storage =
                    analysis::is_soroban_storage(self.cx, object_type, SorobanStorageType::Any);

                // A `storage.has(&key)` check on a privileged key is a guard.
                if is_storage && method_name == Symbol::intern("has") {
                    if let Some(first_arg) = args.first() {
                        if is_privileged_key(first_arg) {
                            self.guard_found = true;
                        }
                    }
                }

                // Privileged storage write sink: `storage.set(&PrivilegedKey, ..)`.
                if_chain! {
                    if is_storage;
                    if method_name == Symbol::intern("set");
                    if let Some(first_arg) = args.first();
                    if is_privileged_key(first_arg);
                    then {
                        self.sink_spans.push(expr.span);
                    }
                }
            }
        }

        // An `is_initialized`-style guard, called as either a method or a free
        // function, gates the initialization regardless of receiver type.
        if is_initialized_check(expr) {
            self.guard_found = true;
        }

        walk_expr(self, expr)
    }
}

/// Returns `true` if `expr` is a call whose name denotes an initialization check
/// (e.g. `is_initialized`, `has_admin`, `assert_uninitialized`).
fn is_initialized_check(expr: &Expr<'_>) -> bool {
    let name = match &expr.kind {
        ExprKind::MethodCall(path, ..) => Some(path.ident.name),
        ExprKind::Call(callee, _) => {
            if let ExprKind::Path(QPath::Resolved(_, path)) = &callee.kind {
                path.segments.last().map(|seg| seg.ident.name)
            } else {
                None
            }
        }
        _ => None,
    };

    name.is_some_and(|name| {
        let lower = name.as_str().to_ascii_lowercase();
        lower.contains("initialized") || lower.contains("has_admin") || lower.contains("has_owner")
    })
}
