#![feature(rustc_private)]

//! # storage-change-events
//!
//! Detects Soroban contract entry points that modify storage without emitting an
//! event anywhere in their call flow.
//!
//! ## What it detects
//! A public Soroban function that, directly or transitively through the call
//! graph, calls a storage mutator (`set`, `update`, `remove`, `try_update` on
//! `Instance`/`Persistent`/`Temporary` storage) but never calls `.events()` in
//! that same flow.
//!
//! ## Why it matters
//! Without events, off-chain observers and clients cannot reliably track state
//! changes. Emitting events on storage mutation keeps the contract transparent
//! and observable, which is expected of well-behaved contracts.
//!
//! ## Remediation
//! Emit an event via the contract's `events()` interface whenever storage is
//! modified.
//!
//! Severity: Enhancement · Class: BestPractices.

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use common::{
    analysis::{is_soroban_function, FunctionCallVisitor},
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use rustc_hir::{
    intravisit::{walk_expr, Visitor},
    Expr, ExprKind,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::ty::TyKind;
use rustc_span::{def_id::DefId, Span};
use std::{
    collections::{HashMap, HashSet},
    vec,
};

const LINT_MESSAGE: &str = "Consider emiting an event when storage is modified";

#[expose_lint_info]
pub static STORAGE_CHANGE_EVENTS_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "Emiting an event when storage changes is a good practice to make the contracts more transparent and usable to its clients and observers",
    severity: Severity::Enhancement,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/storage-change-events",
    vulnerability_class: VulnerabilityClass::BestPractices,
};

dylint_linting::impl_late_lint! {
    pub STORAGE_CHANGE_EVENTS,
    Warn,
    LINT_MESSAGE,
    StorageChangeEvents::default()
}

#[derive(Default)]
struct StorageChangeEvents {
    function_call_graph: HashMap<DefId, HashSet<DefId>>,
    checked_functions: HashSet<String>,
    eventless_storage_changers: HashSet<DefId>,
    defids_with_events: HashSet<DefId>,
    /// Functions whose own body directly contains a storage mutator. The
    /// transitive write check would otherwise flag read-only getters that merely
    /// reach a mutator through a branch they never take.
    direct_storage_writers: HashSet<DefId>,
}

/// Whether a function returns a value worth observing. A getter returns a
/// concrete value (`-> u64`, `-> bool`, `-> Result<State, E>`); a mutator either
/// returns unit or a value-less wrapper (`()`, `Result<(), E>`, `Option<()>`).
/// Read-only getters that reach a storage mutator only transitively should not
/// be told to emit events.
fn returns_meaningful_value(cx: &LateContext<'_>, func: &DefId) -> bool {
    let output = cx.tcx.fn_sig(*func).skip_binder().output().skip_binder();
    !is_value_less_ty(cx, output)
}

/// `()` itself, or a `Result`/`Option` whose success payload is `()`.
fn is_value_less_ty(cx: &LateContext<'_>, ty: rustc_middle::ty::Ty<'_>) -> bool {
    match ty.kind() {
        TyKind::Tuple(elems) => elems.is_empty(),
        TyKind::Adt(adt_def, args) => {
            let path = cx.tcx.def_path_str(adt_def.did());
            let is_wrapper = path.ends_with("Result") || path.ends_with("Option");
            is_wrapper
                && args
                    .types()
                    .next()
                    .is_some_and(|inner| matches!(inner.kind(), TyKind::Tuple(e) if e.is_empty()))
        }
        _ => false,
    }
}

/// Used to verify if, starting from a specific parent in the call graph, an event is emitted at any point of the flow.
/// # Params:
///     - fcg: function call graph
///     - parent: the item from which the analysis starts.
///     - check_against: a HashSet that is used to compare the defids. This HashSet is supposed to contain all the defids of the functions that emit events (collected by the `visit_expr` and `check_func` functions).
fn check_events_children(
    fcg: &HashMap<DefId, HashSet<DefId>>,
    parent: &DefId,
    check_against: &HashSet<DefId>,
) -> bool {
    if check_against.contains(parent) {
        return true;
    }
    let children = fcg.get(parent);
    if let Some(children) = children {
        for c in children {
            if check_against.contains(c) || check_events_children(fcg, c, check_against) {
                return true;
            }
        }
    }
    false
}

/// Used to verify if, starting from a specific parent in the call graph, a function that sets storage in a considered "unsafe" way is called in any part of its flow.
/// # Params:
///     - fcg: function call graph
///     - func: the defid from which the analysis starts.
///     - unsafe_set_storage: a HashSet that is used to compare the defids. This HashSet is supposed to contain all the defids of the functions that are considered "unsafe storage setters".
fn check_storage_setters_calls(
    fcg: &HashMap<DefId, HashSet<DefId>>,
    func: &DefId,
    unsafe_set_storage: &HashSet<DefId>,
) -> bool {
    if unsafe_set_storage.contains(func) {
        return true;
    }
    let children = fcg.get(func);
    if let Some(children) = children {
        for c in children {
            if unsafe_set_storage.contains(c)
                || check_storage_setters_calls(fcg, c, unsafe_set_storage)
            {
                return true;
            }
        }
    }
    false
}

impl<'tcx> LateLintPass<'tcx> for StorageChangeEvents {
    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        // Emit the alerts for the considered "unsafe" functions.
        for func in self.function_call_graph.keys() {
            // Only take into account those functions that are public and exposed in a soroban contract (entrypoints that can be called externally). We do not advise on functions that are used auxiliarily.
            if is_soroban_function(cx, &self.checked_functions, func) {
                // Verify if the function itself or the ones it calls (directly or indirectly) emit an event at any point of the flow.
                let emits_event_in_flow = check_events_children(
                    &self.function_call_graph,
                    func,
                    &self.defids_with_events,
                );

                // Verify if the function itself or the ones it calls (directly or indirectly) call an unsafe storage setter at any point of the flow.
                let calls_unsafe_storage_setter = check_storage_setters_calls(
                    &self.function_call_graph,
                    func,
                    &self.eventless_storage_changers,
                );

                // Suppress read-only getters: a function that returns a concrete
                // value but never writes storage in its own body is reading, not
                // mutating. Any reachable mutator belongs to a branch it does not
                // take, so advising it to emit events is a false positive.
                let is_read_only_getter = returns_meaningful_value(cx, func)
                    && !self.direct_storage_writers.contains(func);

                // If both conditions are met, emit an warning.
                if !emits_event_in_flow && calls_unsafe_storage_setter && !is_read_only_getter {
                    span_lint_and_help(
                        cx,
                        STORAGE_CHANGE_EVENTS,
                        cx.tcx.hir_span_if_local(*func).unwrap(),
                        LINT_MESSAGE,
                        /* cx.tcx.hir().span_if_local(r) */ None,
                        "",
                    );
                }
            }
        }
    }

    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        _: rustc_hir::intravisit::FnKind<'tcx>,
        _fn_decl: &'tcx rustc_hir::FnDecl<'tcx>,
        body: &'tcx rustc_hir::Body<'tcx>,
        span: Span,
        local_def_id: rustc_span::def_id::LocalDefId,
    ) {
        let def_id = local_def_id.to_def_id();
        self.checked_functions.insert(cx.tcx.def_path_str(def_id));

        if span.from_expansion() {
            return;
        }

        let mut function_call_visitor =
            FunctionCallVisitor::new(cx, def_id, &mut self.function_call_graph);
        function_call_visitor.visit_body(body);

        let mut storage_change_events_visitor = StorageChangeEventsVisitor {
            cx,
            is_storage_changer: false,
            emits_event: false,
        };

        storage_change_events_visitor.visit_body(body);

        // If the function's own body directly mutates storage, record it so that
        // the transitive check below can tell direct writers apart from callers
        // that only reach a mutator through a branch they never take.
        if storage_change_events_visitor.is_storage_changer {
            self.direct_storage_writers.insert(def_id);
        }

        // If the function modifies the storage and does not emit event, we keep record of its defid as an eventless storage changer.
        if storage_change_events_visitor.is_storage_changer
            && !storage_change_events_visitor.emits_event
        {
            self.eventless_storage_changers.insert(def_id);
        }

        // If the function emits an event, we storage its defid.
        if storage_change_events_visitor.emits_event {
            self.defids_with_events.insert(def_id);
        }
    }
}

struct StorageChangeEventsVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    is_storage_changer: bool,
    emits_event: bool,
}

impl<'a, 'tcx> Visitor<'tcx> for StorageChangeEventsVisitor<'a, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'_>) {
        if let ExprKind::MethodCall(path, receiver, _, _) = expr.kind {
            let name = path.ident.name.as_str();

            let receiver_type = self.cx.typeck_results().node_type(receiver.hir_id);

            // verify if it is an event emission
            if name == "events" {
                self.emits_event = true;
            }

            // verify if it is a storage change
            if (name == "set" || name == "update" || name == "remove" || name == "try_update")
                && (receiver_type.to_string() == "soroban_sdk::storage::Instance"
                    || receiver_type.to_string() == "soroban_sdk::storage::Persistent"
                    || receiver_type.to_string() == "soroban_sdk::storage::Temporary")
            {
                self.is_storage_changer = true;
            }
        }
        walk_expr(self, expr);
    }
}
