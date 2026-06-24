extern crate rustc_hir;
extern crate rustc_lint;
extern crate rustc_span;

use std::collections::{HashMap, HashSet};

use rustc_hir::{
    intravisit::{walk_expr, Visitor},
    Expr, ExprKind,
};
use rustc_lint::LateContext;
use rustc_span::def_id::DefId;

/// Returns `true` if authorization is reachable from `start` through the call graph,
/// i.e. `start` itself, or any function it transitively calls, performs authorization
/// (is contained in `authorized`).
///
/// This generalizes the inline-only authorization model: a Soroban entry point that
/// delegates its `require_auth` to a helper is still considered authorized, which
/// avoids false positives on idiomatic helper-delegated access control.
pub fn is_auth_reachable(
    start: DefId,
    call_graph: &HashMap<DefId, HashSet<DefId>>,
    authorized: &HashSet<DefId>,
) -> bool {
    let mut visited: HashSet<DefId> = HashSet::new();
    let mut stack = vec![start];
    while let Some(def_id) = stack.pop() {
        if !visited.insert(def_id) {
            continue;
        }
        if authorized.contains(&def_id) {
            return true;
        }
        if let Some(callees) = call_graph.get(&def_id) {
            stack.extend(callees.iter().copied());
        }
    }
    false
}

/// `FunctionCallVisitor` is a visitor struct used to construct a call graph of functions within Rust code.
///
/// It records which functions are called by each function, helping in understanding
/// the relationships between different parts of the codebase.
pub struct FunctionCallVisitor<'a, 'tcx> {
    /// Context from the compiler's late lint pass, providing access to various compiler internals.
    cx: &'a LateContext<'tcx>,

    /// The `DefId` of the current function being visited. This acts as a key in the `call_graph`.
    current_fn: DefId,

    /// A mutable reference to a HashMap acting as the call graph. Each function (`DefId`) is mapped
    /// to a set of functions (`DefId`) it calls.
    call_graph: &'a mut HashMap<DefId, HashSet<DefId>>,
}

impl<'a, 'tcx> FunctionCallVisitor<'a, 'tcx> {
    /// Constructs a new `FunctionCallVisitor`.
    ///
    /// # Parameters
    /// - `cx`: The context from the compiler's late lint pass.
    /// - `current_fn`: The `DefId` of the current function being analyzed.
    /// - `call_graph`: A mutable reference to the call graph being constructed.
    ///
    /// # Returns
    /// A new instance of `FunctionCallVisitor`.
    pub fn new(
        cx: &'a LateContext<'tcx>,
        current_fn: DefId,
        call_graph: &'a mut HashMap<DefId, HashSet<DefId>>,
    ) -> Self {
        FunctionCallVisitor {
            cx,
            current_fn,
            call_graph,
        }
    }
}

impl<'a, 'tcx> Visitor<'tcx> for FunctionCallVisitor<'a, 'tcx> {
    /// Visits expressions within the code. If the expression is a function call, it is added to the call graph.
    ///
    /// # Parameters
    /// - `expr`: The expression being visited.
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        // Resolve the callee `DefId` for both free/path calls (`foo()`, `Self::foo()`)
        // and method calls (`receiver.foo()`). Method calls are type-dependent, so
        // they are resolved through the typeck results rather than the path.
        let callee_def_id = match expr.kind {
            ExprKind::Call(call_expr, _) => match call_expr.kind {
                ExprKind::Path(ref qpath) => {
                    self.cx.qpath_res(qpath, call_expr.hir_id).opt_def_id()
                }
                _ => None,
            },
            ExprKind::MethodCall(..) => self.cx.typeck_results().type_dependent_def_id(expr.hir_id),
            _ => None,
        };

        if let Some(def_id) = callee_def_id {
            self.call_graph
                .entry(self.current_fn)
                .or_default()
                .insert(def_id);
        }

        // Continue walking through the expression tree.
        walk_expr(self, expr);
    }
}
