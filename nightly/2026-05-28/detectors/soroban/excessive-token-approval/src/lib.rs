#![feature(rustc_private)]
//! # excessive-token-approval
//!
//! Flags `approve` calls on a Soroban token client that grant an effectively
//! unlimited or never-expiring allowance.
//!
//! ## What it detects
//! A method call `approve(from, spender, amount, expiration_ledger)` whose
//! receiver type is `soroban_sdk::token::TokenClient` where, as a compile-time
//! constant, the `amount` sits within ~0.1% of `i128::MAX` or the
//! `expiration_ledger` sits within ~0.1% of `u32::MAX`. The receiver type gate
//! keeps `i128::MAX` sentinels in other contexts from being flagged.
//!
//! ## Why it matters
//! A near-max `amount` or far-future `expiration_ledger` leaves a standing
//! allowance the spender can drain at any time, the Soroban analog of an
//! unlimited ERC-20 approval.
//!
//! ## Remediation
//! Approve only the amount required, and set `expiration_ledger` relative to
//! `env.ledger().sequence()` rather than a far-future constant.
//!
//! Severity: Medium · Class: Authorization.

extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::{consts::Constant, diagnostics::span_lint_and_help};
use common::{
    analysis::{match_type_to_str, ConstantAnalyzer},
    declarations::{Severity, VulnerabilityClass},
    macros::expose_lint_info,
};
use if_chain::if_chain;
use rustc_hir::{
    intravisit::{walk_expr, FnKind, Visitor},
    Body, Expr, ExprKind, FnDecl,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{def_id::LocalDefId, Span};

const LINT_MESSAGE: &str =
    "This token approval grants an effectively unlimited or never-expiring allowance.";

/// Fully-qualified type fragment of the Soroban token client. The
/// `#[contractclient(client_name = "TokenClient")]` attribute on
/// `soroban_sdk::token::TokenInterface` generates a struct whose
/// `def_path_str` is `soroban_sdk::token::TokenClient`, so a `contains`
/// match on this fragment identifies the receiver while excluding sibling
/// clients such as `StellarAssetClient`.
const SOROBAN_TOKEN_CLIENT: &str = "token::TokenClient";

/// Largest representable `i128`, as its `u128` bit pattern. A non-negative
/// `i128` constant maps directly onto this range; negative values map to
/// `>= 2^127`, i.e. strictly above this bound, so they are never mistaken for
/// a near-max allowance.
const I128_MAX_BITS: u128 = i128::MAX as u128;

/// An `amount` constant within this many units of `i128::MAX` is treated as an
/// effectively unlimited allowance (~0.1% of the maximum).
const I128_AMOUNT_SLACK: u128 = I128_MAX_BITS / 1000;

/// Largest representable `u32`, as a `u128` for comparison against the
/// constant's bit pattern.
const U32_MAX_BITS: u128 = u32::MAX as u128;

/// An `expiration_ledger` constant within this many units of `u32::MAX` is
/// treated as a never-expiring allowance (~0.1% of the maximum).
const U32_EXPIRATION_SLACK: u128 = U32_MAX_BITS / 1000;

#[expose_lint_info]
pub static EXCESSIVE_TOKEN_APPROVAL_INFO: LintInfo = LintInfo {
    name: env!("CARGO_PKG_NAME"),
    short_message: LINT_MESSAGE,
    long_message: "Calling `token::TokenClient::approve` with a compile-time `amount` at or near `i128::MAX`, or an `expiration_ledger` at or near `u32::MAX`, leaves a standing allowance the spender can drain at any time. This is the Soroban analog of an unlimited ERC-20 approval. Approve only the amount required and set an expiration tied to the current ledger sequence.",
    severity: Severity::Medium,
    help: "https://coinfabrik.github.io/scout-audit/docs/detectors/soroban/excessive-token-approval",
    vulnerability_class: VulnerabilityClass::Authorization,
};

dylint_linting::declare_late_lint! {
    pub EXCESSIVE_TOKEN_APPROVAL,
    Warn,
    LINT_MESSAGE
}

/// Removes a single `&`/`&mut` borrow wrapper. `approve` takes its arguments by
/// reference (`&i128::MAX`), so the literal sits one `AddrOf` below the call
/// argument; peeling it lets the constant analyzer see the underlying value.
fn peel_borrow<'a, 'tcx>(expr: &'a Expr<'tcx>) -> &'a Expr<'tcx> {
    if let ExprKind::AddrOf(_, _, inner) = &expr.kind {
        inner
    } else {
        expr
    }
}

/// Returns the integer bit pattern of a compile-time-constant expression, or
/// `None` if it is not a known integer constant.
fn constant_int<'tcx>(analyzer: &ConstantAnalyzer<'_, 'tcx>, expr: &Expr<'tcx>) -> Option<u128> {
    match analyzer.get_constant(peel_borrow(expr)) {
        Some(Constant::Int(value)) => Some(value),
        _ => None,
    }
}

/// An `amount` is excessive when it is a non-negative constant within
/// `I128_AMOUNT_SLACK` of `i128::MAX`.
fn amount_is_excessive(amount: u128) -> bool {
    (I128_MAX_BITS - I128_AMOUNT_SLACK..=I128_MAX_BITS).contains(&amount)
}

/// An `expiration_ledger` is excessive when it is a constant within
/// `U32_EXPIRATION_SLACK` of `u32::MAX`.
fn expiration_is_excessive(expiration: u128) -> bool {
    (U32_MAX_BITS - U32_EXPIRATION_SLACK..=U32_MAX_BITS).contains(&expiration)
}

struct ExcessiveTokenApprovalVisitor<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    constant_analyzer: ConstantAnalyzer<'a, 'tcx>,
    findings: Vec<Span>,
}

impl<'tcx> ExcessiveTokenApprovalVisitor<'_, 'tcx> {
    /// Returns `true` if the receiver of a method call has the Soroban token
    /// client type. The detector gates strictly on this type so that an
    /// `i128::MAX` sentinel in any other context (transfers, balance caps,
    /// non-token clients) is never flagged.
    fn receiver_is_token_client(&self, receiver: &Expr<'tcx>) -> bool {
        let receiver_ty = self.cx.typeck_results().expr_ty(receiver).peel_refs();
        match_type_to_str(self.cx, receiver_ty, SOROBAN_TOKEN_CLIENT)
    }
}

impl<'tcx> Visitor<'tcx> for ExcessiveTokenApprovalVisitor<'_, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if_chain! {
            if let ExprKind::MethodCall(segment, receiver, args, _) = &expr.kind;
            if segment.ident.as_str() == "approve";
            // `args` excludes the receiver, so the four token-client arguments
            // `(from, spender, amount, expiration_ledger)` are `args[0..4]`.
            if args.len() == 4;
            if self.receiver_is_token_client(receiver);
            then {
                let amount_excessive = constant_int(&self.constant_analyzer, &args[2])
                    .is_some_and(amount_is_excessive);
                let expiration_excessive = constant_int(&self.constant_analyzer, &args[3])
                    .is_some_and(expiration_is_excessive);
                if amount_excessive || expiration_excessive {
                    self.findings.push(expr.span);
                }
            }
        }
        walk_expr(self, expr);
    }
}

impl<'tcx> LateLintPass<'tcx> for ExcessiveTokenApproval {
    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        _: FnKind<'tcx>,
        _: &'tcx FnDecl<'tcx>,
        body: &'tcx Body<'tcx>,
        span: Span,
        _: LocalDefId,
    ) {
        if span.from_expansion() {
            return;
        }

        let mut constant_analyzer = ConstantAnalyzer::new(cx);
        constant_analyzer.visit_body(body);

        let mut visitor = ExcessiveTokenApprovalVisitor {
            cx,
            constant_analyzer,
            findings: Vec::new(),
        };
        visitor.visit_body(body);

        for span in visitor.findings {
            span_lint_and_help(
                cx,
                EXCESSIVE_TOKEN_APPROVAL,
                span,
                LINT_MESSAGE,
                None,
                "Approve only the amount required, and set `expiration_ledger` relative to `env.ledger().sequence()` instead of a far-future constant.",
            );
        }
    }
}
