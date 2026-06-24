# New Soroban/Rust Detector Catalog (research synthesis)

Candidate detectors beyond the current 38, targeting the harder pitfalls: auth &
cross-contract permission leakage, TTL/storage-key correctness, loop termination,
asserts, and memory. Each is deduped against the existing detectors and external prior
art (Scout upstream, OZ stellar-contracts, Veridise/sorobansecurity), and was graded for
detectability against the real `common/analysis` primitives and FP-risk against
`rs-lending-xlm` (a strong negative corpus) plus four other Soroban repos.

Scoring weights noise heavily (our worst failure mode): `0.35·Value + 0.30·Detectability
+ 0.25·(6−FP_risk) + 0.10·(6−Effort)`, with a hard gate rejecting anything FP_risk ≥ 4.

Feasibility tiers reflect what the infra can do today: "this address/key/storage-tier/
method-name at this site, optionally gated by interprocedural auth-reachability" is
EASY/MEDIUM (every primitive exists); "track the value of X from entry to sink" is HARD
(no taint/dataflow infra).

---

## Tier 1 — build first (high value, low FP)

### 1. unscoped-authorize-as-current-contract — Authorization / Critical
The Soroban analog of unlimited ERC-20 approval. Flags `env.authorize_as_current_contract(entries)`
where an entry is unscoped: non-empty `sub_invocations` (delegates onward authority) or a
value-moving `fn_name` with a non-constant param-derived amount.
- Detect (HIR late): MethodCall `authorize_as_current_contract` on `is_soroban_env`; resolve
  the entries `vec!`/`push_back` chain; for each `SubContractInvocation` literal check
  `sub_invocations` is `Vec::new` and the amount slot via `ConstantAnalyzer`.
- FP-scope: do NOT flag empty `sub_invocations` (clears all 5 protocol sites); bounded param
  amount → single fixed transfer is fine.
- Grounding: 5 SAFE sites in rs-lending-xlm (flash-loan-receiver/src/lib.rs:154,
  pool/src/utils.rs:184, controller/src/strategies/{swap.rs:124,migrate_blend.rs:304},
  defindex-strategy/src/lib.rs:132) — all use empty sub_invocations → silence-validation set.

### 2. sac-privileged-op-missing-auth — Authorization / High
Privileged SAC/token ops (`mint`/`burn`/`clawback`/`set_authorized`/`set_admin`) invoked
with no reachable `require_auth`. 765 hits across the corpus; the single highest-prevalence
gap.
- Detect: clone the `set-contract-storage` two-phase skeleton; swap the storage-set sink for
  a method-name match in the privileged set; reuse `is_auth_reachable` + OZ-macro recognition
  verbatim.
- FP-scope: MUST be macro-aware (`#[only_owner]`/`#[only_admin]`, 69 hits) and call-graph
  reachable or it floods.
- Feasibility: EASY (existing skeleton).

### 3. unvalidated-cross-contract-target — Authorization / High
A fn takes an `Address` param, builds `SomeClient::new(&env,&addr)`, and calls it with no
allowlist/equality/storage-membership guard → attacker passes a malicious token/oracle/pool.
Distinct from unrestricted-transfer-from (which checks the `from` arg, not the client target).
- Detect: collect `is_soroban_address` params; match `*Client::new` with a param-resolved 2nd
  arg; require a real method call on the binding; guard = allowlist `.contains()`, `==` vs a
  storage read, or `require_auth()` on that address, checked reachable via the call graph.
- FP-scope: exclude clients built from storage/config (dominant safe pattern); exclude tests;
  rank `__constructor` context lower (deployer-controlled).
- Grounding: plausible positive at defindex-strategy/src/lib.rs:157 (`ControllerClient::new`
  from attacker-supplied `init_args.get(0)`, no allowlist).
- Feasibility: MEDIUM. Prevalence: `Client::new` = 1781 hits.

### 4. missing-reinitialization-guard — Authorization / High
A public `initialize`/`init` writes admin/owner/critical state with no preceding `has(&key)`
guard or panic-if-set → re-invocation = admin seizure.
- Detect: identify init fns; find privileged storage `set` sink (reuse `is_privileged_key`);
  search same fn + reachable callees for `.has(&key)`, an OZ `set_owner`/`set_admin` (panics
  if set), or `is_initialized`.
- FP-scope: CREDIT OZ `set_owner`/`set_admin` as guards (every protocol `__constructor` uses
  them); target public `initialize`/`init`, not host-once `__constructor`.
- Grounding: NO vuln instance — protocol uses `__constructor`+`ownable::set_owner`
  (pool/src/lib.rs:257, controller/src/governance/access.rs:63) and an explicit `has()` guard
  at pool/src/lib.rs:266 → negative corpus.
- Feasibility: MEDIUM.

### 5. unchecked-cross-contract-result — ErrorHandling / Medium
Soroban `Client::try_<m>` returns `Result<Result<T,_>,_>` and does NOT panic on a failed
cross-contract/token call; discarding it (`let _ =` / bare statement) swallows the failure.
- Detect (late): MethodCall whose name starts `try_` (minus try_into/from/borrow/lock/reserve),
  return type `Result`, receiver `…Client`, and result ignored (parent `StmtKind::Semi` or
  `let _`). Single-fn, no call graph.
- FP-scope: require `…Client` receiver (excludes local `try_cached_market_config` returning
  Option); exclude tests.
- Grounding: no ignored instance in protocol; SAFE anchors handle it (redstone client.rs:33
  `match … {Ok(Ok(d)) if .. => .., _ => None}`) → regression-grade.
- Feasibility: MEDIUM. Prevalence: cross-contract calls = 1781.

### 6. debug-assert-in-contract — ErrorHandling / Medium (RESCOPE, not new)
Verified by HIR dump: under the Soroban release profile (`debug-assertions=false`,
`panic="abort"`) every `debug_assert*!` lowers to `if false {…}` = dead code — a security
check that does not run on-chain. `assert-violation` (pre-expansion early lint) ALREADY
matches debug_assert but emits a backwards "assert causes panic" Enhancement message.
- Change: 3-line split of `is_assert_macro` into hard vs debug; emit a distinct Medium
  diagnostic for the debug arm: "`debug_assert!` compiles to nothing under the Soroban release
  profile; this check does not run on-chain."
- Grounding: LIVE instance — `rs-lending-xlm/common/src/math/fp_core.rs:143`
  `div_by_int_half_up` guards the divisor with `debug_assert!(b > 0)` then divides by `b`; on
  chain the guard vanishes (b==0 aborts, b<0 silently flips rounding in interest/liquidation).
- Feasibility: EASY. Best value/effort ratio in the catalog.

---

## Tier 2 — build next (solid value, manageable FP)

### 7. temporary-storage-for-critical-data — ResourceManagement / Medium
`temporary()` (auto-deleted, unrecoverable after archival) used for admin/balance/critical
keys → permanent loss. Detect: `set/get/has` on `is_soroban_storage(Temporary)` with an
enum-variant key whose ident matches a sensitivity lexicon. FP-scope: ephemeral allow-list
(`pending session flash lock guard temp cache ongoing`); never flag `remove`. EASY, low FP
(70 temporary() hits; protocol only stores `FlashLoanOngoing`/`PendingAdmin` → negatives).

### 8. missing-persistent-ttl-extension — ResourceManagement / Medium
Crate-wide pass: durable (instance/persistent) storage used but `extend_ttl` called NOWHERE →
archival bricks the contract. Distinct from ineffective-extend-ttl (bad params). Two-phase
accumulate `uses_durable` / `has_extend_ttl` across all fns (renewal often lives in a helper
file), emit once. FP-scope: crate-global not per-fn; skip mock/test crates. MEDIUM.

### 9. excessive-token-approval — Authorization / Medium
`token::Client::approve(from,spender,amount,expiration_ledger)` with compile-time
`i128::MAX`/near-max amount and/or `u32::MAX`/far-future expiry. Detect via `ConstantAnalyzer`
on args[2]/[3], gated strictly on `approve` method + `token::Client` receiver. FP-scope: NEVER
flag `i128::MAX` in transfer/withdraw/cap contexts (the protocol's full-balance sentinel);
never flag dynamic `sequence()+k` expiry. EASY, tight scope.

### 10. auth-address-mismatch — Authorization / High (deepest correctness gap)
Current auth detectors check auth PRESENCE/reachability, not that the *authorized* address
matches the address mutated/charged. Flags `a.require_auth()` followed by a storage write/
charge keyed on a DIFFERENT address `b`. Detect: thread "which address was authorized" through
the auth pass, then `are_equivalent(authorized_expr, key_expr)`. The hard primitive
(`expr_analyzer::are_equivalent`) EXISTS; MEDIUM only because of the threading. Must be macro +
reachability aware. Highest latent value; build with care.

---

## Tier 3 — enhancement / advisory (optimization, higher heuristic)

- **instance-storage-per-user-key** (Enhancement): `instance()` keyed by an Address-bearing
  variant → unbounded growth of the always-loaded map. REQUIRES a bounded-set exemption
  (sibling `…Count` variant or a `< MAX` assert) — protocol's `ApprovedToken(Address)` is
  correct-but-capped. Hardest FP-scoping; ship advisory.
- **raw-symbol-storage-key** (Enhancement): storage key is a `Symbol`/str literal not a
  `#[contracttype]` enum; bonus collision check if one literal maps to ≥2 value types. Gate on
  the storage-call key position (args[0]) so Symbol-as-value (events/roles/fn_names) is excluded.
- **clone-in-loop** (Enhancement, GasUsage): `.clone()` on a soroban `Vec`/`Map`/`Bytes`/`String`
  declared outside a loop, inside the loop body. Never flag Address/i128 clones.
- **linear-scan-in-loop** (Enhancement, GasUsage): `Vec::contains`/`contains_key` inside a loop
  → O(n²); suggest a Map. Distinct from vec-could-be-mapping (which owns `.iter().find`). REAL
  interprocedural TP: `push_unique_address` (controller/src/helpers/utils.rs:18) called inside
  the per-asset loop (controller/src/strategies/mod.rs:36) — ship intraprocedural v1, note the
  helper-delegated miss.
- **non-terminating-loop, sub-rule A** (Medium, DoS): bare `loop {}` with no reachable
  `break`/`return`/`panic` — on-chain there are no servers, so an escapeless loop is ~always a
  bug. Near-zero FP. (Sub-rule B, invariant `while`, deferred pending corpus validation.)

---

## Deferred / dropped

- **swallowed-result / silent-failure** (broader `let _ =`/`.ok()` on security calls): viable
  if narrowed to security-relevant calls; overlaps unchecked-cross-contract-result — start there.
- **unwrap-on-archivable-storage-read**: fold archival wording into `unsafe-unwrap`'s help for
  persistent/temporary receivers unless a corpus instance is produced.
- **unscoped-require-auth-on-value-transfer**: DROP — unsound. Bare `require_auth()` already
  binds the call's actual args; `require_auth_for_args` is only for sub-invocation pre-auth.
  Protocol uses bare require_auth ~20+ times correctly. Detector 1 captures the real risk.
- **recursion-without-base-progress**: DROP — needs a decreasing-measure/termination analysis.
- **INFRA-BLOCKED (need a new dataflow pass first)**: reentrancy / write-after-external-call
  ordering (no side-effect model); storage key-collision (needs symbolic key reasoning);
  taint-refined panic-on-attacker-input (call graph is reachability-only, no value propagation).

---

## Recommended build order

1. debug-assert-in-contract (3-line rescope, live protocol instance)
2. sac-privileged-op-missing-auth (EASY, 765-hit prevalence, clone existing skeleton)
3. unscoped-authorize-as-current-contract (Critical, clean FP story)
4. unchecked-cross-contract-result (regression-grade, no protocol FP)
5. temporary-storage-for-critical-data + excessive-token-approval (EASY, low FP)
6. unvalidated-cross-contract-target + missing-reinitialization-guard (MEDIUM, real gaps)
7. missing-persistent-ttl-extension, then the Tier-3 advisories
8. auth-address-mismatch (highest latent value; build once the simpler ones validate the infra)

Every Tier-1/2 detector ships with a manifest test corpus including NO-FIRE fixtures mirroring
the cited safe protocol patterns — if a detector fires on those, its FP rules are wrong.
