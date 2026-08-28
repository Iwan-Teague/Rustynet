# RustyDNS Tandem — D-6a Phase 1 Notes (2026-08-28)

Status: **implemented (control plane only), gates green.** Scope, invariants, and
every STOP-AND-FLAG sub-decision from the D-6a Phase-1 directive.

Owning design: `RustydnsTandemIntegrationDesign_2026-08-27.md` (§5.1 toggle
semantics, §3 invariants, §5.2 prepare intent, §10.1 phases, §11 reason codes).
Owning decree: `RustydnsExitIntegrationDecree_2026-08-25.md`.

## 1. What Phase 1 delivers

New module `crates/rustynet-control/src/tandem_dns.rs` (domain layer,
transport-agnostic, no backend types):

- **`TandemTogglePhase`** — the operator-visible toggle state enum mapping §5.1
  onto §10.1: `Off`, `PreparingContained`, `Prepared`,
  `Active(TandemMode)`, `RuntimeContained { reason, desired_mode }`,
  `Draining`, `ResidueError`.
- **`reconcile(...)`** — the total, pure transition function: one deterministic
  output per `(phase, desired signed policy, policy validity, readiness
  observation, prepare-intent validity, exit assignment, deactivation barrier,
  residue)` input tuple. No panics, no catch-all arms, no fallbacks.
- **`contain_now(...)`** — the local safety veto, plus
  **`capability_width(...)`**, the machine-checkable ordering used by tests to
  prove the veto strictly tightens.
- **`TandemReasonCode`** — the closed §11 vocabulary (24 codes, pinned by a
  round-trip test; unknown strings never parse).
- **`TandemDnsPrepareIntentV1`** — the abstract, NON-authorizing prepare
  intent: typed fields (`network_id`, `exit_node_id`, three 32-byte digests,
  `membership_epoch`, `not_before`/`not_after`, `nonce`) and a fail-closed
  `validate(now, membership_epoch)`. **No wire format.** See §3.2 below.
- **`RustydnsReadinessProvider`** — the readiness input trait (fail-closed
  contract: an untrustworthy observation MUST degrade, never report `Ready`)
  and `StaticReadinessProvider`, the test/placeholder stub. The real compound
  readiness contract (§6.2) is later-phase wiring.
- **`validate_tandem_enable_eligibility`** — §3 invariant-10 enforcement:
  `blind_exit` and tandem DNS are mutually exclusive
  (`BLIND_EXIT_CONFLICT`).

Existing-pattern extensions in `crates/rustynet-control/src/role_presets.rs`
(exactly the §16.1 implementation map, appended per the capability
append-only rule):

- `Capability::ServesDns` (`"serves_dns"`) — appended last; **no preset grants
  it** (pinned by test). Signed toggle only.
- `ServiceKind::Dns` (`"dns"`, binary `rustydnsd`), `all()` now 4 kinds,
  `capabilities_require_dns_binary`.
- `crates/rustynet-cli/src/role_cli.rs`: `ConcreteAction::DeployDnsService` /
  `UndeployDnsService` mirror the nas/llm planning actions.
- `crates/rustynet-cli/src/main.rs` + `ops_install_systemd_service.rs`: the
  executor and systemd installer **refuse** the `dns` kind fail-closed (hard
  error, never a no-op or a wrong service) — Phase 1 is control-plane only and
  no reviewed `rustydnsd` unit exists yet.

Not implemented (per directive): managed-DNS handoff wiring (D-6b ph2), exit
`:53` NAT redirect (D-6c ph3), per-OS dataplane, cross-repo calls to `rustydns`.

## 2. Fail-closed invariants (each has enforcement + negative tests)

1. **Only fresh signed state enables.** `PolicyValidity` other than `Fresh`
   (expired / replay-rejected / invalid) can never enter or keep the ON family.
   From `Off` it refuses in place; from ON family it yields
   `RuntimeContained` — never an automatic OFF data path.
2. **ON + rustydns not-ready ⇒ contained, never fail-open.** Every readiness
   degradation (`NotReady(code)`, `Stale`, `Unauthenticated`,
   `Incompatible(code)`) maps to a closed §11 code and lands in
   `RuntimeContained`. No transition reaches the system resolver, port-53
   egress, or `Active`.
3. **`ResidueError` refuses every enabling path** (all validity × readiness
   combinations tested).
4. **`contain now` strictly tightens.** `capability_width` ordering
   (`Off == ResidueError < contained/drain/preparing < prepared < active(managed)
   < active(managed_redirect)`) is proven to never increase under the veto;
   `contain_now(Off)` refuses (cannot create state), `contain_now(ResidueError)`
   refuses, already-contained is idempotent, desired mode is preserved as data.
5. **No mode fallback (TDNS-19).** No input combination turns
   `Active(ManagedRedirect)` into `Active(Managed)`; a direct mode switch while
   active is refused with `PROFILE_MISMATCH` (the legal path is signed disable →
   drain → enable); a contained phase whose desired mode drifted refuses
   recovery rather than silently changing mode.
6. **Assignment proof required (§3 inv 3).** Unknown exit assignment is NOT
   treated as proven-same: it fails closed as `ASSIGNMENT_MISMATCH`.
7. **Drain is bounded.** Enforcement is not removed before
   `deactivation_barrier_passed`; residue after the barrier lands in
   `ResidueError`; `Off` is only reachable from `Draining` (barrier ∧ no
   residue) or from `ResidueError` with residue explicitly cleared.
8. **The full ON-family × degradation matrix never reaches `Off` or
   `ResidueError`** (exhaustive nested-loop negative test).

## 3. FLAGGED owner sub-decisions (STOP-AND-FLAG per directive)

### 3.1 §3 fail-closed call specifics — decided within the doc, one residual flag
The §7-style mapping (contained-not-off on degradation) is unambiguous in the
design and is implemented as specified. **Flag:** the manual `contain now` veto
and readiness-staleness have no dedicated §11 code; `CONTROL_STALE_WARNING` is
used (`CONTAIN_NOW_REASON`). Owner may prefer a dedicated code (a closed-enum
append) — semantics unchanged either way.

### 3.2 `TandemDnsPrepareIntentV1` signed wire format — **GATED (not defined)**
Defined abstractly (typed struct + `validate`); the signed record shape
(canonical serialization, signature envelope, strict decode, signer/quorum
binding) is an owner/security-gated decision of the same class as the
`blind_relay` §16 gate. The state machine consumes only `prepare_intent_valid:
bool` from the caller, so the wire-format decision does not block Phases 2/3.

### 3.3 §10.4 deactivation barrier — input parameter only
`Draining → Off` takes `deactivation_barrier_passed: bool`; the barrier's
concrete definition (lease expiry + verification proof) is Phase-2/3 owner
work and is NOT invented here.

### 3.4 Residue detection oracle — input parameter only
`residue_present: bool` is consumed; *how* owned state (nft/pf rules, resolver
config, leases) is detected and proven absent is dataplane-scope owner work.
`ResidueError → Off` additionally requires the explicit not-present verdict.

### 3.5 `contain now` from `Draining` — chose ALLOW (tightening)
§5.1 says the veto applies ON→contained; `Draining` is ON-family, so the veto
is permitted there (it can only tighten an already-shrinking state). Recorded
here in case the owner wants `Draining` excluded.

### 3.6 Mid-drain re-enable refusal code — chose `CONTROL_STALE_WARNING`
A signed ON policy does not cut short a drain; the phase stays `Draining`.
§11 has no dedicated "enable refused during drain" code; the choice is
recorded for owner review.

### 3.7 Scope bound — chose `TANDEM_SCOPE_MAX_NODE_IDS = 64`
§5.4 requires a "sorted dedup bounded" explicit list without pinning the
bound. 64 is a placeholder constant, validated fail-closed
(`SIGNED_POLICY_INVALID` on violation); owner may change the number.

### 3.8 Readiness observation staleness code — chose `CONTROL_STALE_WARNING`
A stale readiness observation is unreadiness, not absence of evidence; owner
may prefer `IDENTITY_STALE` or a dedicated code.

### 3.9 `rustydnsd` deployment executor refuses (Phase 1 boundary)
`DeployDnsService`/`UndeployDnsService` exist for transition-plan parity with
nas/llm, but the executors return hard errors until the tandem service
deployment phase (decree DoD step 2/3) lands. Wiring them to a real
`rustydnsd` unit is owner-gated on the decree's compose-e2e milestone.

## 4. Verification

- `cargo test -p rustynet-control --all-targets --all-features`: **496 tests
  pass**, including the full legal/illegal transition matrix, the
  ON-family × degradation sweep, contain-now widening negatives,
  residue refusals, reason-code closure, scope-bound negatives, prepare-intent
  validation matrix, blind-exit conflict, no-preset-grants-ServesDns pin.
- `cargo check --workspace --all-targets --all-features`: clean (the two
  exhaustive `ServiceKind` matches in `rustynet-cli` were completed with
  fail-closed arms).
- fmt / clippy (`--workspace --all-targets --all-features --locked -D
  warnings`) / `cargo audit --deny warnings` / `cargo deny check bans licenses
  sources advisories`: all clean. The tandem nonce zero-check uses
  `subtle::ConstantTimeEq` to satisfy the workspace secret-material equality
  audit.
- Full workspace test: **one pre-existing, environment-dependent macOS failure
  remains, provably outside this change**:
  `rustynetd::phase10::tests::macos_assert_dns_protection_requires_active_dns_rules`
  shells out to the real `networksetup -getdnsservers`, which fails on this
  host (status 4, "asterisk denotes a disabled network service"). The
  worktree's only `rustynetd` delta is a whitespace reformat in an unrelated
  test file; the failing path (phase10) is untouched. The test needs runner
  stubbing to be host-independent — recorded as pre-existing Phase-1-unrelated
  work, not a regression of this change.
- One adjacent stale assertion was fixed in passing (root cause pre-existing at
  HEAD, macOS-only):
  `rustynet-cli::tests::macos_doctor_custody_paths_are_installer_roots_not_linux_defaults`
  asserted `!=` against `rustynetd::daemon::DEFAULT_WG_*_PATH`, but rustynetd
  now carries macOS-cfg defaults that are by design the installer roots, so
  the assertion was tautologically violated on macOS. The test now asserts
  equality with the daemon's macOS-cfg defaults (the Linux-defaults guard is
  preserved structurally by the cfg branches).

## 5. Not claimed here

No dataplane behavior, no live-lab evidence, no OS enforcement, no signed wire
format, no `rustydnsd` service unit. The decree's DoD steps 2 (toggle with
negative coverage — delivered at the state-machine level here) and 3 (live-lab
stage + `--node` ledger row) remain open and require the later phases.
