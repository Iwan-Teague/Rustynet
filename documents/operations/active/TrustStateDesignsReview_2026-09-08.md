# Trust-State Designs Review — 2026-09-08

Scope: independent review of two design documents that touch signed state or the
fail-closed posture, per the review rubric (A problem statement true? / B chosen
option vs rejected alternatives / C fail-closed on absent·malformed·stale·wrong-writer /
D implementable as written / E what missed / F effort and counts believable).

Method: every load-bearing claim below was verified against the working tree by
reading the cited code. Line numbers are from this tree (the design docs' own
citations were re-checked and drift is noted where material). Both reviews are
docs-only; no code was changed.

Reviewed:
1. `FailClosedPostureFloorDesign_2026-09-08.md` (QH-78 wiring, `crates/rustynetd`)
2. `MembershipTombstoneDesign_2026-09-08.md` (`crates/rustynet-control/src/membership.rs`)

Verdicts:
1. **BUILD-AS-WRITTEN** — problem statement verified end-to-end; no behavioral
   defect found. Three documentation corrections and two implementation notes,
   all non-blocking (§1.7).
2. **BUILD-WITH-CHANGES** — problem statement verified and the residual gap is
   real; the design is coherent, but it under-enumerates the operation set
   (misses `RotateApprover`/`SetQuorum`) and sits on one implementation trap in
   `requires_owner_signer`'s catch-all arm that the specified tests must be
   proven to kill before merge (§2.7).

---

## 1. FailClosedPostureFloorDesign_2026-09-08

### 1.1 A — Problem statement: TRUE, verified point by point

| Claim | Evidence | Verdict |
| --- | --- | --- |
| `force_fail_closed` clears serve/exit, applies strict pf, transitions to FailClosed | `phase10.rs:8120-8126` — `current_serve_exit_node = false; system.block_all_egress()?; current_exit_mode = ExitMode::Off; transition_to(DataplaneState::FailClosed, ...)`. No state guard: it re-runs on every invocation. | TRUE (design cited ~8037; actual 8120 — line drift only) |
| Stale node computes `ScopedResolverOnly` | `phase10.rs:894-900` — `(ExitMode::Off, false) => ScopedResolverOnly`. The function's own doc (`:884-892`) promises it "never returns Untouched". | TRUE |
| Both `macos_dns_posture` production call sites are apply sites | `daemon.rs:8909` (bootstrap) and `daemon.rs:10651` (reconcile) — both feed `apply_dataplane_generation`; `protected_dns: true` hard-coded at both (`daemon.rs:8924`, `:10665`). | TRUE |
| Apply path is unreachable while trust is stale, reachable from FailClosed once trust verifies | Reconcile failure pattern (`daemon.rs:10446` trust_reconcile_failed, and every sibling): increment `reconcile_failures` → `restrict_recoverable`/`restrict_permanent` → `force_fail_closed_or_restrict` → `promote_to_permanent_if_over_limit()` → **early `return`**, before the apply block. The apply block itself runs when `will_apply_generation` includes the `state == DataplaneState::FailClosed` disjunct (`daemon.rs:10507`, re-read at `:10531`), and `apply_dataplane_generation` accepts a FailClosed start state (`phase10.rs:7529-7539`). | TRUE |
| `persist_state` writes exactly `{timestamp_unix, peer_ids, selected_exit_node, lan_access_enabled}`; restore reads `selected_exit_node` untouched | `daemon.rs:10302-10312` (`SessionStateSnapshot` construction), `restore_state` at `:10399`. The field list is even quoted verbatim in `shutdown_residue.rs:31-33`. | TRUE |
| `maybe_assert_dns_posture` gated off while FailClosed/restricted | `daemon.rs:10927-10946` — returns early on `state == FailClosed` or `restriction_mode != None`, and on `!dns_protected()`. | TRUE |
| Escalation ladder exists (`max_reconcile_failures` → `restrict_permanent`) | `promote_to_permanent_if_over_limit` at `daemon.rs:11112-11119`; counter reset on successful apply at `:10771`. Design decision D-2 (reuse this ladder for floor failures) is implementable exactly as written. | TRUE |
| Startup guards run before the runtime exists | QH-40 residue scan at `daemon.rs:11882-11903`; M1 startup recovery `run_startup_dns_recovery` (`macos_dns_sc_protect.rs:845`) — its own doc states it is "called from `daemon.rs` BEFORE preflight has created anything". Backup verify-then-retire (`verify_and_retire_backup`, `:944-958`). | TRUE |
| Marker/intent schema precedent | `shutdown_residue.rs`: `SHUTDOWN_RESIDUE_MARKER_SCHEMA_VERSION = 1`, suffix `.shutdown-residue.json`, `ShutdownResidueMarker { schema_version, recorded_unix, platform, node_id }`. The proposed intent record mirrors this shape faithfully. | TRUE |
| Sibling-file (not snapshot-extension) is the right storage choice | Stronger than the design states: the Linux mesh-status collector **rejects unknown snapshot fields** — the fixture test at `linux_mesh_status.rs:183-195` feeds `future_field=value` and asserts `overall_ok == false`. Extending `SessionStateSnapshot` would break external validators, not merely churn parsers. | TRUE, and understated in the design's favor |

The structural answers to the open questions:

- **Does the reconcile loop keep entering fail-closed handling per tick?** Yes.
  Each tick with stale trust hits a `force_fail_closed_or_restrict` call site
  and early-returns; the next tick re-enters, and `controller.force_fail_closed`
  re-runs `block_all_egress` unconditionally (`phase10.rs:8120` has no
  already-fail-closed guard). An entry hook inside
  `force_fail_closed_or_restrict` therefore fires **every tick** while the node
  is dark — the design's separate "drift re-check at top of tick" hook is
  redundant with it (harmless, but deletable; see §1.7).
- **Does a legitimate signed demotion still lower the floor?** Yes. The
  demotion arrives inside a fresh signed bundle; loading it makes
  `load_verified_trust` succeed; the FailClosed disjunct forces an apply the
  same pass; the apply computes `ScopedResolverOnly` from the withdrawn exit
  state and returns `Ok`; the design's post-apply intent write then rewrites
  the intent to scoped, and the floor computes scoped from then on. The node
  does **not** get stuck protected forever. (One citation fix: the design
  credits the clear to `daemon.rs:9407`, which is the local `ExitNodeOff` IPC
  path; the signed-bundle withdraw lands post-apply at `daemon.rs:10752`
  (`self.selected_exit_node = auto_exit`). Conclusion unaffected.)
- **Can the loopback resolver probe answer under the strict pf ruleset?** Yes.
  `render_macos_killswitch_pf_rules` emits `pass quick on lo0 all`
  **unconditionally, before the strict/non-strict branch** (phase10.rs:3781,
  rule at ~`:3797`), precisely so "the daemon's local IPC, the loopback DNS
  resolver, and loopback health checks keep working". `verify_loopback_resolver_live`
  (`phase10.rs:4793`) probes `127.0.0.1:53535` over UDP — loopback — so the
  A6 gate is answerable while the strict ruleset is loaded. The floor can
  genuinely re-pin under a live daemon while fail-closed.

### 1.2 B — Chosen option vs rejected alternatives: sound

The core move — install the **more restrictive** of (live-computed posture,
last-persisted intent) via a *new* system method rather than reusing
`apply_dns_protection` — is forced by the code, not stylistic:

- `apply_dns_protection` calls `apply_pf_rules(false)` — the **non-strict**
  DNS anchor (`phase10.rs:5309-5315`). Reusing it from a fail-closed context
  would replace the strict egress floor with a weaker anchor: a fail-open. A
  dedicated `enforce_dns_posture_fail_closed` that never touches pf is the
  only correct shape, and the design's T-4 (assert zero `apply_pf_rules`
  calls across the floor) pins exactly the tempting wrong mutation.
- `apply_dns_protection_for_posture`'s `ScopedResolverOnly` arm never touches
  pf at all (`phase10.rs:5463-5474`), so no existing entry point installs
  FullyProtected-without-pf; the new method is not duplicating one.
- The M1 capture guard semantics the floor must reproduce are real and strict
  today (`phase10.rs:5337-5357`: unreadable prior backup refuses; residue
  without a prior entry refuses), all-or-nothing before first mutation is the
  documented M2 contract, and the backup is written before the first
  `networksetup` mutation — the design's T-6 (backup carries pre-pin
  baselines) protects the real next-boot restore path.

The rejected alternative (do nothing) is correctly rejected: the rebooted
fail-closed node genuinely sits at `ScopedResolverOnly` until fresh bundles —
that is the state the live-lab reboot cell observed.

### 1.3 C — Fail-closed audit of every new surface: passes

- **Intent file absent** → floor computes from live state only (no-op) — the
  zero-effort path is the status quo, which is the correct zero-state.
- **Malformed / wrong `schema_version` / wrong platform / wrong `node_id` /
  bad permissions** → reader returns `Some(FullyProtected)` (restrictive-only)
  plus a loud error. Consistent with the QH-40 rule that an unreadable marker
  is residue-present, never clean, and with the sidecar mode-600 loader rule.
- **Stale intent** → never expires, by design, and this is *safe*: the only
  legitimate way to lower it is a signed demotion that rewrites it at the next
  successful apply (verified reachable, §1.1). An attacker "waiting out" the
  intent gains nothing — the floor is availability-only inside an already-dark
  node.
- **Tamper / wrong-writer** → the intent is unsigned, which the design
  discloses honestly with the QH-40 precedent (presence+parse protection, not
  authentication). Deleting both the intent and the daemon state file degrades
  the floor to live-computed — operator-visible teardown, flagged as the
  residual (owner decision D-3). The cross-digest hardening is correctly
  deferred rather than half-designed.
- **Floor install failure** → no pins, failure counted, `restrict_permanent`
  at the existing threshold; never treated as installed. Matches the M2
  all-or-nothing contract in the code.
- **Non-macOS invocation** → `Err` (loud), behind a `cfg!` guard — a future
  caller removing the guard hits an error, not a no-op.

No zero-effort-permissive path exists anywhere in the matrix.

### 1.4 D — Implementable as written: yes

All the machinery the design assembles exists and is reachable as described:
the two apply-site hooks (`daemon.rs:8906-8910`, `:10647-10653`),
`promote_to_permanent_if_over_limit`, `verify_loopback_resolver_live`, the
capture-guard helpers in `macos_dns_sc_protect`, and the test seams
(`DryRunSystem` records every operation into an `operations` vec,
`phase10.rs:1163+`, so T-4/T-5-style "count privileged calls" tests are
writable; note the design's ":7015 RuntimeSystem records calls" citation is
imprecise — `RuntimeSystem` (:6992) is the dispatch enum; the recording seam
is `DryRunSystem.operations`). `dns_resolver_bind_addr` ordering is already
documented at the probe site (`phase10.rs:5306-5310`: the daemon binds the
resolver in its run loop before applying generations).

### 1.5 E — What the design missed (all minor)

1. **The entry hook fires from ~40 call sites, not two.**
   `force_fail_closed_or_restrict` is invoked from bootstrap failures, IPC
   command paths (`ExitNodeOff`, `LanAccessOn`), persist failures, key
   revocation, and reconcile paths. The design describes two wiring sites;
   the hook as placed actually arms from all of them. That is *correct* (the
   invariant is the same and the hook is fail-closed-gated and idempotent),
   but the doc should say so, and the per-tick idempotence must hold even when
   one reconcile pass and an IPC command both trigger it in the same window —
   a per-tick latch (or "already at target posture → skip") prevents
   double-counting `reconcile_failures` toward `restrict_permanent`.
2. **Per-tick observe cost.** While dark, every tick re-runs the floor's
   observe step (service enumeration + per-service reads). Bounded and
   privileged-mutation-free on no-drift (T-5), but worth stating.
3. **`maybe_heartbeat_persist_state` skips while FailClosed** (`daemon.rs:10329`)
   — no interaction with the intent file, but it is the reason the snapshot
   can go stale while the intent does not; worth one sentence.

### 1.6 F — Effort and counts: believable

~3.5 days is credible: the mechanical half reassembles existing reviewed
helpers; the live-lab macOS reboot cell (T-11) is correctly identified as the
long pole. Test names map to real seams. The claim count in §1's problem
statement matched the code on every line we checked (two line-number drifts,
one wrong attribution, none affecting conclusions).

### 1.7 Verdict: BUILD-AS-WRITTEN

No behavioral changes required. Before/during implementation:

- *Docs corrections (non-blocking):* fix the `daemon.rs:9407` attribution
  (signed withdraw lands at `:10752`); fix the "RuntimeSystem records calls
  (:7015)" citation (recording seam is `DryRunSystem.operations`);
  `force_fail_closed` is at `phase10.rs:8120`, not ~8037.
- *Implementation notes (non-blocking):* drop the redundant top-of-tick drift
  hook or document its relation to the entry hook; add the per-tick latch so
  multi-call-site invocation cannot double-count failure accounting.

---

## 2. MembershipTombstoneDesign_2026-09-08

### 2.1 A — Problem statement: TRUE, verified

| Claim | Evidence | Verdict |
| --- | --- | --- |
| Residual gap named and accepted | `OwnerSignerSplitReview_2026-09-08.md` §1.5 (`:37-39`) verbatim: "after an owner-signed `RemoveNode` ... that node's `node_pubkey_hex` (and `node_id`) leave no trace, so a guardian quorum may re-mint the same identity as `{Client}` owner-free." | TRUE |
| 14b174c4 / 8d82ff53 did what they say | Commit messages verified; the pubkey clause scans **only `state.nodes`** (`membership.rs:524-531`), case-insensitively per F1. A removed node's id+key are invisible to it. | TRUE |
| Reducer leaves no trace on remove; rotate forgets the old key | `RemoveNode` is a bare `retain` (`:2202-2210`, with a NotFound guard); `RotateNodeKey` overwrites `node_pubkey_hex` (`:2233-2245`). | TRUE |
| Re-mint of removed identity as `{Client}` is owner-free | `requires_owner_signer` AddNode arm (`:503-528`): caps-unprivileged → no owner requirement; pubkey scan finds nothing (node absent); reducer dup-id check finds nothing (node absent) → quorum alone admits. Re-mint of a removed **key** under a **new** id likewise. | TRUE |
| `apply_signed_update` order as described | `:1108-1152` — validate → network_id → expiry → skew(90s) → `prev_state_root` match → strict epoch+1 → `verify_membership_signatures` → reduce → re-validate → root match → replay cache. | TRUE |
| Schema consts and version sites | `MEMBERSHIP_SCHEMA_VERSION = 1` (:21), `MEMBERSHIP_CLOCK_SKEW_SECS = 90` (:22), `MAX_MEMBERSHIP_NODE_COUNT = 65_536` (:70); five `!= MEMBERSHIP_SCHEMA_VERSION` comparison sites confirmed (:1274, :1857, :1959, :2273, :2394). | TRUE |
| Capabilities precedent | `:2890-2925` — field added without a schema bump; `canonical_payload` always writes it; absence fails closed with the named diagnostic "capabilities are never inferred from roles — re-issue the membership snapshot..."; explicit-empty decodes. | TRUE |
| No duplicate-pubkey-across-live-nodes check in `validate()` | `:196-305` — dup **node_id** rejected, approver-key reuse rejected (`:265-290` region), but node pubkeys are only individually decoded; no cross-node key set. The pubkey overlap guard exists solely in `requires_owner_signer`. | TRUE |
| Review doc line citations | Spot-checked ~20; all matched within a line or two. | TRUE |

### 2.2 B — Chosen option vs rejected alternatives: sound

- The signature model makes the proposed override mechanism coherent. Verified
  model: signers are approvers; `owner_signed` = a signer holds
  `MembershipApproverRole::Owner`; `requires_owner_signer(state) && !owner_signed`
  → `OwnerSignatureRequired` (`membership.rs:1996-2030`). Because
  `requires_owner_signer` already receives `&MembershipState`, extending its
  AddNode arm to scan tombstones is a drop-in: a tombstoned re-add becomes
  owner-required at the single verify choke point (`apply_signed_update` is
  the only caller, `:1137`), a quorum-only attempt is refused before the
  reducer ever runs, and an owner-co-signed update legitimately overrides.
  The design's placement analysis matches the real code.
- Rejected do-nothing: correctly rejected — the residual is real (§2.1), and
  the fix is additive state, not a protocol change.
- Rejected auto-expiry: correctly rejected under the house rule that cut the
  omittable-precondition proposal; an expiry an attacker can wait out is a
  no-check-proceed.
- OD-1 (schema stays 1) is defensible **because the exact mixed-fleet
  consequence already shipped once**: `parse_key_values` (`:2651`) tolerates
  unknown fields, so an old binary loads a tombstone-bearing snapshot
  silently, then refuses the first update via root mismatch — precisely the
  capabilities-field rollout behavior. The design's "fleet refresh one wave"
  mitigation is the same one that worked for capabilities.

### 2.3 C — Fail-closed audit of every new surface: passes, with two pin-points

- **Tombstone section absent** → new parser refuses with a named diagnostic
  (mirrors the capabilities precedent verbatim). Old binaries don't refuse at
  parse — they tolerate the unknown field — but refuse at the first update via
  `PrevStateRootMismatch`/`NewStateRootMismatch`. Fail-closed either way; note
  the old-node refusal is *not* self-explaining ("integrity mismatch", not
  "upgrade required") — that is the accepted cost of OD-1(a) and should be
  written into the rollout note.
- **Malformed row** (bad hex, empty id, unknown authority, duplicate
  (id, pubkey)) → `validate()` rejects the whole state → every update refuses
  on it. Consistent with how validate already fails the world on one bad node.
- **`authority` drafter-claimed vs derived-at-reduce** — deriving from
  `requires_owner_signer` at reduce time is right and matches how the reducer
  already stamps `op_created_at_unix` from the signed record (RSA-0009
  comment, `:2130-2140`): the producer's `new_state_root` reproduces at apply
  time only if derived from signed inputs.
- **`PruneTombstones`** → owner-only, age-bounded, guard consults tombstones
  without an age exemption. Pruning grants quorum nothing (owner needed to
  prune AND to override), so the thesis "the owner is the only actor who can
  ever weaken identity protection" holds.
- **Cap at `MAX_MEMBERSHIP_TOMBSTONE_COUNT`** → refuse removal at cap. There
  is no attacker path to the cap (only signed removals grow it), so the freeze
  is a governance liveness issue, already surfaced as OD-3.

### 2.4 D — Implementable as written: yes, with one trap to pin

See §2.6 (1). Otherwise: single verify choke point, single reducer mutation
site (`.nodes` is mutated nowhere outside `reduce_membership_state` — audited;
all other `.push`/`retain` hits are tests), five known version-comparison
sites, and the deterministic-root contract documented at the reducer.

### 2.5 E — What the design missed

**The operation enum has eight variants, not six.** `MembershipOperation`
(`membership.rs:402-418`) also carries `RotateApprover(MembershipApprover)` and
`SetQuorum { threshold }`, and the design's §2 reducer enumeration and §4.2
guard table omit both. Verified: **no hole results** — both are already
unconditionally owner-required (`requires_owner_signer`, `:491-495`), and
neither mutates node identity, so both are correctly outside tombstone scope.
But a design that argues "the owner is the only actor who can weaken
identity protection" must say why the *approver-set* mutators don't threaten
that claim (answer: they cannot be quorum-driven), and the reducer table
should enumerate all eight arms so the next reader does not re-audit them.
Docs fix, cheap, should land with the design.

### 2.6 F — Effort and counts: believable; changes required

~3.5 days is credible. The fixture-claim checks out directionally: `state_root`
appears 144 times in `membership.rs` alone, plus 78 in `rustynet-cli/src/main.rs`
and 49 in `rustynetd/src/daemon.rs`; re-minting hardcoded roots is plausibly
the bulk of the mechanical half.

Changes:

1. **(Blocking-to-verify at merge, zero design change)** —
   `requires_owner_signer` ends in a `_ => false` catch-all (`:541-543`). A
   new `PruneTombstones` variant will **silently match that arm** and be
   quorum-sufficient unless an explicit `PruneTombstones(_) => true` arm is
   added — Rust will not flag it, because the match is exhaustive via `_`.
   The design's `prune_tombstones_requires_owner` test kills exactly this
   mutation, so the requirement is: that test must be written first and must
   fail on the catch-all-only implementation before the explicit arm lands.
   Recommend the design doc call this trap out by name so it is not
   rediscovered.
2. **(Non-blocking, docs)** — enumerate `RotateApprover`/`SetQuorum` in §2/§4.2
   with the one-line exclusion rationale (§2.5).
3. **(Non-blocking, docs)** — correct "six reducers" to eight arms; note the
   old-node mixed-fleet refusal surfaces as a root-mismatch integrity error,
   not a named upgrade diagnostic (§2.3).

### 2.7 Verdict: BUILD-WITH-CHANGES

The design is correct, honest about its break (§4.3 is one of the more
forthcoming signed-state migration write-ups this repo has), and its
owner-override architecture matches the verified signature model. The changes
above are a merge-gate on one test (1) and two documentation corrections (2-3).
No re-architecture required.

---

## 3. Cross-cutting notes

- Both designs follow the repo's strongest recent pattern: refuse-and-name at
  parse/validate, derive authority from signed inputs at reduce/apply time,
  and pin every contemplated shortcut with a mutation-killing test that names
  the shortcut. Both test lists are concrete and mapped to real seams.
- Both designs' residual-risk sections disclose real weaknesses rather than
  claiming coverage (D-3 both-sources-deleted; OD-1 no rolling upgrade) —
  consistent with how the capabilities precedent and the QH-40 marker were
  landed.
- Verification lineage: every table row above was checked against the working
  tree in this session; where a design citation drifted (phase10 `8037`→`8120`,
  `daemon.rs:9407` attribution, "RuntimeSystem records calls"), the drift is
  recorded rather than silently corrected in place.
