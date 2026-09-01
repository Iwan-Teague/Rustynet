# Live-Lab Stage Design: ACL Deny Re-Probe Across Failover / Failback (GAP-3)

**Date:** 2026-09-01
**Status:** DESIGN ONLY, adversarial review COMPLETE — amended per review verdict READY-WITH-AMENDMENTS (A1–A8 folded below). No code changed. Implementation is owner-gated stage work pending live-lab availability (the lab VMs are currently DOWN, so live-proving is explicitly pending; nothing here is claimed as live-proven).
**Scope:** GAP-3 from the coverage-gap hunt — re-probing ACL denied pairs across failover/failback path transitions. This doc re-grounds the claim against the real code rather than trusting the hunt doc (which misread GAP-2).

> **Adversarial-review amendments folded (2026-09-01)** — from `LiveLabAclDenyAcrossFailoverStageAdversarialReview_2026-09-01.md` §8:
> - **A1 — explicit verdict gates.** §2.2 now specifies verbatim the `if !checks.passed("<name>")` arms appended to `execute`'s verdict chain, and states that `ScenarioOutcome::passed(checks)` aggregates nothing and `record` on an undeclared name silently appends.
> - **A2 — window semantics.** §2.1 attribution rule reworked: mid-transition samples with an unreachable control are expected-inconclusive and recorded, not failing; `Reachable` on the denied pair is VIOLATED unconditionally; each post-transition settled window must contain ≥1 attributed pass; every window sampled or the stage fails.
> - **A3 — fourth-node integration.** §2.2 specifies which early stages `client-2` joins via `ctx.assignments` and how `traffic_test_matrix`'s positive-probe loop learns `client-2 → exit` is expected-blocked (per-pair expectation map keyed on the allow spec), with the stage-order citation (traffic_test_matrix runs at `plan.rs:882`, before the failback scenario at `:909`).
> - **A4 — mechanism narration.** The asserted property is renamed: not "routable-but-denied" (an evaluator verdict) but **"the re-derived generation excludes the absent pair"** — enforcement absence (no WG peer entry, no route), since the policy gate is all-or-nothing per bundle and re-runs every reconcile tick; the "nftables ACL surface" phrase is qualified (there is no per-pair nft ACL generation).
> - **A5 — probe surface.** The existing adapter surface cannot express a pair-targeted probe: `probe_denied_peer` maps any ping failure to `Blocked` on every platform, and `ping_mesh_peer` never returns `Blocked` on Linux. §2.1 specifies the new probe result shape (`Blocked`/`Reachable`/`Error`) and the control-`Error` ⇒ inconclusive mapping.
> - **A6 — timing/alias budget.** §2.2 states the effective sampling period with the probe commands inline, moves the pair probes out of the SLO-critical in-loop path, and adds `client-2`'s address to the `choose_alias` avoid list.
> - **A7 — artifact completeness.** §2.3 requires the new counters and per-window probe outcomes to land in the SLO summary artifact, matching §2.3's own report promise.
> - **A8 — survey corrections.** Negative-probe precedent citation corrected to `probe_service_blocked_from_client` (BYPASS_CHECKS mode; the in-family negative-probe and missing-evidence fail-closed convention source); citation drift fixed (policy gate `daemon.rs:5400–5463`; empty-set test `rustynet-policy/src/lib.rs:1075`).
> - Offline test 3 drops its control precondition (A2); new window-semantics tests added (§2.4).

---

## 1. Grounding verdict: CONFIRMED (with two corrections)

The core GAP-3 claim is **CONFIRMED**: no stage re-probes ACL/policy denied pairs after a failover or failback path transition. Two claims in the hunt doc needed correction and are corrected below.

### 1.1 What `cross_network_failback_roaming` asserts after failback

`crates/rustynet-cli/src/vm_lab/orchestrator/stage/cross_network/scenario/failback_roaming.rs` — after the relay→direct failback, the scenario records exactly four checks (`execute`, lines 292–312):

- `failback_reconnect_within_slo` (lines 292–300): `baseline_ok && topology_distinct && reconvergence_secs within 0..=slo`.
- `no_underlay_leak_while_reconnecting` (lines 301–304): `failback.underlay_leak_samples == 0`.
- `signed_state_valid_while_reconnecting` (lines 305–308): `failback.signed_state_invalid_samples == 0`.
- `relay_to_direct_failback_success` (lines 309–312): aggregate of the three above via `checks.all_passed(FAILBACK_CHECKS)` (`FAILBACK_CHECKS`, lines 94–98).

The post-roam half adds `endpoint_roam_recovery_success` (lines 381–388) and `remote_exit_no_underlay_leak` (line 413, the only verdict consumed from the server-IP bypass validator).

**No check in the file probes an ACL/policy denied pair.** `CHECKS` (lines 83–91) names all seven; none is an ACL denial probe. The monitoring loop `monitor_failback` (lines 497–553) samples only route/status/endpoints/netcheck; the grep for `deny|acl|policy` in the file returns nothing outside comments. The hunt doc's claim is accurate here.

### 1.2 Correction 1: the "default-deny negative probes" are not pair probes

`crates/rustynet-cli/src/vm_lab/orchestrator/stage/traffic_test_matrix.rs` lines 164–203: the negative probe is a **single never-routable TEST-NET-2 address** (`denied_ip = "198.51.100.1"`, line 173) probed once per source node via `probe_denied_peer` (lines 174–178). It validates the global default-deny posture (an unroutable destination must be unreachable), not an ACL deny between two real mesh peers. The fail-closed strings are exactly as claimed: `default-deny VIOLATED` (line 190), `default-deny INCONCLUSIVE` (lines 182, 195 — including the probe-errored case), and `no adapter; cannot run default-deny negative test (failing closed)` (line 201), plus the `src_reached_peer` attribution gate (lines 108–115, 180–186): a `Blocked` result only counts when the same node proved baseline reachability, otherwise it is inconclusive and fails the stage.

**When it runs: steady state only.** The stage's `dependencies()` is `&[StageId::ValidateBaselineRuntime]` (lines 16–18) and it executes exactly once, early in the run, before any role-switch, exit-handoff, roam, or failback scenario executes. Nothing re-runs it after a path transition.

### 1.3 Correction 2: the live pair-level denial proof exists but is steady-state too

The nearest thing to a live denied-**pair** proof is the revoked-peer battery: `rustynetd revoked-peer-denied-audit` (`crates/rustynetd/src/revoked_peer_denied_audit.rs`), evaluated orchestrator-side by the pure evaluator at `crates/rustynet-cli/src/vm_lab/mod.rs:20598–20651` (fails closed: vacuous gate, wrong case count, or over-broad allow all error out). It proves live denial for revoked peers (exit-node and LAN-route cases) with active-peer baselines still allowed — but it runs in the security-audit role-validation chain (`crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/security_audit.rs:50,300`) at steady state, against a static membership snapshot. It is never re-run after a path transition, and it tests *revocation*, not a *deny rule that survives a path change*.

### 1.4 Whether a path change can lapse a deny — the mechanism

Policy is enforced at **signed-bundle application time**, not continuously per packet path:

- `crates/rustynetd/src/daemon.rs` `policy_gate_auto_tunnel` (lines 5400–5463): for every peer and every route in an applied auto-tunnel bundle, the daemon evaluates `policy.evaluate_with_membership` on the route's destination CIDR **and its `via` node** (lines 5393–5427), with the traffic context derived from the route kind — `RouteKind::Mesh` → `TrafficContext::Mesh`, exit routes → `TrafficContext::SharedExit` (lines 5394–5397). Any non-`Allow` aborts the bundle (`PolicyDenied`, lines 5385–5390, 5407–5412, 5422–5427). The gate is **all-or-nothing per bundle**: one `PolicyDenied` aborts the whole application, and the daemon then restricts fail-closed (`daemon.rs:10326–10339`) — it never applies a partially-allowed bundle. The gate re-runs on **every reconcile tick**, so the evaluator verdict tracks the newest bundle spec, not the path that carried it.
- `crates/rustynet-policy/src/lib.rs` is default-deny throughout (terminal default-deny on no rule match; empty set denies everything — pinned by the unit tests at lines 1075, 2015–2051, 1211, and the daemon truth-table audit `crates/rustynetd/src/policy_default_deny_audit.rs` which drives the real evaluator).

Consequence: the deny decision is a function of the **route spec in the signed bundle** (destination + via node + context). When a path transitions — relay→direct failback, endpoint roam — the client installs a *new* bundle whose route spec names a different `via` node and context. The evaluator is re-run on the new spec, so a deny is not "attached" to the old path in the evaluator's sense. **But two things make the transition a genuine unproven seam:**

1. The nftables ruleset and the WireGuard peer allowlist are **re-derived from the new bundle's allow spec** (this is generation replacement, not a per-pair nft ACL surface — the daemon derives no per-pair nft ACL entries; the enforcement is the WG peer list + routes). `failback_roaming.rs` `reissue_for_roam` (lines 580–735) rewrites the allow spec and assignments mid-scenario — it keeps **all six directed pairs allowed** (lines 620–630) by design — and asserts afterwards that traffic flows (`endpoint_roam_recovery_success`) and does not leak. It never asserts that a **denied** pair stayed excluded through the re-derivation. If the re-derivation dropped or over-broadened the allow spec (the exact class the revoked-peer audit guards at steady state), this scenario would pass while the control lapsed.
2. The evaluator gate is on the bundle's *spec*; the live enforcement is the derived nft/peer state. Only a live probe of a denied pair after the transition observes the enforcement surface itself. No stage does this after `reissue_for_roam` or after any failover.

So GAP-3 stands: the seam is real, and it is the scenario's *own* mid-run signed-state rewrite that creates it. A stage is warranted.

---

## 2. Stage design

### 2.1 What it asserts

New scenario-level checks, re-run the denied-pair probes **immediately after each failover AND after each failback/roam completion**:

1. **`acl_denied_pair_blocked_after_failover`** — after every path transition (each relay→direct switch, each endpoint roam), probe the denied pair. Expected: `Blocked`.
2. **`acl_denied_pair_blocked_after_failback`** — same probe after the failback reconverges. Expected: `Blocked`.
3. **`acl_allowed_pair_control_reachable`** — the control: an explicitly allowed pair must be `Reachable` at each of those same moments. Without it, a `Blocked` denied pair is indistinguishable from a dead data path (the exact vacuous-deny fake-pass the `src_reached_peer` gate in `traffic_test_matrix.rs:108–115` guards).
4. Existing checks are unchanged and still gate; the new checks join the verdict.

**How a denied pair is created:** the scenario currently allows all six directed pairs among three nodes. The stage introduces a fourth lab node (a second client, `client-2`) whose allow spec deliberately omits its pair toward the exit (`AllowSpec` without `allow(client2, exit)` / `allow(exit, client2)`), and whose assignment names no exit. The denied pair is then a real mesh peer pair: `client-2 → exit` must be blocked by policy before, during, and after every transition the scenario performs.

**What the stage asserts — enforcement absence, not an evaluator verdict (amendment A4).** Because the policy gate is all-or-nothing per bundle and re-runs every reconcile tick (§1.4), a policy-level "routable-but-denied" phrasing would be wrong: the evaluator never attaches a deny to a path. The asserted property is **"the re-derived generation excludes the absent pair"** — after every transition, the newly derived generation contains **no WireGuard peer entry and no route** for the denied pair (`daemon.rs:14159–14229` derives peer/route state from the applied bundle; `daemon.rs:10345–10370` replaces the whole generation per apply — the QH-04 comment). The live probe is how that absence is observed: if the exclusion lapsed, traffic would flow; if it held, the pair is unreachable *because the pair does not exist in the enforced generation*.

**Probe surface (amendment A5).** The existing adapter traffic surface cannot express this probe as-is:
- `probe_denied_peer` (Linux `linux_traffic.rs:458–471`; Windows `windows_traffic.rs:133–147`; macOS `macos_traffic.rs:363–376`) maps **any** ping failure to `Blocked` — it cannot distinguish a policy exclusion from a dead data path, which is exactly the confusion the control pair exists to prevent.
- `ping_mesh_peer` never returns `Blocked` on Linux (`linux_traffic.rs:446–453`) — it reports reachable/unreachable only.

The stage therefore adds a **pair-targeted probe to the scenario host trait** with a three-state result shape, not a reuse of either existing call:

- `PairProbeResult::Blocked` — probe traffic to the denied peer failed **while the control pair on the same node is known-`Reachable`** in the same window (attribution carried with the result, not inferred later);
- `PairProbeResult::Reachable` — probe traffic reached the denied peer;
- `PairProbeResult::Error` — the probe command itself failed to run (adapter absent, host error).

Mapping rule: a control `Error` ⇒ the window's denied result is downgraded to inconclusive (§2.1 attribution below); a probe `Error` ⇒ inconclusive and failing per the FAIL-LOUD contract. The in-family precedent for a deliberate negative probe with fail-closed missing-evidence handling is `probe_service_blocked_from_client` (BYPASS_CHECKS mode, `remote_exit_common.rs:23–28`; consumed by `failback_roaming.rs:394–413`; its missing-evidence convention is `remote_exit_common.rs:118–120`) — amendment A8.

**Attribution rule and window semantics (fail-closed, amending the pre-review rule per A2):** the pre-review rule ("`Blocked` counts only when the control is `Reachable` in the same sampling window, else `INCONCLUSIVE` and fails") conflated two sample classes and would fail the stage on expected mid-transition noise. Amended semantics:

1. **Mid-transition samples are expected-inconclusive and recorded, not failing.** While a transition is in flight (reconvergence underway, control pair not yet back), a denied-pair result without a reachable control is recorded as an attributed-inconclusive sample in the window transcript and does not fail the stage.
2. **`Reachable` on the denied pair is `VIOLATED` — unconditionally.** No control precondition softens this: if probe traffic reaches the denied peer, the exclusion lapsed, whatever the control state. (Offline test 3 asserts exactly this with no control attached.)
3. **Each post-transition settled window must contain ≥1 attributed pass.** A *settled window* is the final probe round after `POST_ADVERTISE_SETTLE` and the post-failback settled point. Each such window must contain at least one `Blocked` denied result with a `Reachable` control in the same window. A settled window containing only inconclusive samples fails the stage — a deny that cannot be positively attributed after the transition has settled is not a proven deny.
4. **Every window is sampled or the stage fails.** A transition with no probe samples recorded is a failure (missing evidence, never vacuous pass).

### 2.2 Where it plugs in

**Extend `cross_network/scenario/failback_roaming.rs`** — preferred, for three reasons:

- It already owns the transition machinery: `reissue_for_roam` (the mid-run signed-state rewrite) and the `monitor_failback` sampling loop, which is the natural place to fold in per-sample pair probes without adding a new orchestration stage, stage registry entry, or dependency edge.
- The transition it creates is the *only* place the lapse could occur; a standalone stage running after the scenario would measure a settled state and miss the seam.
- Extending `traffic_test_matrix.rs` instead would be wrong: it is a one-shot early steady-state stage (`dependencies() = [ValidateBaselineRuntime]`, lines 16–18) whose wiring has no notion of transitions; repurposing it would entangle the whole-run baseline with one scenario's needs.

Concretely: `FailbackObservation` gains denied/control sample counters alongside `underlay_leak_samples` / `signed_state_invalid_samples`; `CHECKS` gains the three new names; the `execute` verdict block records them from the counters; `reissue_for_roam` (or the post-roam evidence phase) performs one final probe round after `POST_ADVERTISE_SETTLE`. The LAB VMs ARE DOWN, so this stage cannot be live-proven now — it is owner-gated work pending lab availability, and until then its only execution is the offline decision-logic tests below.

**Fourth-node (`client-2`) integration (amendment A3).** `client-2` must exist before the scenario's own early dependencies run, so the bundle that excludes its exit pair is in force from the first probe onward:

- **Join point:** `client-2` joins via `ctx.assignments` in the same early setup stages that create the existing three-node membership — i.e. it is assigned in the mesh-setup/assignment stages before `ValidateBaselineRuntime` and before `traffic_test_matrix` executes, so both the baseline validators and the scenario see a four-node mesh with one deliberately-excluded pair.
- **Teaching `traffic_test_matrix` the new pair:** the stage's positive-probe loop (`traffic_test_matrix.rs:27` builds the pair set; `:101–161` runs the probes; `:151–155` consumes per-pair outcomes) currently assumes every mesh pair is expected-reachable. It gains a **per-pair expectation map keyed on the allow spec**: a pair absent from the allow spec (here `client-2 → exit`) is expected-`Blocked`, so the loop records a `Blocked` there as pass-shaped evidence rather than a positive-probe failure. Without this map the baseline stage would fail on the very pair GAP-3 introduces — or worse, force the scenario to over-broaden the allow spec to keep the baseline green.
- **Ordering guarantee:** the stage order in `plan.rs` places `traffic_test_matrix` at line 882, before the failback scenario registration at line 909, so the expectation map is in force before the scenario's transitions run.

**Verdict gates are explicit, per-check `if !checks.passed(...)` arms (amendment A1).** The `execute` verdict block does NOT rely on the aggregate: `ScenarioOutcome::passed(checks)` aggregates nothing (`cross_network/scenario/mod.rs:222–231`), and `checks.record(...)` on a name absent from the declaration list **silently appends** without failing (`mod.rs:125–135`) — so an undeclared or unrecorded new check would pass vacuously. The verdict chain therefore gains three explicit arms, mirroring the existing per-check style:

```rust
if !checks.passed("acl_denied_pair_blocked_after_failover") {
    outcome.fail(format!(
        "acl_denied_pair_blocked_after_failover: {}",
        checks.summary("acl_denied_pair_blocked_after_failover")
    ));
}
if !checks.passed("acl_denied_pair_blocked_after_failback") { /* same shape */ }
if !checks.passed("acl_allowed_pair_control_reachable") { /* same shape */ }
```

(each with its own per-check failure summary naming the exact failed check; the sketch shows the shape, all three arms are written out in full in implementation). The declare/aggregate test pattern (`the_failback_aggregate_covers_its_three_sampled_checks`, `failback_roaming.rs:952–966`) is extended to assert the three new names are declared in `CHECKS`, recorded, and each covered by an explicit verdict arm — so a future rename that breaks the `record`/declaration pairing fails offline instead of silently passing.

**Timing and alias budget (amendment A6).** The probes are not free at the sampling cadence:

- Base sampling period in `monitor_failback` is 1 s (`endpoint_switch.rs:240`); the denied-pair probe (`ping -c 1 -W 2` — 2 s worst case) and control probe (`ping -c 3 -W 5` — 15 s worst case) inflate the effective per-window period by up to ~17 s when run inline every sample.
- The pair probes therefore run **out of the SLO-critical in-loop path**: the in-loop `failback_reconnect_within_slo` measurement keeps its existing cadence untouched, and the denied/control probes run on their own slower cadence (and once more in the settled windows), so the SLO baseline is not silently re-baselined by probe cost. If implementation instead folds them into the in-loop path, the `failback_reconnect_within_slo` baseline MUST be re-measured and re-pinned in the same change — one of the two, never an unmeasured interaction.
- `client-2`'s address is added to the `choose_alias` avoid list (`failback_roaming.rs:332–339`) so probe alias resolution never lands on the injected fourth node.

### 2.3 FAIL-LOUD contract

- No skip, dry-run, or absent-evidence path can produce a pass: a missing probe result is a stage failure naming the missing evidence, same convention as `no adapter; cannot run default-deny negative test (failing closed)` (`traffic_test_matrix.rs:200–202`).
- `INCONCLUSIVE` is a failure, never a soft pass (§2.1 attribution rule).
- The scenario's report carries the raw per-sample probe transcript (mirroring `MONITOR_LOG_FILE`) so a pass claim can be re-verified from the artifact, not just the check column.
- **Artifact completeness (amendment A7):** the new counters and **per-window probe outcomes** (each window's denied result, control result, settled/in-flight classification, and attribution verdict) are added to the SLO summary artifact (`failback_roaming.rs:763–783`) — not just the scenario log — so the report's own §2.3 promise is met by the machine-readable summary, and a re-verifier can reconstruct every window verdict from the artifact alone.

### 2.4 Offline validator unit tests (no lab required)

Pure decision logic extracted as a small evaluator (inputs: probe results + control result per window; output: check verdicts), unit-tested in `#[cfg(test)]`:

1. `denied_blocked_with_reachable_control_passes` — `Blocked` + control `Reachable` → pass.
2. `denied_blocked_without_control_is_inconclusive_and_fails` — `Blocked` with no reachable control → fail (vacuous-deny guard) **in a settled window**; in a mid-transition window it is recorded as attributed-inconclusive without failing (A2 window semantics, item 1).
3. `denied_reachable_fails_loudly` — `Reachable` on the denied pair → `VIOLATED` failure **unconditionally — no control precondition attached** (A2 item 2: the control exists to catch vacuous denies, never to soften a lapse).
4. `probe_error_is_inconclusive_and_fails` — any error variant → failure.
5. `missing_window_fails` — a transition with no probe samples recorded → failure (fail-loud, no vacuous pass).
6. `every_transition_sampled_not_just_the_first` — counters accumulate across all samples/iterations, mirroring `every_leaking_sample_is_counted_not_just_the_first` (`failback_roaming.rs:856–867`).
7. `checker_names_declared_and_aggregated` — the new check names appear in `CHECKS`, are covered by the aggregate, and each has an explicit verdict arm, mirroring `the_failback_aggregate_covers_its_three_sampled_checks` (`failback_roaming.rs:952–966`) and guarding the silent-append hazard (`mod.rs:125–135`) per A1.
8. `settled_window_without_attributed_pass_fails` (A2 item 3) — a settled window (post-`POST_ADVERTISE_SETTLE` round or post-failback settled point) containing only attributed-inconclusive samples → failure; the same window with one `Blocked`+`Reachable`-control pass → pass.
9. `mid_transition_inconclusive_recorded_not_failing` (A2 item 1) — during an in-flight transition, inconclusive samples accumulate in the window transcript without failing, and are visible in the report artifact.
10. `control_error_downgrades_window_to_inconclusive` (A5 mapping) — a control `Error` downgrades the same window's denied result to attributed-inconclusive (settled-window rule then decides pass/fail per test 8).

---

## 3. Explicit non-claims

- No code is changed by this document. No stage exists yet.
- Nothing here is live-proven. The lab VMs are down; the live-proving step is explicitly pending lab availability and is a hard requirement before any pass can be recorded in `documents/operations/live_lab_node_run_matrix.csv`.
- This design does not weaken any existing check: all current `failback_roaming` checks and all `traffic_test_matrix` fail-closed semantics are preserved unchanged.
- The hunt doc's GAP-2 misread is a reminder, not evidence: GAP-3 was re-derived above from the cited sources directly. The corrected details (§1.2, §1.3) supersede the hunt doc's phrasing.
