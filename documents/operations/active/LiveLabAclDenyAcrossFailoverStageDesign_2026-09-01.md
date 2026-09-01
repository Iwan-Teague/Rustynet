# Live-Lab Stage Design: ACL Deny Re-Probe Across Failover / Failback (GAP-3)

**Date:** 2026-09-01
**Status:** DESIGN ONLY — no code changed. If a stage is warranted (the grounding below says it is), it is owner-gated stage work pending (a) this design's separate adversarial review and (b) live-lab availability (the lab VMs are currently DOWN, so live-proving is explicitly pending; nothing here is claimed as live-proven).
**Scope:** GAP-3 from the coverage-gap hunt — re-probing ACL denied pairs across failover/failback path transitions. This doc re-grounds the claim against the real code rather than trusting the hunt doc (which misread GAP-2).

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

- `crates/rustynetd/src/daemon.rs` `policy_gate_auto_tunnel` (lines 5368–5431): for every peer and every route in an applied auto-tunnel bundle, the daemon evaluates `policy.evaluate_with_membership` on the route's destination CIDR **and its `via` node** (lines 5393–5427), with the traffic context derived from the route kind — `RouteKind::Mesh` → `TrafficContext::Mesh`, exit routes → `TrafficContext::SharedExit` (lines 5394–5397). Any non-`Allow` aborts the bundle (`PolicyDenied`, lines 5385–5390, 5407–5412, 5422–5427).
- `crates/rustynet-policy/src/lib.rs` is default-deny throughout (terminal default-deny on no rule match; empty set denies everything; explicit deny wins — pinned by the unit tests at lines 1063, 2015–2051, 1211, and the daemon truth-table audit `crates/rustynetd/src/policy_default_deny_audit.rs` which drives the real evaluator).

Consequence: the deny decision is a function of the **route spec in the signed bundle** (destination + via node + context). When a path transitions — relay→direct failback, endpoint roam — the client installs a *new* bundle whose route spec names a different `via` node and context. The evaluator is re-run on the new spec, so a deny is not "attached" to the old path in the evaluator's sense. **But two things make the transition a genuine unproven seam:**

1. The nftables ACL surface and the WireGuard peer allowlist are re-derived from the new bundle's allow spec. `failback_roaming.rs` `reissue_for_roam` (lines 580–735) rewrites the allow spec and assignments mid-scenario — it keeps **all six directed pairs allowed** (lines 620–630) by design — and asserts afterwards that traffic flows (`endpoint_roam_recovery_success`) and does not leak. It never asserts that a **denied** pair stayed denied through the re-derivation. If the re-derivation dropped or over-broadened the ACL (the exact class the revoked-peer audit guards at steady state), this scenario would pass while the control lapsed.
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

**How a denied pair is created:** the scenario currently allows all six directed pairs among three nodes. The stage introduces a fourth lab node (a second client, `client-2`) whose allow spec deliberately omits its pair toward the exit (`AllowSpec` without `allow(client2, exit)` / `allow(exit, client2)`), and whose assignment names no exit. The denied pair is then a real mesh peer pair: `client-2 → exit` must be blocked by policy before, during, and after every transition the scenario performs. The probe mechanism is the existing adapter surface (`ping_mesh_peer` / `probe_denied_peer` style — the stage adds a pair-targeted probe to the scenario host trait rather than reusing the TEST-NET-2 non-routable probe, since the point is a *routable-but-denied* peer).

**Attribution rule (fail-closed, mirroring `traffic_test_matrix.rs:180–186`):** a `Blocked` result counts only when the allowed control pair proved `Reachable` in the same sampling window; otherwise the result is `INCONCLUSIVE` and **fails the stage**. A probe error is `INCONCLUSIVE` and fails. `Reachable` on the denied pair is a `VIOLATED` failure.

### 2.2 Where it plugs in

**Extend `cross_network/scenario/failback_roaming.rs`** — preferred, for three reasons:

- It already owns the transition machinery: `reissue_for_roam` (the mid-run signed-state rewrite) and the `monitor_failback` sampling loop, which is the natural place to fold in per-sample pair probes without adding a new orchestration stage, stage registry entry, or dependency edge.
- The transition it creates is the *only* place the lapse could occur; a standalone stage running after the scenario would measure a settled state and miss the seam.
- Extending `traffic_test_matrix.rs` instead would be wrong: it is a one-shot early steady-state stage (`dependencies() = [ValidateBaselineRuntime]`, lines 16–18) whose wiring has no notion of transitions; repurposing it would entangle the whole-run baseline with one scenario's needs.

Concretely: `FailbackObservation` gains denied/control sample counters alongside `underlay_leak_samples` / `signed_state_invalid_samples`; `CHECKS` gains the three new names; the `execute` verdict block records them from the counters; `reissue_for_roam` (or the post-roam evidence phase) performs one final probe round after `POST_ADVERTISE_SETTLE`. The LAB VMs ARE DOWN, so this stage cannot be live-proven now — it is owner-gated work pending lab availability, and until then its only execution is the offline decision-logic tests below.

### 2.3 FAIL-LOUD contract

- No skip, dry-run, or absent-evidence path can produce a pass: a missing probe result is a stage failure naming the missing evidence, same convention as `no adapter; cannot run default-deny negative test (failing closed)` (`traffic_test_matrix.rs:200–202`).
- `INCONCLUSIVE` is a failure, never a soft pass (§2.1 attribution rule).
- The scenario's report carries the raw per-sample probe transcript (mirroring `MONITOR_LOG_FILE`) so a pass claim can be re-verified from the artifact, not just the check column.

### 2.4 Offline validator unit tests (no lab required)

Pure decision logic extracted as a small evaluator (inputs: probe results + control result per window; output: check verdicts), unit-tested in `#[cfg(test)]`:

1. `denied_blocked_with_reachable_control_passes` — `Blocked` + control `Reachable` → pass.
2. `denied_blocked_without_control_is_inconclusive_and_fails` — `Blocked` with no reachable control → fail (vacuous-deny guard).
3. `denied_reachable_fails_loudly` — `Reachable` on the denied pair → `VIOLATED` failure even with control `Reachable`.
4. `probe_error_is_inconclusive_and_fails` — any error variant → failure.
5. `missing_window_fails` — a transition with no probe samples recorded → failure (fail-loud, no vacuous pass).
6. `every_transition_sampled_not_just_the_first` — counters accumulate across all samples/iterations, mirroring `every_leaking_sample_is_counted_not_just_the_first` (`failback_roaming.rs:856–867`).
7. `checker_names_declared_and_aggregated` — the new check names appear in `CHECKS` and are covered by the aggregate, mirroring `the_failback_aggregate_covers_its_three_sampled_checks` (`failback_roaming.rs:952–966`).

---

## 3. Explicit non-claims

- No code is changed by this document. No stage exists yet.
- Nothing here is live-proven. The lab VMs are down; the live-proving step is explicitly pending lab availability and is a hard requirement before any pass can be recorded in `documents/operations/live_lab_node_run_matrix.csv`.
- This design does not weaken any existing check: all current `failback_roaming` checks and all `traffic_test_matrix` fail-closed semantics are preserved unchanged.
- The hunt doc's GAP-2 misread is a reminder, not evidence: GAP-3 was re-derived above from the cited sources directly. The corrected details (§1.2, §1.3) supersede the hunt doc's phrasing.
