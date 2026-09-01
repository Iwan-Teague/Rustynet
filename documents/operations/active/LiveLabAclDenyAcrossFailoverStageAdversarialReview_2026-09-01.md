# Adversarial Review: GAP-3 ACL-Deny-Across-Failover Stage Design

**Date:** 2026-09-01
**Subject:** Independent adversarial review of `LiveLabAclDenyAcrossFailoverStageDesign_2026-09-01.md` (owner decree: every recommended design gets an adversarial review before impl).
**Method:** every design claim re-verified against the cited code in this tree; each attack below ends in either CONFIRMED-SAFE (with the mechanism cited) or RISK (failure scenario + amendment). Line numbers are from this worktree and were re-verified, not copied from the design doc; where the design's own citations drifted, the corrected numbers are given.
**Reviewer posture:** the hunt doc already misread GAP-2 once; every grounding claim below was re-derived from source, including claims the design got right.

---

## 1. Attack 1 — Is GAP-3 actually uncovered?

**Verdict: CONFIRMED, with one survey omission and one sharpening.**

Re-verified uncovered:

- `failback_roaming.rs` — the `CHECKS` list (lines 83–91) names seven checks; `FAILBACK_CHECKS` (94–98) aggregates three. The verdict block (`execute`, lines 292–312) records only SLO/leak/signed-state; `endpoint_roam_recovery_success` (381–388) and `remote_exit_no_underlay_leak` (413) complete the set. `monitor_failback` (497–553) samples `status` / `ip route get` / `wg show endpoints` / `netcheck` only. No denied-pair probe anywhere in the file. The design's §1.1 is accurate.
- `traffic_test_matrix.rs` — `dependencies()` = `&[StageId::ValidateBaselineRuntime]` (16–18); the stage order (`plan.rs:860–918`) places `TrafficTestMatrix` at line 882, after `RelayValidation`, before `RoleSwitchMatrix` (883) and all `CrossNetwork*` stages (905–916) — so it runs exactly once in steady state, before any transition. The negative probe is the never-routable TEST-NET-2 address `198.51.100.1` (line 173) via `probe_denied_peer` (174–178) with the `src_reached_peer` attribution gate (108–115, 180–186). The design's §1.2 is accurate.
- The revoked-peer battery — `evaluate_revoked_peer_denied_report` (`vm_lab/mod.rs:20598–20654`; design cited 20598–20651, close enough) is a **fixed 2-revoked + 2-active internal controller battery** (`total_cases < 4`, `revoked_denied < 2`, `active_allowed < 2` all fail closed, 20616–20633), dispatched from the security-audit chain (`security_audit.rs:49–51` battery entry, `:300` dispatch). Because the case set is fixed (it drives `Phase10Controller::set_exit_node` / `ensure_lan_route_allowed` in-process, not live lab topology), **adding a 4th node does not disturb it** — a question this review raised and the code answers. It is never re-run after a transition. The design's §1.3 is accurate.

**Survey omission (correction to the design, not the verdict):** the design's §1 survey misses `probe_service_blocked_from_client` — a member of `BYPASS_CHECKS` (`remote_exit_common.rs:23–28`) whose verdict *is consumed inside this very scenario* post-roam (`bypass_verdicts`, remote_exit_common.rs:45–51; `failback_roaming.rs:394–413`). It is a live negative-reachability probe with a paired positive (`internet_route_via_rustynet0`), run across the transition, with a fail-closed missing-evidence convention (`run_bypass_validator`, remote_exit_common.rs:118–120: validator failed + no report ⇒ `Err`). It does **not** close GAP-3 — it probes underlay *bypass containment* (client must not reach the exit's server IP around the tunnel), not a mesh-pair ACL deny — but it is the in-family precedent the new probes should mirror, and the design should cite it rather than imply the scenario carries zero negative probes. Similarly, `traversal_adversarial`'s blocked probes (`traversal_adversarial.rs:79,92` — `remote_underlay_dns_probe_blocked`, `control_surface_exposure_blocked`) are control-surface exposure checks, not pair ACL.

**Sharpening:** GAP-3 as stated is confirmed — no stage re-probes an ACL **pair** after a transition. But see Attack 2 below: the design's "routable-but-denied" framing is wrong for the enforcement model this codebase actually uses, and that changes what the probe proves.

---

## 2. Attack 2 — The 4th-node (client-2 denied→exit) approach

### 2.1 "Routable-but-denied" is not the state this codebase can produce

**RISK (mechanism mischaracterization; probe still salvageable).**

The design (§2.1) claims the denied pair is "a real mesh peer pair: `client-2 → exit` must be blocked by policy" and calls it *routable-but-denied*. The code says otherwise:

- The lab's `ALLOW_SPEC` (directed `from|to` pairs, `provisioning.rs:306`) drives what becomes a peer + mesh route in the signed assignment bundle. The daemon's validation comment states it directly: "every policy-allowed peer becomes a `mesh` route to its own assigned cidr" (`daemon.rs:14159–14164`), and every peer `allowed_ip` **must** have a matching signed route (`daemon.rs:14181–14190`), with one claim per mesh host (`claimed_mesh_hosts`, 14216–14221).
- Omitting `allow(client2, exit)` from the allow spec therefore means client-2↔exit is **absent** from the bundle spec: no WG peer entry (cryptokey routing drops the traffic), no route. The pair is enforcement-absent — unroutable — which is the *same class* the design itself dismisses in §1.2 for TEST-NET-2.
- The alternative — keep the route and deny it at `policy_gate_auto_tunnel` — is structurally impossible as a per-pair state: the gate is all-or-nothing. Any non-`Allow` on a peer (5407–5423), route destination (5425–5444), or route `via` node (5445–5459) returns `PolicyDenied` and **aborts the entire bundle**, and the reconcile loop then restricts the daemon fail-closed (`daemon.rs:10326–10339`, `restrict_recoverable` + `force_fail_closed_or_restrict`). A "routable-but-denied" pair cannot exist through the signed-bundle path.

**Does the probe still mean anything? Yes — but for a different, and arguably the correct, reason.** The real seam (§1.4 of the design, and Attack 5 below) is whether the re-applied generation correctly *absents* the pair — i.e., that re-derivation neither leaves a **stale peer entry** from the pre-transition generation nor over-broadens. `Blocked`-with-attributed-control (control pair `Reachable` in the same window) is a valid live proxy for "the re-derived enforcement surface excludes the pair". What it is *not* is a "policy deny between two routable peers". The design's own vacuous-deny criticism of TEST-NET-2 is answered by the control gate, not by routability.

**Amendment A4 (also covers the mechanism narration):** reframe the asserted property from "deny survives the transition" to "the re-derived generation excludes the absent pair (no stale/over-broad peer state survives re-derivation)". Drop or qualify the phrase "routable-but-denied" and the §1.4 sentence implying the pair deny is evaluator-derived.

### 2.2 Adding a 4th node collides with the run's earlier stages

**RISK (run-blocking; the biggest practical hole in the design).**

Scenario nodes and stage fanout come from the **same** `ctx.assignments`:

- `traffic_test_matrix.rs:27`: `let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();`
- The cross-network stage consumes the same assignments to build its scenario inputs (`cross_network.rs:1055,1085,1111`).

A 4th node must exist in the inventory to be bootstrapped, mesh-joined, and reachable — at which point it is in `ctx.assignments`, and `TrafficTestMatrix` (which runs **before** the scenario, plan.rs:882 vs 909) will run its positive loop over `client-2 → exit` **expecting Reachable** and fail the run with `"blocked (expected reachable)"` (`traffic_test_matrix.rs:151–155`) — before the failback scenario ever executes. `RoleSwitchMatrix` (deps `&[StageId::TrafficTestMatrix]`, `role_switch_matrix.rs:39`; aliases from assignments at :50) also fans out over the enlarged node set. The design says "the scenario introduces a fourth lab node" as if the node were scenario-local; nothing in the cited wiring supports a scenario-local node that the earlier stages cannot see.

Confidence note: this is inferred from the shared `ctx.assignments` source (both sides cited above); this review did not trace the inventory→assignments builder end-to-end to rule out an exclusion mechanism. No such mechanism appears anywhere in the files the design cites, so the burden is on the design.

**Amendment A3:** specify client-2's integration explicitly: which early stages it joins (membership init, bundle distribution, traversal distribution, enforce/validate — each of which fans over `ctx.assignments`), how `collect_mesh_ip`'s 60 s settle/collision loop (`traffic_test_matrix.rs:39–79`) treats it, and how the positive-probe loop learns that `client-2 → exit` is *expected-blocked* (an expectation map keyed on the allow spec, or equivalent). Without this the stage cannot ship; with it, note honestly that `traffic_test_matrix` gains a per-pair expectation dimension — the very entanglement the design used to justify not extending it.

### 2.3 Topology/timing shift masking the seam

**CONFIRMED-SAFE for the seam itself, RISK for collateral timing (→ A6).** The transition seam is created by `reissue_for_roam` re-writing signed state mid-run (`failback_roaming.rs:580–735`); adding a node to `nodes_spec`/allow handling does not hide that seam — the probes target it directly. But two timing effects are real: (a) `choose_alias` only avoids the addresses passed to it (`endpoint_switch.rs:60`, `used: &[&str]`), and the caller hardcodes exactly three (`failback_roaming.rs:332–339`) — the roam alias could land on client-2's address and corrupt both existing checks and the new ones; (b) see Attack 4/6 for per-sample cost inflating the SLO-critical loop.

---

## 3. Attack 3 — Attribution rule: both probes fail for an unrelated reason

**RISK — the rule as written self-defeats during the very window the stage observes.**

The design's rule (§2.1): a `Blocked` denied result counts only when the allowed control pair proved `Reachable` in the same sampling window; otherwise `INCONCLUSIVE` **and fails the stage**; offline test 2 (`denied_blocked_without_control_is_inconclusive_and_fails`) bakes that in. Now combine with §2.2, which folds the probes per-sample into `monitor_failback`:

- `monitor_failback` deliberately samples **through the whole transition window** (35 iterations, no early break — module docs, failback_roaming.rs:23–28) against a reconvergence SLO of 30 s.
- During reconvergence, the data path is, by hypothesis, down or flapping. In that state the control pair is *expected* to be not-yet-`Reachable`, and the denied pair's ping fails for the same reason. Every such sample is therefore `Blocked`-denied + control-unreachable → `INCONCLUSIVE` → stage failure.
- So the attribution rule as written fails the scenario on essentially every run in which any sample lands mid-reconvergence — which the loop's design guarantees. The `link down mid-transition` case in this attack's prompt is not an edge case; it is the *modal* case.

The unrelated-failure question itself is answered correctly by the design — link-down producing both-fail must and does read `INCONCLUSIVE`, never a pass; that half is fail-closed and matches `traffic_test_matrix.rs:180–186`.

**Amendment A2 (window semantics):** distinguish mid-transition samples from settled windows:
- Mid-transition sample: `Reachable` on the denied pair is a `VIOLATED` failure **unconditionally** (a lapse is a lapse regardless of control state — test 3 should not condition on control `Reachable`); `Blocked`-without-control is *expected* inconclusive — recorded, neither pass evidence nor a failure.
- Each post-transition **settled** window (the final probe round after `POST_ADVERTISE_SETTLE`, and the equivalent settled point after the failback completes) must contain at least one *attributed* pass (`Blocked` denied + `Reachable` control in the same window); a settled window with no attributed pass fails.
- Every window must be sampled at all; a missing window is a failure (design test 5 stands).

This preserves fail-closed behavior (no silent pass anywhere) while not converting the scenario's own reconvergence tolerance into a permanent false-fail amplifier.

---

## 4. Attack 4 — Extend `failback_roaming` vs a new stage: sampling blind spot

**CONFIRMED-SAFE on the placement decision; RISK on per-sample cost (→ A5/A6).**

- Extending the scenario is right: the seam exists only inside its own mid-run signed-state rewrite (`reissue_for_roam`) and its monitor window; a standalone stage after the scenario measures settled state and misses it. The design's three reasons (§2.2) hold against the code.
- **Blind spot:** `SAMPLE_INTERVAL` is 1 s (`endpoint_switch.rs:240`), but each iteration already issues four SSH round-trips (`monitor_failback`, 511–520), so the *effective* period already exceeds 1 s; adding a denied probe (`ping -c 1 -W 2` — up to 2 s on a drop-to-floor deny) plus a control probe (`ping -c 3 -W 5` + retry semantics) roughly triples-to-quadruples it. A deny lapse — or, more importantly here, a *stale-peer lapse* — that exists only between samples is invisible; the same blind spot the leak/signed-state sampling already carries, now wider. Folding probes into the loop is still the correct choice (dense coverage around the transition), but the design must (a) state the effective sampling period, (b) add a dense burst immediately after each transition completes plus the settled-window round, and (c) record the residual blind spot as a documented limitation, mirroring how the leak checks live with theirs.
- **Timing collateral:** stretching iterations delays `first_direct_unix` latching (542–548), which can push measured reconvergence past the 30 s SLO and fail the **pre-existing** `failback_reconnect_within_slo` spuriously. Either move the pair probes out of the SLO-critical in-loop path (settled windows only, with mid-window burst sampling for VIOLATED detection), or explicitly re-baseline the SLO/iteration budget in the design. Silent interaction is not acceptable.

---

## 5. Attack 5 — "Policy-eval-at-bundle-apply" and the real seam

**Partially confirmed; the design's mechanism narration needs correction (folded into A4).**

Confirmed against the code:

- The gate exists and is exactly where the design says: `policy_gate_auto_tunnel` evaluates every bundle peer under `TrafficContext::Mesh` (5407–5423), every route destination under its kind-derived context (5425–5444; `RouteKind::Mesh` → `Mesh`, exit routes → `SharedExit`, 5426–5428), and every route's `via` node (5445–5459); any non-`Allow` ⇒ `PolicyDenied`. Design citation drift: the design says lines 5368–5431; in this tree the function spans **5400–5463**. Content matches.
- The gate is re-run **more often than the design claims** — not merely at apply: `reconcile` calls `load_verified_auto_tunnel` → policy gate on **every tick** (`daemon.rs:10325–10343`), gated by watermark change for the apply step (`assignment_changed`, 10345–10347). A deny lapsing in the evaluator is structurally loud: the daemon restricts fail-closed (10328–10339) rather than applying a degraded state. So "the deny is not attached to the old path" is confirmed, and stronger than stated: a spec-level deny aborts and restricts, every tick.
- `rustynet-policy` default-deny confirmed: `empty_policy_set_denies_every_request_shape` (`lib.rs:1075` — the design cites 1063; minor drift) and `evaluate_with_membership_falls_through_to_terminal_default_deny_when_no_rule_matches` (`lib.rs:2015`; the design's 2015–2051 range is right). Terminal default-deny on no-match, empty-set-denies, explicit-deny-wins all pinned.
- The real seam is exactly where the design points, with sharper wording: `reissue_for_roam` → per-node assignment refresh → fresh signed bundles → reconcile observes a new watermark and re-applies the generation; the QH-04 comment (`daemon.rs:10355–10360`) states the managed peer set "is about to be **replaced**". The unproven property is that this replacement is total — that no peer entry from the pre-transition generation survives into the re-derived set. Only a live probe of the absent pair after the transition observes that surface. Confirmed.

Correction: because the pair-level deny lives in *enforcement absence* (Attack 2.1), the design's §1.4 framing — deny decision as a function of the route spec evaluated by the gate — describes the **exit-route** surface, not the pair surface. The pair surface is never "evaluated then denied"; it is simply not emitted. The seam claim survives; the narration must be fixed so the implementing engineer probes the right thing and does not go looking for a per-pair nft ACL that the cited code does not contain.

---

## 6. Attack 6 — FAIL-LOUD completeness: paths readable as Passed

**RISK — the natural implementation fake-passes. This is the sharpest finding.**

- **`ScenarioOutcome::passed` is unconditional.** `passed(checks)` sets `status: Verdict::Pass` and does **not** aggregate declared checks (`cross_network/scenario/mod.rs:222–231`). Pass/fail lives *solely* in the explicit `if !checks.passed(...) { return Err(...) }` chain at the end of `execute` (`failback_roaming.rs:416–442`). The design's §2.1 item 4 says "the new checks join the verdict" but never names the mechanism. An implementer who does the obvious thing — `checks.declare(...)` the new names (which seed fail-closed defaults, mod.rs:145–151) and `record_bool` them — produces a scenario that **passes while all three new checks read fail**, because nothing consults them. The fail-closed default is real but inert without an explicit gate.
- **Typo'd names are silently inert.** `record` on an undeclared name *appends a new entry* rather than erroring (`mod.rs:125–135`), so `record_bool("acl_denied_pair_blocked_after_failover ", …)` (note the trailing space) both leaves the declared check at its fail default *and* gates nothing — which in the absence of A1's gates means nothing at all.

**Amendment A1:** the design must specify, verbatim: (i) the three new `if !checks.passed("<exact name>")` arms appended to `execute`'s verdict chain, each with its own failure summary in the `failback_failure_summary` style; (ii) that `ScenarioOutcome::passed` aggregates nothing and this is why the arms are mandatory; (iii) the existing test pattern `the_failback_aggregate_covers_its_three_sampled_checks` (failback_roaming.rs:952–966) extended to assert the new names are declared **and** explicitly gated.

Other fail-loud paths, checked:

- Missing probe result / probe error → fail: covered by §2.3 and consistent with `traffic_test_matrix.rs:200–202` and `run_bypass_validator`'s missing-evidence `Err` (remote_exit_common.rs:118–120). CONFIRMED-SAFE given A1/A2.
- Zero iterations / zero SLO: structurally impossible — `FailbackRoamingOptions::new` rejects both (failback_roaming.rs:148–158). CONFIRMED-SAFE.
- Artifact re-verifiability: §2.3 promises the raw transcript, but the SLO summary artifact (763–783) currently persists only leak/signed-state counters and three check verdicts; the new counters and the per-window probe results must be added there too, or a pass claim is not re-verifiable from the machine-readable artifact the report requires to exist. **Amendment A7.**
- Early-return paths: every step is wrapped in `during(phase, ...)`, which fails the scenario on error before the verdict chain is reached — no path records a pass and returns `Ok` with probes skipped, provided A1's gates exist. CONFIRMED-SAFE (conditional on A1).

---

## 7. Attack 7 — Does the design weaken existing checks?

**No designed weakening; three collateral risks, all covered by amendments above.**

- The design preserves the six-pair allow spec in `reissue_for_roam` (620–630) and all existing checks verbatim — §3's non-claim is consistent with the code as far as the scenario itself is concerned. CONFIRMED-SAFE.
- Collateral 1: per-sample probe cost distorting `failback_reconnect_within_slo` — Attack 4/A6.
- Collateral 2: roam-alias collision with client-2's address (choose_alias avoid list is caller-supplied and currently three entries, 332–339) — A6 must add client-2's address to the avoid list.
- Collateral 3: `traffic_test_matrix` positive-probe failure on the new denied pair (Attack 2.2/A3) — this is the existing check being *violated by the new topology*, not weakened, but it breaks the run identically and must be designed for, not discovered in the lab.

---

## 8. Overall verdict

**READY-WITH-AMENDMENTS.**

The GAP-3 grounding survives adversarial re-derivation (the hunt doc's GAP-2 misread did not recur), the placement decision (extend `failback_roaming`, not `traffic_test_matrix`) is right, and the seam it targets — totality of the generation re-derivation that replaces the managed peer set — is real and unproven by any existing stage. But the design as written would (a) fail the scenario on nearly every run via its attribution rule interacting with the deliberately-never-breaks-early monitor loop, (b) break the run earlier still via the unaddressed `traffic_test_matrix` positive-probe collision, and (c) admit a natural implementation that records the new checks while nothing gates on them. All three are fixable by amendment, not rework.

### Amendments

1. **A1 — explicit verdict gates (mandatory):** specify the exact `if !checks.passed("<name>")` arms appended to `execute`'s verdict chain for all three new checks, with per-check failure summaries; state that `ScenarioOutcome::passed(checks)` aggregates nothing (`mod.rs:222–231`) and that `record` on an undeclared name silently appends (`mod.rs:125–135`); extend the declare/aggregate test pattern (failback_roaming.rs:952–966) to prove the new names are declared *and* gated.
2. **A2 — window semantics for the attribution rule:** mid-transition samples with unreachable control are *expected inconclusive* — recorded, not failing; `Reachable` on the denied pair is `VIOLATED` unconditionally (drop the control precondition from test 3); each post-transition settled window (final round after `POST_ADVERTISE_SETTLE`, plus the post-failback settled point) must contain ≥1 attributed pass (`Blocked` denied + `Reachable` control, same window); every window sampled or the stage fails.
3. **A3 — fourth-node integration plan:** specify which early stages client-2 joins via `ctx.assignments`, and how `traffic_test_matrix`'s positive loop learns `client-2 → exit` is expected-blocked (per-pair expectation map or equivalent). Cite `traffic_test_matrix.rs:27,101–161,151–155` and the stage order (plan.rs:882 before 909) explicitly.
4. **A4 — mechanism narration correction:** reframe the asserted property as "the re-derived generation excludes the absent pair" (enforcement absence: no WG peer entry, no route — daemon.rs:14159–14229; generation replacement — 10345–10370, QH-04 comment), not "routable-but-denied" or evaluator-attached deny; note the policy gate is all-or-nothing (`PolicyDenied` aborts the bundle and the daemon restricts fail-closed, 10326–10339) and re-runs every reconcile tick; qualify the "nftables ACL surface" phrase (no per-pair nft ACL generation appears in the cited code).
5. **A5 — probe surface spec:** the existing adapter cannot express the pair-targeted probe — `probe_denied_peer` maps *any* ping failure to `Blocked` (linux_traffic.rs:458–471; same shape windows_traffic.rs:133–147, macos_traffic.rs:363–376) and `ping_mesh_peer` never returns `Blocked` on Linux (446–453, failure ⇒ `Error` with diagnostics). Specify the new probe's result shape (Blocked / Reachable / Error) and the control-`Error` ⇒ inconclusive mapping.
6. **A6 — timing & alias budget:** state the effective sampling period with probes included (base interval 1 s, endpoint_switch.rs:240; denied probe `ping -c 1 -W 2`, control `ping -c 3 -W 5`); either move pair probes out of the SLO-critical in-loop path or explicitly re-baseline SLO/iteration interaction; add client-2's address to `choose_alias`'s avoid list (failback_roaming.rs:332–339).
7. **A7 — artifact completeness:** add the new counters and per-window probe outcomes to the SLO summary artifact (763–783) so a pass is re-verifiable from machine-readable evidence, per §2.3's own promise.
8. **A8 — survey correction:** cite `probe_service_blocked_from_client` (`BYPASS_CHECKS`, remote_exit_common.rs:23–28; consumed at failback_roaming.rs:394–413) as the in-family negative-probe precedent and source of the missing-evidence fail-closed convention (remote_exit_common.rs:118–120); correct the citation drift (policy gate 5400–5463, not 5368–5431; empty-set test lib.rs:1075, not 1063).

### Explicitly considered and dismissed

- *Revoked-peer audit covers the gap:* no — fixed 2+2 internal controller battery (`vm_lab/mod.rs:20616–20633`), steady-state only, revocation not path-transition; and the design already says so correctly.
- *A standalone post-scenario stage instead of extending the scenario:* rejected — measures settled state, misses the seam; the design's placement reasons verify.
- *Case-count drift in the revoked-peer battery from the 4th node:* dismissed — the battery's case set is fixed by construction, not derived from lab topology.
