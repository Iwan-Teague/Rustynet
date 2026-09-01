# Live-Lab Traversal Hint Wire-Replay Stage — Design (GAP-4)

Date: 2026-09-01
Status: DESIGN ONLY, no code changed. Adversarial review COMPLETE (verdict: READY-WITH-AMENDMENTS); design amended accordingly and implementation-ready. Implementation remains owner-gated stage work pending lab availability.

**Adversarial-review amendments folded (2026-09-01)** — amendments A1–A8 from `LiveLabTraversalHintWireReplayStageAdversarialReview_2026-09-01.md` §3 are folded into this document:
- **A1** — primary mechanism re-aimed at the bundle-load watermark/anti-rollback layer; `validate_signed_coordination_record` demoted to secondary in-envelope layer (§1.3, §3.2).
- **A2** — threat model relabeled **bundle-path replay with a forced refresh**; vantage defined by assertions (injector not on the coordinator, delivery via the node's real bundle path, load via a real refresh trigger) rather than self-attestation (§2, §3.2).
- **A3** — fixture guards: envelope watermark recorded and asserted older than live watermark at injection; nonce consumption derived from the receiving node's persisted watermark state; single-snapshot intactness asserted; envelope nonce + payload digest carried as the report correlation id (§3.2, §3.4).
- **A4** — attributable rejection requires a forced/observed refresh trigger post-injection and nonce+digest correlation; log channel and retention specified; fetch-race overwrite deliberately handled (§3.2, §3.3, §3.5).
- **A5** — daemon-observed `now_unix` recorded at capture AND injection via a specified channel; staleness pass-reason rule evaluated against daemon clocks only (§3.2, §3.5).
- **A6** — stage placed last in a run (or isolated); teardown restores the legitimate bundle and verifies recovery from the enforced-mode fail-closed state before any later stage observes the node (§3.6).
- **A7** — additional unit test: validator failure mid-soak / incomplete soak is a fail even when the report file exists with some checks recorded pass (§4).
- **A8** — reading daemon state from the receiving node requires a new validator-side host capability beyond the current `ScenarioHost` surface; scoped in §6.

Scope: A live-lab stage design for the missing adversarial proof that an attacker who captures an **old but still validly signed traversal hint** and replays it into the node's **real bundle path with a forced refresh** during an established, running session cannot move that session's endpoint. This document designs the stage; it changes no code and claims no lab-proven status.

---

## 1. Grounding verdict

**Verdict: CONFIRMED.** The existing traversal adversarial coverage proves forged, stale, wrong-signer, and nonce-replayed traversal state rejection **at the offline gate / bundle-load level**, and rogue-endpoint hijack denial **at the live endpoint level**, but there is **no stage that injects an old, validly signed hint onto the wire of an established running session** to prove the live apply path rejects it. The claim is grounded in the following code, read from this worktree at the time of writing.

Note on paths: the traversal adversarial stage lives at `crates/rustynet-cli/src/vm_lab/orchestrator/stage/cross_network/scenario/traversal_adversarial.rs` (832 lines). There is no `stage/scenario/` directory; earlier notes that cited that path were wrong about the location, though right about the content.

### 1.1 What exists today — the gate layer (offline, not on the wire)

The stage's module contract requires three `rustynetd` unit-level gate tests, declared at `traversal_adversarial.rs:50-56` (`TRAVERSAL_GATE_TESTS`, crate `rustynetd`, line 59):

1. `daemon::tests::traversal_adversarial_gate_rejects_forged_stale_wrong_signer_and_nonce_replay` (line 53) — a single unit test covering the forged / stale / wrong-signer / nonce-replay quartet in-process.
2. `daemon::tests::load_traversal_bundle_rejects_tampered_signature_and_replay` (line 54) — the bundle **load** path rejects tampered signatures and replays.
3. `daemon::tests::daemon_runtime_netcheck_rejects_forged_traversal_hint_fail_closed` (line 55) — the daemon runtime netcheck fails closed on a forged hint.

These are `cargo test` invocations the stage runs on a guest via `host.run_required_test` (`traversal_adversarial.rs:184-199`), short-circuiting on the first failure (lines 180-183 preserve the shell-era `&&` semantics). When the combined status is zero, the stage records the trio of report checks `forged_traversal_rejected` / `stale_traversal_rejected` / `replayed_traversal_rejected` as `Pass` (`CHECK_FORGED` line 88, `CHECK_STALE` line 89, `CHECK_REPLAYED` line 90; recording at lines 200-204). The report validator requires the gates' combined-output file for any pass (`local_tests_log`, declared at lines 110-116 with the requirement stated at lines 110-112).

The critical observation: **a unit test that constructs a stale record in-process is not a wire replay.** It proves the validator function rejects stale input when the validator is called. It does not prove that a real daemon, with a real session established and a real older (previously accepted, not yet expired, validly signed) hint arriving over its actual gossip/coordination transport, routes that hint through the rejection path rather than dropping it unconsumed or applying it through a different code path.

### 1.2 What exists today — the live endpoint-hijack layer (live, but not hint replay)

The stage's second act is a live rogue-endpoint injection via a sibling validator binary (`ENDPOINT_HIJACK_BIN = "live_linux_endpoint_hijack_test"`, line 62), whose report the stage reads with `host.read_report_checks` and requires to contain `hijack_drives_fail_closed`, `rogue_endpoint_not_adopted`, and `recovery_keeps_rogue_endpoint_rejected` (`ENDPOINT_HIJACK_CHECKS`, lines 67-71; read at lines 238-242; `CHECK_ROGUE` line 91). The rogue endpoint defaults to RFC 5737 TEST-NET-3 `203.0.113.44` (`DEFAULT_ROGUE_ENDPOINT_IP`, lines 82-85).

This is genuinely live and genuinely adversarial, but it injects an **unsigned, fabricated endpoint** — there is no scenario in which a **validly signed, previously accepted** hint is replayed after the session has moved on. The live proof and the signature-aware proof have never been combined.

### 1.3 The daemon-side apply path the gap leaves unexercised live

**A1 (folded): the primary live rejection layer under test is the bundle-load watermark/anti-rollback layer, not the in-envelope validator.** The daemon's bundle-load path enforces a watermark/anti-rollback check at `crates/rustynetd/src/daemon.rs:15486-15501` — an older bundle carrying a watermark that orders behind the node's persisted state is rejected there — and that rejection is surfaced at `daemon.rs:5902-5910` as `TraversalBootstrapError::ReplayDetected`. This is the layer a replayed old-but-validly-signed hint actually hits live, and it is the primary assertion target of this stage.

The in-envelope validator `validate_signed_coordination_record` (`crates/rustynetd/src/traversal.rs:1466-1511`, taking `replay_window: &mut CoordinationReplayWindow` at line 1472, enforcing expiry sanity 1475-1479, max TTL 1480-1485, staleness 1486-1488, future-start 1490-1493, node-pair match 1495-1501, signature 1503, and nonce replay 1504) is a **secondary, in-envelope nonce-replay layer**. It still matters — a replayed envelope whose watermark were not behind would need to fail here — but the stage's primary expected rejection is the watermark layer.

On the daemon side, the hint state path is: `crates/rustynetd/src/daemon.rs` — `refresh_traversal_hint_state` (line 5824) is the sole mutator of the daemon's hint state, bumping `traversal_hint_generation`; the state itself is `traversal_hints: Option<TraversalBundleSetEnvelope>` (line 4671) with the last failure surfaced as `traversal_hint_error` (line 4677); a fingerprint memo keyed on generation caches apply decisions (lines 6162-6188); the apply path fans out through `apply_traversal_authority_to_peers` (referenced at line 5886).

Every one of these enforcement points is exercised offline by the gates in §1.1. **None of them is exercised live, mid-session, with an attacker-controlled replay of a genuinely signed old hint delivered through the node's real bundle path.** That is GAP-4.

## 2. Threat model for the new stage

**A2 (folded): honest framing — bundle-path replay with a forced refresh, not raw wire replay.** The daemon has no attacker-reachable raw-wire ingestion point for traversal hints: hints reach the node through its **bundle path** (fetch/load through the daemon's coordination-plane bundle channel) and are applied only when `refresh_traversal_hint_state` actually fires. The threat this stage models is therefore: an adversary who has captured an older traversal hint bundle — one that was validly signed by the coordinator, whose signature still verifies, and whose watermark is behind the node's live watermark — delivers it into the **node's real bundle path** and induces a **real refresh**, so the daemon loads the replayed bundle through its legitimate ingestion path. The attacker's goal is endpoint steering: make one node believe the peer's endpoint has moved to an address the attacker controls (a relayed or hostile address), enabling traffic capture or denial.

**Vantage is defined by assertions, not self-attestation.** The stage never asks the injector to *claim* an attacker position; it asserts it: (a) the injector does not run on the coordinator; (b) delivery is via the node's real bundle path (the same path a hint legitimately arrives on); and (c) the load is via a real refresh trigger (`refresh_traversal_hint_state` actually fires on the receiving node after injection). A report that cannot demonstrate all three does not pass. (A fetch-channel MITM scope — intercepting and substituting a bundle mid-fetch — remains explicitly out of scope for this stage; see §6.)

The failure modes the stage must distinguish:

1. **Correct rejection (desired):** the daemon's bundle-load path rejects the replayed bundle — via the watermark/anti-rollback layer (§1.3, primary) or the in-envelope nonce-replay layer (secondary) — the session endpoint does not change, the rejection is observable (log + counted error state), and the established session continues unaffected.
2. **Silent drop (partial failure):** the bundle is dropped without ever reaching a rejection layer, or the refresh never fires — the endpoint does not move, but the rejection is not attributable to the anti-replay machinery, so the stage cannot distinguish "protected" from "lucky". The stage treats an unattributable outcome as a failure.
3. **Application (critical failure):** the endpoint moves to the replayed bundle's endpoint. Fail the stage, fail the run.

## 3. Proposed stage design

### 3.1 Name and placement

New sibling scenario module `traversal_hint_wire_replay.rs` under `crates/rustynet-cli/src/vm_lab/orchestrator/stage/cross_network/scenario/`, alongside `traversal_adversarial.rs`, reusing the same `Checks` / `ScenarioOutcome` / `Verdict` / `ScenarioHost` infrastructure.

**Why a new stage rather than extending `traversal_adversarial.rs`:** the existing stage's shape is "run offline gates, then drive one live sibling binary against a probe topology". The new proof needs a **two-node established session** as its precondition — a different topology and a different live harness phase (the session must exist before the injection begins). Extending the existing stage would force the established-session precondition onto a stage whose current siblings do not need it, and would make the existing stage's report contract depend on a new failure class. A sibling keeps both stages independently runnable, independently attributable in the run matrix, and keeps the existing stage's green history intact.

### 3.2 Topology and sequence

Two lab nodes (client + exit, or any role pair that forms a session) on the mesh, plus the coordination plane that issues signed hints.

1. **Establish.** Bring up the two-node session and confirm the current hint state: record the session's live endpoint pair and the daemon's `traversal_hint_generation` on both nodes, plus the daemon's current traversal watermark state. This is the baseline; the stage fails here if a stable session cannot be established.
2. **Capture.** Capture one older, **still validly signed** hint envelope addressed to this node pair (from an earlier coordination round retained for the test, or captured from the wire during an earlier refresh). **A3 (folded) fixture guards**, all asserted before injection proceeds (fail-closed on a malformed fixture):
   - The capture records the envelope's **watermark** and asserts it orders **older** than the receiving node's live watermark at injection time.
   - The envelope's nonce is recorded as **already consumed**, derived from the **receiving node's persisted watermark/replay state** (read from the node), not from harness bookkeeping.
   - The envelope's signature-verification status is recorded as *valid* — a hint whose signature does not verify is not a replay and the stage refuses to proceed.
   - **Single-snapshot intactness** is asserted: the envelope must be a single snapshot (per the bundle-load single-snapshot contract, `daemon.rs:15455-15463`, with duplicate-pair rejection at `:15472-15477`) so the load path rejects it for replay, never pre-empted by an `InvalidFormat` false rejection.
   - The **envelope nonce + payload digest** are pinned as the report's correlation id (§3.4).
   - **A5 (folded):** the **daemon-observed `now_unix`** at capture time is recorded via the specified observation channel (§3.5 clock-skew guard).
3. **Replay via the real bundle path, with a real refresh trigger (A2/A4 folded).** Deliver the captured envelope into the receiving node's actual bundle path — the same path a hint legitimately arrives on — carrying the **old** envelope byte-for-byte (no re-signing, no nonce mutation — mutation would make it a forgery test, which GAP-4 explicitly is not). Delivery alone proves nothing: the load happens only when `refresh_traversal_hint_state` fires, and it fires **only** at its call sites `daemon.rs:6015, 8755, 8882, 8993, 9220, 10375`. The stage therefore **forces or explicitly observes a refresh trigger post-injection** (e.g. the state-refresh event that fires at one of those sites) and records which site fired; a soak window with no observed refresh is an unattributable outcome (§3.3 `wire_replay_rejected`), not a pass. **A4 (folded) fetch-race handling:** the stage deliberately detects and handles the fetch-race overwrite — the state fetcher (`state_fetcher.fetch_traversal()`, `daemon.rs:5949-5953`) can replace the injected bundle with a fresh legitimate fetch before the refresh reads it. The report records whether the race was won or lost; a lost race is graded per §3.3 (an unattributable outcome), and the stage must state so rather than silently reading a pass.
4. **Observe.** For a bounded soak window: re-read the session endpoint pair on both nodes and the daemon hint state (`traversal_hint_generation`, `traversal_hint_error`) on the receiving node, from the daemon state channel with the retention specified in §3.3. **A5 (folded):** the **daemon-observed `now_unix`** at injection/refresh time is recorded through the same channel, so staleness judgments in the report are made against daemon clocks, never harness clocks.
5. **Assert.** See §3.3.

### 3.3 Checks (fail-loud contract)

The stage declares its checks up front (`Checks::declare`) in the same style as `traversal_adversarial.rs:94-100`, and every check must be *earned by evidence read from the run* — never defaulted:

| Check | Pass condition |
| --- | --- |
| `wire_replay_rejected` | The replayed envelope's rejection is **attributable** (A4, folded): (a) a **forced or explicitly observed refresh trigger** fired post-injection (one of the `refresh_traversal_hint_state` call sites, §3.2 step 3 — a soak window with no observed refresh cannot pass this check); (b) the receiving daemon's `traversal_hint_error` (or its structured log stream) records a replay/staleness/generation rejection **correlated to the injected envelope's nonce + payload digest** (the §3.2 correlation id) within the soak window; and (c) the fetch race is recorded as won (the injected bundle was still in place when the refresh read it). A silent drop, an unobserved refresh, or a lost fetch race is a **fail** (unattributable outcome), not a pass (§2 case 2). **Log channel + retention (A4):** the rejection is read from the daemon's structured traversal log stream on the receiving node, captured for the full soak window and retained in the stage artifact directory alongside the report so the attribution is auditable after the run. |
| `session_endpoint_immovable` | The established session's endpoint pair on both nodes is byte-identical to the §3.2 step-1 baseline after the soak window. |
| `hint_generation_stable` | The receiving node's `traversal_hint_generation` is unchanged; a replay must never bump the generation. |
| `session_survives_replay` | Mesh traffic over the established session continues to pass during and after the soak window (a liveness probe, proving rejection did not come at the price of tearing the session). |

A missing report, an unparseable report, a skipped injection, a dry-run marker, or a stage that never reached the injection step must produce a **failed** outcome, never an absent-and-ignored check. This mirrors the existing stage's fail-closed contract (`traversal_adversarial.rs:149-155`: an unassertable run must not read as a pass).

### 3.4 Harness integration

- Register the new scenario in the cross-network stage registry beside `cross_network_traversal_adversarial`, with its own suite name (proposed: `cross_network_traversal_hint_wire_replay`), so the run matrix records it as its own column rather than folding into the existing stage's.
- The injection tool follows the sibling-validator pattern: a dedicated `live_linux_*`-style test binary (or a subcommand of the existing endpoint-hijack binary, if the owner prefers) that takes `--client-host`, `--exit-host`, `--ssh-identity-file`, the captured envelope path, and a `--report` path, and writes a JSON report the stage validates with `read_report_checks`.
- Report artifacts land in the stage artifact directory under `cross_network_traversal_hint_wire_replay_*` names, in the pattern of `TraversalAdversarialPaths` (`traversal_adversarial.rs:105-135`), including the injected-envelope hash so the report is self-describing about *what* was replayed. **A3 (folded):** the report's **correlation id is the envelope nonce + payload digest** pair, so every rejection record, refresh-trigger record, and soak-window log line the report cites is correlatable back to the exact injected bytes; the retention of the captured soak-window log stream is part of the artifact contract (§3.3).
- The stage appends its row to `documents/operations/live_lab_node_run_matrix.csv` through the normal `--node` orchestrate path; the pass/fail claim for this stage must always be taken from the stage's own report artifact, never from the CSV column alone (existing ledger hygiene rule).

### 3.5 What would make this stage lie, and the guards

- **Fixture drift:** if the "old" hint's nonce was never actually consumed, or its signature does not verify, the stage tests forgery/rejection generally — not replay. Guard: step-2 fixture validation asserts *valid signature + consumed nonce + not-yet-expired-at-capture* before injection proceeds, and fails the stage otherwise.
- **Rejection-by-accident:** the endpoint not moving proves nothing if the envelope never reached the daemon (transport dropped it, wrong address, daemon crashed). Guard: the `wire_replay_rejected` check requires the attributable rejection record, not just endpoint immobility.
- **Clock skew masquerading as staleness:** if lab clocks drift, a *fresh* hint could be rejected as stale, passing the stage for the wrong reason. Guard (A5, folded): **staleness is evaluated against daemon clocks only** — `unix_now()` is daemon-internal, so the stage records the **daemon-observed `now_unix`** at capture AND at injection/refresh through a specified observation channel (the daemon status field or a timestamped daemon log line, pinned in the report) and evaluates the staleness-as-pass-reason rule against those daemon observations, never harness wall-clock. The rejection reason recorded must be replay-window/watermark or generation; staleness is accepted as a *pass reason* only if the report also shows, from daemon-observed time, that the envelope was within its TTL at capture time.
- **Injection from the wrong vantage:** injecting from the coordinator's own position would prove nothing an attacker cannot do. Guard: the injector runs from the probe/attacker position (the same vantage the endpoint-hijack sibling uses), recorded in the report — and the A2 vantage assertions (not on the coordinator, real bundle path, real refresh trigger) are checked, not self-attested.
- **Fetch-race overwrite (A4, folded):** `state_fetcher.fetch_traversal()` (`daemon.rs:5949-5953`) can replace the injected bundle with a fresh legitimate fetch before the refresh reads it — the node then rejects/ignores nothing because there is nothing to reject, and the endpoint simply never moves. Guard: §3.2 step 3 detects the race, records won/lost in the report, and a lost race is graded an unattributable outcome per §3.3 — never a silent pass.

### 3.6 Isolation and teardown (A6, folded)

**Placement:** this stage mutates the receiving node's traversal bundle state, so it is placed **last in a run** (or isolated into a dedicated run) so its mutations cannot contaminate later stages. **Teardown:** the teardown step (a) restores the legitimate traversal bundle on the receiving node, (b) triggers a refresh so the node reloads it, and (c) **verifies recovery from the enforced-mode fail-closed state** — the daemon's traversal hard-stop (`daemon.rs:8029-8033`) or restrict path (`daemon.rs:5932-5935`) is cleared and hint state is healthy — **before the run proceeds to any later stage**. A teardown that cannot verify recovery fails the stage; the node is never left behind in enforced-mode fail-closed for a subsequent stage to trip over.

## 4. Offline validator unit tests (companion to the live stage)

The live stage's report validator and fixture gate get their own unit tests, runnable without the lab (the same pattern as `traversal_adversarial.rs`'s stage-level tests, e.g. line 431, `a_failing_traversal_gate_fails_the_whole_forged_stale_replayed_trio`):

1. `wire_replay_report_without_rejection_record_fails` — a report with endpoint immobility but no attributable rejection record produces a failed outcome (the silent-drop case).
2. `wire_replay_report_with_moved_endpoint_fails` — endpoint moved → fail, even if all other checks pass.
3. `fixture_with_unconsumed_nonce_is_refused` — capture validation refuses a hint whose nonce was not consumed (not a replay).
4. `fixture_with_invalid_signature_is_refused` — capture validation refuses an unsigned/forged envelope (that is the existing stage's job).
5. `missing_report_is_fail_not_skip` — absent/partial artifacts produce a failed outcome.
6. `staleness_rejection_with_expired_at_capture_fixture_is_refused` — an envelope already expired at capture is refused as a fixture (it tests the expiry gate, not replay).
7. `dry_run_marker_cannot_pass` — any dry-run/skip marker in the report forces a failed outcome.
8. `validator_failure_mid_soak_or_incomplete_soak_is_fail` (A7, folded) — the report validator itself failing partway through the soak window, or the soak ending incomplete (window truncated before the required refresh + rejection records exist), is a **fail** even when the report file exists and some checks already recorded pass. This mirrors the sibling precedent: a partial/mid-flight failure must not read as a pass (`traversal_adversarial.rs:232-237, 274-279`, tested at `:516-537`).

## 5. Live-proving status

**LAB VMs DOWN at the time of this design.** No live-lab run has exercised this stage; it has no row in the `--node` run matrix and no report artifacts. Per the parity ledgers, a stage that has never run live is *not proven*, and this design claims nothing otherwise. The stage's first live run is pending (a) the owner-gated implementation review of this document and (b) lab availability. When it runs, the evidence contract is: the stage's own report artifact in the run's report directory, plus the appended matrix row attributed to the implementing commit.

## 6. Explicitly out of scope for this design

- No changes to `rustynetd` enforcement logic — the anti-replay machinery (`traversal.rs:1466-1511`) and the apply path (`daemon.rs:5824`, `5886`, `6162-6188`) are assumed correct per their offline gates; this stage proves them live.
- No changes to the existing `traversal_adversarial` stage's checks or report contract.
- No new cryptography, no new transport, no nonce or signing scheme changes.
- No claim of live-proven status for any role or OS; this is a stage design, and the cross-platform parity matrices are owned by their own ledgers.
- A fetch-channel MITM scope (intercepting/substituting a bundle inside the coordinator's fetch stream mid-flight) is **not** modeled by this stage; the modeled threat is delivery into the node's real bundle path with a real refresh trigger (§2).
- **A8 (folded) — host-capability prerequisite:** reading the receiving node's daemon state (hint generation, `traversal_hint_error`, applied endpoint pair, watermark state, daemon-observed `now_unix`) requires a **new validator-side host capability beyond the current `ScenarioHost` surface**. The implementation must add and owner-review that capability before this stage can run; until then the stage remains design-complete but not implementable as specified.
