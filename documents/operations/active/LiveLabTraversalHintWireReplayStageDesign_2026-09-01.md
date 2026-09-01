# Live-Lab Traversal Hint Wire-Replay Stage — Design (GAP-4)

Date: 2026-09-01
Status: DESIGN ONLY, no code changed; if warranted, owner-gated stage work pending (a) separate adversarial review of this design and (b) lab availability.
Scope: A live-lab stage design for the missing adversarial proof that an attacker who captures an **old but still validly signed traversal hint** and replays it **on the wire into an established, running session** cannot move that session's endpoint. This document designs the stage; it changes no code and claims no lab-proven status.

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

On the daemon side, the traversal hint apply path is:

- `crates/rustynetd/src/traversal.rs:1466-1511` — `validate_signed_coordination_record`, taking `replay_window: &mut CoordinationReplayWindow` (line 1472) and enforcing, in order: expiry window sanity (1475-1479), max TTL (1480-1485), **staleness** (`now_unix > record.expires_at_unix` → `TraversalError::CoordinationExpired`, lines 1486-1488), future-start rejection (1490-1493), node-pair match (1495-1501), signature verification (1503), and **nonce replay** (`replay_window.verify_and_record(record.nonce, record.expires_at_unix, now_unix)?`, line 1504).
- `crates/rustynetd/src/daemon.rs` — `refresh_traversal_hint_state` (line 5824) is the sole mutator of the daemon's hint state, bumping `traversal_hint_generation`; the state itself is `traversal_hints: Option<TraversalBundleSetEnvelope>` (line 4671) with the last failure surfaced as `traversal_hint_error` (line 4677); a fingerprint memo keyed on generation caches apply decisions (lines 6162-6188); the apply path fans out through `apply_traversal_authority_to_peers` (referenced at line 5886).

Every one of these enforcement points is exercised offline by the gates in §1.1. **None of them is exercised live, mid-session, with an attacker-controlled replay of a genuinely signed old hint.** That is GAP-4.

## 2. Threat model for the new stage

An adversary who has passively observed (or exfiltrated) an older traversal hint bundle — one that was validly signed by the coordinator, whose signature still verifies, and whose nonce has already been consumed — replays it onto the wire while the two nodes have an established session. The attacker's goal is endpoint steering: make one node believe the peer's endpoint has moved to an address the attacker controls (a relayed or hostile address), enabling traffic capture or denial.

The failure modes the stage must distinguish:

1. **Correct rejection (desired):** the daemon's apply path rejects the replayed hint — via replay window, staleness, generation/epoch, or fingerprint match — the session endpoint does not change, the rejection is observable (log + counted error state), and the established session continues unaffected.
2. **Silent drop (partial failure):** the hint is dropped without ever reaching the validator — the endpoint does not move, but the rejection is not attributable to the anti-replay machinery, so the stage cannot distinguish "protected" from "lucky". The stage treats an unattributable outcome as a failure.
3. **Application (critical failure):** the endpoint moves to the replayed hint's endpoint. Fail the stage, fail the run.

## 3. Proposed stage design

### 3.1 Name and placement

New sibling scenario module `traversal_hint_wire_replay.rs` under `crates/rustynet-cli/src/vm_lab/orchestrator/stage/cross_network/scenario/`, alongside `traversal_adversarial.rs`, reusing the same `Checks` / `ScenarioOutcome` / `Verdict` / `ScenarioHost` infrastructure.

**Why a new stage rather than extending `traversal_adversarial.rs`:** the existing stage's shape is "run offline gates, then drive one live sibling binary against a probe topology". The new proof needs a **two-node established session** as its precondition — a different topology and a different live harness phase (the session must exist before the injection begins). Extending the existing stage would force the established-session precondition onto a stage whose current siblings do not need it, and would make the existing stage's report contract depend on a new failure class. A sibling keeps both stages independently runnable, independently attributable in the run matrix, and keeps the existing stage's green history intact.

### 3.2 Topology and sequence

Two lab nodes (client + exit, or any role pair that forms a session) on the mesh, plus the coordination plane that issues signed hints.

1. **Establish.** Bring up the two-node session and confirm the current hint state: record the session's live endpoint pair and the daemon's `traversal_hint_generation` on both nodes. This is the baseline; the stage fails here if a stable session cannot be established.
2. **Capture.** Capture one older, **still validly signed** hint envelope addressed to this node pair (from an earlier coordination round retained for the test, or captured from the wire during an earlier refresh). The capture must record its signature-verification status as *valid* and its nonce as *already consumed* by the live session — a hint whose signature does not verify, or whose nonce was never accepted, is not a replay and the stage must refuse to proceed (fail-closed on a malformed fixture).
3. **Replay on the wire.** Inject the captured envelope into the session's actual hint transport path — the same path a hint legitimately arrives on — the way the endpoint-hijack sibling injects its rogue endpoint: from a position the attacker could occupy. The injection carries the **old** envelope byte-for-byte (no re-signing, no nonce mutation — mutation would make it a forgery test, which GAP-4 explicitly is not).
4. **Observe.** For a bounded soak window: re-read the session endpoint pair on both nodes and the daemon hint state (`traversal_hint_generation`, `traversal_hint_error`) on the receiving node.
5. **Assert.** See §3.3.

### 3.3 Checks (fail-loud contract)

The stage declares its checks up front (`Checks::declare`) in the same style as `traversal_adversarial.rs:94-100`, and every check must be *earned by evidence read from the run* — never defaulted:

| Check | Pass condition |
| --- | --- |
| `wire_replay_rejected` | The replayed envelope's rejection is **attributable**: the receiving daemon's `traversal_hint_error` (or its structured log stream) records a replay/staleness/generation rejection attributable to the injected envelope within the soak window. A silent drop with no attributable record is a **fail**, not a pass (§2 case 2). |
| `session_endpoint_immovable` | The established session's endpoint pair on both nodes is byte-identical to the §3.2 step-1 baseline after the soak window. |
| `hint_generation_stable` | The receiving node's `traversal_hint_generation` is unchanged; a replay must never bump the generation. |
| `session_survives_replay` | Mesh traffic over the established session continues to pass during and after the soak window (a liveness probe, proving rejection did not come at the price of tearing the session). |

A missing report, an unparseable report, a skipped injection, a dry-run marker, or a stage that never reached the injection step must produce a **failed** outcome, never an absent-and-ignored check. This mirrors the existing stage's fail-closed contract (`traversal_adversarial.rs:149-155`: an unassertable run must not read as a pass).

### 3.4 Harness integration

- Register the new scenario in the cross-network stage registry beside `cross_network_traversal_adversarial`, with its own suite name (proposed: `cross_network_traversal_hint_wire_replay`), so the run matrix records it as its own column rather than folding into the existing stage's.
- The injection tool follows the sibling-validator pattern: a dedicated `live_linux_*`-style test binary (or a subcommand of the existing endpoint-hijack binary, if the owner prefers) that takes `--client-host`, `--exit-host`, `--ssh-identity-file`, the captured envelope path, and a `--report` path, and writes a JSON report the stage validates with `read_report_checks`.
- Report artifacts land in the stage artifact directory under `cross_network_traversal_hint_wire_replay_*` names, in the pattern of `TraversalAdversarialPaths` (`traversal_adversarial.rs:105-135`), including the injected-envelope hash so the report is self-describing about *what* was replayed.
- The stage appends its row to `documents/operations/live_lab_node_run_matrix.csv` through the normal `--node` orchestrate path; the pass/fail claim for this stage must always be taken from the stage's own report artifact, never from the CSV column alone (existing ledger hygiene rule).

### 3.5 What would make this stage lie, and the guards

- **Fixture drift:** if the "old" hint's nonce was never actually consumed, or its signature does not verify, the stage tests forgery/rejection generally — not replay. Guard: step-2 fixture validation asserts *valid signature + consumed nonce + not-yet-expired-at-capture* before injection proceeds, and fails the stage otherwise.
- **Rejection-by-accident:** the endpoint not moving proves nothing if the envelope never reached the daemon (transport dropped it, wrong address, daemon crashed). Guard: the `wire_replay_rejected` check requires the attributable rejection record, not just endpoint immobility.
- **Clock skew masquerading as staleness:** if lab clocks drift, a *fresh* hint could be rejected as stale, passing the stage for the wrong reason. Guard: the harness records the daemon's observed `now_unix` vs the envelope's `expires_at_unix` in the report; the rejection reason recorded must be replay-window or generation, with staleness rejected as a *pass reason* only if the report also shows the envelope was within its TTL at capture time.
- **Injection from the wrong vantage:** injecting from the coordinator's own position would prove nothing an attacker cannot do. Guard: the injector runs from the probe/attacker position (the same vantage the endpoint-hijack sibling uses), recorded in the report.

## 4. Offline validator unit tests (companion to the live stage)

The live stage's report validator and fixture gate get their own unit tests, runnable without the lab (the same pattern as `traversal_adversarial.rs`'s stage-level tests, e.g. line 431, `a_failing_traversal_gate_fails_the_whole_forged_stale_replayed_trio`):

1. `wire_replay_report_without_rejection_record_fails` — a report with endpoint immobility but no attributable rejection record produces a failed outcome (the silent-drop case).
2. `wire_replay_report_with_moved_endpoint_fails` — endpoint moved → fail, even if all other checks pass.
3. `fixture_with_unconsumed_nonce_is_refused` — capture validation refuses a hint whose nonce was not consumed (not a replay).
4. `fixture_with_invalid_signature_is_refused` — capture validation refuses an unsigned/forged envelope (that is the existing stage's job).
5. `missing_report_is_fail_not_skip` — absent/partial artifacts produce a failed outcome.
6. `staleness_rejection_with_expired_at_capture_fixture_is_refused` — an envelope already expired at capture is refused as a fixture (it tests the expiry gate, not replay).
7. `dry_run_marker_cannot_pass` — any dry-run/skip marker in the report forces a failed outcome.

## 5. Live-proving status

**LAB VMs DOWN at the time of this design.** No live-lab run has exercised this stage; it has no row in the `--node` run matrix and no report artifacts. Per the parity ledgers, a stage that has never run live is *not proven*, and this design claims nothing otherwise. The stage's first live run is pending (a) the owner-gated implementation review of this document and (b) lab availability. When it runs, the evidence contract is: the stage's own report artifact in the run's report directory, plus the appended matrix row attributed to the implementing commit.

## 6. Explicitly out of scope for this design

- No changes to `rustynetd` enforcement logic — the anti-replay machinery (`traversal.rs:1466-1511`) and the apply path (`daemon.rs:5824`, `5886`, `6162-6188`) are assumed correct per their offline gates; this stage proves them live.
- No changes to the existing `traversal_adversarial` stage's checks or report contract.
- No new cryptography, no new transport, no nonce or signing scheme changes.
- No claim of live-proven status for any role or OS; this is a stage design, and the cross-platform parity matrices are owned by their own ledgers.
