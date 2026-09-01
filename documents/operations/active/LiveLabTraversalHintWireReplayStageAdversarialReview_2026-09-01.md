# Adversarial Review — Live-Lab Traversal Hint Wire-Replay Stage (GAP-4)

Date: 2026-09-01
Subject: `documents/operations/active/LiveLabTraversalHintWireReplayStageDesign_2026-09-01.md` — independent adversarial review before implementation.
Method: read-only design + code review against the current worktree. No lab run was performed; LAB VMs are down and nothing in this review is live-proven.

## 0) Confidence and scope

This review reads the design document and the code it cites (primarily `crates/rustynet-cli/src/bin/traversal_adversarial.rs`, `crates/rustynetd/src/traversal.rs`, and `crates/rustynetd/src/daemon.rs`). Every code citation below was verified against the source in this worktree. Conclusions about live behavior are inferences from code structure, not laboratory observations; where a claim depends on runtime conditions (refresh scheduling, fetch races, clock offsets), it is flagged as such.

Two factual corrections to the design's citations, noted up front because later sections depend on the corrected lines:

- `refresh_traversal_hint_state` is defined at `daemon.rs:5856`, not 5824 as §1.3 cites. `traversal_hints` is at `daemon.rs:4701` (design says 4671) and `traversal_hint_error` at `daemon.rs:4707` (design says 4677). The fingerprint memo spans roughly `6195-6230` (design says 6162-6188).
- `apply_traversal_authority_to_peers` is defined at `daemon.rs:8021-8083`; the design's reference to 5886 points at a call site inside the refresh path, not the function itself.

The design's citations of `traversal.rs:1466-1511` (`validate_signed_coordination_record`) and of `traversal_adversarial.rs` (§1.1 and §1.2) are accurate.

## 1) The decisive architecture fact the design does not state

Traversal hints do not arrive over a per-hint wire protocol on the node. `traversal_hints: Option<TraversalBundleSetEnvelope>` (`daemon.rs:4701`) is loaded **from disk** by `refresh_traversal_hint_state` (`daemon.rs:5856-5937`) via `load_traversal_bundle_set(&self.traversal_bundle_path, ...)` (`daemon.rs:5874-5880`), and the bundle file itself is delivered by the control-plane fetch: `state_fetcher.fetch_traversal()` inside `refresh_signed_state_with_reason` (`daemon.rs:5949-5953`). The envelope's freshness is anchored by a persisted `TraversalWatermark { generated_at_unix, nonce, payload_digest }` (`daemon.rs:15481-15485`), with anti-rollback enforced at load time: an envelope whose watermark orders **Less** than the previous watermark, or **Equal** with a different digest, is rejected as `TraversalBootstrapError::ReplayDetected` (`daemon.rs:15486-15501`).

This matters because replay defense against an **old envelope** lives at the bundle-load/watermark layer, not in `validate_signed_coordination_record`. That function is called only from `validated_traversal_coordination_schedule` (`daemon.rs:8099-8147`), which consumes coordination records **already loaded and signature-verified** from an accepted envelope (`verified_traversal_coordination_index`, populated at `daemon.rs:5846-5853`). Its nonce replay window (`replay_window.verify_and_record`, `traversal.rs:1504`) guards lazy per-pair use of records *within* an accepted envelope. An old, previously applied envelope never reaches that layer — it is rejected earlier, at the watermark check, and surfaces as `traversal_hint_error = Some(TraversalBootstrapError::ReplayDetected...)` set in the refresh error path (`daemon.rs:5902-5910`).

Consequence for the design: "inject an old validly signed hint onto the wire" does not map onto a wire in the daemon. The injection medium is the bundle file (or the fetch channel that writes it), and the live rejection under test is primarily the watermark anti-rollback check.

## 2) Attack vector-by-vector findings

### 2.1 Attack 1 — Is the grounding real?

**Verdict: the gap is real; the cited mechanism is the wrong layer.**

The design's claim that no stage exercises a live signed-old-hint replay is confirmed. `TRAVERSAL_GATE_TESTS` (`traversal_adversarial.rs:50-56`) runs three rustynetd unit tests through `run_required_test` (`traversal_adversarial.rs:184-199`, short-circuit at 180-183) — these execute at `cargo test` level, not against a live mesh. The endpoint-hijack validator (`live_linux_endpoint_hijack_test`, `traversal_adversarial.rs:62`) injects an **unsigned, fabricated** endpoint (`203.0.113.44`, lines 82-85); no validly signed stale material is ever replayed. GAP-4 is a genuine gap.

However, §1.3 and §3 frame the live rejection under test around `validate_signed_coordination_record`. As established in §1 of this review, a replayed old envelope is rejected at the bundle-load watermark layer (`daemon.rs:15486-15501`, surfacing via `daemon.rs:5902-5910`) before the coordination-record layer is ever consulted. A stage built to "prove `validate_signed_coordination_record` rejects a replayed hint live" would either prove nothing (the layer is never reached) or produce rejection records attributable to the wrong mechanism. **Amendment A1:** re-aim the mechanism wording — the bundle-load watermark/anti-rollback layer is the primary live rejection under test; `validate_signed_coordination_record`'s nonce-replay window is a secondary, in-envelope layer that only becomes exercisable if the stage also replays records inside a *freshly accepted* envelope (a different, narrower experiment).

### 2.2 Attack 2 — Fixture validation: is the step-2 guard sufficient?

**Verdict: necessary, not sufficient. Four additions required.**

The design's step-2 guard (verify signature, confirm consumed nonce, confirm within TTL at capture) is directionally right but incomplete against how the daemon actually loads bundles:

1. **No wire capture point exists.** The transport is a signed bundle **file** written by the fetch path. "Capture from the wire" is not constructible; the fixture must capture from the node's bundle path, and the design should say so.
2. **"Nonce already consumed" is daemon-internal state.** The replay window lives inside the receiving daemon; harness-side tooling cannot observe it. The only sound evidence of consumption is receiver-side: the envelope was previously applied, therefore its watermark (nonce + digest) is recorded in the receiving node's persisted watermark state. The fixture guard must derive consumption from the receiving node's watermark/generation history, not from harness-local bookkeeping.
3. **Capture intactness.** `load_traversal_bundle_set` requires every bundle entry to share a single `generated_at`/`expires_at`/nonce snapshot (`daemon.rs:15455-15463`, otherwise `InvalidFormat`) and rejects duplicate coordination pairs (`daemon.rs:15472-15477`). A partial or re-assembled capture fails as `InvalidFormat` — a rejection reason that is *not* replay. If the stage reads "rejection observed" as pass regardless of reason, a mangled fixture manufactures a false pass. The fixture must record the envelope's watermark and assert it orders **older** than the live watermark at injection time.
4. **Correlation identity.** The fixture should record the envelope's nonce + payload digest as the correlation id carried into the report, so a rejection record can be tied to *this* envelope (see §2.3).

**Amendment A3** covers items 2-4.

### 2.3 Attack 3 — Silent drop and attributable rejection

**Verdict: the observable the design names is real, but three failure modes can still yield a silent drop or a misattributed pass.**

The good news first: `traversal_hint_error` is set on every failure path of `refresh_traversal_hint_state` (watermark load failure `daemon.rs:5866-5872`; persist failure `5884-5889`; `ReplayDetected`/`Stale`/`InvalidFormat` `5902-5910`), and `apply_traversal_authority_to_peers` hard-stops when it is present (`daemon.rs:8029-8033`). Rejection is therefore observable from daemon state.

The hazards:

1. **Evidence evaporation.** A successful refresh clears the error (`traversal_hint_error = None`, `daemon.rs:5892`). If the coordinator pushes a fresh bundle mid-soak, the next successful refresh overwrites the error, and a poll that arrives late sees a clean daemon. The "structured log stream" alternative in §3.3 is unspecified: which log, what retention, what correlation id. Without a correlation id tying the log line to the injected envelope's nonce/digest, an unrelated stale-fetch failure can be misread as the replay rejection.
2. **The injected file is only observed at the next refresh trigger.** `refresh_traversal_hint_state` fires only at specific call sites (`daemon.rs:6015, 8755, 8882, 8993, 9220, 10375`). If the injector writes the bundle and no refresh trigger fires during the soak, the file is simply never read — a true silent drop, correctly scored as fail by §3.3, but for a reason (no trigger) that makes the *test itself* vacuous. The stage must force or observe an actual refresh trigger after injection.
3. **Fetch race.** `state_fetcher.fetch_traversal()` may re-pull the coordinator's current bundle over the injected file before the daemon reads it. The rejection never happens; endpoint stays immobile; no error. This is a fail per the design, but it is an environmental flake the stage should detect and retry deliberately, not silently absorb.

**Amendment A4:** attributable rejection requires (a) a forced or explicitly observed refresh trigger post-injection, (b) rejection records correlated to the injected envelope's nonce + payload digest, and (c) a specified log channel with retention adequate for the soak window.

### 2.4 Attack 4 — Clock skew

**Verdict: the guard's direction is right; the observation channel is unspecified and is the residual risk.**

Staleness lives at **two** layers: the load layer (`parse_traversal_bundle_section` enforces `max_age_secs` → `Stale`, and future-dating via max clock skew) and the record layer (`CoordinationExpired`, `traversal.rs:1486-1488`). Skew shifts the rejection reason class between `ReplayDetected`, `Stale`, and `CoordinationExpired`; the design's rule (staleness acceptable as pass reason only when the envelope was within TTL at capture) correctly prevents a skew-shifted expiry from being laundered into a replay pass.

The gap: "within TTL at capture" is only meaningful on the **daemon's** clock, and the design does not say how the harness observes it (`unix_now()` is internal to the daemon). Harness-clock TTL evaluation is defeated by harness↔daemon skew. The report must record the daemon-observed `now_unix` at capture **and** at injection, via a specified channel (daemon status field or log line), and the staleness pass-reason rule must be evaluated against those daemon-clock observations. **Amendment A5.**

### 2.5 Attack 5 — Vantage honesty

**Verdict: the design's vantage language overclaims; the honest framing is bundle-path replay.**

"Attacker vantage recorded in report" is self-attestation by the injector — unverifiable after the fact. More fundamentally, the achievable delivery paths are: (i) writing the node's bundle path directly — file-level injection requiring node access, i.e. effectively root, which is outside the threat model the stage claims to test; (ii) MITM of the control-plane fetch channel — a capability that does not exist in the lab today; (iii) a compromised coordinator — explicitly out of scope.

Path (i) is what the stage will actually do, and it is still valuable: it proves the live watermark anti-rollback and the enforced-mode hard-stop under a real refresh, on a real session. But the stage must say what it is: **bundle-path replay with a forced refresh**, not wire replay. The vantage guard should assert, rather than self-attest: the injector did not run on the coordinator, delivery went through the node's real bundle path, and the load occurred through a real refresh trigger. **Amendment A2** (renaming/framing) and the assertion half of A4.

### 2.6 Attack 6 — New sibling stage: ordering, interaction, and scope creep

**Verdict: sibling placement is reasonable; four operational hazards are unaddressed.**

1. **Host capability gap.** The sibling validator pattern (`ScenarioHost` in `traversal_adversarial.rs`) runs binaries over SSH and reads reports. This stage additionally needs to read daemon state (hint generation, `traversal_hint_error`, applied endpoint pair) from the receiving node — a new host capability. The design's §6 says no changes to existing code, which is right for rustynetd but leaves this validator-side surface change unaccounted. **Amendment A8.**
2. **Collateral fail-closed.** A rejection leaves `traversal_hints = None` and `traversal_hint_error = Some(...)`; `apply_traversal_authority_to_peers` then hard-stops (`daemon.rs:8029-8033`), and in enforced mode the trailing sync path can restrict/fail-closed the node (`daemon.rs:5932-5935`). The node loses traversal authority until the coordinator refreshes. Run later stages after this one on the same node and they inherit the damage. The stage needs explicit run placement (own run, or last in sequence) and a teardown that restores the legitimate bundle and confirms recovery. **Amendment A6.**
3. **Session definition.** The existing cross-network topology is three hosts (client, exit, probe — `traversal_adversarial.rs`). The design says "2-node established session" without mapping which peers form the session under test or which node receives the injection. It must name the client↔exit pair and the receiving node explicitly.
4. **Teardown ordering.** Restoring the legitimate bundle must happen before any stage that re-reads traversal state, and the restore itself must pass the watermark check (the injected envelope's watermark, if it were ever accepted, would poison later legitimate bundles — the fail-closed behavior prevents this, but the teardown should verify the live watermark matches the coordinator's current one).

### 2.7 Attack 7 — Fail-loud contract

**Verdict: sound as far as it goes; one unit test missing.**

The design's §3.3 checks mirror the sibling's fail-closed contract (declare checks, default-fail, record from report only — `traversal_adversarial.rs:149-155`, default-fail discipline tested at 738-745). The five named failure→fail mappings are correct.

The gap: the sibling precedent deliberately allows a validator to exit non-zero **and still contribute a report** (`traversal_adversarial.rs:232-237, 274-279`; "the report is the evidence, not the exit status", tested at 516-537). If the new stage copies that pattern, an injector that crashes *after* writing a partial report but *before* completing the soak leaves a report whose checks were never exercised — default-fail saves the unrecorded ones, but a partially recorded soak (some checks pass, injection never confirmed delivered) can read as a narrow pass. §4's test list covers missing-report and unparseable-report but not this case. **Amendment A7:** add a unit test — validator failure mid-soak / incomplete soak is fail even when the report file exists and some checks recorded pass.

### 2.8 Attack 8 — Does the stage weaken existing security?

**Verdict: confirmed safe, with one hygiene caution.**

§6 explicitly changes nothing in `rustynetd` or the existing adversarial stage; the review found no path by which the new stage relaxes any enforcement. One caution: the fixture validator performs signature verification of captured envelopes. It must reuse the same verifier key path and parse/verify code path as the daemon — no parallel validation implementation that could drift from the hardened one (one-execution-path rule). This is a note for implementation, not a defect in the design.

## 3) Overall verdict

**READY-WITH-AMENDMENTS.**

The grounding is real (nothing live-proves a signed stale-hint replay), the fail-loud contract is sound, and the sibling-stage placement fits the established pattern. But the mechanism as written targets the wrong layer, the "wire" framing does not match the bundle-file transport, and the attributable-rejection check has three independently sufficient failure modes (evidence evaporation, missing refresh trigger, fetch race) unless amended.

### Amendments

1. **A1 — Re-aim the mechanism.** The bundle-load watermark/anti-rollback layer (`daemon.rs:15486-15501`, surfaced at `5902-5910`) is the primary live rejection under test; `validate_signed_coordination_record` is a secondary, in-envelope layer. Update §1.3/§3 accordingly.
2. **A2 — Honest framing.** Rename/relabel the stage's threat model from "wire replay" to bundle-path replay (or add an explicit fetch-channel MITM scope); define vantage as assertions (injector not on coordinator, delivery via real bundle path, load via real refresh trigger), not self-attestation.
3. **A3 — Fixture guard additions.** Record the envelope watermark and assert it orders older than the live watermark; evidence nonce consumption from the receiving node's watermark state (not harness bookkeeping); assert single-snapshot intactness to preclude `InvalidFormat` false rejections; carry envelope nonce + digest as the report correlation id.
4. **A4 — Attributable rejection.** Require a forced or explicitly observed refresh trigger post-injection; correlate rejection records to the injected envelope identity; specify the log channel and its retention for the soak window; detect and deliberately handle the fetch-race overwrite.
5. **A5 — Daemon-clock observations.** Record the daemon-observed `now_unix` at capture and injection via a specified channel; evaluate the staleness-as-pass-reason rule against daemon clocks only.
6. **A6 — Isolation and teardown.** Place the stage last in a run (or isolate it); teardown restores the legitimate bundle and verifies recovery from the enforced-mode fail-closed state before any later stage observes the node.
7. **A7 — Additional unit test.** Validator failure / incomplete soak mid-run is fail even when a report exists with some checks recorded pass.
8. **A8 — Host-capability scope note.** Reading daemon state (generation, error, endpoint pair) requires a new validator-side host capability beyond the current `ScenarioHost` surface; account for it in §6.

All eight are documentation-level amendments to the design; none blocks implementation on its own, but A1-A4 change what the stage must actually assert to be evidence.
