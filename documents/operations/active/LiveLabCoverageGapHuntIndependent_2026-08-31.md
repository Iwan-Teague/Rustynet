# Independent Live-Lab Coverage Gap Hunt — 2026-08-31

**Status:** active — independent follow-up to `LiveLabCoverageGapAudit_2026-08-31.md`
**Method:** fresh cross-reference of the actual stage catalog (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/`) and its validator bodies against the invariants in `documents/SecurityMinimumBar.md`, `documents/Requirements.md`, and `AGENTS.md` §10.7, deduplicated against every existing coverage ledger (see Dedupe Baseline).
**Motivation:** all three of the audit's new release-blocking findings (M-1, M-2, M-3) were independently verified this session as over-elevated (see Calibration). That error pattern — stage *names* read, validator *bodies* not — means the audit may both over-elevate known items and miss real gaps. This document reports only genuinely unlisted gaps and recalibrates how to read the audit.

---

## 1. Dedupe Baseline

Nothing in this document re-reports an item already tracked in one of these ledgers:

| Source | Items excluded from this hunt |
| --- | --- |
| `LiveLabCoverageGapAudit_2026-08-31.md` | M-1..M-12, W-1..W-7, C-1..C-7 |
| `LiveLabCoverageGapDiscovery_2026-08-19.md` | G1–G9 (chaos/negative-control never-run, cross-network unproven, flap narrowness, shared-UDP recovery, relay HP-3, traffic-matrix ICMP/TEST-NET-only, exit-handoff conntrack residue, platform-posture false-green) |
| `LiveLabStageCoverageGapPlan_2026-08-10.md` | G1–G5 + I1–I5 (incl. nas/llm zero live stages, ~25 unreachable columns) |
| `QualityHardeningTodo_2026-07-25.md` | live subset QH-02/25/35/39/42–43/46–49/50–57/64 |
| `CrossPlatformRoleParityRefresh_2026-07-23.md` | mac/win ~0% parity on the engine of record (macro-level; this doc only sharpens specific Linux-only validators, § GAP-6) |
| `BashOrchestratorRetirementProgram_2026-08-22.md` | 44 lost bash-era cells |

Two audit items were *confirmed real* during this hunt but are already tracked, so they are noted only as confirmations, not new gaps: **M-4** (no audit-log tamper-evidence stage — confirmed: the only `tamper`/`audit_log` hits in `stage/` are a comment in `scenario/traversal_adversarial.rs` and the contract-digest unit test in `finalize.rs:299`) and the **nas/llm zero-live-stages** item (confirmed: a word-boundary grep for `\bnas\b|\bllm\b` across `orchestrator/stage/` returns zero hits; but Plan_08-10 already tracks it).

## 2. Catalog Ground Truth

What this hunt read first-hand (file:line under `crates/rustynet-cli/src/vm_lab/orchestrator/`):

- `stage/mod.rs` (570 lines): the full `define_stage_catalog` — chaos family (`ChaosClockAttack` @ `Chaos/T4Security` mod.rs:292 with binary `live_chaos_clock_attack_test` per `chaos.rs:68-71`; `ChaosMembershipAdversarial`, `ChaosPrivilegedBoundary`, `ChaosSignedStateAdversarial` @ T4Security; `ChaosCrashRecovery`/`DaemonFault`/`SigstopSigcont`/`NetworkImpairment`/`ResourceExhaustion` @ T2Resilience), negative-control family (`SignedBundleRejection`/`PlantedResidue`/`WrongNodeSubstitution`/`DaemonKillMidStage` @ T5NegativeControl mod.rs:308-311), both gated behind opt-in flags (mod.rs:109-111) — i.e. cataloged but, per Discovery G2, with zero ledger rows.
- Validator bodies read directly: `role_switch_matrix.rs` (full file, 128 lines), `live_key_custody_validation.rs`, `runtime_acls_validation.rs`, `live_secrets_not_in_logs_validation.rs` (dispatch lines), `scenario/failback_roaming.rs:293-310`, `scenario/traversal_adversarial.rs` (doc comment + check list), `traffic_test_matrix.rs:164-201`, `security_audit_validation.rs:30-32`, `exit_nat_lifecycle_validation.rs`/`exit_demotion_residue_validation.rs`/`blind_exit_dataplane_validation.rs` (existence + role), `deploy_relay.rs:276` comment.
- Grep sweeps: `\bnas\b|\bllm\b`, §10.7 ordering terms (`deploy.*before|ordering|undeploy`), `audit_log|tamper` across `stage/` and `role_validation/`.
- Directory listings: `role_validation/` (19 files: admin_issue, anchor, authenticode, blind_exit, blind_exit_dataplane, dns_failclosed, exit_demotion_residue, exit_dns_failclosed, exit_nat_lifecycle, gossip_convergence, identity_challenge, ipv6_leak, key_custody, mesh_status, mod.rs, relay, runtime_acls, security_audit, service_hardening) and `stage/` (57 files incl. `cross_network/` + `scenario/`).
- Doc heading maps for invariant citations: SecurityMinimumBar §2 (l.8), §3 (l.13), §4 (l.256), §6.B/C/D/E (l.292/353/478/568), §6 test evidence (l.279), §8 (l.737); Requirements §5 (l.165), §12 (l.355), §13 (l.386).

## 3. Genuinely New Gaps (ranked by fail-closed security severity)

### GAP-1 — HIGH: `role_switch_matrix` validates tunnel liveness only; no live stage asserts §10.7 transition side-effect ordering

- **Scenario:** a node transitions client → relay (or client → exit, or exit → blind_exit) under live lab conditions. The signed bundle mutates role/capabilities while service deploy/undeploy and NAT teardown happen as side-effects. An ordering bug (bundle emitted before service deployed; revocation before undeploy; NAT left behind) is exactly the class AGENTS.md §10.7 enumerates.
- **Invariant:** AGENTS.md §10.7 ("Adding serves_relay: deploy service BEFORE emitting signed bundle; Removing serves_relay: undeploy service BEFORE revocation bundle; Exit NAT: tear down BEFORE removing capability (residue = release-blocker); blind_exit is irreversible; all transitions emit append-only audit log entries") — mirroring SecurityMinimumBar §6.D Node Role Transition Controls (l.478).
- **Why uncovered:** `stage/role_switch_matrix.rs` (128 lines) — despite the name — only calls `collect_active_tunnels()` + `verify_tunnels_active()` (lines 7-27, 48-73): "tunnels survived role distribution". It asserts nothing about transition ordering, capability deltas, NAT teardown, irreversibility, or audit entries. No other stage greps positive for transition-ordering assertions; the only ordering mentions in `stage/` are comments (`deploy_relay.rs:276`, `macos_anchor_profile_deploy.rs:5`). The per-side-effect stages that do exist (`exit_nat_lifecycle_validation.rs`, `exit_demotion_residue_validation.rs`, `blind_exit_dataplane_validation.rs`) each cover one directed side-effect, not the *ordering/atomicity* of a transition sequence, and none assert the append-only audit entries.
- **Risk if ships unverified:** a relay bundle could advertise `serves_relay` for a node whose relay service never deployed (peers route frames at a black hole), or an exit demotion could strip the capability before NAT teardown, leaving residue — the exact release-blocker §10.7 names.
- **Stage sketch:** extend `role_switch_matrix` (or add `live_transition_ordering_validation`): after each scripted transition, assert (a) side-effect completion *timestamps* against bundle emission/revocation, (b) no capability advertised without its service verified live, (c) an append-only audit entry exists per transition with the expected transition kind.

### GAP-2 — HIGH: failed relay-service deploy → signed-bundle residue never proven negative

- **Scenario:** inject a failure into the relay service deploy path (undeployable service, port conflict, binary crash) and verify the node does *not* end up advertising `serves_relay` in a signed bundle.
- **Invariant:** §10.7 deploy-before-bundle is fail-closed ordering; SecurityMinimumBar §3 Critical Controls (l.13) — signed state must never advertise capability that cannot be honored.
- **Why uncovered:** no negative stage exists for this. The only related signal is the `deploy_relay.rs:276` comment ("silently skip an undeployable relay") — which is itself the anti-pattern: a silent skip plus a later bundle emission would be exactly the residue. The T5 `PlantedResidue` negative control is opt-in and has zero ledger rows (Discovery G2), and it plants *staged* residue rather than driving a failed service deploy.
- **Risk if ships unverified:** peers receive a validly-signed bundle claiming relay capability for a dead service; frames black-hole until manual intervention. Silent-skip semantics make this a plausible implementation shape, not a hypothetical.
- **Stage sketch:** negative-control stage: break the relay deploy on a candidate node, run the promote path, assert no bundle advertising `serves_relay` is emitted (or that the node self-revokes), and no frames route to it.

### GAP-3 — MED-HIGH: ACL denied-pair preservation across failover/failback path transitions

- **Scenario:** node A has a policy denying pair (A→B). Steady state, the deny is enforced (probe fails). Now force failover relay→direct and back (link flap, relay loss). After *each* transition, re-probe the denied pair.
- **Invariant:** default-deny must survive path changes — `documents/Requirements.md` §5 Security Requirements (l.165) + policy default-deny (AGENTS.md §10.4); a deny attached to a path (direct vs relay) that silently lapses when the path changes is a policy-evaluation-order bug.
- **Why uncovered:** `scenario/failback_roaming.rs:293-310` checks `underlay_leak_samples == 0`, `signed_state_invalid_samples == 0`, and `failback_reconnect_within_slo` — leak and signed-state invariants across the transition, but it **never re-probes ACL denied pairs after failback**. `traffic_test_matrix.rs:164-201` does live default-deny negative probes ("default-deny VIOLATED/INCONCLUSIVE" fail-closed strings), but only at steady state, and (per Discovery G7) only ICMP/TEST-NET breadth.
- **Risk if ships unverified:** policy evaluated per-path with a fail-open default on an unseen path is a classic live-lab-invisible hole: every steady-state test passes, the deny opens exactly when a link transitions.
- **Stage sketch:** extend `failback_roaming` (or the `live_acl_negative_probe` portion of traffic matrix) to re-run the denied-pair probes immediately after each failover and failback completion; fail on any allow.

### GAP-4 — MED: live mid-session wire replay of a stale signed traversal hint

- **Scenario:** an established two-node session is running; an attacker (lab negative actor) re-injects an *old but validly signed* traversal hint onto the wire mid-session. The receiving daemon must reject it via its replay window, not re-negotiate the session toward the stale endpoint.
- **Invariant:** anti-replay at the dataplane-adjacent apply layer — SecurityMinimumBar §4 High Controls (l.256) anti-replay/rollback where state freshness matters.
- **Why uncovered:** coverage is real but at the wrong layer: `scenario/traversal_adversarial.rs` covers forged/stale/wrong-signer/nonce-replay at gate + bundle-load level (`traversal_adversarial_gate_rejects_forged_stale_wrong_signer_and_nonce_replay` lines 51-55; `CHECK_STALE = "stale_traversal_rejected"` line 89; rogue endpoint injection). No stage performs a *live wire injection* of an old hint into an established session and observes session behavior end-to-end. The unit/gate layer proves the gate logic; only a live stage proves the wire path (ordering, caching, re-apply) honors it under a running session.
- **Risk if ships unverified:** a gate that is correct in isolation can still be bypassed by a wire path that re-accepts a cached hint after the replay window check ran once at load.
- **Stage sketch:** scenario stage: establish session, replay a captured stale hint onto the wire (rogue endpoint), assert session endpoint does not move and the daemon logs/counts the replay rejection.

### GAP-5 — MED: signed-state rollback at the dataplane apply layer (old-but-valid epoch on a running mesh)

- **Scenario:** a running mesh; present a *previously valid, older-epoch* signed state to the apply path mid-run and prove end-to-end rejection + watermark enforcement — not just bundle-load rejection.
- **Invariant:** rollback protection (SecurityMinimumBar §4, l.256; §10.5 verify-then-check-epoch-then-apply) enforced where it matters: at apply time on a live node.
- **Why uncovered:** signed-state adversarial coverage exists as control-plane gates (`ChaosSignedStateAdversarial` @ T4Security, never-run per G2) and as offline in-daemon self-audits (`security_audit_validation.rs:30-32`: membership-revoke, revoked-peer-denied, membership-signature, etc. — self-audits, not live wire tests). No live stage drives an old-epoch-but-validly-signed state through the apply path of a running mesh and asserts rejection at the enforcement point.
- **Risk if ships unverified:** a node that validates epochs at load but not at apply accepts a replayed older mesh view under live conditions — membership rollback is a take-over primitive.
- **Stage sketch:** live stage: distribute current state, then replay the previous epoch's signed bundle to a running daemon via the normal distribution path; assert rejection, watermark unchanged, and membership view unchanged.

### GAP-6 — MED: Linux-only enforcement in security validators whose names read platform-neutral (validator-weaker-than-name dimension)

- **Scenario:** the same attacks already staged on Linux — runtime chmod downgrade of key material, secrets surfacing in logs, ACL root-set drift — run on the macOS and Windows guests.
- **Invariant:** key custody (SecurityMinimumBar §6.B l.292), secrets hygiene (§4), default-deny posture (§3) are platform-uniform controls.
- **Why uncovered:** the enforcing binaries are Linux-only by construction: `live_key_custody_validation.rs:57` dispatches to `live_linux_key_custody_test` (validates rejection + recovery of a chmod-downgrade *on a running daemon*, but targets the `client` role, Fanout=Once, Linux binary); `live_secrets_not_in_logs_validation.rs:54` dispatches to `live_linux_secrets_not_in_logs_test`; `runtime_acls_validation` is an nft root-set *posture* check, Linux-only (mac/win reported-skipped, never silent-pass). These stages *skip* on mac/win — honest, but the invariants are then simply unproven there.
- **Dedupe note:** this is *not* the tracked "mac/win ~0% parity" macro item — it is the specific observation that three security validators are weaker than their names suggest on the platforms where they are most needed (macOS file permissions and Windows ACLs differ from POSIX chmod, so the Linux test cannot silently stand in).
- **Risk if ships unverified:** runtime key-custody downgrade on macOS/Windows (DPAPI/Keychain-backed files) is exactly the custody path most likely to differ from Linux, and it has zero live coverage anywhere.
- **Stage sketch:** platform-native equivalents of the three validators (macOS: chmod/ACL probe on the custody path; Windows: ACL probe via `rustynet-windows-native`), same fail-closed assertions as the Linux binaries.

### GAP-7 — LOW-MED: `role_switch_matrix` naming is a coverage-honesty hazard

- **Scenario (meta):** any reader — auditor, release signer, future agent — infers from the stage name that role *transition semantics* are validated. They are not (GAP-1). This is the same name-vs-body error pattern that inflated the 2026-08-31 audit (see Calibration).
- **Why uncovered/in-scope:** coverage honesty is a first-class concern in this repo (audit §9, QH-07 ledger-column contamination). A misnamed stage that green-lights "role switch" while checking only tunnel liveness invites exactly the over-claiming this hunt exists to correct.
- **Stage sketch:** rename to `live_tunnel_survival_after_role_distribution` (or extend per GAP-1 and keep the name).

## 4. Calibration — how to weight the 2026-08-31 audit after this hunt

Independently verified this session:

| Audit item | Verdict | Evidence |
| --- | --- | --- |
| M-1 anchor TLS pinning | **Over-elevated** — already-tracked design contract, not a new release-blocking live gap | anchor design contract docs; audit's own novelty claim fails |
| M-2 enrollment replay | **Refuted** — enforced *and* live-proven (`live_enrollment_restart_validation.rs`; enforcement + ledger row) | stage body + validator |
| M-3 pin-rotation grace | **Partial** — documented-accepted residual, correctly tracked elsewhere, not release-blocking-new | prior ledger |
| M-7 traversal stale-hint replay | **Largely refuted** — `scenario/traversal_adversarial.rs` covers forged/stale/wrong-signer/nonce-replay at gate level (lines 51-55, 89); only the live mid-session wire layer remains (this doc GAP-4, lower severity) | validator body |
| M-10 runtime key-custody downgrade | **Mostly covered** — `live_key_custody_validation.rs` does exactly the live chmod-downgrade-on-running-daemon test; residual is the Linux-only scope (GAP-6) | validator body |
| M-11 protocol-filter ACL breadth | **Partial** — live default-deny negative probes *do* exist (`traffic_test_matrix.rs:164-201`); residual is breadth/topology only (Discovery G7 already tracks the breadth half) | validator body |

**The audit's failure pattern:** §9 admits validator bodies were never read first-hand (M-7/M-8/M-10/M-11 were flagged UNVERIFIED) and Requirements.md was used at heading level only; its research fan-out failed (DeepSeek 402 / Kimi 429). Every item this hunt could check against a body came back over-elevated, refuted, or already-tracked.

**Corrected weighting for the remaining unverified items:**
- **M-4 (audit-log tamper evidence): confirmed real** by this hunt's grep — no tamper stage exists; the only hits are comments and a contract-digest unit test (`finalize.rs:299`). Treat as the audit's most solid remaining finding, though it was already tracked.
- **M-8 (failover/failback denied-pair): confirmed partial-but-real** — and sharpened into GAP-3 (the specific missing assertion is denied-pair re-probing, not failover generally).
- **M-5, M-6, M-9, M-12:** plausible but unproven — not checked against validator bodies this session (see §5). M-5's *platform dimension* is sharpened by GAP-6 (its enforcing binary is Linux-only). Weight these as "likely worth a validator-body read before any release claim," not as established gaps.
- **General rule:** any audit finding whose coverage claim rests on a stage *name* is unproven until the validator body is read. This hunt's GAP-7 exists precisely because one stage name (`role_switch_matrix`) actively misleads.

## 5. Not Checked (explicit limits of this hunt)

- `role_validation/*.rs` validator bodies: directory listed only (19 files); the `stage/` counterparts read are those named in §2.
- `chaos.rs` / `negative_control.rs` bodies beyond doc comments and binary names (their never-run status is already tracked as Discovery G2, so body detail would not change the verdict).
- `scenario/` subdir bodies other than `traversal_adversarial.rs` and `failback_roaming.rs`.
- `security_audit_validation.rs` beyond the doc-comment audit list (lines 30-32) — the 8 Tier-0 self-audits are taken as described.
- nas/llm crates' own binaries (`rustynet-nas`, `rustynet-llm-gateway`) — only their absence from the stage catalog was verified (tracked item).
- M-6 (web/admin RBAC/MFA/CSRF surface), M-9 (host-OS boundary), M-12 (SBOM/deployed-binary provenance breadth) — none verified.
- Clause-level sweep of SecurityMinimumBar §3/§4/§6 (heading-level map only, §2 above) — additional uncovered invariants may exist below the heading level.
- Ledger rows were not re-counted this session (G2's zero-chaos/negctl-rows status is taken from Discovery).

## 6. Recommended Order of Work

1. GAP-1 + GAP-7 together (extend or rename `role_switch_matrix`) — highest severity, smallest change, and it retires a naming hazard.
2. GAP-2 (negative deploy-failure residue) — pairs with GAP-1's ordering assertions.
3. GAP-3 (denied-pair re-probe in `failback_roaming`) — small addition to an existing live scenario.
4. GAP-4 + GAP-5 (live replay layers) — need a wire-injection/old-epoch harness; plan before implementing.
5. GAP-6 (platform-native custody/secrets/ACL validators) — aligns with the mac/win parity program's ordering; do alongside the relevant parity cells rather than standalone.
