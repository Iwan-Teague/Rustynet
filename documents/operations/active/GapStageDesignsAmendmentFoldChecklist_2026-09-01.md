# GAP Stage Designs — Amendment Fold Checklist (2026-09-01)

**Status: PLANNING ONLY — no code.** This checklist exists so that a FUTURE implementation session folds every adversarial-review amendment into its GAP stage design **before any code is written**. No `.rs` file was touched to produce this document, and none may be touched by following it until the fold is complete.

Every GAP implementation remains **OWNER-GATED and lab-pending**: the lab VMs were down on the design/review dates, nothing in any GAP is live-proven, and each design's own closure condition (a recorded pass in the run-matrix ledger at a pinned commit) is still unmet.

This document is a consolidation of already-merged material. It collects, per GAP, every amendment its review requires — faithfully, with the file:line grounding the review itself gives. It does **not** re-derive, re-review, or add findings. Read the two source docs per GAP before folding.

---

## GAP-1 — Role-transition ordering stage

- **Design doc:** `LiveLabTransitionOrderingStageDesign_2026-09-01.md`
- **Review doc:** `LiveLabTransitionOrderingStageAdversarialReview_2026-09-01.md`
- **Review verdict:** READY-WITH-AMENDMENTS (A1–A4, all grounded). With A1–A4 folded, implementation may proceed; the live-proving acceptance gate is unchanged.

Fold checklist (review §9 numbering):

- [ ] **A1 — rename blast-radius checklist.** Add a checklist enumerating every name-keyed reader of `role_switch_matrix` / `live_role_switch_matrix`, all updated in the same change as the rename: `crates/rustynet-cli/src/live_lab_stage_registry.rs:996,1956` (spec `name` + `logical`), `crates/rustynet-cli/src/ops_live_lab_failure_digest.rs:335`, `crates/rustynet-cli/src/live_lab_evidence_verifier.rs:448,1395-1407`, `crates/rustynet-lab-monitor/src/data/run_matrix.rs:984` (TUI coverage column construction), the three MCP binaries (`crates/rustynet-mcp/src/bin/lab_state.rs:68,89,110,7357`, `repo_context.rs:2115`, `ai_agent.rs:6121,10839`), the `scripts/e2e/live_*_role_switch_matrix_test.sh` wrappers and their bin target, the live ledger column family (`documents/operations/live_lab_node_run_matrix.csv`), and `rustynet_live_lab_loop_prompt.md:1256`. Also add the one-sentence anchor-capability-advertisement disambiguation (anchor bundle-pull vs `serves_relay` bundle emission) to design §1.1.
- [ ] **A2 — audit-assertion scope (pin the drive mechanism).** Pin all four transition kinds to the public-CLI drive path per node (matching §2.4(a)); scope assertion (c) to CLI-driven transitions; pre-register the verified fact that daemon-side bundle application emits no audit entries today (zero `append_role_audit_entry` call sites in `rustynetd`; sole production executor `execute_role_plan`, `crates/rustynet-cli/src/main.rs:19546`, appender `:19633`/`:19636`); add an offline source-scanning test pinning this wiring fact so a future daemon-side emitter flips the expectation deliberately.
- [ ] **A3 — state-based fallback anchor.** The ordering fallback must anchor liveness to an effect the transition itself performed: a post-transition deploy/restart acknowledgment with fresh process identity (fresh PID / boot-id / start-time), or a first-ever observation against a pre-transition snapshot recording the service absent. Every fallback acceptance records its anchor in the evidence artifact; an unanchored acceptance is a failure, never a pass.
- [ ] **A4 — sampling window honesty.** §2.1(b) requires a trailing stability check — two spaced liveness probes (fixed settle interval recorded in the artifact) with process-identity equality across them — and must state its semantics as bounded-window liveness evidence, not continuous availability (residual crash-after-window risk documented as out of claim).

GAP-7 note: the hunt's GAP-7 (`role_switch_matrix` naming hazard, `LiveLabCoverageGapHuntIndependent_2026-08-31.md:85`) is **folded into GAP-1's rename** — retiring the misleading name is A1's precondition, so GAP-7 needs no separate design or section here.

---

## GAP-2 — REFUTED (no design)

The coverage-gap hunt's GAP-2 (failed relay-service deploy → signed-bundle residue) was **refuted during follow-up and stays out of scope**: no design was written, no review exists, and nothing is folded. The GAP-1 design and its README index line both record this explicitly.

---

## GAP-3 — ACL-deny-across-failover stage

- **Design doc:** `LiveLabAclDenyAcrossFailoverStageDesign_2026-09-01.md`
- **Review doc:** `LiveLabAclDenyAcrossFailoverStageAdversarialReview_2026-09-01.md`
- **Review verdict:** READY-WITH-AMENDMENTS (A1–A8). All three structural risks (self-defeating attribution rule, `traffic_test_matrix` positive-probe collision, ungated new checks) are amendment-fixable, not rework.

Fold checklist (review §8 numbering):

- [ ] **A1 — explicit verdict gates (mandatory).** Specify, verbatim, the three new `if !checks.passed("<exact name>")` arms appended to `execute`'s verdict chain with per-check failure summaries; state that `ScenarioOutcome::passed(checks)` aggregates nothing (`crates/rustynet-cli/src/vm_lab/orchestrator/cross_network/scenario/mod.rs:222-231`) and that `record` on an undeclared name silently appends (`mod.rs:125-135`); extend the declare/aggregate test pattern (`failback_roaming.rs:952-966`) to prove the new names are declared AND gated.
- [ ] **A2 — window semantics for the attribution rule.** Mid-transition samples with unreachable control are *expected inconclusive* — recorded, not failing; `Reachable` on the denied pair is `VIOLATED` unconditionally (drop the control precondition from offline test 3); each post-transition settled window (final round after `POST_ADVERTISE_SETTLE`, plus the post-failback settled point) must contain ≥1 attributed pass (`Blocked` denied + `Reachable` control, same window); every window sampled or the stage fails.
- [ ] **A3 — fourth-node integration plan.** Specify which early stages client-2 joins via `ctx.assignments`, and how `traffic_test_matrix`'s positive-probe loop learns `client-2 → exit` is expected-blocked (a per-pair expectation map keyed on the allow spec, or equivalent). Cite `crates/rustynet-cli/src/vm_lab/orchestrator/stage/traffic_test_matrix.rs:27,101-161,151-155` and the stage order (`plan.rs:882` before `:909`) explicitly.
- [ ] **A4 — mechanism narration correction.** Reframe the asserted property as "the re-derived generation excludes the absent pair" (enforcement absence: no WG peer entry, no route — `daemon.rs:14159-14229`; generation replacement `:10345-10370`, QH-04 comment), not "routable-but-denied" or evaluator-attached deny; note the policy gate is all-or-nothing (`PolicyDenied` aborts the bundle and the daemon restricts fail-closed, `daemon.rs:10326-10339`) and re-runs every reconcile tick; qualify the "nftables ACL surface" phrase (no per-pair nft ACL generation in the cited code).
- [ ] **A5 — probe surface spec.** The existing adapter cannot express a pair-targeted probe — `probe_denied_peer` maps any ping failure to `Blocked` (`linux_traffic.rs:458-471`; same shape `windows_traffic.rs:133-147`, `macos_traffic.rs:363-376`) and `ping_mesh_peer` never returns `Blocked` on Linux (`:446-453`). Specify the new probe's result shape (Blocked / Reachable / Error) and the control-`Error` ⇒ inconclusive mapping.
- [ ] **A6 — timing and alias budget.** State the effective sampling period with probes included (base interval 1 s, `endpoint_switch.rs:240`; denied probe `ping -c 1 -W 2`, control `ping -c 3 -W 5`); either move the pair probes out of the SLO-critical in-loop path or explicitly re-baseline the `failback_reconnect_within_slo` interaction; add client-2's address to `choose_alias`'s avoid list (`failback_roaming.rs:332-339`).
- [ ] **A7 — artifact completeness.** Add the new counters and per-window probe outcomes to the SLO summary artifact (`failback_roaming.rs:763-783`) so a pass is re-verifiable from machine-readable evidence, per the design's own §2.3 promise.
- [ ] **A8 — survey correction.** Cite `probe_service_blocked_from_client` (`BYPASS_CHECKS`, `remote_exit_common.rs:23-28`; consumed at `failback_roaming.rs:394-413`) as the in-family negative-probe precedent and source of the missing-evidence fail-closed convention (`remote_exit_common.rs:118-120`); correct the citation drift (policy gate `daemon.rs:5400-5463`, not 5368-5431; empty-set test `rustynet-policy/src/lib.rs:1075`, not 1063).

---

## GAP-4 — Traversal hint wire-replay stage

- **Design doc:** `LiveLabTraversalHintWireReplayStageDesign_2026-09-01.md`
- **Review doc:** `LiveLabTraversalHintWireReplayStageAdversarialReview_2026-09-01.md`
- **Review verdict:** READY-WITH-AMENDMENTS (A1–A8). All eight are documentation-level amendments; A1–A4 change what the stage must actually assert to be evidence.

Fold checklist (review §3 numbering):

- [ ] **A1 — re-aim the mechanism.** The bundle-load watermark/anti-rollback layer is the primary live rejection under test (`daemon.rs:15486-15501`, surfaced at `:5902-5910` as `TraversalBootstrapError::ReplayDetected`); `validate_signed_coordination_record` (`traversal.rs:1466-1511`) is a secondary, in-envelope nonce-replay layer. Update design §1.3/§3 accordingly.
- [ ] **A2 — honest framing.** Rename/relabel the threat model from "wire replay" to **bundle-path replay with a forced refresh** (or add an explicit fetch-channel MITM scope); define vantage as assertions (injector not on the coordinator, delivery via the node's real bundle path, load via a real refresh trigger), not self-attestation.
- [ ] **A3 — fixture-guard additions.** Record the envelope watermark and assert it orders **older** than the live watermark at injection; derive nonce consumption from the receiving node's persisted watermark state, not harness bookkeeping; assert single-snapshot intactness (`daemon.rs:15455-15463`, duplicate-pair rejection `:15472-15477`) to preclude `InvalidFormat` false rejections; carry envelope nonce + payload digest as the report correlation id.
- [ ] **A4 — attributable rejection.** Require a forced or explicitly observed refresh trigger post-injection (`refresh_traversal_hint_state` fires only at `daemon.rs:6015, 8755, 8882, 8993, 9220, 10375`); correlate rejection records to the injected envelope's nonce + digest; specify the log channel and its retention for the soak window; detect and deliberately handle the fetch-race overwrite (`state_fetcher.fetch_traversal()`, `daemon.rs:5949-5953`).
- [ ] **A5 — daemon-clock observations.** Record the daemon-observed `now_unix` at capture AND at injection via a specified channel (daemon status field or log line); evaluate the staleness-as-pass-reason rule against daemon clocks only (`unix_now()` is daemon-internal).
- [ ] **A6 — isolation and teardown.** Place the stage last in a run (or isolate it); teardown restores the legitimate bundle and verifies recovery from the enforced-mode fail-closed state (`daemon.rs:8029-8033` hard-stop; `:5932-5935` restrict path) before any later stage observes the node.
- [ ] **A7 — additional unit test.** Validator failure mid-soak / incomplete soak is **fail** even when the report file exists and some checks recorded pass (sibling precedent `traversal_adversarial.rs:232-237,274-279`, tested at `:516-537`).
- [ ] **A8 — host-capability scope note.** Reading daemon state (hint generation, `traversal_hint_error`, applied endpoint pair) from the receiving node requires a new validator-side host capability beyond the current `ScenarioHost` surface; account for it in design §6.

---

## GAP-5 — Signed-state rollback apply-layer stage

- **Design doc:** `LiveLabSignedStateRollbackApplyLayerStageDesign_2026-09-01.md`
- **Review doc:** `LiveLabSignedStateRollbackApplyLayerStageAdversarialReview_2026-09-01.md`
- **Review verdict:** READY-WITH-AMENDMENTS (5 required amendments; grounding PARTIAL confirmed). As written, the design would grade a **correct** daemon as failed and forbids the only apply path that exists — both fixable on paper.

Fold checklist (review §9 numbering; this review numbers its amendments 1–5, no `A` prefix):

- [ ] **1 — expected-reason set (§2.3-4, §2.5, §1.2).** Replace "epoch chain / replay watermark" with the ordered, code-accurate set on the `membership apply` IPC response: primary `previous state root mismatch` (`PrevStateRootMismatch`, `membership.rs:1052-1054` — fires FIRST, before the epoch-chain guard), defensive `epoch chain mismatch for membership update` (`:1055-1059`), id-dedup `membership replay detected` (`ReplayDetected`, `:737-742`). Remove `EpochRegression` from the apply-path assertion — it is constructed only in `verify_attested_snapshot` (`:1513`), a different surface. Rewrite the §2.5 first offline unit test to expect prev-root mismatch for the genuine-old-bundle shape; add a root-forged shape to actually reach the epoch-chain guard.
- [ ] **2 — mechanism wording (§2.3-3, §4).** The replay goes through the daemon's membership-apply ingestion entry — local IPC `membership apply` (`ipc.rs:92-94`, dispatch `daemon.rs:9758`), driven with the admin-role credential (role gate `daemon.rs:36873-36883`) — which IS the legitimate apply surface and its documented dual gate (`daemon.rs:9739-9744`). Delete the "gossip/bundle distribution channel … not a hand-crafted IPC poke" clause; explicitly forbid the snapshot-file-drop mechanism instead.
- [ ] **3 — capture model (§2.2).** Capture the envelope bytes at the **mint point** (the lab distribution path delivers snapshot files, not envelopes — `adapter/linux_membership.rs:136` et al.), pin a SHA-256 digest in the report, re-verify it before replay, and require an offline decode + signature sanity check against the epoch E-2 state as a precondition. Add a validity-window guard (`now < expires_at_unix`) graded `Blocked` on expiry. Any `decode failed`/`SignatureInvalid`/`Expired`/role-refusal rejection grades `Blocked`, not `Failed`.
- [ ] **4 — observability (§2.3-2/3/4).** Name the concrete surfaces: the IPC response string (`"membership apply rejected: …"`, `daemon.rs:9808`) and the snapshot/log/watermark artifacts per OS (Linux `/var/lib/rustynet/…`, macOS `/usr/local/var/rustynet/membership/…`, Windows `C:\ProgramData\RustyNet\membership\…`), with before/after **byte digests** of all three in addition to parsed `(epoch, state_root)` fields (the field is `state_root`, not `max_epoch` — `membership.rs:1546-1549`).
- [ ] **5 — fail-loud wiring (§2.3-5, §2.4).** Inherit the `AuditVerdict` precedent verbatim (`security_audit.rs:104-125`): `Blocked` distinct from `Failed`, both fail the stage, `"blocked"` outranks skip/pass in the run-matrix `status_rank`; any reported-skipped node forces `Skipped` (naming the node on disk, `:89-96`); a missing report artifact is a failure.

---

## GAP-6 — Cross-platform custody / secrets / ACL stage

- **Design doc:** `LiveLabCrossPlatformCustodySecretsAclStageDesign_2026-09-01.md`
- **Review doc:** `LiveLabCrossPlatformCustodySecretsAclStageAdversarialReview_2026-09-01.md`
- **Review verdict:** READY-WITH-AMENDMENTS (A1–A7; A1 and A3 required, A2/A4–A7 alongside). Grounding fully CONFIRMED; the design is purely additive.

Fold checklist (review §8 numbering):

- [ ] **A1 (required, §3/§4) — delete the custody-watcher fiction.** No watcher exists on any platform (`macos_key_custody.rs` / `windows_key_custody.rs` are pure check-time collect+evaluate). Pin **restart-based rejection** mirroring `live_linux_key_custody_test`: baseline custody check clean → chmod/ACL attack → daemon restart → rejection asserted as daemon-failed-to-start OR custody-check drift → restore → restart → recovery. A daemon still running under a downgraded key at assertion time is a **failure**, not a pass. macOS detection: launchd restart + `macos-key-custody-check`; Windows: native argv-only ACL helper + service restart + `windows-key-custody-check`.
- [ ] **A2 (§4 Attack B) — DPAPI probe discipline.** Assert inertness via custody-check status plus hash/size only; never attempt decryption; log no key material.
- [ ] **A3 (required, §5.1) — pin the secrets pattern set.** No canonical forbidden-pattern table exists in the repo; pin the new `secrets-not-in-logs-check` to the proven scanners (64-hex WireGuard key, 32-hex ed25519 key, base64 EC-key headers — `live_linux_secrets_not_in_logs_test.rs`), define the checked shapes explicitly in the design so `overall_ok=true` is meaningful evidence, and record any additional shapes as new scanner requirements.
- [ ] **A4 (§5.2) — absent-secret honesty.** The macOS/Windows live secrets binaries must treat "enrollment secret absent on the node → stimulus path not exercised" as a reported limitation in the report artifact, never as a pass (the Linux binary's own comment, lines 113–118, records a former generate-only stimulus removed as a false-pass mode — a weak stimulus is a known failure mode here).
- [ ] **A5 (§8 prereq 4) — doc-drift prerequisite.** Keep the stale-comment correction prerequisite; the exact lines are `key_custody_validation.rs:19-21` and `runtime_acls_validation.rs:17-20` (both claim a reported-skip that is dead code today).
- [ ] **A6 (citations) — §1 fixes.** The dispatch-table citation "532–568" should read "532 onward"; path citations should include the `orchestrator/` segment (`crates/rustynet-cli/src/vm_lab/orchestrator/{role_validation,stage,adapter}/…`).
- [ ] **A7 (keep) — Windows §4.7 gating confirmed.** Windows live custody/secrets stages remain reported-skipped behind the `status`-subcommand gap until it lands; the identity challenge fails closed (`adapter/node_adapter.rs:463-479, 525-530`). Retained as an amendment to record the review's confirmation of the gating mechanism.

---

## Cross-cutting themes

The same failure patterns recur across the five reviews. When folding, check each design against all of them, not only its own amendments:

1. **Rename / name-keyed blast radius.** A stage name is read by far more tooling than the stage registry: failure digest, evidence verifier, lab-monitor coverage columns, MCP stage tables, e2e wrappers, ledger column family, prompt docs (GAP-1 A1; the GAP-6 review's A6 path-prefix note is the same lesson at citation scale). Any rename moves every reader in one change, or evidence integrity silently degrades.
2. **Assertion aimed at the wrong enforcement layer.** Both a mechanism-first read and a reason-first read can name a layer the fault never reaches: GAP-4's replay defense lives at the bundle-load watermark, not `validate_signed_coordination_record` (A1); GAP-5's `PrevStateRootMismatch` fires before the epoch-chain guard, and `EpochRegression` lives on a different surface entirely (amendment 1). Verify the check order of the enforcement point before pinning an expected reason.
3. **False pass via mischaracterized enforcement model.** If the asserted property names a state the system cannot produce, the probe proves nothing: GAP-3's "routable-but-denied" is enforcement-absence (A4); GAP-6's "checker sees drift" is weaker than Linux's restart-based rejection — a daemon can run happily under a downgraded key (A1). Characterize what the code actually enforces before asserting it.
4. **`ScenarioOutcome::passed` / verdict-gate wiring.** Aggregation helpers pass unconditionally; declared checks with fail-closed defaults are inert until explicitly gated. Every new check needs an `if !checks.passed(<name>)` arm (GAP-3 A1), an incomplete-soak unit test (GAP-4 A7), or the `AuditVerdict`-style status_rank inheritance (GAP-5 amendment 5). A recorded-but-ungated check fake-passes.
5. **Fail-closed `Blocked`-vs-`Failed` grading.** Infrastructure/plumbing faults (capture corruption, validity-window miss, role refusal, unreachable entry, fetch race) are `Blocked`, not `Failed` — they say nothing about the control under test (GAP-5 amendments 3/5; GAP-4 A4/A6; GAP-3 A2's expected-inconclusive mid-transition samples). Both grades fail the stage; the distinction keeps the signal attributable.
6. **Research-tier + lab-availability constraints.** Every review is design-read-plus-code-verification only: the lab VMs were down, no live reproduction was performed, and each review deliberately under-claims confidence. Runtime-dependent verdicts are flagged as such and remain gated on a live run — the fold changes designs, not evidence.

---

## Shared hard precondition

For every GAP, design closure is not the finish line. No parity or coverage claim is made until the run-matrix ledger carries a **green row for the new stage in `documents/operations/live_lab_node_run_matrix.csv` at a pinned commit** — and the pass/fail verdict is taken **from the stage's own report artifact** in the run's report directory (its `status` plus its data block), never from the ledger column alone (AGENTS.md §12.3; QH-07). Until then, every GAP here remains design-amended, owner-gated, and lab-pending.
