# Rustynet Full TODO Inventory — 2026-07-28

Status: active repository-wide roll-up (raw capture, not curated)

Snapshot date: 2026-07-28

## 0. What this file is

**As of 2026-07-28, every open/outstanding item in every dated TODO-bearing
document in this repository has been captured into this file, up to this
point in time.** The sweep covered all 291 markdown docs under `documents/`
(117 in `operations/active/`, 43 in `operations/` non-active, 17 top-level
plus the 4 repo-root prompt docs) with full-file reads or grep-assisted
targeted reads, and a direct code-level grep of `crates/`, `third_party/`,
`scripts/`, `gui/`, and `fuzz/` for `TODO`/`FIXME`/`XXX:` markers.

This supersedes **[RustynetUnifiedTodoLedger_2026-07-10.md](./RustynetUnifiedTodoLedger_2026-07-10.md)**
as the current master roll-up (that file is now 18 days stale as of this
snapshot; a pointer to this file has been added at its top). Everything that
ledger's own §2–§22 tracked is either re-captured here under its owning
source ledger, or superseded by more current status found during this sweep.

**This is a raw capture, not a filtered priority list.** Nothing here was
judged for importance — every item that read as open, unresolved, unchecked,
or "not yet done" in its source document was kept, including items later
found to be already-resolved-but-undocumented or duplicated across sibling
docs (both are called out explicitly where found, see §2 below).

**This is a point-in-time snapshot, not a live tracker.** Unlike the focused
ledgers it draws from, nothing updates this file automatically as work
lands. Treat it as "what the doc tree said was open on 2026-07-28" — re-run
the same sweep methodology (or a narrower one) before trusting it as current
beyond a few weeks, exactly as this snapshot itself found necessary for the
2026-07-10 ledger it replaces. See
[[stale_branch_triage_methodology]]-style caution: several source docs
contradicted a sibling or their own later sections (§2 lists every instance
found) — a status line in any single doc is not proof by itself.

Tracking contract, unchanged from the ledger this supersedes:

1. `documents/Requirements.md` and `documents/SecurityMinimumBar.md` win on
   conflict.
2. The newest focused active ledger and current code/evidence win over this
   roll-up.
3. Historical session logs and old unchecked boxes do not become active work
   without re-verification.
4. This roll-up does not replace the owning ledger for any item — every
   entry below names its source document; go there for full context before
   acting on anything load-bearing.

## 1. Headline stats

- Code: **zero** real `TODO`/`FIXME`/`XXX:` markers anywhere in the
  workspace. The only 3 grep hits are the policy-enforcement script itself
  and two comments quoting the "no TODO/FIXME" rule. All open work lives in
  the doc tree.
- Numbered backlogs represented: **RSA-0001–0089** (security audit
  findings), **QH-01–30** (quality hardening), **FIS-0001–0030** (Fable
  intelligent-systems R&D proposals), **DA-01–55** (doc-vs-code discrepancy
  audit), **RNQ-01–20ish** (Rust node-orchestrator quality), **D1–D14**
  (dataplane execution phases), **G1–G9 / W5.x** (cross-platform parity
  gates), **HP-1–5** (hole-punching/relay), **AUDIT-001–053** (2026-06-10
  audit pass), **RN-01–38** (earlier security-review numbering).
- Release-blocking mandate (stated in multiple docs): every role ×
  {macOS, Windows} must be live-lab-proven on the `--node` engine — not yet
  true for any OS pairing per the most recent parity refresh
  (`CrossPlatformRoleParityRefresh_2026-07-23.md`).
- The `--node` engine has **never once passed `linux_stage_two_hop`** (0
  lifetime passes) vs 52 passes on the legacy bash engine — the two evidence
  ledgers are non-interchangeable (`documents/operations/LiveLabRunMatrix.md`).
- Per the July 23 parity refresh: `--node` ledger = 88 rows, **zero rows
  fully passing** (81 fail / 7 partial); cross-OS join never proven (0/88);
  Windows never successfully bootstrapped on `--node`.

## 2. ⚠️ Stale or internally-contradictory documents found during this sweep

Worth checking before trusting any single doc's status line at face value —
each of these either contradicts a sibling doc, contradicts its own later
sections, or was confirmed stale by a separate audit:

1. **`AnchorBundlePullAttestationSecurityReview_2026-07-20.md`** — header
   says "not merged, 1 finding open"; §8 (bottom of the same doc) says it
   merged and the finding closed. Header never updated.
2. **`CrossNetworkRemoteExitNodePlan_2026-03-16.md`** — confirmed ~6 months
   stale by `DocCodeDiscrepancyAudit_2026-07-18.md` (DA-48/49): claims relay
   transport unbuilt and cites a compile break that is false; relay/WAN work
   has actually shipped and grown further.
3. **`CrossPlatformRoleParityPlan_2026-06-21.md`** +
   **`CrossPlatformRoleParityRoadmap_2026-06-22.md`** — their "✅ DONE"
   markers are bash-engine-proven only. Per
   `CrossPlatformRoleParityRefresh_2026-07-23.md`, none of that counts
   toward the release-blocking `--node`/G2 gate (bash is being retired) —
   both docs significantly overstate current readiness.
4. **`LiveLabMonitorTUIAccuracyImprovements_2026-07-10.md`** — a section
   headed "OPEN TODO" has body text reading "**Done**, landed in two steps."
   Heading and content disagree.
5. **`NodeRoleTaxonomy_2026-05-21.md`** — never states its own D12 build
   slices are complete, but later docs treat the taxonomy as already
   operative.
6. **`LiveLabVmConnectivityImplementation_2026-07-10.md`** — one section
   says Slice B real-VM application is "awaiting explicit approval"; another
   section of the *same doc* says that migration "SUCCEEDED."
7. **`UbuntuHostLabControlRemediationPlan_2026-07-23.md`** — status line
   says "DESIGN / PATCH PLAN — no code written." Its sibling
   `UbuntuHostLabControlFindings_2026-07-23.md` (same date) says all 5 of
   these exact bugs are "RESOLVED... fixed + proven live," explicitly citing
   this remediation plan as the design doc that was implemented.
8. **`WindowsWorkingNodePlan_2026-04-17.md`** — chronologically superseded
   by newer Windows docs showing real partial progress on several "still
   open" streams, but never reconciled/updated itself.
9. **`SecurityAuditLedger_2026-06-18.md`** — its own Executive Summary /
   severity table / closing Verdict are self-flagged stale by a 2026-07-27
   correction note *inside the same document* (finding-count undercounts,
   wrong Medium tally, stale "2 unmet Highs" verdict — both since applied).
10. **`SecurityRemediationPlan_2026-06-19.md`** — scoped to RSA-0001..0074,
    but the ledger now runs to RSA-0089. RSA-0075/76/78/79/81 (and 80) have
    no wave, owner, or effort entry anywhere in this plan.
11. **RN-08 / RSA-0001 disposition conflict** — `SecurityAnalysis_2026-06-12.md`
    says still open; `SecurityRemediationPlan_2026-06-19.md` records the same
    finding DEFERRED 2026-06-24. Unresolved "owner call" between the two.
12. **RSA-0026 disposition conflict** — `SecurityAuditLedger_2026-06-18.md`
    reads open/net-new; `SecurityRemediationPlan_2026-06-19.md` says applied
    2026-06-24 with a smaller residual.
13. **RN-02 doc-comment** — still describes dead-code semantics for
    `MembershipDirectory::is_populated()`, even though RSA-0008's own fix now
    calls that exact pattern at 2 production sites.
14. **`SecurityHardeningAudit_2026-04-28.md`** — original claim that
    Rustynet "strictly matches or exceeds" WireGuard/Tailscale/Nebula on
    every comparative axis is explicitly walked back by an embedded
    2026-07-27 correction (the §B.5 revocation path was non-functional when
    written; §B.7's WireGuard PSK is unset in production).
15. **QH-07** — a prior *retraction* of this finding was itself wrong and
    needs re-reverting; `QualityHardeningTodoReview_2026-07-25.md` flags the
    register text as still not updated to reflect that.
16. **`SecurityAuditCatalogStalePathsTodo_2026-07-28.md`** —
    `security_audit_catalog.rs` itself references a deleted file
    (`dataplane.rs`) in its `affected_files` list; the bug is itself
    RSA-0049-class (an audit catalog citing something that no longer
    exists).
17. Multiple docs reference `SecurityHardeningBacklog_2026-03-09.md`
    (relocated to `done/`), while a live `SecurityHardeningBacklog_2026-06-01.md`
    also exists — ambiguous which one current tooling/checks should target.

## 2a. Addendum 2026-07-28 — items verified against code and found ALREADY DONE

This roll-up is a doc-tree sweep: an entry here means *a document said this was
open*, which is not the same as *the code leaves it undone*. The distinction was
measured, not assumed. Six harness-side items below were checked against the
tree at `2e742929` before any work started; **five were already implemented** and
one was half-implemented.

Recorded because the cost is asymmetric: acting on a stale "open" wastes a
session re-deriving a landed fix, and a live-lab campaign planned around these
would budget for work that does not exist. **Assume this staleness rate applies
to the rest of the file** — verify against code before scheduling anything here.

| Claim (source doc) | Verdict | Evidence |
| --- | --- | --- |
| "flock the run-matrix CSV append" not done (`CrossPlatformRoleParityRoadmap` §11) | **DONE** | `live_lab_run_matrix.rs:922` and `:2293` both hold `acquire_append_lock` across the whole read-modify-write; the shared mechanism is `append_lock.rs`, whose module doc records that it was *extracted from* this very path |
| `cleanup_hosts` must bootout `com.rustynet.anchor` (`CrossPlatformRoleParityPlan`) | **DONE** | `cleanup_hosts` → macOS adapter → `macos_traffic::cleanup_runtime_state`; `MACOS_LAUNCHD_STOP_COMMAND` boots the label *and* the plist path (`macos_traffic.rs:27-28`) |
| iproute2 6.19 FIB regression "root cause identified but NOT implemented" (`LiveLabFindings_2026-07-12`) | **DONE** | `phase10.rs:1091-1101` — narrow fail-closed match on exit-2 + `FIB table does not exist`, with pinning tests at `:11728`-`:11776` |
| Tier 0: `validate_linux_membership_revoke_applies` / `validate_linux_revoked_peer_denied_e2e` "neither stage exists" (`LiveLabSecurityTestCoverage`) | **DONE** | both wired through `live_lab_stage_registry.rs`, `live_lab_run_matrix.rs`, `vm_lab/mod.rs`, and both MCP servers |
| "Add a lock to `live_lab_stage_triage.rs`'s `append_stub` (TOCTOU window)" (`FleetEvidenceCollectionPlan`) | **DONE** | `live_lab_stage_triage.rs:228` takes the lock; the dedupe read and append are one critical section, with a barrier-based negative-control test |
| Triage ledger T1/T2/T4/T5 "not built" (`LiveLabStageTriageLedgerPlan`) | **MOSTLY DONE** — see that plan's corrected status block | T1 built; T2 built *and wired* at `live_lab_run_matrix.rs:710`; T4 read-half live in the MCP, write-half landed `fd8c5d04`; T5 backfilled (51 records). **Only T3 is genuinely open.** |

One item in this addendum's scope was found genuinely broken and was fixed in
`fd8c5d04`: `fill_patch`, the ledger's only whole-file rewrite, ran unlocked,
non-atomically, and silently overwrote an already-recorded attempt while its own
doc-comment claimed it "only ever fills a `null`". That defect was not in this
inventory or any source doc — it surfaced only from reading the code the stale
entries pointed at, which is the argument for verifying rather than scheduling.

---

## Part 1 — `documents/operations/active/` (117 files, A→Z)

### AnchorBundlePullAttestationSecurityReview_2026-07-20.md
- Status (header, **stale** — see §2.1): "implementation complete... one High-severity finding remains open... Not merged." §8 says it actually merged and the finding closed.
- Reviewer-2 finding: `handle_membership_apply` has zero direct test coverage (integration test bypasses it via a helper) — uncorrected minor gap.
- Low-severity, accepted-as-non-issue: some public-value `==` comparisons aren't constant-time.

### AnchorBundlePullRollbackWatermarkInvestigation_2026-07-20.md
- Status: IMPLEMENTED (commit `e0cc8e5`, merged to main) — nothing open. Documented (non-actionable) residual risks only: first-ever pull is irreducibly TOFU; a long-offline device with wiped watermark storage degrades back to TOFU; an undetected compromised-key holder is out of scope entirely.

### AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md
- Track A sub-stages A1–A3 live-pass criterion open pending a clean run against current HEAD.
- Enrollment (A1.4) and downgrade-revocation (A1.5) destructive sub-stages remain follow-up work before `live_anchor` can be release-gate-required.
- Track C chaos: OOM, SIGSTOP/SIGCONT, helper-socket daemon-fault sub-stages (C1.1) skipped pending live-safe implementations.
- Track C: live daemon ingestion/rejection proof for signed-state adversarial inputs (C1.3) hermetic-only.
- Track C categories C1.2 (clock attack), C1.4 (crash recovery), C1.5 (resource exhaustion), C1.6 (network impairment), C1.7 (membership adversarial), C1.8 (privileged-boundary stress) scaffolded/dry-run only.
- Linux parity (DNS fail-closed, killswitch precedence, relay, anchor, genesis, IPv6 schema-v2) flagged repeatedly as "follow-up Linux slices."
- Windows live anchor execution fails closed until a reviewed PowerShell/SCM-safe runner is added.
- macOS/Windows anchor live SSH traffic validation deferred to Track A/C.

### AnchorNodeRoleDesign_2026-05-21.md
- §11 open questions (defaults chosen, revisitable): anchor list servable off-LAN via relay? (No); anchors auto-elect a primary? (No); anchor capabilities revocable by non-owner? (No); `advertise`/`list` Client-available? (read yes/write no); mobile sees anchor capability info? (yes, read-only).

### AutonomousSecurityParityPassLog_2026-06-24.md
- macOS exit client-egress NAT-session assertion needs the two-node activate→assert path reworked for macOS's enforce-time `pf` model.
- Windows anchor: `cfg(windows)` call sites need a Windows builder/CI compile-check; a live serving stage remains.
- Deferred: RSA-0001 (envelope v0/v1 framing) needs a migration + back-compat design first.
- RSA-0028/0034 (gossip), RSA-0035 (uPnP) dormant/forward-locking only.
- RSA-0002/0025/0039 (Windows key custody) + Windows anchor listener wiring — not locally compile-verifiable, needs Windows builder/CI.
- ~21 environment-blocked test failures in the sandbox (not regressions, but unresolved here).
- Windows exit WinNAT still blocked live; relay live session forwarding HP-3-gated on all OSes.
- Missing: a Linux-buildable contract test for the FAIL-LOUD gating decision matrix on all mac/win stages.

### BashRetirementPlan_2026-07-24.md
- Status: PLAN — W5.7 not started. Full G3 differential sweep + owner-signed dispositions not run. Direction-diagnose every bash↔`--node` diff — not started. Verify no un-dispositioned `--node` coverage drop — not started. Delete the bash-orchestrator surface in one reviewable change — not started. Post-deletion verification — not started. Mark spec §8 (G3) satisfied — not started.

### BlindExitPcbHardwarePlan_2026-07-22.md
- Status: DESIGN. No schematic/BOM/PCB layout exists; nothing fabricated.
- Open: benchmark throughput on real Orange Pi Zero 2 hardware before finalizing schematic; confirm multi-core RX packet distribution/RSS or plan Linux RPS; thermal validation for peak bursts; all pricing directional, needs real quotes at BOM-lock; H616 vs H618 pending availability/price; enclosure design, full BOM assembly, anti-tamper beyond reset button undiscussed; FPGA/open-softcore path parked as v2.
- Ethernet PHY and WiFi+BT module not yet sourced/qualified.
- Power design (fixed 5V, no PD chip) and RAM/eMMC sizing are RECOMMENDED not LOCKED.
- Device-level FCC/CE certification not started.

### CrossNetworkRemoteExitNodePlan_2026-03-16.md
- **STALE per §2.2 above** — confirmed ~6 months stale (DA-48/49), relay+WAN work already shipped, compile-break claim false.
- As literally written: Phase 1 candidate acquisition, Phase 2 HP-2 WAN simultaneous-open, Phase 3 HP-3 production relay transport, Phase 4 remote-exit dataplane integration, Phase 5 testing/gates + six canonical `cross_network_*` evidence reports all still read "open"; Appendix A has ~250 unchecked checklist items duplicating the above.

### CrossNetworkSubstrateIntegrationSpec_2026-06-21.md
- §0 architecture redesign is a DESIGN PROPOSAL, **PARKED** (owner directive 2026-07-13) pending an architecture brainstorm.
- §8 gaps: `double_nat_cgnat` unsupported on Tier A (netns); uPnP/IPv6 modifiers not wired into `vxlan_tier_b.sh`; underlay-IP wiring contract for e2e validators unconfirmed; §4.1 fix dependencies D14.a–f gated/pending; anchor role surface (D11) presence for cold-enroll/double-nat-anchor unconfirmed; the "make cross-network first-class in `--node`" question is the highest-order open question and is PARKED.
- Migration path CN-1 through CN-5 (trait-based substrate abstraction) — proposed, not built.
- Phase X1 Increment 2 partly live-validated; Increment 3 (relay-fallback) not started. X2/X3/X4 not started.

### CrossNetworkTraversalDesignDecisions_2026-07-19.md
- D14.a port-mapping default flip — blocked on real-router acceptance evidence.
- D14.c NAT discovery + CGNAT detection — buildable now, not built.
- D14.d signed punch timing — owner must pick Option A vs B first; not built.
- D14.e port-delta prediction — GATED (owner sign-off + D14.c field evidence); not built.
- D14.f encrypted endpoint mailbox — GATED (owner sign-off + threat model needed); not built.

### CrossOsRoleSwitchPlan_2026-06-24.md
- Status: macOS `LocalOnly` and Windows `LocalOnly` role transitions both LIVE-PROVEN 2026-07-04.
- Remaining: `SignedMembership`-kind role transitions (capability changes) remain design-only for both OS.

### CrossPlatformCiHealth_2026-06-25.md
- §4 remaining CI TODOs: macOS flaky `vm_lab` Gatekeeper/`trustd` subprocess tests (user-deferred); Debian 13 + Linux real-WireGuard-E2E both fail at "Bootstrap CI tools" (`cargo: not found`).
- Follow-up filed, not done: make `secret_log_audit`'s `REVIEWED_SECRET_EQUALITY_EXCEPTIONS` allowlist anchor on line content not line number.
- CI snapshot: Debian 13 build+security and Linux real WireGuard E2E both still red.

### CrossPlatformRoleParityPlan_2026-06-21.md
- **STALE per §2.3** — ✅ markers are bash-proven only, don't count toward `--node`/G2.
- Net remaining CODE work: `SignedMembership` transition kind unbuilt both OS; mac/win stage-gating contract tests missing; anchor `gossip_seed`/`enrollment_endpoint` unproven both OS; `port_mapping_authoritative` unproven on Windows (no `windows_membership_capabilities` equivalent); `enrollment_endpoint` has zero runtime enforcement, needs a design pass.
- Windows exit blocked on WinNAT/HNS-capable lab guest (hardware). Relay live session forwarding HP-3-gated all OSes. macOS exit client-egress NAT-session assertion is a scoped follow-up.
- `cleanup_hosts` must bootout `com.rustynet.anchor` between runs. DNS-leak active-probe fix only scoped to macOS this pass — same fix still needed Linux/Windows exit DNS proofs.

### CrossPlatformRoleParityRefresh_2026-07-23.md
- The current authoritative reframe: `--node` ledger = 88 rows, zero fully passing (81 fail/7 partial); cross-OS never proven (0/88); Windows never bootstrapped on `--node`.
- CP-1: macOS `two_hop` fails 8/8 on `--node`; root-cause hypothesis UNVERIFIED, needs fresh triage.
- CP-2: `network_flap`/traversal self-sustenance — sole Linux `--node` fail; increments I3–I6 remain.
- CP-3: Windows exit WinNAT needs a physical Windows-11-on-ARM device (UTM/QEMU on Apple Silicon can't do it) — external hardware blocker.
- CP-4: Windows `--node` bootstrap fails every attempted row — root cause (code vs guest) unverified, gates the whole Windows column.
- Windows authoritative port mapping still open. `SignedMembership` transitions unproven on `--node` both OS. Anchor `enrollment_endpoint` needs triage. Cross-OS join 0-for-88, never attempted.
- Stale-doc corrections still needed to `ParityPlan` §3 and `Roadmap`.

### CrossPlatformRoleParityRoadmap_2026-06-22.md
- Remaining anchor sub-surfaces (`gossip_seed`/`enrollment_endpoint` both OS, `port_mapping_authoritative` Windows); `SignedMembership` transition kind design-only both OS; Windows relay forwarding blocked on HP-3; Windows exit blocked on WinNAT guest.
- §11 enabling tasks not done: `flock` the run-matrix CSV append; optional `--no-rebuild` alias; optional second Debian exit-capable flag; Appendix A.3 security-hardening adopt-items (#11 gossip revocation propagation, #12 owner-key rotation overlap window, #13 distribution-layer default-deny) not yet landed.
- **STALE note** — same as ParityPlan: ✅ markers are bash-proven only.

### CrossPlatformSecurityGapRemediationPlan_2026-03-05.md
- **Internal contradiction**: top summary block still lists GAP-06 open; the GAP-06 section itself is marked "(Remediated 2026-05-27)."
- §8 unchecked: "Linux/Debian baseline unchanged and validated after each macOS change."
- GAP-08 (open): phase-scope docs vs runtime reality mismatched, needs published per-OS/feature support matrix.
- GAP-10 (partial): `start.sh` — `write_daemon_environment` migrated to Rust, full modularization into `rustynet-operator` still pending.
- GAP-07 residual: expand macOS coverage from unit-tests to richer integration/leak tests.
- GAP-09 residual (ongoing watch): audit any temporary enablement of the emergency plaintext-passphrase fallback override.

### DataplanePerfBacklog_2026-06-12.md
- P1: engine outcome-sink — remove last per-frame copy each direction.
- P2: relay await-based recv — remove 100µs poll + per-frame global lock.
- P3: macOS utun framing via `readv`/`writev` — remove one full-packet copy per direction.
- P4: endpoint→peer reverse index for inbound dispatch — only matters above ~10 peers.
- Deferred: runtime-fingerprint memoize, gossip candidate-build gate — waiting on a concurrent `daemon.rs` edit stream to settle.

### DeepSeekLiveLabOrchestrationPipeline_2026-06-27.md
- Remaining future phase: v4-pro stage-by-stage orchestrator (`lab_run_stage`/`lab_recover_vm`/`lab_clean_env` as model-called tools) — not built.
- §11 open decisions: step budget/wall-clock cap/max recovery-attempts values unfinalized; whether auto-fetch ships v1 or v2 undecided; whether `lab_clean_env`/`lab_restart_vm` need extra confirmation undecided.

### DiagnosticFunctionsRoadmap.md
- PKG-G subset (8 functions) landed. ~32 of 40 catalogued functions remain unconfirmed-as-landed: §1 Network (6 of 8), §2 Security/Crypto (all 8), §3 Resource limits (all 6), §4 Daemon/service health (all 6), §5 Storage/IO (all 5), §6 Compliance/Audit (all 4), §7 Baseline/anomaly detection (all 3). Phase 2/3 priority lists entirely unscheduled.

### DocCodeDiscrepancyAudit_2026-07-18.md
- Status: complete, 54 of 55 original findings still applicable (only DA-16 fixed/dropped). Every DA-XX below is itself an open doc-vs-code discrepancy:
- **Critical**: DA-01 (TLS control-plane claim false + new worse self-asserted field), DA-17 (WireGuard-boundary-leakage gate fails live, 16 violations, worse), DA-36 (revoked-peer live teardown not wired to production reconcile).
- **High**: DA-04 (`capability add/remove` hard-stubbed), DA-05 (`anchor init` dry-run only), DA-18 (PrivacyRetentionPolicy unenforced), DA-19 (relay called "placeholder" at 3,848 real lines), DA-20 (role-transition capability under-reported), DA-26 (macOS launchd doc wrong labels/unit type), DA-33 (DR restore/verify non-functional), DA-34 (zero SLO instrumentation), DA-35 (compatibility policy enforced only in own tests), DA-37 (PolicyRolloutController zero wiring), DA-39/40 (release-readiness gates not CI-wired), DA-49 (cross-network doc claims relay/WAN unbuilt), DA-02/03 (CLI category docs wrong).
- **Medium**: DA-06 through DA-51, ~26 items — policy-engine doc example mismatch, nonexistent IPC variants documented, `--json` coverage, capability enum duplication, exit-code taxonomy stale, IPv6 parity mischaracterized, D11.a contradiction, snapshot integrity self-checksum not signature, checklist filename mismatches, release-readiness blocker itself stale, systemd hardening mismatches, `patch_sla_tracker.json` empty, ADR-003 stale, PFX-password-safety false claim spread further, "Security Minimum Bar verified" checkbox has no automated gate, compile-break claim false, UDP hole-punching docs describe superseded algorithm, "no second backend" claim stale.
- **Low**: DA-12 through DA-55, ~16 items — CI toolchain mismatch repo-wide, file:line citation drift, undocumented capability, quoted text not in real script, test-count drift, dead-code marker count off by 95, postcard migration claim false, invalid `--phase` example, line-count citation gap widened.
- Recommended priority (open action item): fix DA-01/DA-17 first, then DA-36, then the High-severity runbook findings.

### EfficiencyAndAdvancedTechniqueOpportunityCatalog_2026-07-19.md
- Status: RESEARCH CATALOG — UNSCHEDULED, UNRANKED. All 29 findings open (WIN-1 confirmed-sound, not a finding): SEC-1 (key-custody re-run unmemoized), SEC-2 (no Ed25519 batch verification), ACL-1 (unindexed linear policy scan), ACL-2 (costlier predicate before cheap one), ACL-3 (no decision caching), MEM-1 (redundant full-roster re-serialize ~2x per apply), MEM-2 (no incremental membership verification), ENR-1 (admission cost scales with total historical ops), ENR-2 (bundle-pull no post-fetch re-verify), ENR-3 (flat roster disclosure), SER-1 (zero-clone builder landed in only 1 of 7+), SER-2 (audit log double-hex-encodes + full rewrite per append), SER-3 (hex-nesting doubles bytes for signed bundles), NAT-1/2/3 (ICE pair race actually serial; zero observation window; two STUN impls drifted), RLY-1/2/3 (heap alloc per forwarded frame; all-aggregate usage accounting; one-socket-per-session scale tradeoff), CCY-1/2/3 (single-thread reactor stall risk; unconditional reload every tick; manually-resynced gossip shadow-state), BLD-1/2/3 (one-hop-only `--affected` scoping; no cargo-nextest; check+clippy fully serial), CLI-1/2/3 (double bundle parse/verify at startup; `rustc --version` shelled out unmemoized; interface enumeration implemented 3x), WIN-2/3 (subprocess-per-item + full DPAPI re-encrypt; no TCP_NODELAY).

### FableEfficiencyImplementationPlans_2026-07-19.md
- Status: UNSCHEDULED, PLAN-ONLY, NO CODE WRITTEN. 11 chosen-fix plans await building: BLD-1/2/3, CLI-2/3, RLY-1, CCY-3, WIN-3, NAT-3, CCY-1-narrow, NAT-2-narrow.
- Separately flagged, not yet filed anywhere: per-request read errors on the admin IPC socket are fatal to the daemon today.

### FableForkConsistentMembershipTransparency_2026-07-01.md
- Status: SPECULATIVE R&D — UNSCHEDULED, no code written. Phase 1 (Merkle history lib) open. Phase 2 (STH minting, report-only) open. Phase 3 (STH gossip + fork detection, needs a new equivocation-injection live-lab stage) open. Phase 4 (witness cosigning, needs a governance design decision first) open.

### FableIntelligentSystemsProposals_2026-07-01.md
- Status: SPECULATIVE R&D, UNSCHEDULED. FIS-0001 superseded by FIS-0013. FIS-0002/0019 formal model landed, full TLC run pending. FIS-0003 Phase 1 landed, 2–3 gated on D2.7. FIS-0004 Phases 1–2 landed, Phase 4 bench-gated. FIS-0005 Phase 1 landed, 2–4 open. FIS-0006 landed, PriorVerdict wiring open decision. **FIS-0007 NOT STARTED**. **FIS-0008 NOT STARTED**. FIS-0009 Phases 1–3 landed (flag OFF), Phase 4 open decision. FIS-0010 Phases 1–2 landed (flag OFF), 3 sign-off-gated, 4 lab-gated. FIS-0011 landed. FIS-0012 commits 1–2 landed, 3–7 open. FIS-0013/0021 core landed, deltas 1/2/4 gate full migration. FIS-0014 commits 1–3 landed, 4 lab-gated. FIS-0015 commits 1–3 landed, 4 sign-off-gated, 5 lab-gated. FIS-0016 landed. FIS-0017 Phase 1 landed, 2 gated on nas being live-proven. FIS-0018 landed, commit 3 optional/open. FIS-0020 commit 1 landed, 2–3 gated on D2.7. **FIS-0022 through FIS-0030 — all proposal-only, no code written**: DNS-zone-pull channel, mid-session relay candidate failover, property-based killswitch/ACL verification (also flags a possible missing guard in `render_macos_killswitch_pf_rules`), age-gated jittered WG key rotation, config-drift fingerprinting, DPLPMTUD path-MTU, UDP GSO/GRO batching, Vivaldi network coordinates, VRF-ordered backup-relay succession (GATED, needs crypto-allowlist governance decision).
- Windows gossip transport: mechanical fix needed (remove `cfg(unix)` split, add `ConnectionReset` arm) — but the deeper gap is `attach_gossip_runtime` has **zero production callers on any platform**.
- Considered-and-set-aside: hardening `enrollment_consume.rs` token semantics against lossy-link token burn, no field evidence yet.

### FleetEvidenceCollectionPlan_2026-07-28.md
- Status: OPEN — design only, nothing implemented (Rev 2, post adversarial review).
- Decide §0: is driver-host attribution worth the schema cost given `node_id` already answers "which guest."
- Clone-test the host-id anchor (`/etc/machine-id`) before adoption — cloned guests may collide.
- Write the required migration for `stage_results.csv` header (exact-match schema) — no upgrade path exists, blocks any column addition until written.
- Add a lock to `live_lab_stage_triage.rs`'s `append_stub` (TOCTOU window) or declare the triage merge single-writer.
- Build fetch-and-merge for `host_id`, plus a reaper for runs whose pidfile died before rows were collected.
- Build log collection pipeline: triage JSONL, failed-stage logs, passing-stage log tail, diagnostics archives, `report_state.json`.
- Handle binary version skew (flagged "dominant operational risk"). Decide git-merge-conflict handling for 3 tracked ledgers under multi-machine appends. No rotation/compaction for growing `stage_results.csv`. Nothing pins NTP/clock skew for merge ordering.

### FocusedLiveLabRoleGapAnalysis_2026-07-02.md
- Linux `blind_exit`: add live stage capturing real `nft list ruleset`; active probes (mesh-source allow, non-mesh block, NAT absent, local-origin block, DNS-leak block); verify rollback/failure; fix stale helper test protocol mismatch; record live evidence only after guest-applied rules pass.
- macOS `admin`: add stricter live stage (secure-custody signing, issue bundle for real peer, transfer, apply via daemon/CLI verify-before-apply); negative tests (stale generation, forged signature, unauthorized escalation, revoked admin); verify no secrets in logs.
- Windows `anchor`: fix deploy transport (force local-UTM execution, surface UTM errors); add Windows preflight; capability-negative proof; full anchor sub-stages. Current recorded failure: Windows anchor bundle-pull fails during deploy (SSH exit 255).

### FullRepoAnalysis_2026-05-24.md
- Multi-agent review, open action-plan (5 critical/9 high/25 medium/27 low across 2 passes). Selected highlights:
- P0: fix `AlgorithmPolicy::with_exceptions()` inverted guard; fix `context_matches()` empty-context permit-all; extend `validate_policy_safety()` for all-protocol wildcards; add membership-directory enforcement mode; fix broken Phase 7/8/9 links; create SecurityMinimumBar_VerificationProcedures.md.
- P1: EnrollmentTokenOperatorRunbook.md, KeyRotationAndRevocationRunbook.md, AnchorNodeOperatorRunbook.md; `rustynet-operator` crate Phase 1; `ops install-binaries` verb; port `save_config()` to Rust; replace `unreachable!()` in stun_client.rs; fix 8x `.lock().unwrap()`; SAFETY comment on privileged-helper UID check; fix RwLock-across-`.await`; HTTP response body size limit.
- P2/P3: ~30 more items — IPC protocol version+handshake, benchmarks, `deny_unknown_fields`, several operator runbooks, DaemonDpapiScope newtype, graceful shutdown, CI gate blocking `test-harness` in release, docs for CIDR validation and adapter pattern, cellular/traversal/mobile guides, clone/alloc hotspot reduction, SecretKey zeroization doc, Phase 10 state diagram, `--log-redact-peers` flag.
- 6 proposed new "expansion" docs never written: Cellular, Traversal-probe, LAN-toggle, Relay load-balancing, Mesh partitioning, Audit forensics.

### G3EnumerationDiff_2026-07-23.md
- Enumeration half COMPLETE (W5.6 flip precondition satisfied); full G3 sweep (outcome-level proof) still gates bash deletion (W5.7).
- §3.2: 8 Linux security audits coverage-present but attainment-pending on `--node` (0 ledger passes).
- §3.4: macOS/Windows role-parity attainment gap for many cells bash proved but `--node` hasn't driven green.
- §3.5: two bash meta-stages need owner sign-off at W5.7.
- §3.6: `role_switch_matrix` depth caveat — `--node` version may be shallower than bash pairing, unresolved.
- §5 finding #4: stale doc comment in `security_audit_validation.rs:28-32` needs separate cleanup.

### HeterogeneousLiveLabEvidence_2026-04-28.md
- §3.2: install WireGuard for Windows on `windows-utm-1`; re-run install service script; verify running; re-run Windows security validation.
- §3.3: 5 Debian UTM VMs offline, need starting (operator action).
- windows-key-custody-check: "Not yet captured to file."
- §5 does NOT yet confirm: W4.5 orchestrator wiring, W3.2-followup-7/8 Linux validators, full Linux-exit→Windows-peer distribution path.
- §7.3 (Track B): operator still needs a real heterogeneous lab run (Debian+Windows+macOS).
- §8.3 (Track C): 6 items — replace dry-run reports with live implementations; tcpdump proof of zero plaintext leakage; measure recovery time vs deadline; post-run invariants; expand chaos test beyond first sub-stage; connect offline signed-state fixtures to live daemon proof.
- §9.2: add Linux killswitch precedence producer; capture live Debian 13 evidence for relay/anchor/membership/exit-DNS; flip NAT-lifecycle schemas to v2 once dual-stack membership lands.

### HomelabConnectivityParityDeltaPlan_2026-05-21.md
- macOS ~85% ready, Windows ~65%.
- M4 — macOS boot-time killswitch (pfctl): entirely unimplemented.
- W3 — Windows relay & direct-P2P E2E test coverage: entirely open, depends on W1+W2.
- DoD unchecked: killswitch (M4), E2E suite (W3), all-3-platforms gates green.
- W1/W2 code-complete but Windows live/CI evidence pending.

### HostObservabilityStabilityPlan_2026-07-24.md
- Status: ACTIVE. Layer 2 one-time privileged stand-up not folded into first-boot bootstrap. Layer 3 physical/firmware checklist (PSU, UPS, reseat, wired eno1, BIOS SEL) not done.
- §6: separate the libvirt-driving identity from a lower-privilege one — tracked, out of scope here.
- §7.9 steps 2-7 not done: `onboard-host --new`, `add-guest`, `remove-guest`+`offboard-host`, `fleet-status`+`fleet-converge`, Layer-1 MCP tools, portability scrub.
- §7.9.1: catalog SHA256 digests are placeholders (64 zeros) for all 3 images. `fetch-image`/`provision-guest` don't mandate digest.
- §7.10: pre-implementation validation owed for a polkit-rule change on `ubuntu-kvm-1`; privilege-shape readback assert would currently FAIL (agent identity still has sudo group membership).
- §7.6: Layer 0/2 observability fold-in to `onboard-host` — design only.

### LabMonitorTUIDesign_2026-06-29.md
- §12 Open Question 1: stage order/expected-stage list — no manifest emitted before a run starts, approach not finalized.
- §12 Open Question 2: active-stage detection during a run — inference approach described, not confirmed implemented.
- §12 Open Question 3: singleton-gate integration — should warn not block, described, not confirmed implemented.

### LinuxBlindExitDataplane_2026-06-25.md
- DoD 4/5 checked. Live-lab proof on a real Linux blind_exit node (human step) — pending.
- Pre-existing broken test helper: `phase10::tests::spawn_privileged_capture_helper` speaks line-delimited JSON, `PrivilegedCommandClient` uses framed protocol — every socket test using it is latently broken. A blind_exit apply/rollback integration test was drafted and removed rather than shipped failing.

### LinuxMtuPrivilegedHelperAllowlistGap_2026-07-21.md
- Status: diagnosed + confirmed live, fix NOT implemented. Step 1 (re-export `SAFE_BRINGUP_TUNNEL_MTU`) not done. Step 2 (allowlist entry in `validate_ip_args`) not done. Step 3 (regression test) not done. Step 4 (verify caller-side test still passes) not done. Full gate suite + live re-verification post-fix not done.

### LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md
- Bucket B (reopened): stricter 5-node `live_two_hop` blocked on `second_client_route_via_rustynet0` check failing.
- Bucket C: remove/replace `tun-rs 2.8.2` (RUSTSEC-2024-0436 via unmaintained `paste 1.0.15`); resolve `cargo deny` license failures; regenerate stale fresh-install matrix; generate six missing canonical cross-network reports.
- §0.1: commit-bound fresh-install evidence needed for current HEAD; canonical cross-network evidence blocked on missing pinned host-key for `debian-lan-11`.
- §9.2/9.3: neither "Reduced Live-Lab Runtime Proof" nor "repo-level pre-live-lab readiness" is complete.

### LinuxVmHostPlan_2026-07-14.md
- §6.5.4: no Linux/libvirt implementation of the network mutation boundary — "the biggest unimplemented gap."
- §6.5.3: provisioned guest violates ADR-004 dual-NIC target (single NIC on libvirt NAT).
- §6.5.2: Tailscale/mesh-CIDR collision — OWNER DECISION REQUIRED before cross-host runs (ZeroTier recommended, not adopted).
- §6.6.3: Tailscale on the Mac still fails `vm-lab-network-audit` (host_route_collision), blocks enforced-profile runs.
- §8: open decision #1 (is a dedicated Linux host even the goal) and #4 (is VM lifecycle mgmt needed at all) still open.
- §12.9: `eno1` still NO-CARRIER, guests remain NAT-only behind `virbr0`, violating ADR-004; cross-machine transport stays on Tailscale.

### LiveLabCoverageAndHonestyAudit_2026-06-25.md
- Status: IN EXECUTION.
- Wave 3 (cross-OS security/adversarial parity) — OPEN entirely: endpoint-hijack, server-IP-bypass, rogue-path, enrollment-token replay/forge, gossip/membership adversarial, STUN/ICE traversal adversarial, signed-state forgery/replay, secrets-not-in-logs, control-surface exposure — none ported to macOS/Windows; plus Windows IPv6-leak producer+validator.
- Wave 4 (cross-network dataplane on mac/win) — OPEN entirely.
- Wave 2: network-flap, reboot-recovery, enrollment-restart cross-OS backings still open.
- Wave 5: nas + llm service-hosting-role live stages — zero coverage anywhere; host-resource-exhaustion class uncovered even on Linux.
- Relay data-plane frame forwarding still unproven on any OS; macOS exit active-NAT egress still fail-closed/no-proof; Windows relay deploy+validation still reported-skip.
- §8.2 TODO-1 through TODO-8: cross-OS chaos retrofit, macOS CI flake, nas+llm live stages, host-resource-exhaustion class, Windows blind_exit WFP dataplane unimplemented, Debian/Linux-E2E CI "cargo not found."

### LiveLabExecutionEfficiencyPlan_2026-06-20.md
- §8 remaining execution order: (1) Linux runtime tail items (lan_toggle, managed_dns, network_flap, reboot, secrets, key_custody, enrollment) to reconfirm; (2) macOS-as-client remaining stages; (3) Windows front-loaded prep→bootstrap→runtime→DPAPI/named-pipe/NRPT not executed; (4) cross-OS same-LAN chain (mixed_topology→membership convergence→peer visibility→direct/exit→role_switch, "16-fail historical hard nut") not green.
- §6: queued but unshipped Windows fixes — `windows_stage_bootstrap` regression, DPAPI key custody (RSA-0002/0025), named-pipe ACL hardening, `windows_managed_dns` NRPT via reg.exe.

### LiveLabFindings_2026-07-03.md
- FINDING 1: no shared stage contract — needs a run-scoped Stage Manifest + single registry.
- FINDING 2: two run-matrix writers, no owner; interim (bash) writer wrong 94% of the time it disagrees.
- FINDING 3: no terminal-state taxonomy across jobs/stages/platform streams.
- FINDING 4: converge the two orchestrators on the recording contract first.
- FINDING 5: security-control coverage tracked by prose with holes — make it machine-checkable.
- FINDING 6: timer-estimate fallback uses wrong statistic (P50 not P90).
- FINDING 7: header math conflates `completed`/`enabled`.
- FINDING 8: `area` string is a load-bearing mini-DSL — should be display-only.
- FINDING 9: `disabled_stages` is write-only config, never validated or pruned.
- FINDING 10: evidence is a convention not a contract — no declared expected-evidence-set enforcement.

### LiveLabFindings_2026-07-12.md
- Findings A/B/C dispositioned but "live re-verify pending in the next focused run" for all three.
- iproute2 6.19 FIB-table regression blocking Ubuntu 2-node mesh — root cause + fix identified but NOT implemented; needs a negative test pinning the message, then a green re-run.

### LiveLabMonitorTUIAccuracyImprovements_2026-07-10.md
- **Stale-classification flag (see §2.4 above)**: "OPEN TODO" heading, body says Done.
- "Recommended, not implemented" (4 items): PID-reuse hardening (no cheap cross-platform primitive); malformed-vs-absent CSV cell diagnostics; header "data source age" label clarity (cosmetic); prefer `live_ips[0]` over static `ssh_target`.

### LiveLabSecurityTestCoverage_2026-06-22.md
- Tier 0 (2 items, code fixed but stage missing): `validate_linux_membership_revoke_applies`, `validate_linux_revoked_peer_denied_e2e` — neither stage exists.
- Tier 1 (16 items, mostly unbuilt): GM-1 gossip-revoked-readmit, ENR-1 enrollment replay, TOCTOU-1 concurrent-consume, DOS-1 relay hello flood, RT-2 blind_exit reversal denied, RR-01/02/03 replay persistence, FCF-1/2/3 crash/corrupt/keystore fail-closed, RPT-01 relay ciphertext-only (currently the *only* relay-forwarding proof of any kind, and even that is now doubted), S3-10 codesign, RSA-0063 macOS privesc residue, KC-04 Windows key-custody negative path, PH-7 macOS helper allowlist, KL-2/3/4 killswitch-leak parity, KC-07 secrets-not-in-logs parity, CNT-1 uPnP SSRF, PH-2/3 helper socket fuzz.
- Tier 2 (4 larger): HP-3 relay packet-forwarding proof ("single biggest looks-done-but-isn't gap"); nas/llm M5 live evidence chain; cross-network NAT-profile substrate; real cross-OS role-switch.
- CPA-1 marked DONE elsewhere but zero code hits found — UNVERIFIED.
- §2.4: 111 confirmed-implementable gaps across 19 surface categories; only 6 stages committed.
- §9: no per-stage isolation mechanism for live-validation/adversarial stages — flagged highest-leverage infra gap.

### LiveLabStageContractPlan_2026-07-03.md
- Finding 1C PARTIAL (per-stage recorder validation moves with Finding 4). Finding 4 PARTIAL (bash per-stage recorder not done, report_state heartbeat not done). Finding 5 v1 DONE but gate enforcement open. Finding 10 OPEN (evidence contract enforcement not built).
- `issue_and_distribute_traversal`/`_dns_zone` logical-column gap documented but not healed.

### LiveLabStageTriageLedgerPlan_2026-07-16.md
- Status: PROPOSED — schema+phases agreed, implementation pending. T1 (schema+module) not built. T2 (auto-stub) not built. T3 (launch-time gate) not built. T4 (MCP tools) not built. T5 (backfill+doc update) not done.

### LiveLabVmConnectivityImplementation_2026-07-10.md
- **Stale-classification flag (see §2.6 above)**: Slice B says both "awaiting approval" and "MIGRATION SUCCEEDED" in different sections.
- Slice B: decision needed on network-mutation mechanism (raw plutil vs AppleScript Configuration Suite).
- Slice B: stale `network_group` inventory labels for 3 migrated guests, no sanctioned CLI to update.
- Slice C: management/scenario-endpoint-split binding not_run; `double_nat_cgnat` not_run (chained two-router site unimplemented).
- Slice E not_run: deterministic DHCP/DNS/NTP; management quarantine/link-down stages; multi-VM dual-plane proof; Tier 3/4 blocked on owner decisions.
- Final pending operator decisions: Slice B approval; rulebook §15.9 decisions 3-7.

### LiveLabWave0_LinuxHonestyFixes_2026-06-25.md
- OUTCOME: COMPLETE. Nothing open.

### LiveLabWave1_IntegratedPipelineHonestSkips_2026-06-25.md
- OUTCOME: COMPLETE. One explicitly deferred item: thread per-node role-runtime proof status into `NodeStatus` so the role×OS matrix shows each skipped cell individually — not built.

### LiveLabWave2_CoreRoleCrossOsParity_2026-06-25.md
- Batch A COMPLETE (code); Batch B partial. Overall: "code-complete + unit-tested, LIVE-RUN-PENDING" for all ported binaries.
- Batch B remaining: network-flap, reboot-recovery, enrollment-restart not yet ported (Windows-transport-gated).
- Follow-up: migrate POSIX-transport binaries to the `RemoteShellHost` seam for Windows parity; port the Linux control-plane setup preamble cross-OS.
- Daemon-side gaps: Windows-as-exit unsupported at role gate; macOS-exit needs Linux-only `anchor` capability; Windows `blind_exit` dataplane unimplemented; no standalone managed-DNS service on mac/win.

### LiveLabWave5Chaos_InertScaffolds_2026-06-25.md
- Code-complete + unit-tested; live fault injection is the remaining human step for all 3 chaos tests.
- Host-resource exhaustion class (fd-limit/inotify/read-only-fs) now uncovered after re-declaration — needs separate stages.

### LiveT5NegativeControlProofPlan_2026-07-24.md
- Live-verify blocked on `mac-lab-token` (shared/serialized with WS-A two_hop).
- M3: live-verify must not combine `--rebuild-nodes` with `--enable-negative-control` — constraint, not yet exercised.
- M4: if SSH transport dies inside the kill-window script, `rustynetd` can stay down ~2s until systemd self-heals — accepted residue.
- (Cross-ref suggests D2 was subsequently proven live same day — likely resolved after writing.)

### LlmNodeRoleDesign_2026-06-11.md
- Not yet implemented (deferred as "separate program" per NodeEngineAcceptanceSpec §6.1).
- Entire build plan open: D13.d.1 (`rustynet-llm-gateway` crate), D13.d.2 (daemon integration), D13.d.3 (exit-node coexistence route exception), D13.d.4 (preset+CLI wiring), D13.d.5 (Linux service install; mac/win scaffolds gated).
- Open questions: gRPC vs SSE primary transport; gateway embeds vs proxies inference engine.

### MacosUserspaceSharedBackendPlan_2026-05-08.md
- Phase 7 (only remaining phase): run `phase10_hp2_gates.sh` on macOS; generate live `rustynet netcheck` artifact; record evidence in PlugAndPlayTraversalRelayDeltaPlan §18.2.

### MacWinStageParityPlan_2026-07-02.md
- Tier 2 (5 items, open): `membership_revoke_applies`, `signature_forgery`, `gossip_revoked_readmit`, `enrollment_replay`, `hello_limiter_flood` — need mac/win stage functions.
- Tier 4 (open): `privileged_helper_allowlist` (PH-7), `policy_default_deny`.
- Tier 1 (open): one-off matrix columns for `runtime_acls` + `service_hardening`.
- Tier 3 (open, hardest): `revoked_peer_denied_e2e` (needs per-OS killswitch harness); `blind_exit_reversal_denied` (macOS: column only; Windows: blocked by design).

### MagicDnsSignedZoneSchema_2026-03-09.md
- Rerun the adversarial live/semi-live managed-DNS proof — blocked (SSH timeout to lab host).
- Refresh live proof that OS DNS integration routes to loopback resolver without weakening protected DNS.
- Residual: privileged helper socket still newline JSON, needs Phase-B framing hardening.
- Unrelated blockers: `state_fetcher.rs` DNS-zone test failure; `ops_write_daemon_env.rs` compile failure blocking `phase10_gates.sh`.

### MasterWorkPlan_2026-03-22.md
- Track E (evidence) is the primary open track; Tracks A/B/C/D/F/G largely implemented in code.
- RELEASE-BLOCKING: cross-platform role parity (tracked separately in ParityPlan).
- Track E1: fresh-install matrix refresh for current HEAD, recurring/open.
- Track E2: 6 canonical cross-network reports missing for current HEAD; blocked on distinct-underlay topology + pinned host-key.
- Track B WS-4: live network-switch gates not yet run live.
- G3 residual: handshake-initiation call sites not wired to `InFlightHandshakeTracker`. Line-pinned secret-equality allowlist is brittle.
- G6 residual: no live cross-network evidence for `rustynet membership apply --daemon`. G5 residual: live macOS blind_exit PF hard-lock evidence pending.
- `fresh_install_os_matrix_release_gate.sh` fails (macOS Phase-1-scaffolding only at time of writing). `cargo deny`/`cargo audit` blocked by dependency policy issues (per that log).
- Post-parity backlog (not release-blocking): 32-bit ARM support, compile blockers not fixed.

### NasNodeRoleDesign_2026-06-11.md
- Not yet implemented (deferred, separate program). Entire build plan open: D13.c.1 (`rustynet-nas` crate), D13.c.2 (daemon integration), D13.c.3 (preset wiring), D13.c.4 (Linux service; mac/win gated).
- Open questions: mountable live file-share support; per-peer vs single node at-rest key; multi-NAS replication.

### NodeEngineAcceptanceSpec_2026-07-23.md
- SIGNED OFF (the bar itself), but G2 (parity attainment) not yet met: deferred cells nas/llm, relay HP-3, Windows-exit WinNAT, Windows blind_exit — all still open.
- G3 (bash-retirement) full sweep + signed dispositions pending. `network_flap` must move RED→GREEN for G2. W5.6 flip dispositions D1/D2 still need resolution.

### NodeEngineFlipDispositions_2026-07-24.md
- G1 satisfied (commit `a414ceb`, 5-of-5 stable).
- D1 (`live_two_hop_validation`): real data-plane defect, two-hop path never carries traffic past entry→final-exit leg; confirmed regression, root cause under active investigation, no clean GREEN run yet.
  - No unit test for `extra_peers` fail-closed direction of `apply_traversal_authority_to_peers`.
  - Assignment/traversal-bundle atomicity race not structurally enforced outside opt-in self-minting config — "routed, not fixed here."
  - `net.ipv4.ip_forward` has one setter and 7 clear sites that silently discard restore-failure results.
- D3 (`live_network_flap_validation`): correctly RED, GREEN required for G2, owned by TraversalSelfSustenancePlan (open).
- (D2 resolved/closed 2026-07-24.)

### NodeRoleTaxonomy_2026-05-21.md
- **Stale-classification flag (see §2.5 above)**.
- Open questions (§12, defaults chosen): promote anchor+exit to 7th preset; mobile future anchor role; relay implying gossip_seed; staged/drain role transitions; wizard auto-detection of "home server."

### NodeRoleTaxonomyExtension_2026-06-11.md
- D13.a-e build plan open per cross-reference (nas/llm deferred).
- Open questions: combine nas+llm as a "homelab" preset; off-mesh reachability (no); per-peer/group auth granularity (both, general already).

### NonSecurityParallelHandoff_2026-07-13.md
- PKG-A through PKG-I (9 packages) — dispatch doc, presumed open as of doc date: RNQ-05 durability, RNQ-07 real cancellable deadlines, RNQ-17 vm_lab feature-gate, RNQ-09 subprocess cleanup test, `rustynet-sysinfo` pure-parser extraction, `rustynet-lab-monitor` first-class-gated crate, read-only typed diagnostics, `rustynet-advisor` MCDA property tests, docs/mechanical drift sweep.
- §3.GRAY: dataplane/relay/gossip perf backlog gated on Opus §13.2 security review.
- §16: remove lab-only crates from shipped product packages.

### OpenWorkIndex_2026-04-17.md
- P0-1/2/3: regenerate fresh-install + cross-network evidence for clean HEAD (both blocked); re-run release-readiness signoff.
- P1-4/5/6: finish plug-and-play traversal/relay proof burden; finish cross-network remote-exit proof burden; rerun managed-DNS adversarial proof (blocked SSH timeout).
- P1-7: continue serialization/artifact-format hardening across several artifact families.
- P2-8: implement VM-lab capability reporting (4 slices).
- P2-9: recover authoritative Windows VM-lab access/orchestration (6 phases).
- P3-10/11: refresh Shell-to-Rust Phase I evidence; finish narrow remaining cross-platform parity/security cleanup.

### OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md
- W5.1/5.2/5.3: 5x Windows run, mixed-arrangement matrix, posture promotion — all unchecked.
- IPv6 exit serving fail-closed (Windows NetNat IPv4-only).
- Several live proofs needed but unavailable (SCM-context egress detection, cmdlet pre-flight, DNS-block precedence, killswitch query).
- `verify_signed_auto_tunnel_bundle` has the same outer-struct-vs-payload weakness the endpoint-hint verifier had pre-fix. No replay store on endpoint-hint verifier. No explicit `version=1` gate.
- W2.1b: full PKCS#7/chain/revocation validation not done; air-gapped revocation behavior undecided.
- DPAPI collector validates presence+ACL+extension only, doesn't crack the blob open. TOCTOU window in `validate_secret_file_security`.
- Relay `NonceStore::insert` clones the entire map per accepted hello.
- W4: Windows-side registry-ACL collector validation on a real fixture not done.
- W1.4 negative-bypass test deferred. Node-id case sensitivity unresolved cross-cutting concern.

### OvernightAutonomousBugHuntProposal_2026-06-08.md
- Per-cell VM health pre-flight/recovery not built. Substage-level "Advanced" detection in the live oracle not built. Adversarial second-review agent not built. `--auto-merge-safe-cells` autonomy dial parsed but not wired. Run-matrix auto-seeding not built. `LiveExecutor` implemented+type-checked but intentionally never run live.

### ParallelAgentWorkPlan_2026-07-01.md
- Job 1: HP-3 real relay packet-forwarding proof — no stage has ever proven it.
- Job 2a/2b: cross-OS role transitions; Windows anchor bundle-pull upgrade to live stage.
- Job 3 (security hardening, all zero-coverage at doc time): FCF-1/2/3, RR-01/FCF-4, CNT-1/RSA-0035, PH-2/3, optionally PH-4/5.
- Optional Job 4: RSA-0063, S3-10, KC-04, PH-7, KL-2/3/4.

### Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md
- Fresh-install evidence for current HEAD — blocked (dirty working tree). Canonical cross-network evidence — blocked (missing pinned host-key). Validation note: an `ops vm-lab-run-live-lab` rerun unexpectedly restarted setup instead of reusing state — flagged for separate investigation.

### Phase5ReleaseReadinessSummary_2026-04-12.md
- "Not release-ready." Missing: commit-bound fresh-install evidence, canonical cross-network evidence. Hard gate failing: workspace test suite fails in-host (ephemeral-port PermissionDenied). Windows fresh-install evidence absent. `release_readiness_gates.sh`/`phase10_gates.sh`/`phase5_gates.sh` all recorded failing.

### Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md
- "Release-ready claim: still blocked." Trusted host-key for `debian-lan-11` missing. Canonical cross-network reports + soak report not regenerated for clean HEAD. All six canonical report files missing.

### PlatformImprovementBacklog_2026-05-14.md
- L2: nftables IPv6-parity + drift collector not wired into daemon reconcile loop.
- L6/L7/L8: cross-boot key-custody stability test, `ip6` NAT sibling table, netns-lab reboot integration test — all not built.
- W1/W3/W4: PowerShell JSON success-writers, RA/default-route collector, Windows registry-ACL live validation — all open.
- W5: Win32 FFI signer-thumbprint extraction body — needs live Windows fixture, explicitly not safe to land from non-Windows.
- W7: Windows install-release real runtime path — large, currently a protective stub, "biggest remaining Windows piece."
- X2: remaining `ops_phase9.rs` typed-view migrations explicitly deprioritized as cosmetic.

### PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md
- §18.1: Phase A/B complete; Phase C/D/E NOT complete.
- Phase C: wire daemon relay client to real relay infra — still blocked, no production backend-owned shared-transport socket exists; prove relay-active with live traffic — no fresh artifact.
- Phase D: fresh live direct→relay failover, relay→direct failback/roaming, long-running-uptime token-refresh artifacts — all missing.
- Phase E: six canonical cross-network reports still missing — the dominant recurring blocker (in-tree lab shares one underlay, can't synthesize distinct-WAN topology). Fresh-install OS-matrix artifact repeatedly goes stale relative to advancing HEAD.
- Windows relay: networked/mTLS control-plane token issuance not built (interim local-signing bridge only). Live Windows SCM installer/uninstaller execution + hardening evidence not proven.

### ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md
- Phase 7 not cleanly complete. Linux userspace-shared backend still fail-closes on `apply_routes`/`set_exit_mode`.
- `cargo audit` fails (RUSTSEC-2024-0436 via `tun-rs`→unmaintained `paste`). `cargo deny` fails license policy (BSD-2-Clause/ISC via `boringtun`/`tun-rs` chain).
- `phase10_cross_network_exit_gates.sh` fails (6 reports missing). `phase10_gates.sh`/`membership_gates.sh` fail (stale fresh-install matrix).
- 6 named prerequisites before "pre-live-lab ready," none complete.

### QH01TemplateInjectionFixPlan_2026-07-25.md
- Built+gated on an unpushed branch; **HELD, not integrated** pending corrections: S1 (`$DOM` nested-shell re-parse via `script -qec`, no dry_run test), S2 (`&'static str` doc claim false for body param), S3 (RawFragment "compile-time literal only" claim false via `String::leak`), S4 (no completeness assertion on the invariant table), S5 (backstop scanner misses several patterns), S6 (6 more coverage gaps: fetch_image pool/url/image, host_disk_status pool, fetch_host_artifact path, guest_console domain, recover_host_vms domain, provision_toolchain channel).
- Explicitly out of scope: QH-03 (fail-open `-e` shape) and QH-13 (SSH post-host argv sink) — separate work.

### QualityHardeningTodo_2026-07-25.md
- Status: OPEN. **34** items (QH-01..QH-34) — QH-31..QH-34 added 2026-07-29 from the first
  live run of the triage launch gate: QH-31 lab-monitor reports "idle" during a live run
  (relative `--report-dir` unresolvable from the TUI's cwd), QH-32 a run prints nothing to
  stdout for its whole duration, QH-33 `vm_lab` unit tests do real network I/O against the
  live lab subnet (intermittently red suite, ~5 min/run), QH-34 every run records
  `dirty:worktree` because it mutates an un-excluded tracked file. Selected still-open
  highlights (full detail in the doc):
- QH-01 built, integration pending. QH-02 partially closed, 2 guards uncovered. QH-03 REFUTED for named script but 2 real fail-open scripts + all 10 host-script consts lack `-e`. QH-04 verified, release-blocking, **no owner assigned**. QH-05 convention not adopted. QH-06 stale guidance still lives in 6 places. QH-07 ledger `two_hop` column shows pass for a stage that's never passed (0/379). QH-08 dedicated-worktree convention not implemented. QH-09 disclosure line doesn't name the sidecar artifact across ~8 sites. QH-10 reachability probes use wrong protocol (ICMP not TCP/SSH); `wg show` failure not distinguished from no-peers. QH-11 durable state under `/private/tmp` destroyed a coordination file once — not fixed. QH-13 SSH post-host argv still unvalidated at 7 of 8 sites, upgraded to HIGH. QH-14 `provision-toolchain` Debian/apt-only despite detecting Fedora. QH-15 Windows build timeout hard-coded. QH-16 "read the tool's own exit code" convention not enforced (documents 6 related false-signal instances). QH-17 Windows lab-image provisioning gaps. QH-18 live-lab singleton gate has no real mutual exclusion (fix direction specified, not implemented). QH-19 sink-context classification not complete. QH-21 one sibling StrictMode site still exposed (`script_template.rs:1281`). QH-22 `first_failed_stage` still alphabetical. QH-24 remote-script adapter layer largely unreachable from tests. QH-25 `assert_mesh_client_nat_session` overclaims. QH-26 3 unreviewed WIP commits reached main touching trust path — needs operator decision. QH-27 no tooling fix for the rebase-across-moved-base hazard. QH-28 shipped Windows installer mints self-signed CA cert into product path — needs OPERATOR DECISION. QH-29 fail-closed assertion string-matches generated nftables text — sweep not done. QH-30 `extra_peers` fail-closed branch has no test.
- (QH-12/QH-20 closed/resolved.)

### QualityHardeningTodoReview_2026-07-25.md
- Adversarial review of the above; own open items: QH-07 retraction needs formal reinstatement with cross-ledger proof; QH-12/QH-01 misattribution in register text; QH-02 exemplar tests swapped in prose; README undercounts register (13 vs actual 30); process recommendation (name tree/commit per item) not adopted; untracked file literally named `-` sits at repo root, unresolved.

### RepoReview_2026-07-20.md
- Status: "ACTIVE DEVELOPMENT - Release Blocking Issues Identified."
- CRITICAL: no macOS or Windows nodes present in any of 62 analyzed live-lab runs. `live_two_hop_validation` fails 10+ consecutive runs. `live_managed_dns_validation` fails 6 runs.
- 13 more stages marked UNRESOLVED with 1-3 failures each.
- Backend-boundary/secrets-hygiene gates, cargo audit/deny, AGENTS/CLAUDE sync, ledger currency, mac/win inventory validation, full 3-platform run — 8-item verification checklist, all unchecked.
- 22 stages consistently skipped in "successful" runs, reason not investigated.

### RustNativeMultiPlatformOrchestratorPlan_2026-04-28.md
- §0.a acceptance spec: DRAFT, PENDING OWNER SIGN-OFF.
- Bucket 1 (largest): per-platform execution wiring for mac/win across security/live/role-lifecycle suites, all report-skipped.
- Cross-network suite PARKED (owner directive). Iterate mode (resume/rerun) open. Several CLI flags only work in the bash-router arm.
- Bucket 7: no clean coordinated live bash-vs-Rust parity run pair produced yet. Bucket 8 (bash removal): gated on 1–7.
- "W5 complete" criteria: 7 of 9 unchecked.
- Known blocker: client↔client `traffic_test_matrix` fails in all-clients topology (needs product decision). Windows Exit needs a WinNAT/HNS-capable guest.

### RustNativeNodeOrchestratorQualityAudit_2026-07-10.md
- "Core hardening landed locally, structural split remains." RNQ-02 mac/win live residue fixtures pending. RNQ-05 live green re-proof pending; broader §14 fault-injection ambition open repo-wide. RNQ-07 not yet live-lab-proven. RNQ-15 `build_allow_spec` stays in mod.rs until W5.7. RNQ-20 live Fedora bootstrap proof pending (lab account lacks passwordless-sudo). A same-underlay full-mesh evidence run still required (prior run's topology was invalid).

### RustNodeOrchestratorCompletionBrief_2026-07-12.md
- Track A not complete at time of writing. Track B parity-gate spec not written/approved. Track C zero clean paired runs, no `overall_functional_parity_pass=true`. Track D not started.
- `live_reboot_recovery_validation` flagged as next cascade failure to investigate.
- Environment blocker: Windows exit needs a physical Windows-on-ARM device (UTM/QEMU can't provide nested virt). macOS guest needs repair or full rebuild.
- "Before-launch owner checklist" — 6 unchecked items.

### RustyfinExtensionTrustPlan_2026-05-10.md
- Status: design/scoping, nothing implemented. Entire spec open: private DNS naming model, Rustynet root CA, device trust bootstrap, service cert issuance, local HTTPS termination, Rustyfin public-origin integration, extension-safe reachability, exit-node/service coexistence rules, UX trust-state surfaces, hostname-based pairing migration. 9-item implementation order and 8-item acceptance criteria, none complete. 8-item testing checklist, none run.

### RustynetComparativeVpnExploitCoverage_2026-03-14.md
- 3 partially-covered rows (Tailscale DNS-rebinding, WireGuard endpoint-mobility risk class, TunnelCrack bypass) all need live validation that hasn't run.
- 1 future-surface-gap (Tailscale non-constant-time relay auth) — must stay "blocked into design and tests" before any future HP3 relay-auth comparison ships.
- Session update: `cargo fmt` blocked by unrelated diffs; a target test blocked by unrelated compile failures.

### RustynetDataplaneExecutionPlan_2026-05-18.md
- D14.a-d (anchor port-mapping auto-flip, IPv6-first+PCP, NAT-behavior discovery, gossip-coordinated punch timing) — no landed-status, appear not implemented.
- D14.e/f GATED (owner sign-off needed for both).
- D4 relay: code-complete, live 2-node hardware integration test + tcpdump evidence deferred.
- D12 macOS relay-service: live launchd bootstrap deferred to a reviewed pass.
- D6/D7/D9 Windows: readiness/exit/mixed-platform live validation overlaps still-open D7 cycle. D10 posture-doc promotion not started.
- Final soak requirement (24+ hr dual-device dual-network with a transition each) — not done.
- 8-row open-questions table, all status-quo, none actioned.

### RustynetUnifiedTodoLedger_2026-07-10.md
- **Superseded by this file as the current roll-up (see §0 above)**. The master repo-wide roll-up as of 2026-07-10 (now 18 days old). §2 (9 standing completion rules), §3 (7 P0/P1 critical-path items), and §4 through §22 (stage infra, verification ladder, per-run checklist, security-stage backlog, `--node` engine, canonical VM networking, desktop role parity, cross-network dataplane, Android — entirely unbuilt, iOS — entirely unbuilt, shared mobile gates, nas/llm roles, broader security remediation, test coverage/fuzzing, serialization hardening, CI/supply-chain, performance, operator UX/MCP/monitor, operations/evidence/release, platform expansion, external blockers/owner decisions, definition of done) are almost entirely unchecked `- [ ]` items — this remains the single largest concentration of open work in the whole doc tree; go there for the full section-by-section detail (too large to duplicate here without losing structure).
- 7 top-level Definition-of-Done gates, **none met**.

### SecurityAndQualityAudit_2026-06-10.md
- Status: audit pass COMPLETE, recommendation "NO-SHIP until the P0 set is closed." ~50 AUDIT-XXX findings recorded Open in this document (RN-03/04/10, AUDIT-017/018/019/027/031/040/045, RN-08, AUDIT-005/020/021/022/025/028/029/032/033/034/036/037/038/041/046/047/048/049/001/002/003/004/008/011-016/023/024/026/030/035/042/043/044/050/051/052/053, plus RN-02/05/09/11/13/16/18/25/26/27/28/29/30/34/35/36/37/38 via §8 reconciliation). Several since superseded by the newer RSA-numbered ledger's "applied" markers — but as this document's own tracker reads, all listed above are Open. §11: residual unknowns not settled by this static pass (Windows/macOS firewall+key-custody unvalidated live, relay-DoS magnitudes unmeasured, multi-version dependency duplication untracked).

### SecurityAuditAndMainConsolidation_2026-07-21.md
- "Part B" of the original audit (hunting the same bug shape elsewhere) never attempted, descoped by operator instruction.
- Adjacent bearer-token gap: `anchor pull-bundle` still uses a static long-lived bearer token, not a single-use enrollment token.
- None of the A1-A5 work has been run through the live lab.
- Doc-sync nit: SecurityAuditLedger still names an already-deleted function as needing fix/delete.
- Branch housekeeping flagged but not performed (5 stale branches, worktree chains) — **note: this was subsequently done in a later session, see the branch-consolidation memory.**

### SecurityAuditCatalogStalePathsTodo_2026-07-28.md
- Status: OPEN, not started (itself RSA-0049-class). `security_audit_catalog.rs:279` cites a deleted file. `:693` targets a relocated doc, ambiguous which current doc it should check. Open question: does the harness treat a missing-file `rg` exit code as false-negative "success"? Fix (4 steps) not done, including: no test currently asserts catalog paths exist (0 of 11 candidate paths guarded).

### SecurityAuditLedger_2026-06-18.md
- **Stale-classification flag (see §2.9)** — own Executive Summary/severity table/Verdict self-flagged stale by an internal 2026-07-27 correction.
- Running corpus: 89 raised (RSA-0001–0089), 2 withdrawn, 1 retired. Findings whose own status reads open (severity in parens): RSA-0001 (Med, v0/v1 envelope ambiguity), RSA-0002 (Med, Windows custody no-op), RSA-0003 (Low, inverted guard, protective), RSA-0004 (Low, macOS keychain argv), RSA-0005 (Low, stale doc comment, now live per RSA-0008), RSA-0006 (Low, protocol-enumerated allow-all evades check), RSA-0008 (Med, CLI issuance generator not revocation-aware), RSA-0010 (Low, panicking sign_at), RSA-0011 (Info, no anti-rollback floor), RSA-0012 (Low, audit-append TOCTOU), RSA-0013 (Info, discarded chmod result), RSA-0014 (Question, owner decision needed), RSA-0015 (Info, silent role-string drop), RSA-0016 (Low, non-constant-time compare), RSA-0017 (Low, no DB perm check), RSA-0018 (Question, test-only validation, module unwired), RSA-0019 (Info, redaction gaps), RSA-0020/0021/0022 (Info-level gaps), RSA-0024 (Question, controllers built but unwired — owner decision), RSA-0025 (Med, Windows backup ACL), RSA-0026 (Med, disposition-conflicted, see §2.12), RSA-0028 (Low, no gossip rate limit), RSA-0029 (Low, in-memory-only replay window), RSA-0032/0033 (Low, missing SAFETY comments, unscoped kill), RSA-0034/0035 (Info, dormant/unwired), RSA-0036 (Info, permanent stub), RSA-0038/0040/0042 (Low, no fuzz targets), RSA-0039 (Low, Debug leaks key), RSA-0041 (Low, reflection primitive, correction: volume bound claim was false), RSA-0044 (Info, validation gap parity), RSA-0045 (Question, carry item), RSA-0048 (Low, no timeout, slowloris), RSA-0049 (Low, catalog citing unwired controls — see SecurityAuditCatalogStalePathsTodo), RSA-0050 (Low, panic on malformed output), RSA-0054 (Low, no path confinement), RSA-0060/0061 (Low, world-readable ephemeral keys, no argv separator), RSA-0064/0065 (Med, unpinned installer downloads), RSA-0066 (Low, TOFU divergence), RSA-0067/0069 (Low, self-signed certs into LocalMachine\Root), RSA-0070/0071/0072 (Info, script robustness), RSA-0073 (Info, uncompiled vendored code on disk), RSA-0074 (Low, missing SAFETY comments in production dataplane FFI), RSA-0075 (Info, u8 wrap edge, fail-closed direction), RSA-0076 (Info, no restriction-lint family enabled), RSA-0078 (Info, liveness-blind lock recovery), RSA-0079 (Low/Question, re-enroll watermark wipe, owner question), RSA-0081 (Low, stale path check), RSA-0082 (Med, unbounded prune on every failed forward), RSA-0083 (Low, no SO_RCVBUF), RSA-0084 (Med, Windows relay defaults to public bind, no firewall rule), RSA-0085 (Question, PSK never set in production — effectively Noise_IK not Noise_IKpsk2, owner decision), RSA-0086/0087 (Med, raised not verified — pre-auth verify keying, IPv6 /64 limiter fill), RSA-0088 (Low, partially verified), RSA-0089 (Low, raised not verified — relay client timeout blocks reconcile loop).
- (RSA-0007/0009/0023/0027/0031/0037/0043/0047/0059/0063/0077/0080 recorded applied/closed.)

### SecurityHardeningAudit_2026-04-28.md
- **Stale-classification flag (see §2.14)** — original "matches or exceeds" comparative claim walked back by its own 2026-07-27 correction.
- B.4.1 (Med, partial): RFC1918 resolver-output filter still open — the protocol-level DNS responder itself doesn't exist yet.
- B.7: whether to add WireGuard PSK support is now an open owner decision, not a cleared axis.

### SecurityHardeningBacklog_2026-06-01.md
- HB-1 through HB-7 (Low/Info): secure-scrub for ephemeral keys, Windows ACL-only key protection, PATH-resolved netsh, IPv6 Drop-guard gap, hardcoded Cloudflare IP in a security test, unenforced PowerShell quoting discipline, `AlgorithmPolicy` inverted-guard fix undecided.
- §B highest-priority re-verified OPEN: RN-03 (10/44 sites discard Result), RN-04 (killswitch programmed after backend start, opt-in/Linux-only), RN-05 (non-`node:` selectors bypass revocation), RN-06 (Windows LAN egress allow-all except :53), RN-07 (Windows IPv6 leak, in progress with 3 named gaps), RN-11 (permissive-on-empty defaults).
- Recommends but not yet implemented: move Windows killswitch to WFP; make pre-protective killswitch mandatory cross-platform; deny-by-default on empty membership/context.
- P1/P2 carried items (RN-02, RN-08-10, RN-12/13/16, RN-17..38) explicitly "not re-verified this pass."

### SecurityRemediationPlan_2026-06-19.md
- **Stale-classification flag (see §2.10)** — scope stops at RSA-0074, ledger now runs to RSA-0089.
- Wave P1 still-open Medium items: RSA-0002, RSA-0025, RSA-0046, RSA-0068, RSA-0052, RSA-0053, RSA-0064, RSA-0065.
- Wave P2 still-open: RSA-0038/0040/0042 (fuzz), RSA-0032/0074 (SAFETY comments), RSA-0001 (DEFERRED, high blast-radius), RSA-0039, RSA-0060, RSA-0013/0020, RSA-0033, RSA-0066, RSA-0041, RSA-0056/0061, RSA-0070/0071/0072, RSA-0028/0029, RSA-0073.
- Owner-decision queue: RSA-0018, RSA-0024, RSA-0034, RSA-0035, RSA-0045 — 5 of 6 still open (RSA-0014 alone decided+applied).

### SecurityReview_2026-05-24.md
- Master tracker: 15 Fixed, 1 Partial, 1 Accepted, **21 Open** (3 High/2 Med/11 Low/5 Info): RN-02 (High, dead dataplane.rs), RN-06 (High, Windows LAN egress), RN-07 (High, Windows IPv6 leak), RN-08 (Med, Partial), RN-12 (Med, Linux DNS-leak ordering bug), RN-13 (Med, unbounded flood-guard map, guard doesn't run in prod anyway), RN-18/20/25/26/27/28/29/30/31/32/33 (Low), RN-34/35/36/37/38 (Info).

### SecurityStageBacklogStatusCheck_2026-07-04.md
- §2.1: no StageCategory/SECURITY section in lab-monitor. §2.2: `disabled_stages` toggle mostly non-functional (only one pseudo-stage actually enforced).
- §4: 11-row backlog, zero code for all of it (RR-01/02/03, FCF-1/2/3 "single most severe open item", RPT-01/HP-3 "biggest looks-done-but-isn't gap", S3-10, RSA-0063 live proof, KC-04, PH-7, KL-2/3/4, KC-07, CNT-1, PH-2/3).
- §5: coverage-as-code enforcement still open; barrier-exempt stages open.
- §6: Linux blind_exit, macOS admin, Windows anchor.bundle_pull all still need real live stages.

### SerializationFormatHardeningPlan_2026-03-25.md
- Status: partial. Phase A wider work not started. Phase C (CBOR migration) not started. Phase D (NDJSON→CBOR sequence) not started. Broader artifact-family migrations "remain open and are still not started."
- Managed-DNS live adversarial proof blocked (SSH timeout). Residual blocked gate commands recorded (fmt, phase10_gates.sh both blocked by unrelated issues at last execution).

### ServiceHostingRolesDeltaPlan_2026-06-11.md
- D13.c/d: MagicDNS overlay names for service hosts not added. Linux nas/llm live-lab evidence rows not yet recorded (blocked on in-flight simulator stream at time of writing). macOS/Windows nas/llm stay fail-closed pending cross-OS live evidence.

### ServiceHostingRolesRoadmap_2026-06-11.md
- M0-M4 done. M5 live-lab rows: open, next step. M6 RustyBackup/RustyAI companion apps: future, separate program, not started.

### ShellToRustMigrationPlan_2026-03-06.md
- Phases A-I complete except: refresh the Rust-only remote E2E evidence (Phase I) — lab-dependent, needs a live VM run.

### StartShOperatorUxRustMigrationPlan_2026-05-24.md
- §8 open decisions unresolved: `rustynet-operator` crate vs modules-in-CLI; manual parser vs `clap`; dependency-bootstrap scope (§4.7's full recommendation reads unimplemented — bootstrap was removed, not ported); start.sh retirement timeline not confirmed.
- §4.8.2: future `ops install-binaries`-style command noted as conditional/open.

### TestCoverageImprovementPlan_2026-05-24.md
- P0.6 remaining: no on-disk digest field on gossip watermark spool (wire-format change, deferred).
- P1.1: more `rustynet-sysinfo` IO-fused parsers to split (df/systemctl/launchctl/vm_stat/openssl/stat).
- P1.2: boringtun-seam mock still needed. P1.3: two edge cases still open/untested.
- P2: 8 more open items — traversal.rs isolation, relay_client.rs HMAC tests, stun_client.rs malformed-decode tests, backend-userspace unsupported-OS path untested, runtime.rs worker-thread untested, operations.rs audit-log tamper tests missing, persistence.rs credential-reject paths untested.
- Part C.1-C.5: `cargo llvm-cov` in CI not done; `proptest` not adopted; `cargo-fuzz` targets not registered (sandbox has no nightly); untested-crate coverage floor not done; negative-test convention gate not built.

### TrackC_BashOrchestratorDefects_2026-07-13.md
- BASH-DEF-1/2 documented, intentionally not fixed (path being retired). BASH-DEF-3 spec-level fix applied 2026-07-13; underlying dialect divergence remains inherent/unresolved by design.

### TrackC_Pair1_Linux_2026-07-13.md
- "NOT yet a full G1-G8 PASS." Finding P1-1 open: `cross_network_preflight` skip-vs-pass mismatch on single-subnet topology, recommended fix folded into cross-network Rust-native conversion work. (P1-2 resolved 2026-07-13.)

### TraversalSelfSustenancePlan_2026-07-23.md
*(No separate entry returned by the sweep agent for this specific file within its batch — content likely captured under the cross-references to it in `NodeEngineFlipDispositions_2026-07-24.md` D3/increments I3-I6, which remain open per that doc.)*

### UbuntuHostLabControlFindings_2026-07-23.md
- All 5 BUG-BOX items RESOLVED + proven live. "Remaining to reach full parity (not bugs)": box git checkout was 142 commits stale (blocks sync_host/host_preflight GO until pushed work lands — **note: since resolved by the branch-consolidation session**); `eno1` NO-CARRIER keeps guests NAT-only behind `virbr0` (ADR-004 unmet); a Windows/WinNAT guest — the headline reason for this host — not yet provisioned.

### UbuntuHostLabControlRemediationPlan_2026-07-23.md
- **Stale-classification flag (see §2.7)** — directly contradicts sibling Findings doc. As literally written (if taken at face value): BUG-BOX-1 through BUG-BOX-5 fixes not implemented; §8 has 5 unresolved owner questions.

### UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md
- HP-4 status: partial. Remaining: fix retained-relay periodic direct-recovery regression (test still fails); collect live WAN/NAT evidence for direct/relay-fallback/failback; re-run phase gates once regression resolved. Phase HP-5 (VM matrix hardening/gates) appears not started.

### UdpHolePunchingHP2IngestionPlan_2026-03-07.md
- HP2-02 partial: handshake evidence still local/backend-only. Remaining blocker: periodic-reprobe test still fails. HP2-01/05/06 carry no explicit completion marker — read as unverified/open. Broader simultaneous-open WAN evidence remains open.

### UdpHolePunchingImplementationBlueprint_2026-03-07.md
- "Remains active because the gap table is not yet fully closed." Signed traversal-hint bundle work, backend probe surfaces, HP-4 daemon wiring, phase10 gate coverage all remaining. Gap table: 7 rows still open across control-signing/relay/runtime/CLI/backend-API/WireGuard-backend/phase10-gates. Repeated blocker: periodic-reprobe test failure. DoD (§13) not met.

### UTMVirtualMachineInventory_2026-03-31.md
- "Recommended Next Steps" (all conditional/open): refresh inventory on changes; update connect templates if login user changes; optionally add per-VM SSH config stanza; optionally generate a fresh dedicated keypair. One unmatched historical UTM address in SSH host-key history, unresolved.

### VmLabCapabilityCookbook_2026-04-14.md
- Recommended Phase 5 ("Documentation sync") has no corresponding completion slice recorded in the sibling Reporting Plan — reads as a possible open/untracked item.

### VmLabCapabilityReportingPlan_2026-04-14.md
- Slices 1-4 complete. Nothing else open.

### VmLabCapabilitySources_2026-04-14.md
- Nothing open (pure reference doc).

### WindowsExitAndRelayDeltaPlan_2026-05-10.md
- §2.2/§11: no live SCM-context proof of Windows-as-exit; no live relay traffic proof; no mixed-node/restart/reinstall proof; no cross-network proof. Posture promotion open (Windows still `runtime-host-capable only`).
- §A.7 IPv6 exit serving explicitly deferred, fail-closed by design.
- Progress-ledger TBD items: §A.1-A.6 (live SCM NAT lifecycle, DNS leak, killswitch precedence, cross-network exit — all blocked/TBD), §B.1-B.5 (relay wiring/traffic/failover/signed-fleet/live-execution — all TBD or partial), §C.1-C.3 (Linux-only gate cleanup, heterogeneous evidence, CI Windows gates — in progress/TBD), §D.1-D.4 (posture promotion — TBD, blocked on §A/B/C).
- Track E backlog: 6 of 7 items open (sig-tamper test, peer-map v2→v3 migration "do not start without an operator-approved plan," criterion benchmark, privileged-helper IPC fuzzing, Windows SKU-detection unit test, `force_fail_closed` degraded-state hardening needing an architecture sketch first).

### WindowsExitNodeRunbook_2026-06-04.md
- Success path for `active_exit` needs a WinNAT/HNS-capable Windows guest; current lab VM lacks it (minimal image, no HNS/WinNATWmiProv.dll) — described as "environment, not code," the sole remaining item. `is_supported_for_platform` flip pending that evidence.

### WindowsLabVmStabilityAndSessionModel_2026-04-30.md
- Only Phase L0 (writing the plan) marked done. Phases L1-L6 (reimage guest, install toolchain machine-scoped, bootstrap script changes, gate legacy fallback, E2E verification, sweep/cleanup) all read as not yet executed. DoD criteria not confirmed met.

### WindowsLiveLabReadinessPlan_2026-05-31.md
- G3: opt-in loopback-resolver/NRPT DNS enforcement deferred (stronger control beyond firewall baseline).
- G4: 🟡 — Fix-3 pending: `run_windows_e2e_bootstrap` computes node role but discards it instead of passing `--node-role` into daemon env.
- G6: 🔴 — roles never run on Windows (blind_exit/anchor/exit_server); earlier attempt recorded `overall_status: failed`.
- G8: 🟡 — IPv6 leak validated live but end-to-end leak-proof deferred (lab LAN has no global IPv6). Residual RN-06 (IPv4 LAN-egress unscoped) and HB-4 (Drop-guard doesn't delete IPv6 rule on hard-kill) still open.
- G9: 🔴 — rollback-on-failure/fail-closed persistence across daemon crash unvalidated; `probe_and_recover_local_utm.sh` still skips Windows guests on a stale assumption.
- 3-node follow-up: macOS blocked at `collect_pubkeys` — WG-passphrase Keychain load unreachable as a LaunchDaemon; fix identified (coordinate onto a daemon-accessible store) but explicitly NOT done, security-sensitive.
- Recurring gap: `cleanup_hosts` doesn't reset leftover Windows NRPT/DNS/killswitch rules before `bootstrap_hosts`.
- N5/N6: Windows roles and full live-lab matrix not run/recorded. E3 (stage-timing CSV) queued, not started.

### WindowsUtmTransportArchitecture_2026-04-30.md
- "Future work": inline-exec channel for mesh-join stages (base64-embedded argv via `utmctl exec` to avoid prior SCP) — tracked as next iteration, not built.

### WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md
- Windows SSH/access orchestration explicitly "not yet authoritative." Phase 6 clean-snapshot proof blocked — host-side SSH to `windows-utm-1` times out despite healthy guest-side readiness (host-side reachability issue, not guest setup). Immediate Closure Checklist items unchecked. `verify-runtime` still needs a live data-plane path a standalone guest can't satisfy. M5 milestone not reached.

### WindowsWorkingNodePlan_2026-04-17.md
- **Stale-classification flag (see §2.8)**.
- "Remaining Work Streams" (6, as literally stated, still open per this doc): First Real Windows Backend (called "the primary blocker"), Tunnel/Device/Artifact Lifecycle, Route/DNS Runtime Truth, Windows-Safe Local Operations, Mixed-Node Validation, Fresh-Install/Release Evidence. DoD not met per this doc's own text.

---

## Part 2 — `documents/*.md` (top-level, 17 files) + 4 repo-root prompt docs

### CliCommandsDesign.md
- Categories 8-14 (21 proposed subcommands across node/membership, policy, relay, cert/trust, analytics, backup/restore, config) are designed but **not implemented** — "Proposed Future Commands (Phases 4+)," with a stated priority order.

### CODE_MAP.md
- FIS-0027 `PathMtuDiscovery`: Phase 1 done; probe carriage (Phase 3) and dynamic apply
  (Phase 4) not wired. **Assessed 2026-07-29 — Phase 4 cannot land before Phase 3.** With no
  probe events the machine's fail-closed `effective_plpmtu` is `base_plpmtu` (1280), so
  applying it today would drop every node from the 1420 they currently run. Phase 3 needs a
  padded probe + ack channel on the tunnel, and none exists: there is no ICMP construction,
  no echo facility, and no `IP_RECVERR`/PTB ingestion on the userspace socket (and
  `unsafe_code = "forbid"` rules out raw `setsockopt`, while nix 0.28 exposes `MSG_ERRQUEUE`
  but no safe `IpRecvErr` sockopt). Two candidate carriages, in preference order:
  (a) **in-tunnel padded ICMP echo** to the peer's mesh IP — the peer's kernel replies with
  no new protocol and no peer-side code, and `inject_plaintext_packet` already exists as the
  injection point; the work is packet construction plus reply matching on the inbound TUN
  path. (b) PTB ingestion via the error queue — a real signal needing no protocol, but it can
  only ever *lower*, never confirm, so it cannot drive the search on its own.
  Phase 4 groundwork landed in `e6144250`: `PathMtuConfig::for_bringup_mtu` plus `const`
  drift pins, because deriving the ceiling from the bring-up MTU was previously
  unconstructible on exactly the constrained paths DPLPMTUD exists to serve (base 1280 >
  a legal 1220 ceiling → `CeilingBelowBase`).
- FIS-0028 UDP-offload capability probe: Phase 1 implemented but not called from any packet path.
- RN-03: of 44 `force_fail_closed` sites, 10 were discarded — flagged "open P0."

### MembershipConsensus.md
- Nothing open.

### MembershipImplementationPlan.md
- Nothing open.

### Phase1.md
- §4 Security Gates: **TLS 1.3 (`rustls`) not implemented (2026-07-27)** — cross-ref SecurityMinimumBar.md §3.2.

### phase10.md
- 2026-03-08 note: remaining open work is "production relay transport service plus full WAN simultaneous-open traversal behavior." Self-flagged scope-stale vs current macOS-hardening reality; points to PlatformSupportMatrix for current truth.

### Phase1Implementation.md
- P1-23: "the TLS-1.3-only policy is declared, not enforced (2026-07-27)."
- §12 Definition of Done Checklist (Phase 1) — **all 14 items unchecked**.

### Phase2.md / Phase3.md / Phase4.md / Phase5.md / Phase6.md
- Nothing open in any of the five (forward-looking scope docs, no status/TODO/checklist markers).

### documents/README.md
- Nothing open directly; navigation index pointing to `operations/active/` ledgers.

### Requirements.md
- §9 "Open Decisions to Resolve Early" — 6 undecided: auth model, persistence engine, policy format, DNS strategy, relay deployment model, licensing.
- §14 "Suggested Next Steps" — approve 9-phase split, build execution backlog, define milestone acceptance tests, track phase-handoff risks, run recurring roadmap reviews — all still forward-looking.

### RustyChatIntegrationRequirements_2026-05-29.md
- Status: "design / scoping (no implementation committed yet)." 5 gaps, all unbuilt: local app-identity/discovery API, app-scoped E2E key story, app-aware policy/port reservation, liveness/presence feed, offline delivery architecture (unresolved). §6: messaging-identity model and offline-delivery-in-v1 both undecided.

### SecurityAnalysis_2026-06-12.md
- RN-02 corrected/resolved but flags a residual stale doc-reference in `security_audit_catalog.rs:279`.
- **RN-N1 open**: production `expect()` panic at `daemon.rs:5908` (double `.take()` on `relay_client` → crash), no fix noted.
- RN-08 disposition conflict (see §2.11 above) — partial fix, v0/v1 auto-detect still misclassifies ~255/256 legacy blobs.
- RN-09/RN-10/RN-16/RN-N4/RN-N6/RN-N8 all open (systemd-credential mask, corrupt-ledger silent genesis, mutable-tag Actions pins, no gossip rate limit, no relay-parser fuzz targets, unbounded replay-ledger growth).
- RN-N7 marked open in-body but a later correction says fixed (RSA-0027).
- RN-07: WFP migration still pending (netsh interim only).
- §6: 7 parser families (relay hello, relay session token, gossip bundle, STUN response, PCP MAP, UPnP device description, DNS zone) lack fuzz targets.
- §5 HardeningBacklog: 7 open items (HB-1 through HB-6, B.4.1).
- RSA-0024 "still open" per the 2026-07-27 correction (dead-code positive controls).
- Minor doc-accuracy: `forbid(unsafe_code)` claim overstates the real mechanism (only 29/86 files carry `forbid`).

### SecurityMinimumBar.md
- Critical Control 2: dead-code-shaped TLS control needs a decision (delete vs wire to a real handshake). Adjacent gap: bundle-pull authenticates via static bearer token, not the enrollment-token ledger the Requirements spec calls for. Residual pin-rotation risk: a compromised revoked owner key can still pass co-signed acceptance.
- §6.C control 2: no application-layer peer check beyond the shared bearer token once LAN bind is enabled.
- §6.C control 3: **UNMET REQUIREMENT** — static bearer token, no single-use/replay-rejection semantics.
- §6.C control 4: **UNMET REQUIREMENT on all 3 platforms** — described secret custody (systemd LoadCredentialEncrypted / Keychain / DPAPI) doesn't exist; every platform ships a plaintext 0600 file.
- §6.D control 2: `scripts/ci/blind_exit_irreversibility_gates.sh` doesn't exist despite 3 docs citing it.
- §6.E E1/E3/E4: all three "not wired" — zero production callers for tunnel-only-bind validators, `ServiceExposureController` never constructed, session-token verify/issue never called from the LLM gateway binary. CI gates for these check symbol presence only, not reachability.
- §8 Sign-off Checklist — **all 5 items unchecked** (security/eng/ops owner approval, artifact signing/SBOM, critical controls green).

### rustynet_repo_context_prompt.md
- §8: NAS/LLM roles are the stated exception with no live-lab stage yet.
- §14: Windows exit ⛔ (WinNAT evidence), relay/anchor on mac+win ⛔ (cross-OS green run), nas/llm ⛔ everywhere, mobile client 📋 planned/no adapter.
- §14 features: macOS pre-killswitch not mandatory; Windows IPv4 LAN-egress allow-all (RN-06, open); `windows-wireguard-nt` opt-in only.
- Structural gap: Windows exit/blind_exit blocked by lack of nested virtualization on Apple-Silicon UTM/QEMU.
- §15: SecurityAuditLedger 74/76 findings still standing; SecurityAndQualityAudit AUDIT-027/RN-33/AUDIT-031 not stated fixed here; SecurityReview RN-02/06/07 remained open per cross-reference.
- §17: 2 lab-monitor GUI backlog items + 2 stage-contract gaps still open per SecurityStageBacklogStatusCheck summary.

### rustynet_live_lab_loop_prompt.md
- Explicitly "state-free" (tracker lives elsewhere). Its own embedded journal digest: Wave-2 `rustynet-cli` package dispatch in progress (5 more packages staged, not dispatched). `live_reboot_recovery_validation` surfaced a 3rd open gap (missing `/etc/rustynet/assignment-refresh.env` provisioning in the focused lab). Windows-only validators uncoverable from the Mac host without `ubuntu-kvm-1`. Recurring gotcha: `discover_local_utm` needs an explicit `--utm-documents-root` every time.

### rustynet_hard_problem_prompt.md
- Nothing open — fixed policy template, `## TASK` is an intentional per-invocation placeholder.

### orchestrator_charter.md
- §7 registered workstreams, per-worker state:
- **WS-A**: `two_hop` RED — chained-exit dataplane forwarding never completes; root cause identified, fix not built. Sub-issues: shared-transport handshake proving unreliable (false-negative `direct_handshake_unproven`); TTL-2 check defeated by full-mesh residue.
- `network_flap`: daemon fails closed ~120s post-setup; fix track I3-I6 in TraversalSelfSustenancePlan remain (I1/I2 merged).
- Live T5 negative controls built but `execute()` returns Skipped — need live-guest fault injection (WS-D plan written, live-verify queued behind lab token).
- **WS-C**: fleet onboarding — Layer 0 done; pending in order: image catalog+arch gate → `onboard-host --new` → `add-guest` → teardown → fleet-status/converge → Layer 1 MCP tools. Certificate-based auth explicit future work; polkit `auth_unix_rw` must flip from none→polkit in C1 bootstrap.
- **WS-B** pending queue (priority order): finish Windows node bootstrap (release build unconfirmed); provision Fedora node (toolchain not installed); run Windows WinNAT exit live-lab cell (release-blocking, not yet run); push 2 unpushed inventory commits.
- An uncommitted `vm_lab/mod.rs` edit (WS-B's pidfile guard) was blocking WS-C's later touches to the same file at time of writing.
- W5.7 (bash retirement) explicitly "a SEPARATE, later gate — not started."

---

## Part 3 — `documents/operations/*.md` (non-active, 43 files)

### Arm32BitEmbeddedImplementationGuide_2026-06-23.md
- Status: "open items — work needed before 32-bit ARM can be called supported." Release profile (`strip`/`panic=abort`) missing. `.cargo/config.toml` armv7 cross-toolchain config not committed. Hardening not applied: WireGuard MTU code fix, 3 systemd unit hardening items, UDP socket buffers, relay thread stack size, journald rotation. §9: relay socket re-bind on IP change only has a dhcpcd workaround; netlink fix is future work. No CI gate for armv7. `PlatformSupportMatrix.md` still overstates "compile blocker." No live-lab evidence row for armv7.

### Arm32BitEmbeddedSupportReference_2026-06-23.md
- "Evergreen reference." §28 Known Open Items table — 14 items mirroring the Implementation Guide above (doc-language overstatement, missing cargo config, missing service hardening fields, MTU/socket-rebind/DNS-protected-mode/OOM/watchdog/StartLimitBurst/strip/panic=abort/UDP-buffers/log-rotation/CI-gate).

### BackendAgilityValidation.md
- Policy requires ≥1 additional non-simulated `TunnelBackend`; repo currently only has WireGuard + a simulated stub — second backend not implemented in code.

### CliExitCodeTaxonomy.md / CompatibilitySupportPolicy.md / ComplianceControlMap.md
- Nothing open in any of the three.

### CrossNetworkLiveLabPrerequisitesChecklist.md
- Reusable pre-run go/no-go template (not a tracked backlog) — §9 has 11 unchecked gate items re-verified before every cross-network run; listed for completeness, not a persistent gap.

### CrossNetworkRemoteExitArtifactSchema_2026-03-16.md
- States its own schema exists "before the implementation is complete" — explicit acknowledgment the Phase10 remote-exit implementation wasn't complete when written.

### CrossNetworkRemoteExitIncidentPlaybook.md
- Nothing open.

### CrossNetworkSimulationRunbook.md
- Tier A: lifecycle integration in progress (real `rustynetd`/kernel WireGuard in namespaces, full enrollment→gossip→ICE→direct-punch/relay-fallback flow, tcpdump path oracle, expanded NAT matrix — not done). Tier B: live run pending. Tier C/D: designed, not built. `double_nat_cgnat` refused (chained two-router site unimplemented). Orchestrator `--cross-network-substrate` selector only "planned."

### CryptoDeprecationSchedule.md / DependencyExceptionPolicy.md / DisasterRecoveryValidation.md
- Nothing open in any of the three.

### FinalLaunchChecklist.md
- "Additional non-simulated backend path" explicitly flagged open, requires code work.
- All checklist boxes unchecked: Security Minimum Bar verification, supply-chain integrity (signed artifacts/SBOM/provenance), dependency governance, audit integrity/retention, SLO/error-budget gates, perf/soak gates, incident-drill standards, multi-region DR RPO/RTO, phase9 evidence artifacts, WireGuard-adapter-only boundary, backend conformance/leakage checks, compatibility policy publication, crypto-deprecation schedule publication, insecure-compat auto-expiry, PQ hybrid transition plan publication.
- Final Sign-Off Record: Engineering/Security/Operations owner status all **"Pending."**

### FreshInstallOSMatrixReleaseGate.md
- Windows intentionally excluded from the required OS/scenario set until measured, commit-bound clean-install/one-hop/two-hop/role-switch/runtime evidence exists for current HEAD.

### HeterogeneousLiveLabRunbook.md
- §6: `windows-wireguard-nt` backend not live-tested end-to-end. Mesh-join evidence on Windows shows "state snapshot missing" until daemon ships on a working backend. Authenticode chain validation needs a code-signed release binary (dev builds fail). Production code-signing cert not yet in GitHub Secrets.

### LinuxDaemonValidatorRunbook.md
- Nothing open.

### LiveLabRunMatrix.md
- Rust `--node` engine has never once passed `linux_stage_two_hop` (0 vs 52 bash passes — non-interchangeable ledgers). "Current Truth": macOS/Windows anchor coverage can still be dry-run or non-mutating depending on the stage.

### LiveLabVmConnectivityRulebook.md
- Explicitly proposed, not fully implemented (§16 step 1 is "land this rulebook as policy"). §11.1: 7 current MCP tools misaligned with the rulebook (network-profile args missing, unconditional `--skip-cross-network`, no adapter/topology validation, wrong-direction "on physical LAN is good" logic, mutates with no rollback/evidence contract). §11.2/11.3: required new MCP tools not implemented. §12: typed network-profile Rust model, CLI commands, orchestrator NIC split, inventory migration, VXLAN generalization, dedicated physical lab — none built. §14: "Do not bulk-change attachments yet" pending profile/rollback work. §15.8: slices B-E gated on Slice A + hardware/owner decisions. §15.9: 7 owner decisions still needed (interfaces, address ranges, QEMU attachment, multi-NIC confirmation, lab hardware, remote/cloud policy) — note: `VmLabNetworkStandard.md` refers to ADR-004 as already "the locked decision," suggesting partial supersession.

### LiveLinuxLabOrchestrator.md
- Real capability evaluator only "planned" (`state/platform_capabilities.json` not built). Windows on current branch is bootstrap-scaffolded only, not runtime-capable; `install-release` remains a protective stub.

### MacosInstallRunbook.md
- "Known Issues/Gotchas": pf killswitch blocks SSH without an explicit allow flag; ~15GB build tarball fills a 45Gi VM volume; source tarball must include the boringtun submodule; UTM console keyboard layout requires workarounds.

### MacosLaunchdServiceManagement.md
- Self-flags as stale: "has stale paths and labels from an earlier design," kept for historical context only.

### MeasuredEvidenceGeneration.md / MembershipGovernanceRunbook.md / MembershipIncidentResponseRunbook.md
- Nothing open in any of the three.

### Phase10ExitNodeDataplaneRunbook.md
- §7: "current failover artifact demonstrates path-mode transition/audit evidence; full relay transport failover integration remains open code work."

### PlatformSupportMatrix.md
- Windows: runtime-host-capable only, not dataplane-capable, not fresh-install evidenced, not release-gated/evidenced.
- Direct/relay failover: state tracking only, "needs more work for full relay dataplane transport switching" (Linux+macOS).
- Traversal architecture: "implementation in progress," runtime parity "remains open work."
- Gossip push-loop wiring, enrollment-token CLI wiring, ICE traversal-path integration all "queued."
- Anchor node role: "Planned (D11)" — `rustynet anchor pull-bundle` doesn't exist yet.
- macOS `supports_ipv6=false` until parity complete.
- macOS CI dataplane evidence smoke-level only vs Linux real E2E.
- Additional non-simulated backend: not present in-tree.
- Windows admin/exit/relay/anchor gated on D7/D9. macOS blind_exit live evidence pending. nas/llm fail-closed everywhere with per-platform status notes.
- 64-bit ARM Linux unverified/no CI. 32-bit ARM Linux not supported (compile blockers), explicitly non-release-blocking.

### PolicyRolloutRunbook.md / PostQuantumTransitionPlan.md / PrivacyRetentionPolicy.md / ProductionRunbook.md / ProductionSLOAndIncidentReadiness.md
- Nothing open in any of the five.

### ReleaseReadinessGuardrails.md
- Nothing open directly; points to the (in-scope, already-covered) `active/Phase5ReleaseReadinessSummary_2026-04-12.md` for remaining gate blockers.

### ReleaseSigningRunbook.md
- §3.2: Azure Key Vault / AzureSignTool production signing route explicitly out of scope for the v1 runbook; only the PFX-on-disk flow is exercised. Tracked as a follow-up in SecurityHardeningAudit_2026-04-28.md.

### RustynetdServiceHardening.md / SecretRedactionCoverage.md / SecurityAssuranceProgram.md
- Nothing open in any of the three.

### SecurityPostureSummary.md
- §8 "Known open items (not blocking)": L6/L7/L8 lab-side validation need Linux lab fixtures; W1/W4/W5/W7 collectors need Windows-native infra; L2 nftables IPv6 verifier has no test floor yet; X2 remaining typed-view migrations (cosmetic).

### SecurityRegressionLessons_2026-03-07.md
- "Additional High-Value Backlog Tests (Next)": Role/Auth matrix expansion for membership-health variants; reconcile race/fail-closed invariant expansion; socket/local-IPC abuse hardening tests — none done.

### VmLabNetworkStandard.md
- Stricter dual-plane `isolated_multivm_v1` and the physical/remote lab tiers explicitly "later upgrades, gated on rulebook §15.9 owner decisions and hardware."

### VulnerabilityResponse.md
- Nothing open.

### WindowsWorkingNodeBringUpRunbook.md
- §6 "What's Still Pending": no end-to-end live evidence on a real Windows 11 host with WireGuard confirming traffic flows; signed-release production rollout needs an operator-provided code-signing cert; Linux-side validator parity — orchestrator's `LinuxDaemonProbe` needs `linux-runtime-acls-check`/`linux-service-hardening-check` mirroring the Windows pattern.
