# Rustynet Open Work Index — 2026-04-17

Status: active summary index

## Purpose

This document is a single index of what still appears to be open in Rustynet at the current documented stage of the project, where that work is tracked, and what would actually close it.

This is an index, not an owning execution ledger.
When status conflicts exist, prefer the owning ledgers and the newest explicit `Current Open Work` or `Current Status` block inside them.

## Authoritative Source Order

Use this order when deciding what is still open:

1. `README.md` (`Current Focus`)
2. `documents/operations/active/README.md`
3. `documents/operations/active/MasterWorkPlan_2026-03-22.md`
4. `documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md`
5. `documents/operations/active/Phase5ReleaseReadinessSummary_2026-04-12.md`
6. `documents/operations/active/Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md`
7. `documents/operations/active/Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md`
8. The owning subsystem plan for the specific area

## Repository Snapshot

At the current documented stage:

- Rustynet is **not release-ready**.
- The reduced Linux five-node local-gate route-truth blockers are **cleared**.
- The main remaining repo blockers are **fresh-install evidence on a clean current commit** and **canonical cross-network evidence on a clean current commit**.
- Windows remains **runtime-host-capable only**, not release-gated and not dataplane-capable.
- Several secondary plans remain open, but most of them are now either evidence-refresh work or wrapper/reporting truth work rather than missing core scaffolding.

## Priority Index Of Open Work

### P0 — Release-critical blockers

#### 1. Regenerate fresh-install evidence for current clean `HEAD`

**Status:** Open. Hard release blocker.

**Primary docs:**
- `documents/operations/active/Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md`
- `documents/operations/active/Phase5ReleaseReadinessSummary_2026-04-12.md`
- `documents/operations/active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md`

**What remains:**
- Create a clean commit from the current fixes.
- Rerun the relevant live evidence on that clean commit.
- Generate `artifacts/phase10/fresh_install_os_matrix_report.json`.

**Why it is still open:**
- The current Phase 4 run used working-tree provenance.
- The recorded git state for that run was dirty.
- The repo intentionally refuses to treat that as commit-bound fresh-install evidence.

**Close when:**
- `artifacts/phase10/fresh_install_os_matrix_report.json` exists for a clean current commit.
- The report is accepted by the repo’s own release/readiness path.

---

#### 2. Regenerate canonical cross-network evidence for current clean `HEAD`

**Status:** Open. Hard release blocker.

**Primary docs:**
- `documents/operations/active/Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md`
- `documents/operations/active/Phase5ReleaseReadinessSummary_2026-04-12.md`
- `documents/operations/active/Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md`
- `documents/operations/active/CrossNetworkRemoteExitNodePlan_2026-03-16.md`

**What remains:**
- Add trusted pinned `known_hosts` coverage for `debian-lan-11` / `192.168.0.11`.
- Verify reachability and `sudo -n` on all participating hosts.
- Use a distinct-underlay topology that honestly satisfies the repo’s cross-network contract.
- Re-run the canonical suites on a clean commit.
- Validate the resulting reports with the repo validators.

**Required evidence set:**
- `artifacts/phase10/cross_network_direct_remote_exit_report.json`
- `artifacts/phase10/cross_network_relay_remote_exit_report.json`
- `artifacts/phase10/cross_network_failback_roaming_report.json`
- `artifacts/phase10/cross_network_traversal_adversarial_report.json`
- `artifacts/phase10/cross_network_remote_exit_dns_report.json`
- `artifacts/phase10/cross_network_remote_exit_soak_report.json`

**Why it is still open:**
- The five local UTM guests share the same underlay and cannot by themselves satisfy the canonical proof contract.
- `debian-lan-11` is the only distinct-underlay inventory target currently named as the path to honest cross-network proof.
- Trusted host-key material is still missing for the authoritative run.
- The canonical reports have not yet been regenerated on a clean current commit after the latest hardening.

**Close when:**
- All six reports are regenerated on a clean current commit.
- The reports include the newer SSH trust and shared-transport proof requirements.
- The soak report also passes the strengthened direct-only truth rules.

---

#### 3. Re-run final release-readiness signoff

**Status:** Blocked on items 1 and 2.

**Primary docs:**
- `documents/operations/active/Phase5ReleaseReadinessSummary_2026-04-12.md`
- `documents/operations/active/Phase5ReleaseReadinessChecklist_2026-04-12.md`

**What remains:**
- Re-run `./scripts/ci/release_readiness_gates.sh` only after current clean-commit fresh-install evidence and canonical cross-network evidence exist.

**Close when:**
- The final release gate passes honestly without relying on reduced/local-only evidence.

### P1 — Connectivity/runtime work that is still not honest to call complete

#### 4. Finish honest plug-and-play traversal/relay proof burden

**Status:** Still open overall, even though a lot of groundwork is already present.

**Primary docs:**
- `documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md`
- `documents/operations/active/MasterWorkPlan_2026-03-22.md`

**What remains according to the owning delta plan:**
- Correct server-reflexive candidate acquisition on the actual transport socket/port.
- End-to-end production WAN simultaneous-open behavior on the active runtime path.
- Fully live relay path in the daemon/runtime with measured traffic proof.
- Production relay service binary/runtime and an operator deployment path for a reachable relay fleet.
- Live cross-network evidence that does not depend on manual router work.
- Fresh relay-active, failback, and long-running session/token-refresh proof for the current commit.

**Important note:**
- Some documents describe substantial HP-3/relay hardening as already implemented in code.
- The remaining problem is that the repo still does not permit an honest “plug-and-play from anywhere” claim until fresh live cross-network proof exists.

**Close when:**
- The runtime path is proven in current measured artifacts, not just code slices or local-gate evidence.

---

#### 5. Finish cross-network remote-exit proof burden

**Status:** Open.

**Primary docs:**
- `documents/operations/active/CrossNetworkRemoteExitNodePlan_2026-03-16.md`

**What remains:**
- HP-2 real WAN simultaneous-open behavior.
- HP-3 production relay transport.
- Remote-exit dataplane integration.
- Final cross-network gate/report path.
- Measured direct, relay, failback/roaming, adversarial traversal rejection, managed DNS, and soak evidence.

**Why this matters:**
- This is the subsystem-level plan behind the repo-wide canonical cross-network evidence requirement.

**Close when:**
- The six cross-network reports are real, current, validated, and sufficient for the hard pass gate.

### P1 — Supporting technical plans still open

#### 6. Rerun fresh managed-DNS adversarial live or semi-live proof

**Status:** Partial/open.

**Primary docs:**
- `documents/operations/active/MagicDnsSignedZoneSchema_2026-03-09.md`
- `documents/operations/active/SerializationFormatHardeningPlan_2026-03-25.md`

**What is already done:**
- Hardened baseline is in place.
- The adversarial managed-DNS harness exists for stale, replayed, forged, tampered, and policy-invalid bundle cases.
- Per-node filtered issuance now emits canonical text manifests instead of JSON.

**What remains:**
- Rerun the managed-DNS validator on live or substitute semi-live nodes and emit a fresh report artifact.
- Clear the current lab reachability blocker or provide replacement nodes.

**Current blocker shape recorded in the docs:**
- Attempted fresh proof failed before a new report was emitted because SSH to the target host timed out.

**Close when:**
- A fresh managed-DNS report exists for the current tree and proves loopback-authoritative routing plus fail-closed adversarial rejection.

---

#### 7. Continue broader serialization and artifact-format hardening

**Status:** Partial/open.

**Primary docs:**
- `documents/operations/active/SerializationFormatHardeningPlan_2026-03-25.md`

**What is already done:**
- DNS signer input hardening slice is done.
- Helper IPC framing is done in the owned runtime path.
- The managed-DNS adversarial harness covers the expected local rejection classes.

**What remains:**
- Do the broader artifact-family migrations that the plan still marks open.
- Shared serialization crate work is still future work.
- Discovery bundles, cross-network reports, live-lab summary/failure digests, fresh-install matrix outputs, and other internal machine artifacts are still planned for stricter canonical formats.

**Planned open migration families:**
- Discovery bundle migration.
- Cross-network report migration.
- Live-lab summary/failure digest migration.
- Fresh-install OS matrix and wider phase report family migration.
- Append-only measured source stream migration.

**Close when:**
- The remaining active internal artifact paths use the hardened format path selected by the plan, without long-lived dual readers.

### P2 — Wrapper/reporting truth work still open

#### 8. Implement VM-lab capability reporting

**Status:** Active planning document. Open.

**Primary docs:**
- `documents/operations/active/VmLabCapabilityReportingPlan_2026-04-14.md`
- `documents/operations/active/VmLabCapabilityCookbook_2026-04-14.md`
- `documents/operations/active/VmLabCapabilitySources_2026-04-14.md`

**What remains:**
- Slice 1: add a pure evaluator and unit tests.
- Slice 2: use the evaluator in top-level wrappers while preserving fail-closed behavior.
- Slice 3: emit `state/platform_capabilities.json`.
- Slice 4: optionally add `ops vm-lab-report-capabilities` as a read-only inspection CLI.

**Why it is open:**
- The current top-level wrappers still collapse too much mixed-platform truth into a coarse Linux-only rejection.
- The goal here is not to broaden support yet; it is to report support truth accurately and machine-readably.

**Close when:**
- Wrappers can classify supported / partially supported / unsupported paths with machine-readable reason codes before execution.

---

#### 9. Recover authoritative Windows VM-lab access and orchestration

**Status:** Open.

**Primary docs:**
- `documents/operations/active/WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md`
- `documents/operations/active/Phase5ReleaseReadinessChecklist_2026-04-12.md`

**What is already proven:**
- Windows VM execution through local UTM guest exec.
- Windows source sync through the ZIP/PowerShell path.
- Windows compile capability on the live guest.

**What remains:**
- Phase 1: make the Windows access bootstrap helper verification-based and machine-readable.
- Phase 2: split Windows UTM transport into status/probe and capture paths.
- Phase 3: remove premature SSH fallback during Windows access establishment.
- Phase 4: add a real Windows readiness ladder with finer reason codes.
- Phase 5: rewire higher Windows bootstrap phases to proven access truth.
- Phase 6: prove the repaired path on a clean Windows UTM snapshot with dated artifacts.

**Immediate closure checklist in the plan:**
- Make `Bootstrap-RustyNetWindows.ps1` write fail-closed JSON through `-ResultPath` on both success and top-level failure.
- Rebuild `rustynet-cli` after helper changes.
- Re-run `ops vm-lab-start` and `ops vm-lab-discover-local-utm`.
- Do not advance to runtime install/restart/verify until the access helper result is present and machine-readable.

**Important scope note:**
- This is orchestration/access recovery work, not a claim that Windows dataplane/backend support is complete.

**Close when:**
- Windows access is proven from the host, readiness failures are precise, higher bootstrap phases depend on proven access truth, and clean-snapshot evidence exists for the currently supported scope.

### P3 — Narrow remaining side work

#### 10. Refresh Shell-to-Rust Phase I evidence

**Status:** Narrow remaining work.

**Primary docs:**
- `documents/operations/active/ShellToRustMigrationPlan_2026-03-06.md`

**What is already done according to the current open-work block:**
- The remaining security-relevant `start.sh` privileged flows have been migrated to Rust ops commands.

**What remains:**
- Refresh the Rust-only remote E2E evidence for Phase I.
- Keep the shell path wrapper-only and retain proof that the remote orchestration path is argv-only and Rust-driven.

**Documentation note:**
- This file contains older historical sections that still list old `start.sh` subflows.
- Treat the `Current Open Work` block near the top of the document as authoritative over those historical lists.

**Close when:**
- Fresh Phase I evidence shows the shell path is still wrapper-only and the active remote orchestration path is Rust-driven.

---

#### 11. Finish the remaining narrow cross-platform parity/security cleanup

**Status:** Mostly closed, but still open in a narrow way.

**Primary docs:**
- `documents/operations/active/CrossPlatformSecurityGapRemediationPlan_2026-03-05.md`

**What remains:**
- Re-validate Linux/Debian baseline after macOS-affecting changes.
- Close GAP-06 macOS ops parity for Linux-only manual peer admin flows.
- Keep GAP-08 documentation/support-matrix synchronization current.
- Reduce GAP-10 regression blast radius around `start.sh`.

**Close when:**
- The remaining parity and regression-risk items are verified without weakening the Linux baseline or trust model.

## Work That Appears Closed Or Mostly Closed

These areas do **not** currently look like the main missing work and should not be reopened casually without new evidence:

- `documents/operations/active/Phase1DataplaneTruthHardeningChecklist_2026-04-12.md`
  - Core dataplane route-truth hardening is implemented.
- `documents/operations/active/Phase2WrapperProvenanceAndCompletenessChecklist_2026-04-12.md`
  - Setup reuse provenance/completeness checks are implemented.
- `documents/operations/active/Phase3DependencyAndPolicyCleanupChecklist_2026-04-12.md`
  - Dependency and policy blockers are closed, including audit/deny passing in that checklist.
- `documents/operations/active/SecurityHardeningBacklog_2026-03-09.md`
  - The current tracked backlog is marked complete.
- `documents/operations/active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md`
  - The earlier reduced-live-lab route-truth blockers are no longer the active issue.
- `documents/operations/active/Phase5ReleaseReadinessChecklist_2026-04-12.md`
  - The guardrails, summary, and bundle path exist; the open issue is evidence, not missing release-gate scaffolding.

## Documents To Treat Carefully Because Of Historical Drift

These files are still useful, but their older sections should not outrank newer current-status blocks:

- `documents/operations/active/MasterWorkPlan_2026-03-22.md`
  - Explicitly warns that some lower session logs are historical.
- `documents/operations/active/ShellToRustMigrationPlan_2026-03-06.md`
  - Current open work is narrower than some older historical lists in the file.
- `documents/operations/active/ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md`
  - Best treated as a supporting design/implementation blueprint, not the main status ledger.

## Suggested Maintenance Rule For This Index

When updating this file:

- Prefer the newest explicit `Current Open Work`, `Current Status`, or `Current Phase Truth` block in the owning doc.
- Do not promote reduced/local-gate evidence to canonical cross-network or release-ready evidence.
- If an item becomes complete, move it to the closed section instead of deleting its history entirely.
- If a doc is clearly stale, fix the owning doc before updating this index.

## Suggested README Entry

If this file is added under `documents/operations/active/`, add this line to `documents/operations/active/README.md` under the ledger/index section:

- `[OpenWorkIndex_2026-04-17.md](./OpenWorkIndex_2026-04-17.md)`
