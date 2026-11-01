# Completed Operations Archive

This folder holds completed historical operations reviews and finished
implementation checklists that no longer need to stay in the active
`operations/active/` view.

Archive criteria:
- point-in-time review, audit, or implementation checklist that is satisfied,
- no current open implementation work defined by the document,
- retained for evidence/history rather than as a current operating reference.

## Archived Reviews And Audits

- [ComparativeSecurityFlawAssessment_2026-03-06.md](./ComparativeSecurityFlawAssessment_2026-03-06.md)
- [FallbackLogicAudit_2026-03-06.md](./FallbackLogicAudit_2026-03-06.md)
- [RustynetAdversarialHardeningAudit_2026-03-14.md](./RustynetAdversarialHardeningAudit_2026-03-14.md)
- [SecurityReview_2026-03-03.md](./SecurityReview_2026-03-03.md)
- [SecurityHardeningBacklog_2026-03-09.md](./SecurityHardeningBacklog_2026-03-09.md)
  — all 5 priority queue items complete (including HP3 relay constant-time auth
  done 2026-03-25 with 39 tests). "Current Open Work" section states no
  remaining items. Archived 2026-05-21.
- [SecurityRegressionLessons_2026-03-07.md](./SecurityRegressionLessons_2026-03-07.md) —
  dated incident-lessons doc; archived 2026-08-19.
- [SecurityHardeningAudit_2026-04-28.md](./SecurityHardeningAudit_2026-04-28.md) —
  satisfied security-hardening audit, overtaken by the 2026-06-10 quality audit
  and the 2026-06-18 `SecurityAuditLedger`; archived 2026-08-19.
- [AnchorBundlePullAttestationSecurityReview_2026-07-20.md](./AnchorBundlePullAttestationSecurityReview_2026-07-20.md) —
  design, implementation and three-reviewer adversarial review trail for the
  anchor bundle-pull membership-head attestation (audit finding A4). Merged to
  `main`; the §6 stale-cache rollback finding was later closed (investigation
  kept in [../active/AnchorBundlePullRollbackWatermarkInvestigation_2026-07-20.md](../active/AnchorBundlePullRollbackWatermarkInvestigation_2026-07-20.md)).
  Its header status line was stale; an archive note records that. Archived 2026-11-01.
- [SecurityAuditAndMainConsolidation_2026-07-21.md](./SecurityAuditAndMainConsolidation_2026-07-21.md) —
  session wrap-up of the A1-A5 security audit and the branch-consolidation pass:
  the security work is complete and merged to `main`; the items its §7 lists as
  explicitly open are owned by other ledgers. Archived 2026-11-01.
- [SecurityAuditCatalogStalePathsTodo_2026-07-28.md](./SecurityAuditCatalogStalePathsTodo_2026-07-28.md) —
  RESOLVED 2026-09-01: stale repository paths in the security-audit catalog
  (the deleted `dataplane.rs` entry and the moved hardening-backlog path)
  repointed, and the class closed by the test
  `catalog_repo_path_references_exist_on_disk`. Archived 2026-11-01.
- [RustynetAuditFindings_2026-07-15.md](./RustynetAuditFindings_2026-07-15.md) —
  review-only codebase audit of potential improvements (security, code quality,
  architecture, operations, documentation); no implementations.
- [SecurityAuditFixes_2026-07-15.md](./SecurityAuditFixes_2026-07-15.md) —
  record of the security fixes applied for RN-02 to RN-07 and the new findings
  of the same audit (STUN client and others).

## Archived Completed Programs

- [BashOrchestratorRetirementProgram_2026-08-22.md](./BashOrchestratorRetirementProgram_2026-08-22.md) —
  COMPLETE 2026-08-27: the program (phases A-F) that retired the legacy bash
  live-lab orchestrator; the Rust `--node` engine is the sole engine. Its
  MUST-KEEP evidence artifacts remain in `../active/`
  ([G3EnumerationDiff_2026-07-23.md](../active/G3EnumerationDiff_2026-07-23.md),
  [G3FullSweepDiff_2026-08-22.md](../active/G3FullSweepDiff_2026-08-22.md),
  [BashRetirementGapEnumeration_2026-08-22.md](../active/BashRetirementGapEnumeration_2026-08-22.md),
  [BashRetirementDispositions_2026-08-22.md](../active/BashRetirementDispositions_2026-08-22.md))
  because code and tests cite them by path.
- [BashRetirementPlan_2026-07-24.md](./BashRetirementPlan_2026-07-24.md) — the W5.7
  deletion-mechanics plan, executed as Phase E of the program above (its own
  header predates execution).

## Archived Phase Implementation Checklists

These checklists captured a specific code-side hardening slice that has
since been implemented and either gate-validated or independently tracked
in current execution ledgers. They are kept here for traceability of the
implementation slice itself, not as current execution guidance.

- [Phase1DataplaneTruthHardeningChecklist_2026-04-12.md](./Phase1DataplaneTruthHardeningChecklist_2026-04-12.md)
  - 12/14 boxes checked. Core dataplane route-truth hardening is implemented
    against `crates/rustynetd/src/phase10.rs` with the in-file tests listed
    in the checklist. The two unchecked boxes are not code work; they are
    environment-dependent `cargo audit` / `cargo deny check` invocations
    that this checklist environment did not have installed. Those gates are
    now run from `scripts/ci/phase5_gates.sh` and
    `scripts/ci/release_readiness_gates.sh` in environments that carry the
    pinned security toolchain.
- [Phase2WrapperProvenanceAndCompletenessChecklist_2026-04-12.md](./Phase2WrapperProvenanceAndCompletenessChecklist_2026-04-12.md)
  - 15/17 boxes checked. Setup reuse provenance and completeness checks
    are implemented in `crates/rustynet-cli/src/vm_lab/mod.rs` and write
    `state/setup_manifest.json` + `state/report_state.json` on setup. The
    two unchecked boxes are the same environment-only `cargo audit` /
    `cargo deny check` gates noted above.
- [Phase3DependencyAndPolicyCleanupChecklist_2026-04-12.md](./Phase3DependencyAndPolicyCleanupChecklist_2026-04-12.md)
  - 14/14 boxes checked, including a green `cargo audit --deny warnings`
    and `cargo deny check advisories bans licenses sources` run inside the
    checklist environment. The `paste` supply-chain path was removed by
    replacing `tun-rs` with the narrow in-repo `third_party/rustynet-tun`
    crate, the `boringtun` surface was narrowed to the vendored copy under
    `third_party/boringtun/`, and the workspace direct `rand` dependency
    was upgraded out of `RUSTSEC-2026-0097`.
- [Phase5ReleaseReadinessChecklist_2026-04-12.md](./Phase5ReleaseReadinessChecklist_2026-04-12.md)
  - 4/4 boxes checked. The durable release-readiness gate path
    (`scripts/ci/release_readiness_gates.sh`,
    `crates/rustynet-cli/src/bin/release_readiness_gates.rs`,
    `crates/rustynet-cli/src/bin/phase5_gates.rs`) is in place, operator
    docs carry strict host-key/credential posture explicitly, and the
    Phase 5 readiness summary distinguishes reduced helper evidence from
    full release-gate evidence. The remaining release-blocking work
    (fresh-install evidence and canonical cross-network evidence for a
    clean current `HEAD`) is owned by Phase 4 + Phase 6 and is tracked in
    the active execution ledgers
    ([active/Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md](../active/Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md),
    [active/Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md](../active/Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md))
    and the Phase 5 readiness summary
    ([active/Phase5ReleaseReadinessSummary_2026-04-12.md](../active/Phase5ReleaseReadinessSummary_2026-04-12.md)).

## Rules

- Keep point-in-time evidence here, but do not treat it as current
  execution guidance without re-validating it against the present tree.
- Do not re-open an archived checklist in place; instead create a new
  dated checklist or follow-up plan in `active/` and reference the
  archived one for history.
