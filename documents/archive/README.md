# Historical Document Archive

This folder holds point-in-time assessment and review documents that are retained for historical evidence but are not current normative or active-planning sources.

Archive criteria:
- historical review, audit, or assessment,
- does not define the current required implementation path,
- preserved for traceability and retrospective security analysis.

Archived items:
- [LiveLinuxLabOrchestrator.md](./LiveLinuxLabOrchestrator.md) — runbook of the legacy bash live-lab orchestrator, deleted in W5.7 (BashOrchestratorRetirementProgram_2026-08-22.md); the frozen evidence ledger remains at `documents/operations/live_lab_run_matrix.csv`
- [SecurityReview-2026-03-24.md](./SecurityReview-2026-03-24.md)
- [SimulationSecurityGapAssessment.md](./SimulationSecurityGapAssessment.md)
- [DownloadsResearchImportLedger_2026-04-17.md](./DownloadsResearchImportLedger_2026-04-17.md)

## Executed Phase Architecture And Build Plans (archived 2026-08-19)

Phase documents 3–6 and the membership build plan were executed scaffold/plan
documents, last updated 2026-02/03, superseded as architecture references by
Phase 1/2 + `phase10.md` and the active ledgers:

- [Phase3.md](./Phase3.md)
- [Phase4.md](./Phase4.md)
- [Phase5.md](./Phase5.md)
- [Phase6.md](./Phase6.md)
- [MembershipImplementationPlan.md](./MembershipImplementationPlan.md)

## Fulfilled Implementation Plans From `operations/active/` (archived 2026-08-19)

Each was completed/superseded at the time of archiving; see the index entries
removed from `operations/active/README.md`:

- [ShellToRustMigrationPlan_2026-03-06.md](./ShellToRustMigrationPlan_2026-03-06.md) — migration phases A–I complete
- [StartShOperatorUxRustMigrationPlan_2026-05-24.md](./StartShOperatorUxRustMigrationPlan_2026-05-24.md) — implemented
- [SecurityAndQualityAudit_2026-06-10.md](./SecurityAndQualityAudit_2026-06-10.md) — audit, coverage complete
- [SecurityAnalysis_2026-06-12.md](./SecurityAnalysis_2026-06-12.md) — dated audit snapshot, superseded by the SecurityAuditAndMainConsolidation ledger
- [VmLabCapabilityReportingPlan_2026-04-14.md](./VmLabCapabilityReportingPlan_2026-04-14.md) — slices complete
- [OvernightAutonomousBugHuntProposal_2026-06-08.md](./OvernightAutonomousBugHuntProposal_2026-06-08.md) — tooling now exists
- [FullRepoAnalysis_2026-05-24.md](./FullRepoAnalysis_2026-05-24.md) — point-in-time sweep, complete
- [RustNativeMultiPlatformOrchestratorPlan_2026-04-28.md](./RustNativeMultiPlatformOrchestratorPlan_2026-04-28.md) — the `--node` engine is now the default
- [WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md](./WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md) — gap closed by the Rust `--node` engine
- [TrackC_BashOrchestratorDefects_2026-07-13.md](./TrackC_BashOrchestratorDefects_2026-07-13.md) — completed bash-pair race evidence
- [TrackC_Pair1_Linux_2026-07-13.md](./TrackC_Pair1_Linux_2026-07-13.md) — completed bash↔Rust pair-1 run
- [CrossNetworkRemoteExitNodePlan_2026-03-16.md](./CrossNetworkRemoteExitNodePlan_2026-03-16.md) — superseded by the dataplane execution plan
- [MacosUserspaceSharedBackendPlan_2026-05-08.md](./MacosUserspaceSharedBackendPlan_2026-05-08.md) — shipped; parity owned by the CrossPlatformRoleParity docs
- [RustyfinExtensionTrustPlan_2026-05-10.md](./RustyfinExtensionTrustPlan_2026-05-10.md) — dormant, no Rustyfin work

## Future Commercial Roadmap Documents

These phase documents describe commercial-scale or enterprise features (Postgres
HA, relay fleet, OIDC/SSO, multi-tenant, external audit, KMS/HSM, GA SLOs) that
are not part of the current home-lab connectivity or cross-platform parity work.
No active implementation work is open in these documents. Archived 2026-05-21.

- [Phase7.md](./Phase7.md) — commercial/scale phase (Postgres HA, relay fleet, OIDC/SSO, multi-tenant)
- [Phase8.md](./Phase8.md) — security assurance program (external audit, KMS/HSM, SBOM/signing, compliance)
- [Phase9.md](./Phase9.md) — GA operational maturity (SLOs, DR, protocol agility, PQ transition)

Rule:
- these documents are useful for retrospective context, but they are not a substitute for the active ledgers, current runbooks, or current validated evidence
