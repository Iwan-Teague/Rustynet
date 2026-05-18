# Operations Docs Index

This file separates:
- active execution ledgers and active work plans
- evergreen runbooks, policies, matrices, and gate references
- archived point-in-time reviews

## How To Use This Folder

Start with these, depending on what you are doing:

- active implementation status: [active/README.md](./active/README.md)
- service and runtime operation: [ProductionRunbook.md](./ProductionRunbook.md)
- live-lab execution and evidence: [LiveLinuxLabOrchestrator.md](./LiveLinuxLabOrchestrator.md), [MeasuredEvidenceGeneration.md](./MeasuredEvidenceGeneration.md), and the script-local function map at [scripts/e2e/README.md](../../scripts/e2e/README.md)
- release-readiness and support posture: [FreshInstallOSMatrixReleaseGate.md](./FreshInstallOSMatrixReleaseGate.md) and [PlatformSupportMatrix.md](./PlatformSupportMatrix.md)
- final release sign-off gate: [ReleaseReadinessGuardrails.md](./ReleaseReadinessGuardrails.md)
- phase10 exit-node and dataplane behavior: [Phase10ExitNodeDataplaneRunbook.md](./Phase10ExitNodeDataplaneRunbook.md)
- security and compliance mapping: [SecurityAssuranceProgram.md](./SecurityAssuranceProgram.md), [ComplianceControlMap.md](./ComplianceControlMap.md), and [RustynetdServiceHardening.md](./RustynetdServiceHardening.md)
- reviewer-facing security-posture snapshot (verifier modules, floors, audit gates, taxonomies): [SecurityPostureSummary.md](./SecurityPostureSummary.md)
- shared CLI exit-code taxonomy + operator decision rules: [CliExitCodeTaxonomy.md](./CliExitCodeTaxonomy.md)
- architecture decision records (design rationale, immutable once accepted): [adr/README.md](./adr/README.md)

## Classification Rules

### Active Work
Keep a document in `operations/active/` when it still drives current implementation, migration, or hardening work.

### Evergreen Reference
Keep a document in `operations/` when it is still used to operate, validate, or understand the current system.

### Done Archive
Move a document into `operations/done/` when it is historical evidence rather than current operating guidance.

## Current Active Set

See [active/README.md](./active/README.md) for the current list.

The two primary execution ledgers are:
- [active/MasterWorkPlan_2026-03-22.md](./active/MasterWorkPlan_2026-03-22.md)
- [active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md](./active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md)

Supporting active implementation plan for the remaining production shared-transport delta:
- [active/ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md](./active/ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md)

Supporting active implementation delta for the remaining Linux live-lab blocker:
- [active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md](./active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md)

Supporting active implementation plan for the remaining Windows VM-lab
access/orchestration blocker:
- [active/WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md](./active/WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md)

Supporting active implementation plan for taking Windows from
`runtime-host-capable only` to a real working node:
- [active/WindowsWorkingNodePlan_2026-04-17.md](./active/WindowsWorkingNodePlan_2026-04-17.md)

Supporting active execution ledger for Windows 11 exit-node and relay-node
hardening:
- [active/WindowsExitAndRelayDeltaPlan_2026-05-10.md](./active/WindowsExitAndRelayDeltaPlan_2026-05-10.md)

Current phase-local hardening checklist:
- [active/Phase1DataplaneTruthHardeningChecklist_2026-04-12.md](./active/Phase1DataplaneTruthHardeningChecklist_2026-04-12.md)
- [active/Phase2WrapperProvenanceAndCompletenessChecklist_2026-04-12.md](./active/Phase2WrapperProvenanceAndCompletenessChecklist_2026-04-12.md)
- [active/Phase3DependencyAndPolicyCleanupChecklist_2026-04-12.md](./active/Phase3DependencyAndPolicyCleanupChecklist_2026-04-12.md)
- [active/Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md](./active/Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md)
- [active/Phase5ReleaseReadinessChecklist_2026-04-12.md](./active/Phase5ReleaseReadinessChecklist_2026-04-12.md)
- [active/Phase5ReleaseReadinessSummary_2026-04-12.md](./active/Phase5ReleaseReadinessSummary_2026-04-12.md)
- [active/Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md](./active/Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md)
- [active/VmLabCapabilityCookbook_2026-04-14.md](./active/VmLabCapabilityCookbook_2026-04-14.md)
- [active/VmLabCapabilityReportingPlan_2026-04-14.md](./active/VmLabCapabilityReportingPlan_2026-04-14.md)
- [active/VmLabCapabilitySources_2026-04-14.md](./active/VmLabCapabilitySources_2026-04-14.md)
- [active/WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md](./active/WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md)

## High-Value Evergreen References

- [BackendAgilityValidation.md](./BackendAgilityValidation.md)
- [CliExitCodeTaxonomy.md](./CliExitCodeTaxonomy.md) — shared CLI exit-code taxonomy (sysexits.h-aligned ExitCode enum) + operator decision rules; ADR-003 holds the design rationale
- [CompatibilitySupportPolicy.md](./CompatibilitySupportPolicy.md)
- [ComplianceControlMap.md](./ComplianceControlMap.md)
- [CrossNetworkLiveLabPrerequisitesChecklist.md](./CrossNetworkLiveLabPrerequisitesChecklist.md)
- [CrossNetworkRemoteExitArtifactSchema_2026-03-16.md](./CrossNetworkRemoteExitArtifactSchema_2026-03-16.md)
- [CrossNetworkRemoteExitIncidentPlaybook.md](./CrossNetworkRemoteExitIncidentPlaybook.md)
- [CryptoDeprecationSchedule.md](./CryptoDeprecationSchedule.md) — algorithm deprecation/removal calendar and reviewed exception rules
- [DependencyExceptionPolicy.md](./DependencyExceptionPolicy.md) — controlled-exception workflow for the dependency policy gate
- [DisasterRecoveryValidation.md](./DisasterRecoveryValidation.md)
- [FinalLaunchChecklist.md](./FinalLaunchChecklist.md)
- [FreshInstallOSMatrixReleaseGate.md](./FreshInstallOSMatrixReleaseGate.md)
- [HeterogeneousLiveLabRunbook.md](./HeterogeneousLiveLabRunbook.md)
- [LinuxDaemonValidatorRunbook.md](./LinuxDaemonValidatorRunbook.md)
- [LiveLinuxLabOrchestrator.md](./LiveLinuxLabOrchestrator.md)
- [MacosLaunchdServiceManagement.md](./MacosLaunchdServiceManagement.md)
- [MeasuredEvidenceGeneration.md](./MeasuredEvidenceGeneration.md)
- [MembershipGovernanceRunbook.md](./MembershipGovernanceRunbook.md)
- [MembershipIncidentResponseRunbook.md](./MembershipIncidentResponseRunbook.md)
- [Phase10ExitNodeDataplaneRunbook.md](./Phase10ExitNodeDataplaneRunbook.md)
- [PlatformSupportMatrix.md](./PlatformSupportMatrix.md)
- [PolicyRolloutRunbook.md](./PolicyRolloutRunbook.md)
- [PostQuantumTransitionPlan.md](./PostQuantumTransitionPlan.md) — controlled PQ/hybrid evaluation plan; no custom-crypto in production paths
- [PrivacyRetentionPolicy.md](./PrivacyRetentionPolicy.md) — telemetry data classes, retention windows, and minimization rules
- [ProductionRunbook.md](./ProductionRunbook.md)
- [ProductionSLOAndIncidentReadiness.md](./ProductionSLOAndIncidentReadiness.md)
- [ReleaseReadinessGuardrails.md](./ReleaseReadinessGuardrails.md)
- [ReleaseSigningRunbook.md](./ReleaseSigningRunbook.md) — Windows Authenticode signing flow for rustynetd.exe (W2.1b trust anchor)
- [RustynetdServiceHardening.md](./RustynetdServiceHardening.md)
- [SecretRedactionCoverage.md](./SecretRedactionCoverage.md)
- [SecurityAssuranceProgram.md](./SecurityAssuranceProgram.md)
- [SecurityPostureSummary.md](./SecurityPostureSummary.md) — reviewer-facing snapshot of every fail-closed verifier module, audit-gate floor pin, X2/X3 typed-view and audit-scanner inventory, dependency-deny posture, and known-open-items list
- [SecurityRegressionLessons_2026-03-07.md](./SecurityRegressionLessons_2026-03-07.md)
- [VulnerabilityResponse.md](./VulnerabilityResponse.md)
- [WindowsWorkingNodeBringUpRunbook.md](./WindowsWorkingNodeBringUpRunbook.md) — operator walk-through from fresh Windows 11 host to mesh-joined node on `windows-wireguard-nt`

## Archived Reviews

Historical operations reviews live under [done/](./done/):
- [done/ComparativeSecurityFlawAssessment_2026-03-06.md](./done/ComparativeSecurityFlawAssessment_2026-03-06.md)
- [done/FallbackLogicAudit_2026-03-06.md](./done/FallbackLogicAudit_2026-03-06.md)
- [done/RustynetAdversarialHardeningAudit_2026-03-14.md](./done/RustynetAdversarialHardeningAudit_2026-03-14.md)
- [done/SecurityReview_2026-03-03.md](./done/SecurityReview_2026-03-03.md)

## Documentation Rules

- Keep this index current when documents are added, removed, renamed, or archived.
- Do not add standalone prompt documents under `operations/`.
- Keep execution guidance inside the owning active ledger or plan.
