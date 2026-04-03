# Operations Docs Index

This file separates:
- active execution ledgers and active work plans
- evergreen runbooks, policies, matrices, and gate references
- archived point-in-time reviews

## How To Use This Folder

Start with these, depending on what you are doing:

- active implementation status: [active/README.md](./active/README.md)
- service and runtime operation: [ProductionRunbook.md](./ProductionRunbook.md)
- live-lab execution and evidence: [LiveLinuxLabOrchestrator.md](./LiveLinuxLabOrchestrator.md) and [MeasuredEvidenceGeneration.md](./MeasuredEvidenceGeneration.md)
- release-readiness and support posture: [FreshInstallOSMatrixReleaseGate.md](./FreshInstallOSMatrixReleaseGate.md) and [PlatformSupportMatrix.md](./PlatformSupportMatrix.md)
- phase10 exit-node and dataplane behavior: [Phase10ExitNodeDataplaneRunbook.md](./Phase10ExitNodeDataplaneRunbook.md)
- security and compliance mapping: [SecurityAssuranceProgram.md](./SecurityAssuranceProgram.md), [ComplianceControlMap.md](./ComplianceControlMap.md), and [RustynetdServiceHardening.md](./RustynetdServiceHardening.md)

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

## High-Value Evergreen References

- [BackendAgilityValidation.md](./BackendAgilityValidation.md)
- [CompatibilitySupportPolicy.md](./CompatibilitySupportPolicy.md)
- [ComplianceControlMap.md](./ComplianceControlMap.md)
- [CrossNetworkLiveLabPrerequisitesChecklist.md](./CrossNetworkLiveLabPrerequisitesChecklist.md)
- [CrossNetworkRemoteExitArtifactSchema_2026-03-16.md](./CrossNetworkRemoteExitArtifactSchema_2026-03-16.md)
- [CrossNetworkRemoteExitIncidentPlaybook.md](./CrossNetworkRemoteExitIncidentPlaybook.md)
- [DisasterRecoveryValidation.md](./DisasterRecoveryValidation.md)
- [FinalLaunchChecklist.md](./FinalLaunchChecklist.md)
- [FreshInstallOSMatrixReleaseGate.md](./FreshInstallOSMatrixReleaseGate.md)
- [LiveLinuxLabOrchestrator.md](./LiveLinuxLabOrchestrator.md)
- [MacosLaunchdServiceManagement.md](./MacosLaunchdServiceManagement.md)
- [MeasuredEvidenceGeneration.md](./MeasuredEvidenceGeneration.md)
- [MembershipGovernanceRunbook.md](./MembershipGovernanceRunbook.md)
- [MembershipIncidentResponseRunbook.md](./MembershipIncidentResponseRunbook.md)
- [Phase10ExitNodeDataplaneRunbook.md](./Phase10ExitNodeDataplaneRunbook.md)
- [PlatformSupportMatrix.md](./PlatformSupportMatrix.md)
- [PolicyRolloutRunbook.md](./PolicyRolloutRunbook.md)
- [ProductionRunbook.md](./ProductionRunbook.md)
- [ProductionSLOAndIncidentReadiness.md](./ProductionSLOAndIncidentReadiness.md)
- [RustynetdServiceHardening.md](./RustynetdServiceHardening.md)
- [SecretRedactionCoverage.md](./SecretRedactionCoverage.md)
- [SecurityAssuranceProgram.md](./SecurityAssuranceProgram.md)
- [SecurityRegressionLessons_2026-03-07.md](./SecurityRegressionLessons_2026-03-07.md)
- [VulnerabilityResponse.md](./VulnerabilityResponse.md)

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
