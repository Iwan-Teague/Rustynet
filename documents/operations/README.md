# Operations Docs Index

## Purpose

This index separates:
- active work documents,
- evergreen operational/reference documents,
- archived completed historical reviews.

The goal is to make open implementation work easier to spot without hiding the current runbooks, policies, schemas, and gate-reference material that still defines how Rustynet should operate.

## Classification Rules

### Active Work

Keep a document in `operations/active/` when it:
- contains open implementation work,
- contains pending backlog items,
- defines a current migration/design stream still in progress,
- is the current planning surface for active engineering work.

### Evergreen Reference

Keep a document in the main `operations/` folder when it:
- is a current runbook, checklist, schema, policy, support matrix, or gate reference,
- is still used to operate, validate, or understand the current system,
- would be harmful to hide simply because implementation is mature.

### Done Archive

Move a document into `operations/done/` when it is a point-in-time review or audit that:
- is historical rather than operational,
- does not define current open work,
- is preserved as evidence/history rather than as a current operating reference.

## Current Snapshot

Original audited operations markdown set: `43` documents.

Current classification:
- `11` active work docs under [active/](./active/)
- `28` evergreen reference docs in `operations/`
- `4` archived completed historical docs under [done/](./done/)

## Active Work Documents

- [active/CrossNetworkRemoteExitNodePlan_2026-03-16.md](./active/CrossNetworkRemoteExitNodePlan_2026-03-16.md)
- [active/CrossPlatformSecurityGapRemediationPlan_2026-03-05.md](./active/CrossPlatformSecurityGapRemediationPlan_2026-03-05.md)
- [active/MagicDnsSignedZoneSchema_2026-03-09.md](./active/MagicDnsSignedZoneSchema_2026-03-09.md)
- [active/MasterWorkPlan_2026-03-22.md](./active/MasterWorkPlan_2026-03-22.md)
- [active/SecurityHardeningBacklog_2026-03-09.md](./active/SecurityHardeningBacklog_2026-03-09.md)
- [active/SerializationFormatHardeningPlan_2026-03-25.md](./active/SerializationFormatHardeningPlan_2026-03-25.md)
- [active/ShellToRustMigrationPlan_2026-03-06.md](./active/ShellToRustMigrationPlan_2026-03-06.md)
- [active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md](./active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md)
- [active/UdpHolePunchingHP2IngestionPlan_2026-03-07.md](./active/UdpHolePunchingHP2IngestionPlan_2026-03-07.md)
- [active/UdpHolePunchingImplementationBlueprint_2026-03-07.md](./active/UdpHolePunchingImplementationBlueprint_2026-03-07.md)
- [active/RustynetComparativeVpnExploitCoverage_2026-03-14.md](./active/RustynetComparativeVpnExploitCoverage_2026-03-14.md)

## Evergreen Reference Documents

- [BackendAgilityValidation.md](./BackendAgilityValidation.md)
- [CompatibilitySupportPolicy.md](./CompatibilitySupportPolicy.md)
- [ComplianceControlMap.md](./ComplianceControlMap.md)
- [CrossNetworkLiveLabPrerequisitesChecklist.md](./CrossNetworkLiveLabPrerequisitesChecklist.md)
- [CrossNetworkRemoteExitArtifactSchema_2026-03-16.md](./CrossNetworkRemoteExitArtifactSchema_2026-03-16.md)
- [CrossNetworkRemoteExitIncidentPlaybook.md](./CrossNetworkRemoteExitIncidentPlaybook.md)
- [CryptoDeprecationSchedule.md](./CryptoDeprecationSchedule.md)
- [DependencyExceptionPolicy.md](./DependencyExceptionPolicy.md)
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
- [PostQuantumTransitionPlan.md](./PostQuantumTransitionPlan.md)
- [PrivacyRetentionPolicy.md](./PrivacyRetentionPolicy.md)
- [ProductionRunbook.md](./ProductionRunbook.md)
- [ProductionSLOAndIncidentReadiness.md](./ProductionSLOAndIncidentReadiness.md)
- [RustynetdServiceHardening.md](./RustynetdServiceHardening.md)
- [SecretRedactionCoverage.md](./SecretRedactionCoverage.md)
- [SecurityAssuranceProgram.md](./SecurityAssuranceProgram.md)
- [SecurityRegressionLessons_2026-03-07.md](./SecurityRegressionLessons_2026-03-07.md)
- [VulnerabilityResponse.md](./VulnerabilityResponse.md)

## Done Archive

Archived completed historical documents live under [done/](./done/):
- [done/ComparativeSecurityFlawAssessment_2026-03-06.md](./done/ComparativeSecurityFlawAssessment_2026-03-06.md)
- [done/FallbackLogicAudit_2026-03-06.md](./done/FallbackLogicAudit_2026-03-06.md)
- [done/RustynetAdversarialHardeningAudit_2026-03-14.md](./done/RustynetAdversarialHardeningAudit_2026-03-14.md)
- [done/SecurityReview_2026-03-03.md](./done/SecurityReview_2026-03-03.md)
