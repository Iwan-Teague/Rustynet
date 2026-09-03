# Operations Docs Index

This file separates:
- active execution ledgers and active work plans
- evergreen runbooks, policies, matrices, and gate references
- archived point-in-time reviews

## How To Use This Folder

Start with these, depending on what you are doing:

- active implementation status: [active/README.md](./active/README.md)
- service and runtime operation: [ProductionRunbook.md](./ProductionRunbook.md)
- live-lab execution and evidence: [live_lab_node_run_matrix.csv](./live_lab_node_run_matrix.csv) — the **live Rust `--node` engine ledger** (current runs append here) — with [LiveLabRunMatrix.md](./LiveLabRunMatrix.md), [live_lab_node_stage_results.csv](./live_lab_node_stage_results.csv) (exact distro/version node-stage proof), and [MeasuredEvidenceGeneration.md](./MeasuredEvidenceGeneration.md), plus the script-local function map at [scripts/e2e/README.md](../../scripts/e2e/README.md). [live_lab_run_matrix.csv](./live_lab_run_matrix.csv) is the **frozen legacy bash-orchestrator archive** (read-only history; the bash engine was deleted under W5.7 — its runbook lives at [../archive/LiveLinuxLabOrchestrator.md](../archive/LiveLinuxLabOrchestrator.md)). Before starting a session, run `scripts/vm_lab/lab_preflight.sh` — it warns (never blocks) if the gitignored `bin/rustynet-mcp-*` servers are stale (`--fix` rebuilds) and prints a one-line UTM-fleet readiness summary.
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

The primary execution ledgers are:
- [active/RustynetDataplaneExecutionPlan_2026-05-18.md](./active/RustynetDataplaneExecutionPlan_2026-05-18.md) — source-of-truth for the cross-network dataplane track (D2-D13): peer-distributed coordination, home-server-as-zero-ingress-relay, uPnP/IPv6/ICE, enrollment-token onboarding, service-hosting roles (nas, llm). Read this first for "what are we building and why."
- [active/NodeRoleTaxonomy_2026-05-21.md](./active/NodeRoleTaxonomy_2026-05-21.md) — canonical taxonomy for the eight user-selectable node roles (D13): preset compositions, transition matrix, per-platform eligibility.
- [active/AnchorNodeRoleDesign_2026-05-21.md](./active/AnchorNodeRoleDesign_2026-05-21.md) — canonical design for the anchor node role (D11; one of the presets in the taxonomy doc): per-platform host capability, refactor inventory, security controls.
- [active/AnchorEnrollmentEndpointEnforcementDesign_2026-08-27.md](./active/AnchorEnrollmentEndpointEnforcementDesign_2026-08-27.md) — D-3: runtime enforcement for the `anchor.enrollment_endpoint` capability; design answers plus the landed per-request gate on `EnrollmentConsume`.
- [active/CrossPlatformRoleParityRefresh_2026-07-23.md](./active/CrossPlatformRoleParityRefresh_2026-07-23.md) — **the live per-OS parity-status matrix on the Rust `--node` engine** (supersedes the status half of the ParityPlan §3 + Roadmap; the mandate stays in [the ParityPlan](./active/CrossPlatformRoleParityPlan_2026-06-21.md)).
- [active/MasterWorkPlan_2026-03-22.md](./active/MasterWorkPlan_2026-03-22.md) — superseded as the repo-wide roll-up by [FullTodoInventory_2026-07-28.md](./active/FullTodoInventory_2026-07-28.md); retained for section structure/history.
- [active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md](./active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md) — historical defect inventory; defects largely closed by Dataplane D2–D4.

Supporting active implementation plan for the remaining production shared-transport delta:
- [active/ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md](./active/ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md)

Supporting active implementation delta for the remaining Linux live-lab blocker:
- [active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md](./active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md)

Supporting active implementation plan for taking Windows from
`runtime-host-capable only` to a real working node:
- [active/WindowsWorkingNodePlan_2026-04-17.md](./active/WindowsWorkingNodePlan_2026-04-17.md)

Supporting active execution ledger for Windows 11 exit-node and relay-node
hardening:
- [active/WindowsExitAndRelayDeltaPlan_2026-05-10.md](./active/WindowsExitAndRelayDeltaPlan_2026-05-10.md)

Current phase-local hardening checklists (only the still-open ones; the
finished Phase 1/2/3/5 checklists are archived in
[done/](./done/README.md)):
- [active/Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md](./active/Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md)
- [active/Phase5ReleaseReadinessSummary_2026-04-12.md](./active/Phase5ReleaseReadinessSummary_2026-04-12.md)
- [active/Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md](./active/Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md)
- [active/VmLabCapabilityCookbook_2026-04-14.md](./active/VmLabCapabilityCookbook_2026-04-14.md)
- [active/VmLabCapabilitySources_2026-04-14.md](./active/VmLabCapabilitySources_2026-04-14.md)

Cross-platform code-quality ledger:
- [active/PlatformImprovementBacklog_2026-05-14.md](./active/PlatformImprovementBacklog_2026-05-14.md) — most recently updated cross-platform improvement backlog (X1-X7 numbered tracks are the cleanest current path for code-only quality work)
- [active/DataplanePerfBacklog_2026-06-12.md](./active/DataplanePerfBacklog_2026-06-12.md) — active hot-path performance backlog with measured baselines and bench commands for the userspace-shared engine, relay forward path, utun I/O, and endpoint indexing
- [active/EfficiencyAndAdvancedTechniqueOpportunityCatalog_2026-07-19.md](./active/EfficiencyAndAdvancedTechniqueOpportunityCatalog_2026-07-19.md) — unscheduled research catalog of 31 verified efficiency/architecture findings across the control plane (key custody, ACL, trust-state, enrollment, serialization, NAT traversal, relay, concurrency) and dev tooling (build/test speed, CLI startup, Windows/service data paths), each with multiple candidate technique families and no chosen fix
- [active/SecurityAuditLedger_2026-06-18.md](./active/SecurityAuditLedger_2026-06-18.md) — current file-by-file security audit (RSA-####, 594/594 coverage complete); the satisfied 2026-04-28 security-hardening audit is under [done/](./done/README.md)

## High-Value Evergreen References

- [Arm32BitEmbeddedSupportReference_2026-06-23.md](./Arm32BitEmbeddedSupportReference_2026-06-23.md) — developer reference for running Rustynet on 32-bit ARM Linux (armv7-unknown-linux-gnueabihf) embedded boards; covers compile concerns, toolchain setup, backend selection, systemd/nftables dependencies, memory budget, SD card wear, fd limits, and CI requirements for claiming support
- [Arm32BitEmbeddedImplementationGuide_2026-06-23.md](./Arm32BitEmbeddedImplementationGuide_2026-06-23.md) — implementation guide (Part 2): exact file paths, before/after code snippets, and task-by-task developer instructions for closing every open item in the reference doc §28 Known Open Items table
- [BackendAgilityValidation.md](./BackendAgilityValidation.md)
- [CliExitCodeTaxonomy.md](./CliExitCodeTaxonomy.md) — shared CLI exit-code taxonomy (sysexits.h-aligned ExitCode enum) + operator decision rules; ADR-003 holds the design rationale
- [CompatibilitySupportPolicy.md](./CompatibilitySupportPolicy.md)
- [ComplianceControlMap.md](./ComplianceControlMap.md)
- [CrossNetworkLiveLabPrerequisitesChecklist.md](./CrossNetworkLiveLabPrerequisitesChecklist.md)
- [CrossNetworkRemoteExitArtifactSchema_2026-03-16.md](./CrossNetworkRemoteExitArtifactSchema_2026-03-16.md)
- [CrossNetworkRemoteExitIncidentPlaybook.md](./CrossNetworkRemoteExitIncidentPlaybook.md)
- [CrossNetworkSimulationRunbook.md](./CrossNetworkSimulationRunbook.md) — how to simulate cross-network (NAT traversal/relay/gossip) on the single-host VM lab without real separate networks; the four-tier substrate (netns internet-simulator / VXLAN-overlay multi-VM / slirp cross-OS / chaos), the validated netns NAT mapping/filtering tools, the Tier B VXLAN driver, and the UTM constraints that drive the design
- [CryptoDeprecationSchedule.md](./CryptoDeprecationSchedule.md) — algorithm deprecation/removal calendar and reviewed exception rules
- [DependencyExceptionPolicy.md](./DependencyExceptionPolicy.md) — controlled-exception workflow for the dependency policy gate
- [DisasterRecoveryValidation.md](./DisasterRecoveryValidation.md)
- [FinalLaunchChecklist.md](./FinalLaunchChecklist.md)
- [FreshInstallOSMatrixReleaseGate.md](./FreshInstallOSMatrixReleaseGate.md)
- [HeterogeneousLiveLabRunbook.md](./HeterogeneousLiveLabRunbook.md)
- [LinuxDaemonValidatorRunbook.md](./LinuxDaemonValidatorRunbook.md)
- [LiveLabVmConnectivityRulebook.md](./LiveLabVmConnectivityRulebook.md) — security-first VM-network architecture: dual-plane management + controlled scenario NICs, unique lab-subnet IPs, deterministic/physical/remote evidence tiers, MCP integration audit, and Rust profile/apply roadmap
- [VmLabNetworkStandard.md](./VmLabNetworkStandard.md) — **the operational network standard + new-VM onboarding runbook**: one standard (UTM Shared + vmnet's stable per-MAC DHCP + a self-healing host route + host NAT), the one privileged setup step (the route-keeper launchd job), the few-step onboarding checklist, the macOS gotchas (vmnet route loss, raw-TCP LNP false-negative, plist-vs-running), and the verified dead-ends (vmnet ignores `/etc/bootptab`; per-guest static is fragile). Helper `scripts/vm_lab/ensure_vmnet_route.sh` + `scripts/launchd/com.rustynet.vmnet-route.plist`
- [LiveLabRunMatrix.md](./LiveLabRunMatrix.md) — the run-matrix README; the live ledger for the Rust `--node` engine is `live_lab_node_run_matrix.csv` (`live_lab_run_matrix.csv` is the frozen bash archive)
- [MacosInstallRunbook.md](./MacosInstallRunbook.md) — manual install procedure, known gotchas (pf SSH block, EROFS socket path, disk space, boringtun submodule)
- [MacosLaunchdServiceManagement.md](./MacosLaunchdServiceManagement.md) — launchd service lifecycle reference (see MacosInstallRunbook.md for current paths and labels)
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
- [VulnerabilityResponse.md](./VulnerabilityResponse.md)
- [WindowsWorkingNodeBringUpRunbook.md](./WindowsWorkingNodeBringUpRunbook.md) — operator walk-through from fresh Windows 11 host to mesh-joined node on `windows-wireguard-nt`

## Archived Reviews And Completed Checklists

Historical operations reviews and completed implementation checklists live
under [done/](./done/). See [done/README.md](./done/README.md) for the
classification and per-document completion notes.

Reviews and audits:
- [done/ComparativeSecurityFlawAssessment_2026-03-06.md](./done/ComparativeSecurityFlawAssessment_2026-03-06.md)
- [done/FallbackLogicAudit_2026-03-06.md](./done/FallbackLogicAudit_2026-03-06.md)
- [done/RustynetAdversarialHardeningAudit_2026-03-14.md](./done/RustynetAdversarialHardeningAudit_2026-03-14.md)
- [done/SecurityReview_2026-03-03.md](./done/SecurityReview_2026-03-03.md)
- [done/SecurityRegressionLessons_2026-03-07.md](./done/SecurityRegressionLessons_2026-03-07.md)
- [done/SecurityHardeningAudit_2026-04-28.md](./done/SecurityHardeningAudit_2026-04-28.md) — satisfied security-hardening audit (overtaken by the 2026-06-10/06-18 audits)

Completed phase implementation checklists:
- [done/Phase1DataplaneTruthHardeningChecklist_2026-04-12.md](./done/Phase1DataplaneTruthHardeningChecklist_2026-04-12.md)
- [done/Phase2WrapperProvenanceAndCompletenessChecklist_2026-04-12.md](./done/Phase2WrapperProvenanceAndCompletenessChecklist_2026-04-12.md)
- [done/Phase3DependencyAndPolicyCleanupChecklist_2026-04-12.md](./done/Phase3DependencyAndPolicyCleanupChecklist_2026-04-12.md)
- [done/Phase5ReleaseReadinessChecklist_2026-04-12.md](./done/Phase5ReleaseReadinessChecklist_2026-04-12.md)

## Documentation Rules

- Keep this index current when documents are added, removed, renamed, or archived.
- Do not add standalone prompt documents under `operations/`.
- Keep execution guidance inside the owning active ledger or plan.
