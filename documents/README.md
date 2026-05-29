# Documents Index

This file is the top-level map of the `documents/` tree.

Use it to answer three questions quickly:
- which documents are normative and release-blocking
- which documents currently drive implementation work
- which runbooks or historical reviews are only reference material

## Read Order

Before touching code, read in this order:
1. [AGENTS.md](../AGENTS.md)
2. [CLAUDE.md](../CLAUDE.md)
3. [README.md](../README.md)
4. [Requirements.md](./Requirements.md)
5. [SecurityMinimumBar.md](./SecurityMinimumBar.md)
6. The active scope document for the task
7. The relevant operations runbooks or gate references

Rule:
- if code and docs disagree, follow the higher-precedence document and then fix the stale lower-precedence text

## Normative Documents

These define requirements that implementation work must satisfy.

- [Requirements.md](./Requirements.md)
- [SecurityMinimumBar.md](./SecurityMinimumBar.md)
- [CODE_MAP.md](./CODE_MAP.md) — symbol-level code map: key types, traits, functions, and where they live across the workspace

## Phase And Architecture Documents

These explain architecture, phase boundaries, and longer-running design work.

- [Phase1.md](./Phase1.md)
- [Phase1Implementation.md](./Phase1Implementation.md)
- [Phase2.md](./Phase2.md)
- [Phase3.md](./Phase3.md)
- [Phase4.md](./Phase4.md)
- [Phase5.md](./Phase5.md)
- [Phase6.md](./Phase6.md)
- [phase10.md](./phase10.md)

Phase 7, 8, and 9 documents have been archived to
[`archive/`](./archive/README.md) as future commercial-roadmap material with
no current active implementation work.
- [MembershipConsensus.md](./MembershipConsensus.md)
- [MembershipImplementationPlan.md](./MembershipImplementationPlan.md)
- [CliCommandsDesign.md](./CliCommandsDesign.md)

## Application Integration Planning Documents

These hold forward-looking design for applications built on top of the Rustynet
overlay. They are scoping/design material, not active dataplane ledgers.

- [RustyChatIntegrationRequirements_2026-05-29.md](./RustyChatIntegrationRequirements_2026-05-29.md) —
  capability gap analysis for building RustyChat (encrypted messaging for nodes
  on a Rustynet) on top of Rustynet. Two-repo pair: a companion copy belongs in
  the `Iwan-Teague/rustychat` repo.

## Mobile Planning Documents

These hold future mobile-client architecture and roadmap material.

- [mobile/README.md](./mobile/README.md)
- [RustynetMobileArchitectureDesign_2026-04-17.md](./mobile/RustynetMobileArchitectureDesign_2026-04-17.md)
- [RustynetMobileRoadmap_2026-04-17.md](./mobile/RustynetMobileRoadmap_2026-04-17.md)
- [Imported mobile bundle index](./mobile/imported/rustynet_mobile_docs_bundle_2026-04-17/00_BundleIndex_2026-04-17.md)

## Primary Execution Ledgers

These are the first active work documents to check for current status and remaining work.

- [RustynetDataplaneExecutionPlan_2026-05-18.md](./operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md) — current dataplane track (D2-D12): peer-distributed coordination, home-server-as-zero-ingress-relay, uPnP/IPv6/ICE, enrollment-token onboarding, anchor-role formalisation, 6-role user-selectable surface. Read this first for "what are we building and why."
- [NodeRoleTaxonomy_2026-05-21.md](./operations/active/NodeRoleTaxonomy_2026-05-21.md) — canonical taxonomy for the six user-selectable node roles (D12): `relay`, `anchor`, `exit`, `blind_exit`, `client`, `admin`. Preset compositions, transition matrix, per-platform eligibility.
- [AnchorNodeRoleDesign_2026-05-21.md](./operations/active/AnchorNodeRoleDesign_2026-05-21.md) — canonical design for the anchor node role (D11): role definition, per-platform host capability, refactor inventory, security controls.
- [MasterWorkPlan_2026-03-22.md](./operations/active/MasterWorkPlan_2026-03-22.md)
- [PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md](./operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md)

## Active Work Documents

The active-work folder contains the current implementation and hardening plans.
[`operations/active/README.md`](./operations/active/README.md) is the
canonical index — this list is a shortcut to the active files grouped by
purpose. Keep the two lists in sync when adding, removing, or moving
documents.

Entry point:
- [operations/active/README.md](./operations/active/README.md)

Cross-platform improvement and security ledgers (most recently updated):
- [PlatformImprovementBacklog_2026-05-14.md](./operations/active/PlatformImprovementBacklog_2026-05-14.md)
- [SecurityReview_2026-05-24.md](./operations/active/SecurityReview_2026-05-24.md) — firm-grade security review (RN-01..RN-38, P0/P1/P2 remediation roadmap; load-bearing findings verified first-hand)
- [SecurityHardeningBacklog_2026-06-01.md](./operations/active/SecurityHardeningBacklog_2026-06-01.md) — actionable hardening TODO tracker (net-new smoke/harness items + the highest-priority open review P0s re-verified on `main`)
- [SecurityHardeningAudit_2026-04-28.md](./operations/active/SecurityHardeningAudit_2026-04-28.md)
- [RustynetComparativeVpnExploitCoverage_2026-03-14.md](./operations/active/RustynetComparativeVpnExploitCoverage_2026-03-14.md)
- [DiagnosticFunctionsRoadmap.md](./operations/active/DiagnosticFunctionsRoadmap.md)

Open phase-local hardening checklists (finished Phase 1/2/3/5 are in
[`operations/done/`](./operations/done/README.md)):
- [Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md](./operations/active/Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md)
- [Phase5ReleaseReadinessSummary_2026-04-12.md](./operations/active/Phase5ReleaseReadinessSummary_2026-04-12.md)
- [Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md](./operations/active/Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md)

Live-lab + cross-network execution plans:
- [CrossNetworkRemoteExitNodePlan_2026-03-16.md](./operations/active/CrossNetworkRemoteExitNodePlan_2026-03-16.md)
- [LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md](./operations/active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md)
- [HeterogeneousLiveLabEvidence_2026-04-28.md](./operations/active/HeterogeneousLiveLabEvidence_2026-04-28.md)
- [VmLabCapabilityCookbook_2026-04-14.md](./operations/active/VmLabCapabilityCookbook_2026-04-14.md)
- [VmLabCapabilityReportingPlan_2026-04-14.md](./operations/active/VmLabCapabilityReportingPlan_2026-04-14.md)
- [VmLabCapabilitySources_2026-04-14.md](./operations/active/VmLabCapabilitySources_2026-04-14.md)
- [UTMVirtualMachineInventory_2026-03-31.md](./operations/active/UTMVirtualMachineInventory_2026-03-31.md)

Traversal, relay, and transport-owning backend plans:
- [MasterWorkPlan_2026-03-22.md](./operations/active/MasterWorkPlan_2026-03-22.md)
- [PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md](./operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md)
- [ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md](./operations/active/ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md)
- [UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md](./operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md)
- [UdpHolePunchingHP2IngestionPlan_2026-03-07.md](./operations/active/UdpHolePunchingHP2IngestionPlan_2026-03-07.md)
- [UdpHolePunchingImplementationBlueprint_2026-03-07.md](./operations/active/UdpHolePunchingImplementationBlueprint_2026-03-07.md)
- [AnchorNodeRoleDesign_2026-05-21.md](./operations/active/AnchorNodeRoleDesign_2026-05-21.md)
- [NodeRoleTaxonomy_2026-05-21.md](./operations/active/NodeRoleTaxonomy_2026-05-21.md)

Cross-platform orchestrator, Windows, and macOS plans:
- [OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md](./operations/active/OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md)
- [RustNativeMultiPlatformOrchestratorPlan_2026-04-28.md](./operations/active/RustNativeMultiPlatformOrchestratorPlan_2026-04-28.md)
- [MacosUserspaceSharedBackendPlan_2026-05-08.md](./operations/active/MacosUserspaceSharedBackendPlan_2026-05-08.md)
- [WindowsExitAndRelayDeltaPlan_2026-05-10.md](./operations/active/WindowsExitAndRelayDeltaPlan_2026-05-10.md)
- [WindowsLabVmStabilityAndSessionModel_2026-04-30.md](./operations/active/WindowsLabVmStabilityAndSessionModel_2026-04-30.md)
- [WindowsUtmTransportArchitecture_2026-04-30.md](./operations/active/WindowsUtmTransportArchitecture_2026-04-30.md)
- [WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md](./operations/active/WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md)
- [WindowsWorkingNodePlan_2026-04-17.md](./operations/active/WindowsWorkingNodePlan_2026-04-17.md)
- [RustyfinExtensionTrustPlan_2026-05-10.md](./operations/active/RustyfinExtensionTrustPlan_2026-05-10.md)

Cross-platform security/data-plane plans:
- [CrossPlatformSecurityGapRemediationPlan_2026-03-05.md](./operations/active/CrossPlatformSecurityGapRemediationPlan_2026-03-05.md)
- [MagicDnsSignedZoneSchema_2026-03-09.md](./operations/active/MagicDnsSignedZoneSchema_2026-03-09.md)
- [SerializationFormatHardeningPlan_2026-03-25.md](./operations/active/SerializationFormatHardeningPlan_2026-03-25.md)
- [ShellToRustMigrationPlan_2026-03-06.md](./operations/active/ShellToRustMigrationPlan_2026-03-06.md)

Open-work index (cross-cuts the above):
- [OpenWorkIndex_2026-04-17.md](./operations/active/OpenWorkIndex_2026-04-17.md)

Related active machine-readable lab assets:
- `documents/operations/active/vm_lab_inventory.json`
- `documents/operations/active/vm_lab_readiness_check_2026-04-28.json`
- `documents/operations/active/windows_utm_1_runtime_acls_2026-04-28.json`
- `documents/operations/active/windows_utm_1_service_hardening_2026-04-28.json`
- `documents/operations/active/windows_utm_1_validate_2026-04-28.json`

Rule:
- use active ledgers and plans as the execution surface
- do not add standalone prompt-only documents

## Operational Runbooks And Reference Material

These are the current runbooks, support matrices, gate references, and policies.

- [operations/README.md](./operations/README.md)

Start there when you need:
- deployment or service guidance
- live-lab execution help
- live-lab OS/role/stage evidence tracking:
  [operations/LiveLabRunMatrix.md](./operations/LiveLabRunMatrix.md) and
  [operations/live_lab_run_matrix.csv](./operations/live_lab_run_matrix.csv)
- release-gate expectations
- platform support policy
- evidence generation or incident response context

Release-signoff guardrail:
- [operations/ReleaseReadinessGuardrails.md](./operations/ReleaseReadinessGuardrails.md)

## Historical Archives

These folders are for evidence and retrospective reference, not live implementation truth.

- [archive/README.md](./archive/README.md) — top-level historical archive
  (security reviews, simulation-era gap assessments, downloads-research
  import ledger, future commercial-roadmap Phase 7/8/9 documents)
- [operations/done/README.md](./operations/done/README.md) — completed
  operations reviews + completed phase implementation checklists (Phase 1, 2,
  3, 5)
- [operations/adr/README.md](./operations/adr/README.md) — Architecture
  Decision Records (immutable once accepted)

Rule:
- do not treat archived reviews as current status without re-validating them against present code and artifacts

## Documentation Hygiene Rules

- If you add, remove, rename, archive, or repurpose documents, update the relevant index in the same change.
- Remove dead links and stale references when you find them.
- Keep execution guidance inside the owning ledger or plan instead of creating new standalone prompt documents.
