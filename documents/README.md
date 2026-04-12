# Documents Index

This file is the top-level map of the `documents/` tree.

Use it to answer three questions quickly:
- which documents are normative and release-blocking
- which documents currently drive implementation work
- which runbooks or historical reviews are only reference material

## Read Order

Before touching code, read in this order:
1. [AGENTS.md](/Users/iwanteague/Desktop/Rustynet/AGENTS.md)
2. [CLAUDE.md](/Users/iwanteague/Desktop/Rustynet/CLAUDE.md)
3. [README.md](/Users/iwanteague/Desktop/Rustynet/README.md)
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

## Phase And Architecture Documents

These explain architecture, phase boundaries, and longer-running design work.

- [Phase1.md](./Phase1.md)
- [Phase1Implementation.md](./Phase1Implementation.md)
- [Phase2.md](./Phase2.md)
- [Phase3.md](./Phase3.md)
- [Phase4.md](./Phase4.md)
- [Phase5.md](./Phase5.md)
- [Phase6.md](./Phase6.md)
- [Phase7.md](./Phase7.md)
- [Phase8.md](./Phase8.md)
- [Phase9.md](./Phase9.md)
- [phase10.md](./phase10.md)
- [MembershipConsensus.md](./MembershipConsensus.md)
- [MembershipImplementationPlan.md](./MembershipImplementationPlan.md)

## Primary Execution Ledgers

These are the first active work documents to check for current status and remaining work.

- [MasterWorkPlan_2026-03-22.md](./operations/active/MasterWorkPlan_2026-03-22.md)
- [PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md](./operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md)

## Active Work Documents

The active-work folder contains the current implementation and hardening plans.

- [operations/active/README.md](./operations/active/README.md)
- [CrossNetworkRemoteExitNodePlan_2026-03-16.md](./operations/active/CrossNetworkRemoteExitNodePlan_2026-03-16.md)
- [CrossPlatformSecurityGapRemediationPlan_2026-03-05.md](./operations/active/CrossPlatformSecurityGapRemediationPlan_2026-03-05.md)
- [LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md](./operations/active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md)
- [MagicDnsSignedZoneSchema_2026-03-09.md](./operations/active/MagicDnsSignedZoneSchema_2026-03-09.md)
- [Phase1DataplaneTruthHardeningChecklist_2026-04-12.md](./operations/active/Phase1DataplaneTruthHardeningChecklist_2026-04-12.md)
- [Phase2WrapperProvenanceAndCompletenessChecklist_2026-04-12.md](./operations/active/Phase2WrapperProvenanceAndCompletenessChecklist_2026-04-12.md)
- [Phase3DependencyAndPolicyCleanupChecklist_2026-04-12.md](./operations/active/Phase3DependencyAndPolicyCleanupChecklist_2026-04-12.md)
- [Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md](./operations/active/Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md)
- [Phase5ReleaseReadinessChecklist_2026-04-12.md](./operations/active/Phase5ReleaseReadinessChecklist_2026-04-12.md)
- [Phase5ReleaseReadinessSummary_2026-04-12.md](./operations/active/Phase5ReleaseReadinessSummary_2026-04-12.md)
- [MasterWorkPlan_2026-03-22.md](./operations/active/MasterWorkPlan_2026-03-22.md)
- [PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md](./operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md)
- [ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md](./operations/active/ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md)
- [RustynetComparativeVpnExploitCoverage_2026-03-14.md](./operations/active/RustynetComparativeVpnExploitCoverage_2026-03-14.md)
- [SecurityHardeningBacklog_2026-03-09.md](./operations/active/SecurityHardeningBacklog_2026-03-09.md)
- [SerializationFormatHardeningPlan_2026-03-25.md](./operations/active/SerializationFormatHardeningPlan_2026-03-25.md)
- [ShellToRustMigrationPlan_2026-03-06.md](./operations/active/ShellToRustMigrationPlan_2026-03-06.md)
- [UTMVirtualMachineInventory_2026-03-31.md](./operations/active/UTMVirtualMachineInventory_2026-03-31.md)
- [UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md](./operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md)
- [UdpHolePunchingHP2IngestionPlan_2026-03-07.md](./operations/active/UdpHolePunchingHP2IngestionPlan_2026-03-07.md)
- [UdpHolePunchingImplementationBlueprint_2026-03-07.md](./operations/active/UdpHolePunchingImplementationBlueprint_2026-03-07.md)

Related active machine-readable lab asset:
- `documents/operations/active/vm_lab_inventory.json`

Rule:
- use active ledgers and plans as the execution surface
- do not add standalone prompt-only documents

## Operational Runbooks And Reference Material

These are the current runbooks, support matrices, gate references, and policies.

- [operations/README.md](./operations/README.md)

Start there when you need:
- deployment or service guidance
- live-lab execution help
- release-gate expectations
- platform support policy
- evidence generation or incident response context

Release-signoff guardrail:
- [operations/ReleaseReadinessGuardrails.md](./operations/ReleaseReadinessGuardrails.md)

## Historical Archives

These folders are for evidence and retrospective reference, not live implementation truth.

- [archive/README.md](./archive/README.md)
- [operations/done/README.md](./operations/done/README.md)

Rule:
- do not treat archived reviews as current status without re-validating them against present code and artifacts

## Documentation Hygiene Rules

- If you add, remove, rename, archive, or repurpose documents, update the relevant index in the same change.
- Remove dead links and stale references when you find them.
- Keep execution guidance inside the owning ledger or plan instead of creating new standalone prompt documents.
