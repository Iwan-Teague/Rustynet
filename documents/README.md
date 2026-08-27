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
- [phase10.md](./phase10.md)

Phase documents 3–6 and the executed build plan have been archived to
[`archive/`](./archive/README.md): Phase 3/4/5/6 are executed-phase architecture
documents no longer maintained at top level, and Phase 7/8/9 are future
commercial-roadmap material with no active implementation.
- [MembershipConsensus.md](./MembershipConsensus.md)
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

The authoritative primary-ledger list is [`AGENTS.md` §2](../AGENTS.md). The dataplane/roles subset:

- [RustynetDataplaneExecutionPlan_2026-05-18.md](./operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md) — current dataplane track (D2-D13): peer-distributed coordination, home-server-as-zero-ingress-relay, uPnP/IPv6/ICE, enrollment-token onboarding, service-hosting roles (nas, llm). Read this first for "what are we building and why."
- [CrossNetworkSubstrateIntegrationSpec_2026-06-21.md](./operations/active/CrossNetworkSubstrateIntegrationSpec_2026-06-21.md) — focused integration spec to make the cross-network live-lab stages actually run.
- [CrossPlatformRoleParityRefresh_2026-07-23.md](./operations/active/CrossPlatformRoleParityRefresh_2026-07-23.md) — **the live per-OS parity-status matrix on the Rust `--node` engine** (supersedes the status half of the ParityPlan §3 + Roadmap). The mandate remains the [ParityPlan](./operations/active/CrossPlatformRoleParityPlan_2026-06-21.md).
- [LiveLabExecutionEfficiencyPlan_2026-06-20.md](./operations/active/LiveLabExecutionEfficiencyPlan_2026-06-20.md) — operating method for the same-LAN live-lab loop.
- [ServiceHostingRolesRoadmap_2026-06-11.md](./operations/active/ServiceHostingRolesRoadmap_2026-06-11.md) — top-level program roadmap for the `nas` + `llm` roles (D13).
- [NodeRoleTaxonomy_2026-05-21.md](./operations/active/NodeRoleTaxonomy_2026-05-21.md) — canonical taxonomy for the eight user-selectable node roles: `relay`, `anchor`, `exit`, `blind_exit`, `client`, `admin`, `nas`, `llm`. Preset compositions, transition matrix, per-platform eligibility.
- [AnchorNodeRoleDesign_2026-05-21.md](./operations/active/AnchorNodeRoleDesign_2026-05-21.md) — canonical design for the anchor node role (D11): role definition, per-platform host capability, refactor inventory, security controls.
- [AnchorEnrollmentEndpointEnforcementDesign_2026-08-27.md](./operations/active/AnchorEnrollmentEndpointEnforcementDesign_2026-08-27.md) — D-3: runtime enforcement for `anchor.enrollment_endpoint` (previously a purely declarative capability). Design answers + the landed per-request capability gate on `EnrollmentConsume`; the LAN listener remains an owner decision.
- [SignedMembershipTransitionSigningSubflowDesign_2026-08-27.md](./operations/active/SignedMembershipTransitionSigningSubflowDesign_2026-08-27.md) — D-4a: design for the capability-signing sub-flow of `SignedMembership` role transitions (who signs and where the approver key lives — split-station, no key movement; the generalized §10.7 add/remove ordering per capability; per-step-boundary partial-failure states; idempotent re-run resumability). Landed skeleton: the pure `role_signing_subflow` step sequencer + ordering tests. The automated driver and live proof (D-4b) are not in scope.
- [MasterWorkPlan_2026-03-22.md](./operations/active/MasterWorkPlan_2026-03-22.md) — superseded as the repo-wide roll-up by [FullTodoInventory_2026-07-28.md](./operations/active/FullTodoInventory_2026-07-28.md); retained for section structure/history.
- [PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md](./operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md) — historical defect inventory; the defects it documents are largely closed by Dataplane D2–D4.

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
- [DataplanePerfBacklog_2026-06-12.md](./operations/active/DataplanePerfBacklog_2026-06-12.md) —
  active hot-path performance backlog for the WireGuard userspace-shared engine, relay forwarding,
  utun I/O, and endpoint indexing; records measured baselines and bench commands
- [EfficiencyAndAdvancedTechniqueOpportunityCatalog_2026-07-19.md](./operations/active/EfficiencyAndAdvancedTechniqueOpportunityCatalog_2026-07-19.md) —
  research catalog (unscheduled, not a plan) of 31 independently-verified efficiency/architecture
  findings across key custody, ACL evaluation, trust-state verification, enrollment, serialization,
  NAT traversal, relay accounting, concurrency, build/test speed, CLI startup, and Windows/service
  data paths — each with multiple candidate technique families and no chosen fix, complementary to
  `DataplanePerfBacklog` and the FIS-0001..0008 proposals
- [SecurityReview_2026-05-24.md](./operations/active/SecurityReview_2026-05-24.md) — firm-grade security review (RN-01..RN-38, P0/P1/P2 remediation roadmap; load-bearing findings verified first-hand)
- [SecurityHardeningBacklog_2026-06-01.md](./operations/active/SecurityHardeningBacklog_2026-06-01.md) — actionable hardening TODO tracker (net-new smoke/harness items + the highest-priority open review P0s re-verified on `main`)
- [SecurityAuditLedger_2026-06-18.md](./operations/active/SecurityAuditLedger_2026-06-18.md) — review-only file-by-file security audit (RSA-####, 594/594 coverage complete) — **current audit source of truth**
- [RustynetComparativeVpnExploitCoverage_2026-03-14.md](./operations/active/RustynetComparativeVpnExploitCoverage_2026-03-14.md)
- [DiagnosticFunctionsRoadmap.md](./operations/active/DiagnosticFunctionsRoadmap.md)

Already-satisfied security snapshots (archived): `SecurityAnalysis_2026-06-12.md` and `SecurityHardeningAudit_2026-04-28.md` — see [archive/README.md](./archive/README.md) and [operations/done/README.md](./operations/done/README.md).

Open phase-local hardening checklists (finished Phase 1/2/3/5 are in
[`operations/done/`](./operations/done/README.md)):
- [Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md](./operations/active/Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md)
- [Phase5ReleaseReadinessSummary_2026-04-12.md](./operations/active/Phase5ReleaseReadinessSummary_2026-04-12.md)
- [Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md](./operations/active/Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md)

Live-lab + cross-network execution plans:
- [LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md](./operations/active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md)
- [HeterogeneousLiveLabEvidence_2026-04-28.md](./operations/active/HeterogeneousLiveLabEvidence_2026-04-28.md)
- [VmLabCapabilityCookbook_2026-04-14.md](./operations/active/VmLabCapabilityCookbook_2026-04-14.md)
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
- [AnchorEnrollmentEndpointEnforcementDesign_2026-08-27.md](./operations/active/AnchorEnrollmentEndpointEnforcementDesign_2026-08-27.md)
- [SignedMembershipTransitionSigningSubflowDesign_2026-08-27.md](./operations/active/SignedMembershipTransitionSigningSubflowDesign_2026-08-27.md)

Cross-platform orchestrator, Windows, and macOS plans:
- [OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md](./operations/active/OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md)
- [WindowsExitAndRelayDeltaPlan_2026-05-10.md](./operations/active/WindowsExitAndRelayDeltaPlan_2026-05-10.md)
- [WindowsLabVmStabilityAndSessionModel_2026-04-30.md](./operations/active/WindowsLabVmStabilityAndSessionModel_2026-04-30.md)
- [WindowsUtmTransportArchitecture_2026-04-30.md](./operations/active/WindowsUtmTransportArchitecture_2026-04-30.md)
- [WindowsWorkingNodePlan_2026-04-17.md](./operations/active/WindowsWorkingNodePlan_2026-04-17.md)

Fulfilled plans now archived: `RustNativeMultiPlatformOrchestratorPlan_2026-04-28.md`, `MacosUserspaceSharedBackendPlan_2026-05-08.md`, `WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md`, `RustyfinExtensionTrustPlan_2026-05-10.md` — see [archive/README.md](./archive/README.md).

Cross-platform security/data-plane plans:
- [CrossPlatformSecurityGapRemediationPlan_2026-03-05.md](./operations/active/CrossPlatformSecurityGapRemediationPlan_2026-03-05.md)
- [MagicDnsSignedZoneSchema_2026-03-09.md](./operations/active/MagicDnsSignedZoneSchema_2026-03-09.md)
- [SerializationFormatHardeningPlan_2026-03-25.md](./operations/active/SerializationFormatHardeningPlan_2026-03-25.md)

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
- [operations/Arm32BitEmbeddedSupportReference_2026-06-23.md](./operations/Arm32BitEmbeddedSupportReference_2026-06-23.md) — 32-bit ARM embedded developer reference (armv7 compile status, toolchain, backend selection, memory/fd/SD card pitfalls)
- [operations/Arm32BitEmbeddedImplementationGuide_2026-06-23.md](./operations/Arm32BitEmbeddedImplementationGuide_2026-06-23.md) — implementation guide (Part 2): file-by-file code changes and operator tasks to close the §28 Known Open Items and reach supported status on armv7

Start there when you need:
- deployment or service guidance
- live-lab execution help
- live-lab OS/role/stage evidence tracking:
  [operations/live_lab_node_run_matrix.csv](./operations/live_lab_node_run_matrix.csv) —
  the **live Rust `--node` engine ledger** (current runs append here) and
  [operations/LiveLabRunMatrix.md](./operations/LiveLabRunMatrix.md), plus exact
  distro/version node-stage proof in
  [operations/live_lab_node_stage_results.csv](./operations/live_lab_node_stage_results.csv).
  `operations/live_lab_run_matrix.csv` is the **frozen legacy bash-orchestrator
  archive** — history only, `--node` no longer appends to it.
- release-gate expectations
- platform support policy
- evidence generation or incident response context

Release-signoff guardrail:
- [operations/ReleaseReadinessGuardrails.md](./operations/ReleaseReadinessGuardrails.md)

## Reference Material (general, not Rustynet-specific)

Generalized engineering write-ups distilled from work on this repo but deliberately scrubbed
of Rustynet specifics for reuse on other projects. Not active execution guidance, not part of
the read order above, and not something implementation work depends on.

- [reference/LiveLabOrchestrationBlueprint.md](./reference/LiveLabOrchestrationBlueprint.md) —
  a project-agnostic blueprint for building an automated, evidence-grade, multi-environment
  live-lab test orchestrator, distilled from this repo's `--node` orchestrator + TUI + CI
  experience: the pipeline phases, the data/ledger model, a 19-item pitfalls catalog for
  writing trustworthy validators, and the commit/patch/run operating rhythm.

## Formal Verification Artifacts

Machine-checkable models of trust-sensitive protocols (FIS-0019). The `.tla`
is canonical; the `.cfg` makes TLC one-command-runnable; the Python explorer
is an exhaustive BFS surrogate mirroring the spec transition-for-transition.
These artifacts share constants with the CI-enforced conformance test at
`crates/rustynet-control/tests/membership_model_conformance.rs` and must move
together.

- [formal/MembershipTrustState.tla](./formal/MembershipTrustState.tla) —
  bounded model of `apply_signed_update` (epoch chaining, replay cache,
  root determinism; `BuggyReducer` re-finds RSA-0009)
- [formal/MembershipTrustState.cfg](./formal/MembershipTrustState.cfg) — TLC
  configuration (run: `java -cp tla2tools.jar tlc2.TLC -config
  MembershipTrustState.cfg MembershipTrustState.tla`)
- [formal/membership_trust_state_explorer.py](./formal/membership_trust_state_explorer.py)
  — exhaustive surrogate explorer (`python3 … correct` / `… buggy`)

## Security Scan Archive

Machine-verified static-analysis scan output, retained as dated evidence rather
than live guidance:
- the 92 dated scan reports under [security/antares-scans/](./security/antares-scans/)
  (one per CWE class × date; no index doc — the directory listing is the index)

## Historical Archives

These folders are for evidence and retrospective reference, not live implementation truth.

- [archive/README.md](./archive/README.md) — top-level historical archive
  (security reviews, simulation-era gap assessments, downloads-research
  import ledger, executed Phase 3–6 + MembershipImplementationPlan docs,
  superseded root handovers, fulfilled implementation plans from `active/`,
  future commercial-roadmap Phase 7/8/9 documents)
- [operations/done/README.md](./operations/done/README.md) — completed
  operations reviews + completed phase implementation checklists + satisfied
  audits (Phase 1, 2, 3, 5, plus the 2026-04-28 security-hardening audit)
- [operations/adr/README.md](./operations/adr/README.md) — Architecture
  Decision Records (immutable once accepted)

Rule:
- do not treat archived reviews as current status without re-validating them against present code and artifacts

## Documentation Hygiene Rules

- If you add, remove, rename, archive, or repurpose documents, update the relevant index in the same change.
- Remove dead links and stale references when you find them.
- Keep execution guidance inside the owning ledger or plan instead of creating new standalone prompt documents.
