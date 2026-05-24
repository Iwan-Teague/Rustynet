# Active Operations Work

This folder contains the current implementation ledgers, active plans, and active lab-reference assets.

## Primary Execution Ledgers

Start with these when you need current status, remaining work, or the public implementation ledger:

- [RustynetDataplaneExecutionPlan_2026-05-18.md](./RustynetDataplaneExecutionPlan_2026-05-18.md) — source-of-truth plan for the cross-network dataplane track (peer-distributed coord, home-server-as-zero-ingress-relay, uPnP/IPv6/ICE, enrollment-token onboarding, anchor-role formalisation, 6-role user-selectable surface); supersedes nothing but is the active ledger for D2-D12 work
- [NodeRoleTaxonomy_2026-05-21.md](./NodeRoleTaxonomy_2026-05-21.md) — canonical taxonomy for the six user-selectable node roles (D12): `relay`, `anchor`, `exit`, `blind_exit`, `client`, `admin`; preset compositions; transition matrix; per-platform eligibility
- [AnchorNodeRoleDesign_2026-05-21.md](./AnchorNodeRoleDesign_2026-05-21.md) — canonical design for the anchor node role (D11; one of the six presets in the taxonomy doc): role definition, what already exists in code, what needs building, per-platform host capability (Linux/macOS/Windows host; iOS/Android consume), refactor inventory, security controls
- [MasterWorkPlan_2026-03-22.md](./MasterWorkPlan_2026-03-22.md)
- [PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md](./PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md)
- [OpenWorkIndex_2026-04-17.md](./OpenWorkIndex_2026-04-17.md)
- [PlatformImprovementBacklog_2026-05-14.md](./PlatformImprovementBacklog_2026-05-14.md) — most recently updated cross-platform improvement ledger; the X1-X7 numbered tracks are the cleanest current path for code-only quality work
- [HomelabConnectivityParityDeltaPlan_2026-05-21.md](./HomelabConnectivityParityDeltaPlan_2026-05-21.md) — active delta ledger for closing the macOS/Windows tunnel connectivity gap vs Linux baseline; covers macOS IPv6 (M3), macOS wireguard-go prereq (M2), macOS key-retention bug (M1), macOS killswitch (M4), Windows host candidate enumeration (W1), Windows gateway detection (W2), Windows E2E test coverage (W3), Windows IPv6 audit (W4), and cross-platform uPnP IGD orchestrator (C1)
- [AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md](./AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md) — delta ledger covering three parallel tracks. Track A adds live-lab coverage for the anchor role (five sub-stages exercising bundle-pull, gossip priority, enrollment endpoint, port-mapping authority, and downgrade revocation); non-destructive scaffold has landed; enrollment/downgrade destructive sub-stages are follow-up work. Track B closes the topology-selection + per-platform validator gaps that previously blocked Windows / macOS from being the active exit_server / relay / anchor in the orchestrator; **all seven steps now landed** (topology selector, macOS exit validators, platform-aware role-transition planner + per-OS exit/relay installers, Windows active-exit promotion stage, macOS relay lifecycle dry-run, and `ops e2e-bootstrap-{macos,windows}` non-Linux genesis verbs). Track C adds an adversarial / fault-injection / chaos suite (8 categories, 30+ stages) covering daemon crashes, clock attacks, signed-state forgery, crash recovery, resource exhaustion, network impairment, membership poisoning, and privileged-boundary stress — Track C remains planning-only

## Active Phase Checklists

These are the phase-local hardening checklists that are still open. The
phase checklists that finished (Phase 1, 2, 3, 5) have moved to
[`../done/`](../done/README.md); see that index for the archived slices.

- [Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md](./Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md) — still open on fresh-install + canonical cross-network evidence regeneration for a clean current `HEAD`
- [Phase5ReleaseReadinessSummary_2026-04-12.md](./Phase5ReleaseReadinessSummary_2026-04-12.md) — the Phase 5 checklist itself is archived; this summary is kept active because it is the operator-facing readiness picture and still records remaining full release-gate blockers
- [Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md](./Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md) — code-side cross-network/shared-transport hardening done; canonical cross-network + extended soak evidence still to regenerate

## Active Plans And Backlogs

- [AnchorNodeRoleDesign_2026-05-21.md](./AnchorNodeRoleDesign_2026-05-21.md)
- [NodeRoleTaxonomy_2026-05-21.md](./NodeRoleTaxonomy_2026-05-21.md)
- [CrossNetworkRemoteExitNodePlan_2026-03-16.md](./CrossNetworkRemoteExitNodePlan_2026-03-16.md)
- [CrossPlatformSecurityGapRemediationPlan_2026-03-05.md](./CrossPlatformSecurityGapRemediationPlan_2026-03-05.md)
- [DiagnosticFunctionsRoadmap.md](./DiagnosticFunctionsRoadmap.md)
- [HeterogeneousLiveLabEvidence_2026-04-28.md](./HeterogeneousLiveLabEvidence_2026-04-28.md)
- [LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md](./LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md)
- [MagicDnsSignedZoneSchema_2026-03-09.md](./MagicDnsSignedZoneSchema_2026-03-09.md)
- [OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md](./OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md)
- [RustNativeMultiPlatformOrchestratorPlan_2026-04-28.md](./RustNativeMultiPlatformOrchestratorPlan_2026-04-28.md)
- [VmLabCapabilityCookbook_2026-04-14.md](./VmLabCapabilityCookbook_2026-04-14.md)
- [VmLabCapabilityReportingPlan_2026-04-14.md](./VmLabCapabilityReportingPlan_2026-04-14.md)
- [VmLabCapabilitySources_2026-04-14.md](./VmLabCapabilitySources_2026-04-14.md)
- [WindowsExitAndRelayDeltaPlan_2026-05-10.md](./WindowsExitAndRelayDeltaPlan_2026-05-10.md)
- [WindowsLabVmStabilityAndSessionModel_2026-04-30.md](./WindowsLabVmStabilityAndSessionModel_2026-04-30.md)
- [WindowsUtmTransportArchitecture_2026-04-30.md](./WindowsUtmTransportArchitecture_2026-04-30.md)
- [WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md](./WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md)
- [WindowsWorkingNodePlan_2026-04-17.md](./WindowsWorkingNodePlan_2026-04-17.md)
- [MacosUserspaceSharedBackendPlan_2026-05-08.md](./MacosUserspaceSharedBackendPlan_2026-05-08.md)
- [ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md](./ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md)
- [RustyfinExtensionTrustPlan_2026-05-10.md](./RustyfinExtensionTrustPlan_2026-05-10.md)
- [RustynetComparativeVpnExploitCoverage_2026-03-14.md](./RustynetComparativeVpnExploitCoverage_2026-03-14.md)
- [SecurityHardeningAudit_2026-04-28.md](./SecurityHardeningAudit_2026-04-28.md)
- [SecurityReview_2026-05-24.md](./SecurityReview_2026-05-24.md) — firm-grade security review across six domains (privileged boundary, crypto/key custody, trust/anti-replay, untrusted-input/IPC, dataplane fail-closed/killswitch, secret-hygiene/supply-chain). 38 findings (7 High / 9 Medium / 17 Low / 5 Info) with CWE, file:line, exploit scenario, and a prioritized P0/P1/P2 roadmap; load-bearing findings verified first-hand. Now also includes scope/asset/trust-boundary mapping, a threat model (10 actor profiles), methodology limitations + residual-risk statement, indicative CVSS, compound exploit chains, a CLAUDE.md/SecurityMinimumBar compliance matrix, a master finding-status tracker, reproduction notes, and references/glossary. Remediation log RL-1..RL-8: **8 findings fixed + tested** (RN-01 membership-decoder DoS, RN-14 unsafe-lint enforcement, RN-22 ed25519 verify_strict, RN-24 zeroize, RN-23 keychain id, RN-19 symmetric argv gate, RN-17 helper peer-cred TOCTOU check, RN-15 CI --locked), RN-21 accepted (fail-closed). Headline open P0s: dataplane fail-open paths, Windows killswitch/IPv6 leaks, policy default-allow (revocation bypass)
- [FullRepoAnalysis_2026-05-24.md](./FullRepoAnalysis_2026-05-24.md) — full-spectrum repository analysis (9-agent two-pass review, all passes complete): 66 findings across security (1 critical crypto bug — AlgorithmPolicy inverted guard; 3 high policy-engine issues — empty-context wildcard, rollout validation bypass, membership bypass-on-empty), architecture (IPC versioning gap, relay diagnostics trait gap), code quality (panic paths, allocation inefficiency, async safety — RwLock across await, fire-and-forget tasks, HTTP body unbounded), shell-to-Rust migration status and TIER-1/2 outstanding work, documentation gaps (4 critical release blockers, 8 high-priority missing runbooks), lint/cfg/unsafe audit (clean; missing Windows SAFETY comment), IPC/input validation audit (strong; HTTP body size limit missing); 43-item prioritized remediation plan
- [TestCoverageImprovementPlan_2026-05-24.md](./TestCoverageImprovementPlan_2026-05-24.md) — owning ledger for the test-coverage track; prioritized P0/P1/P2 workstreams (roles.rs zero-coverage, signed-state/crypto/dns-zone negative tests, sysinfo parse/IO split, dataplane default-deny truth tables, gossip anti-replay persistence) plus tooling levers (llvm-cov ratchet, proptest, expanded fuzzing, broadened coverage-gate floors)
- [SerializationFormatHardeningPlan_2026-03-25.md](./SerializationFormatHardeningPlan_2026-03-25.md)
- [ShellToRustMigrationPlan_2026-03-06.md](./ShellToRustMigrationPlan_2026-03-06.md)
- [StartShOperatorUxRustMigrationPlan_2026-05-24.md](./StartShOperatorUxRustMigrationPlan_2026-05-24.md) — implementation guide for migrating the remaining `start.sh` logic (operator UX, config management, role policy, validators, arg parsing, egress detection, dependency bootstrap) into a new `rustynet-operator` Rust crate; continues ShellToRustMigrationPlan (privileged/secret flows already migrated) and closes the last two direct privileged shell ops (config chmod, binary install); motivated by cross-platform (Windows) support and security. Includes **Appendix A: ready-to-paste reference implementations** — complete, tested Rust ports of the pure-logic shell functions (role/preset normalization, launch/LAN/exit-chain validators, arg parser, egress/endpoint parsers, config allowlist/parse, atomic 0600 config persist + file-security gate)
- [UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md](./UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md)
- [UdpHolePunchingHP2IngestionPlan_2026-03-07.md](./UdpHolePunchingHP2IngestionPlan_2026-03-07.md)
- [UdpHolePunchingImplementationBlueprint_2026-03-07.md](./UdpHolePunchingImplementationBlueprint_2026-03-07.md)

## Active Lab Assets

- [UTMVirtualMachineInventory_2026-03-31.md](./UTMVirtualMachineInventory_2026-03-31.md)
- [rustynet_blind_exit_pcb_report_2026-05-10.docx](./rustynet_blind_exit_pcb_report_2026-05-10.docx)
- `vm_lab_inventory.json` — VM topology + role assignments
- `vm_lab_readiness_check_2026-04-28.json` — dated VM lab readiness summary (schema_version=1)
- `windows_utm_1_runtime_acls_2026-04-28.json` — windows-utm-1 runtime-ACL collector evidence
- `windows_utm_1_service_hardening_2026-04-28.json` — windows-utm-1 service-hardening collector evidence
- `windows_utm_1_validate_2026-04-28.json` — windows-utm-1 validate-bundle output

Rule: these JSON evidence files are dated artifacts from specific lab runs.
Add a new dated file when a new run produces fresh evidence; do not edit
existing ones in place.

## Rules

- Keep status and evidence in the owning ledger or plan.
- Do not add standalone prompt documents here.
- If an active file becomes historical, move it or reclassify it honestly and update the indexes in the same change.
