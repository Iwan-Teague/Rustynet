# Documents Index

This file is the top-level orientation guide for the `documents/` tree.

Use it for two purposes:
- quickly identify which documents are normative, active, reference-only, or historical,
- divide remaining implementation work across multiple AI agents without overlapping write scopes.

## Reading Order

Any implementation agent should read in this order before touching code:
1. [AGENTS.md](/Users/iwanteague/Desktop/Rustynet/AGENTS.md)
2. [CLAUDE.md](/Users/iwanteague/Desktop/Rustynet/CLAUDE.md)
3. [README.md](/Users/iwanteague/Desktop/Rustynet/README.md)
4. [Requirements.md](./Requirements.md)
5. [SecurityMinimumBar.md](./SecurityMinimumBar.md)
6. The active scope document for the task
7. Directly linked design, runbook, and gate-reference documents

## Document Groups

### Normative

These define hard requirements or release-blocking security expectations.

- [Requirements.md](./Requirements.md)
- [SecurityMinimumBar.md](./SecurityMinimumBar.md)

Rule:
- never weaken these to match implementation convenience,
- if code and normative docs disagree, fix the code or explicitly tighten the docs with evidence.

### Phase And Architecture Scope

These describe product phases, architecture boundaries, and deeper system design.

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

Rule:
- treat these as scoped execution and architecture references,
- update them when current code reality changes materially.

### Active Work

These are the current implementation-driving documents.

- [operations/active/README.md](./operations/active/README.md)

Active set:
- [CrossNetworkRemoteExitNodePlan_2026-03-16.md](./operations/active/CrossNetworkRemoteExitNodePlan_2026-03-16.md)
- [CrossPlatformSecurityGapRemediationPlan_2026-03-05.md](./operations/active/CrossPlatformSecurityGapRemediationPlan_2026-03-05.md)
- [MagicDnsSignedZoneSchema_2026-03-09.md](./operations/active/MagicDnsSignedZoneSchema_2026-03-09.md)
- [MasterWorkPlan_2026-03-22.md](./operations/active/MasterWorkPlan_2026-03-22.md)
- [RustynetComparativeVpnExploitCoverage_2026-03-14.md](./operations/active/RustynetComparativeVpnExploitCoverage_2026-03-14.md)
- [SecurityHardeningBacklog_2026-03-09.md](./operations/active/SecurityHardeningBacklog_2026-03-09.md)
- [SerializationFormatHardeningPlan_2026-03-25.md](./operations/active/SerializationFormatHardeningPlan_2026-03-25.md)
- [ShellToRustMigrationPlan_2026-03-06.md](./operations/active/ShellToRustMigrationPlan_2026-03-06.md)
- [UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md](./operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md)
- [UdpHolePunchingHP2IngestionPlan_2026-03-07.md](./operations/active/UdpHolePunchingHP2IngestionPlan_2026-03-07.md)
- [UdpHolePunchingImplementationBlueprint_2026-03-07.md](./operations/active/UdpHolePunchingImplementationBlueprint_2026-03-07.md)

Rule:
- these are the primary execution docs for open work,
- each one now contains:
  - an `AI Implementation Prompt`,
  - a `Current Open Work` block,
  - `Agent Update Rules`.

### Operational Reference

These are current runbooks, schemas, policies, and gate references.

- [operations/README.md](./operations/README.md)

Rule:
- do not archive these just because the implementation is mature,
- agents should read them when their task touches the corresponding runtime or gate path.

### Historical Archive

These are point-in-time reviews or assessments retained for evidence, not execution.

- [archive/README.md](./archive/README.md)
- [operations/done/README.md](./operations/done/README.md)

Rule:
- do not treat archived reviews as live source of truth without re-verifying against current code.

## Multi-Agent Coordination Rules

Use these rules whenever more than one AI agent is working in the repository:

1. One package owner per primary write scope.
- If two agents need the same file set, they are not parallel-safe.

2. Update the owning work document during implementation.
- Do not keep private task state that diverges from the document.

3. Keep documentation-owner tasks close to the code owner.
- For example, the agent changing relay auth should update the exploit-coverage and hardening backlog status tied to that relay auth work.

4. Prefer parallelism only across disjoint write scopes.
- Parallel work is good when it reduces cycle time without creating merge confusion.
- Parallel work is bad when two agents edit the same control path, test harness, or gate.

5. If a package depends on another package for real completion, that is acceptable.
- The dependent agent may still improve scaffolding, tests, or docs.
- It must not claim completion until the dependency is real and verified.

## Parallel-Safe Work Packages

The packages below are the recommended split for multiple AI agents.

### Package A: HP-2 Traversal Core

Own these docs:
- [UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md](./operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md)
- [UdpHolePunchingHP2IngestionPlan_2026-03-07.md](./operations/active/UdpHolePunchingHP2IngestionPlan_2026-03-07.md)
- [UdpHolePunchingImplementationBlueprint_2026-03-07.md](./operations/active/UdpHolePunchingImplementationBlueprint_2026-03-07.md)

Primary write scope:
- `crates/rustynetd/src/traversal.rs`
- `crates/rustynetd/src/daemon.rs` traversal-specific sections
- `crates/rustynetd/src/phase10.rs` path-state and failback logic
- `crates/rustynet-backend-api/`
- `crates/rustynet-backend-wireguard/`
- traversal-specific tests and `phase10_hp2` gates

Safe in parallel with:
- Package B if B stays inside `crates/rustynet-relay/` and relay auth/session internals
- Package C
- Package D Phase A/B only
- Package E

Do not run in parallel with:
- another agent editing `traversal.rs`, traversal controller logic, or daemon path selection
- Package F if Package F is changing the same cross-network path controller files

Completion signal:
- HP-2 remaining WAN simultaneous-open behavior is real, tested, and evidenced,
- no assignment-endpoint fallback path reappears.

### Package B: HP-3 Relay Core

Own these docs:
- [UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md](./operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md)
- [UdpHolePunchingImplementationBlueprint_2026-03-07.md](./operations/active/UdpHolePunchingImplementationBlueprint_2026-03-07.md)
- [SecurityHardeningBacklog_2026-03-09.md](./operations/active/SecurityHardeningBacklog_2026-03-09.md)

Primary write scope:
- `crates/rustynet-relay/**`
- relay session auth or token validation in `crates/rustynet-control/`
- relay-specific tests, abuse protections, and constant-time checks

Safe in parallel with:
- Package A if B does not edit daemon integration or traversal controller files
- Package C
- Package D Phase A/B only
- Package E

Do not run in parallel with:
- another agent editing relay transport, session auth, or relay abuse-control internals
- Package F if Package F is integrating relay into the same daemon files

Completion signal:
- relay transport is ciphertext-only, authenticated, replay-safe, rate-limited, bounded, and verified,
- constant-time auth checks are present from day one.

### Package C: Shell-To-Rust And Cross-Platform Runtime Hardening

Own these docs:
- [ShellToRustMigrationPlan_2026-03-06.md](./operations/active/ShellToRustMigrationPlan_2026-03-06.md)
- [CrossPlatformSecurityGapRemediationPlan_2026-03-05.md](./operations/active/CrossPlatformSecurityGapRemediationPlan_2026-03-05.md)

Primary write scope:
- `start.sh`
- `crates/rustynet-cli/src/ops_*`
- `crates/rustynet-cli/src/main.rs` for new ops dispatch
- `scripts/systemd/*`
- macOS launchd or keychain integration files

Safe in parallel with:
- Package A
- Package B
- Package D Phase A/B only if D avoids the same CLI ops modules
- Package E
- Package F

Do not run in parallel with:
- another agent editing the same `start.sh` functions or the same Rust ops command implementations

Completion signal:
- remaining privileged or secret-bearing shell paths are wrapper-only or gone,
- Linux baseline remains validated,
- no second active implementation path exists for rollback.

### Package D: Serialization Hardening, Early Phases Only

Own this doc:
- [SerializationFormatHardeningPlan_2026-03-25.md](./operations/active/SerializationFormatHardeningPlan_2026-03-25.md)

Primary write scope for parallel-safe work:
- new shared serialization crate
- `crates/rustynetd/src/privileged_helper.rs`
- helper client validation path
- typed parser replacements for privileged or trust-adjacent JSON readers

Safe in parallel with:
- Package A
- Package B
- Package C
- Package E

Do not run in parallel with:
- Package F if moving report or artifact formats in Phase C
- any agent editing the same helper IPC wire format or parser modules

Important limit:
- Parallel-safe work here means Phase A and Phase B only.
- Do not start Phase C artifact-family migration in parallel with cross-network report or gate work, because those change the same readers, writers, and validators.

Completion signal:
- typed schemas replace dynamic privileged parsing,
- helper IPC is hardened without a long-lived JSON runtime fallback.

### Package E: Magic DNS Residual Hardening

Own this doc:
- [MagicDnsSignedZoneSchema_2026-03-09.md](./operations/active/MagicDnsSignedZoneSchema_2026-03-09.md)

Primary write scope:
- `crates/rustynet-control/` DNS zone issue and verify paths
- `crates/rustynetd/` DNS resolver and bundle validation
- managed-DNS system integration paths
- managed-DNS E2E tests

Safe in parallel with:
- Package A
- Package B
- Package C
- Package D Phase A/B only

Do not run in parallel with:
- Package F if F is editing the same DNS-related report validators or remote-exit DNS runtime files
- another agent editing DNS-zone issue, verify, resolver, or managed-DNS integration logic

Completion signal:
- per-node filtered issuance, loopback authoritative integration, and adversarial DNS tests are complete,
- no unsigned or fallback naming path exists.

### Package F: Cross-Network Validators, Gates, And Evidence Promotion

Own these docs:
- [CrossNetworkRemoteExitNodePlan_2026-03-16.md](./operations/active/CrossNetworkRemoteExitNodePlan_2026-03-16.md)
- [RustynetComparativeVpnExploitCoverage_2026-03-14.md](./operations/active/RustynetComparativeVpnExploitCoverage_2026-03-14.md)
- [MasterWorkPlan_2026-03-22.md](./operations/active/MasterWorkPlan_2026-03-22.md)

Primary write scope:
- `scripts/e2e/live_linux_cross_network_*`
- `scripts/ci/phase10_cross_network_exit_gates.sh`
- `crates/rustynet-cli/src/ops_cross_network_reports.rs`
- cross-network artifact schema consumers and validators
- exploit-coverage status updates tied to the changed code path

Safe in parallel with:
- Package C
- Package D Phase A/B only

Conditionally parallel with:
- Package A and Package B if F stays on validators, reports, and gates only,
- Package E if F avoids DNS runtime internals and only handles report-side work

Do not run in parallel with:
- Package A if both are editing the same daemon path controller or traversal runtime files
- Package B if both are editing relay integration in daemon files
- Package D Phase C artifact migration

Completion signal:
- cross-network validators, reports, and hard gates are real and fail correctly,
- exploit-coverage statuses are evidence-backed,
- no cross-network capability is marked complete without measured artifacts.

## Packages That Should Usually Not Be Standalone Agent Streams

These should normally be updated by the owner of the related code change, not by a separate doc-only agent:

- [SecurityHardeningBacklog_2026-03-09.md](./operations/active/SecurityHardeningBacklog_2026-03-09.md)
- [RustynetComparativeVpnExploitCoverage_2026-03-14.md](./operations/active/RustynetComparativeVpnExploitCoverage_2026-03-14.md)
- [MasterWorkPlan_2026-03-22.md](./operations/active/MasterWorkPlan_2026-03-22.md)

Reason:
- these documents summarize or coordinate work across multiple code streams,
- they are easiest to keep correct when updated by the code owner at the time the code lands.

## Practical Multi-Agent Assignment Example

A safe split for four agents is:
1. Agent 1: Package A
2. Agent 2: Package B
3. Agent 3: Package C
4. Agent 4: Package D Phase A/B only

Then assign Package E after one of the above agents frees up.
Package F should be owned by the integrator or by an agent that is only touching validators, reports, and gates after the core runtime work is stable enough for evidence promotion.

Ready-to-use prompts for those four assignments:
- [AgentKickoffPrompts.md](./AgentKickoffPrompts.md)

## Final Rule

If there is any doubt about whether two agents overlap, treat them as overlapping until the write scopes are made disjoint explicitly.

Security is more important than parallelism.
