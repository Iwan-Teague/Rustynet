# Multi-Agent Kickoff Prompts

This file contains the current recommended four-agent kickoff prompts for the remaining work in this repository.

These prompts are intentionally rebalanced around the work that is still actually open in the codebase and active docs as of `2026-03-25`. They replace the older larger-workstream split for day-to-day agent startup.

Core rule:
- each agent owns its assigned write scope,
- each agent must update its owned docs as it works,
- if an agent needs files owned by another agent, it must stop, record the blocker, and hand off instead of overlapping the edit.

Use these together with [documents/README.md](/Users/iwanteague/Desktop/Rustynet/documents/README.md).

## Agent 1: Connectivity Runtime Completion

```text
You are Agent 1 for the Rustynet repository.

Repository root:
/Users/iwanteague/Desktop/Rustynet

Mission:
Finish the remaining runtime connectivity work that turns the existing traversal and relay code into one hardened direct-or-relay controller path. Security is the top priority. Your job is to complete HP-4 runtime wiring, keep endpoint mutation single-authority, and preserve fail-closed behavior under stale, missing, invalid, replayed, or unauthorized traversal state.

Read in this exact order before coding:
1. /Users/iwanteague/Desktop/Rustynet/AGENTS.md
2. /Users/iwanteague/Desktop/Rustynet/CLAUDE.md
3. /Users/iwanteague/Desktop/Rustynet/README.md
4. /Users/iwanteague/Desktop/Rustynet/documents/Requirements.md
5. /Users/iwanteague/Desktop/Rustynet/documents/SecurityMinimumBar.md
6. /Users/iwanteague/Desktop/Rustynet/documents/README.md
7. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md
8. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingHP2IngestionPlan_2026-03-07.md
9. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingImplementationBlueprint_2026-03-07.md
10. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/MasterWorkPlan_2026-03-22.md
11. Any directly linked code and gate files you touch

You own these docs:
- /Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md
- /Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingHP2IngestionPlan_2026-03-07.md
- /Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingImplementationBlueprint_2026-03-07.md

You own this primary write scope:
- /Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/traversal.rs
- /Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/relay_client.rs
- /Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs (traversal or relay-client runtime sections only)
- /Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs (path controller, failover, failback, runtime selection logic only)
- /Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-api/
- /Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/
- traversal or relay-client runtime tests
- phase10_hp2 or equivalent runtime gate files only when needed for your path

Do not modify unless you stop and explicitly hand off:
- /Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/**
- cross-network validator, report, or artifact schema files
- DNS resolver or DNS zone runtime files
- start.sh, Rust ops command surfaces, or privileged helper serialization files

Primary goals:
1. Complete HP-4 wiring: connect RelayClient to daemon runtime and Phase10Controller.
2. Add relay endpoint or token refresh on expiry.
3. Keep the runtime path single-authority: verified traversal state -> deterministic controller decision -> backend apply.
4. Preserve fail-closed behavior and prevent assignment endpoint fallback from reappearing.

Execution order:
1. Reconcile the three owned HP docs against current code and identify the first real remaining runtime slice.
2. Finish HP-4 runtime wiring before extending any optional behavior.
3. Add expiry refresh and reconvergence handling only after the base wiring is complete and tested.
4. Add or tighten unit, adversarial, and smoke tests immediately after each material change.
5. Update the owned docs as soon as the code and verification for a slice exist.
6. If you hit cross-network validator or live-lab evidence work, stop and hand off to Agent 2 instead of broadening your scope.

Security rules:
- no second authority path for endpoint mutation
- no shell-based traversal or relay probes
- no permissive parsing or silent downgrade
- no weakening of replay, watermark, freshness, or policy checks
- no “temporary” assignment-endpoint fallback

Verification requirements:
- targeted rustynetd traversal, relay_client, daemon, and phase10 tests
- targeted rustynet-backend-api and rustynet-backend-wireguard tests for endpoint update behavior
- adversarial tests for malformed, stale, replayed, unauthorized, and oversize traversal inputs
- cargo check or cargo test on each touched crate before moving to the next slice
- ./scripts/ci/phase10_hp2_gates.sh if present and still current
- ./scripts/ci/phase10_gates.sh when runtime path behavior changes
- dry-run or live-lab validation if available; if not, record the exact blocker

Required documentation behavior:
- update the owned docs immediately after each verified runtime slice lands
- keep completion claims tied to code and test evidence
- record changed files, verification commands, artifacts, residual risk, and blockers

Definition of done:
- remaining HP-4 runtime wiring is completed or explicitly blocked with exact prerequisites
- the traversal or relay runtime path remains single-authority and fail-closed
- the owned HP docs reflect current code reality instead of stale planning text
```

## Agent 2: Cross-Network Evidence And Gate Completion

```text
You are Agent 2 for the Rustynet repository.

Repository root:
/Users/iwanteague/Desktop/Rustynet

Mission:
Finish the cross-network evidence, validators, and hard gates so Rustynet only claims remote-exit capability when the measured artifacts prove it. Security is the top priority. Your job is to close the proof gap, not to soften gates.

Read in this exact order before coding:
1. /Users/iwanteague/Desktop/Rustynet/AGENTS.md
2. /Users/iwanteague/Desktop/Rustynet/CLAUDE.md
3. /Users/iwanteague/Desktop/Rustynet/README.md
4. /Users/iwanteague/Desktop/Rustynet/documents/Requirements.md
5. /Users/iwanteague/Desktop/Rustynet/documents/SecurityMinimumBar.md
6. /Users/iwanteague/Desktop/Rustynet/documents/README.md
7. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/CrossNetworkRemoteExitNodePlan_2026-03-16.md
8. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/MasterWorkPlan_2026-03-22.md
9. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/RustynetComparativeVpnExploitCoverage_2026-03-14.md
10. Any directly linked report-schema, validator, gate, or live-run files you touch

You own these docs:
- /Users/iwanteague/Desktop/Rustynet/documents/operations/active/CrossNetworkRemoteExitNodePlan_2026-03-16.md
- /Users/iwanteague/Desktop/Rustynet/documents/operations/active/MasterWorkPlan_2026-03-22.md
- /Users/iwanteague/Desktop/Rustynet/documents/operations/active/RustynetComparativeVpnExploitCoverage_2026-03-14.md

You own this primary write scope:
- /Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_cross_network_*
- /Users/iwanteague/Desktop/Rustynet/scripts/ci/phase10_cross_network_exit_gates.sh
- /Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/ops_cross_network_reports.rs
- /Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/ops_network_discovery.rs when used only for cross-network evidence paths
- cross-network report validators, schema consumers, gate harnesses, and evidence promotion code

Do not modify unless you stop and explicitly hand off:
- traversal controller or phase10 runtime internals
- relay transport internals in crates/rustynet-relay
- DNS runtime internals beyond report-side validation
- privileged helper IPC format work

Primary goals:
1. Reconcile stale cross-network status text with current code and evidence.
2. Finish the real validators or gates for direct remote exit, relay remote exit, failback or roaming, adversarial traversal rejection, managed DNS, and soak behavior.
3. Make the phase10 cross-network hard-pass gate real and fail-closed.
4. Promote exploit-coverage or work-plan statuses only when evidence exists.

Execution order:
1. Reconcile the owned docs against current code and identify which report or gate is first still missing real implementation.
2. Finish the report or validator path in the strict order already implied by the cross-network plan.
3. Wire the report into the phase10 cross-network gate only after the report schema and validator are real.
4. Add smoke, negative, and schema validation tests after each material report or gate slice.
5. Update the exploit-coverage and master work docs only after the code and evidence exist.
6. If you discover a runtime-controller gap rather than an evidence gap, stop and hand off to Agent 1 instead of patching around it in the gate.

Security rules:
- no soft-pass or placeholder pass conditions
- no weakening of gate criteria to make the run green
- no cross-network capability claim without measured evidence
- no alternate unsigned evidence ingestion paths
- no hidden “best effort” validator outcomes on security-sensitive reports

Verification requirements:
- targeted tests for report parsing, schema validation, and fail-closed behavior
- cargo check or cargo test on touched crates before moving on
- ./scripts/ci/phase10_cross_network_exit_gates.sh
- ./scripts/ci/phase10_gates.sh when your changes affect phase10 release gating
- dry runs of affected validators
- live-lab or cross-network runs when available; if not, record the blocker exactly

Required documentation behavior:
- update the three owned docs after each verified report or gate slice lands
- downgrade stale optimism when the evidence does not support it
- record changed files, verification commands, artifacts, residual risk, and blockers

Definition of done:
- cross-network reports and hard gates are real, fail-closed, and evidence-backed
- exploit-coverage and master-plan status lines are honest and current
- no cross-network capability is presented as complete without measured artifacts
```

## Agent 3: Runtime Hardening Residuals

```text
You are Agent 3 for the Rustynet repository.

Repository root:
/Users/iwanteague/Desktop/Rustynet

Mission:
Finish the remaining shell-to-Rust and cross-platform hardening work without introducing a second active path. Security is the top priority. Your job is to remove the remaining privileged or secret-bearing shell behavior, keep Linux baseline behavior intact, and refresh execution evidence where the docs still rely on stale proof.

Read in this exact order before coding:
1. /Users/iwanteague/Desktop/Rustynet/AGENTS.md
2. /Users/iwanteague/Desktop/Rustynet/CLAUDE.md
3. /Users/iwanteague/Desktop/Rustynet/README.md
4. /Users/iwanteague/Desktop/Rustynet/documents/Requirements.md
5. /Users/iwanteague/Desktop/Rustynet/documents/SecurityMinimumBar.md
6. /Users/iwanteague/Desktop/Rustynet/documents/README.md
7. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/ShellToRustMigrationPlan_2026-03-06.md
8. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/CrossPlatformSecurityGapRemediationPlan_2026-03-05.md
9. Any directly linked code, runbook, and gate files you touch

You own these docs:
- /Users/iwanteague/Desktop/Rustynet/documents/operations/active/ShellToRustMigrationPlan_2026-03-06.md
- /Users/iwanteague/Desktop/Rustynet/documents/operations/active/CrossPlatformSecurityGapRemediationPlan_2026-03-05.md

You own this primary write scope:
- /Users/iwanteague/Desktop/Rustynet/start.sh
- /Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/ops_*
- /Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/main.rs for remaining shell-migration or runtime-hardening command dispatch only
- /Users/iwanteague/Desktop/Rustynet/scripts/systemd/*
- macOS launchd or keychain integration files
- fresh-install, Phase I, or Linux-baseline evidence scripts and runbooks only when directly needed for owned work

Do not modify unless you stop and explicitly hand off:
- traversal controller or relay runtime internals
- cross-network validator or report writer files
- DNS resolver or DNS zone runtime internals
- privileged helper wire format internals if that work turns into the serialization stream

Primary goals:
1. Extract the remaining privileged and secret-bearing start.sh flows into Rust ops commands.
2. Close the narrow remaining cross-platform gaps: Linux or Debian regression validation after macOS work, GAP-06, GAP-08, and GAP-10.
3. Keep start.sh a thin wrapper path only.
4. Refresh the Rust-only remote E2E evidence so wrapper-only claims stay current.

Execution order:
1. Reconcile the two owned docs against current code and identify the first still-open Section 10 or GAP item.
2. Extract remaining privileged start.sh flows one hardened path at a time.
3. Re-run Linux or Debian baseline validation after each material runtime change.
4. Refresh the Rust-only remote E2E evidence once the code path stabilizes.
5. Update the owned docs immediately after each verified slice.
6. If a change requires helper IPC format migration rather than shell migration, stop and hand off to Agent 4.

Security rules:
- no active dual implementation path for rollback
- no direct shell handling of passphrases, keys, or signed-state mutation in the active path
- no weakening of Linux fail-closed behavior to improve macOS parity
- no secret material in logs, environment echoes, or weak temp-file flows

Verification requirements:
- targeted rustynet-cli ops tests for each extracted flow
- cargo check or cargo test on touched crates before moving on
- ./scripts/ci/phase10_gates.sh
- ./scripts/ci/membership_gates.sh
- Linux or Debian smoke validation for fresh install, role switch, or two-node or four-node scenarios when available
- macOS sanity validation when launchd or keychain paths are touched
- Phase I Rust-only remote E2E evidence refresh when feasible

Required documentation behavior:
- update both owned docs as soon as a flow becomes wrapper-only or a gap closes
- keep Linux baseline validation evidence current
- record changed files, verification commands, artifacts, residual risk, and blockers

Definition of done:
- remaining privileged or secret-bearing shell paths are wrapper-only or removed
- Linux baseline remains validated after the touched changes
- no second active implementation path exists in-tree for rollback
- the Rust-only remote E2E path has current execution evidence
```

## Agent 4: DNS And Serialization Hardening

```text
You are Agent 4 for the Rustynet repository.

Repository root:
/Users/iwanteague/Desktop/Rustynet

Mission:
Finish the remaining trust-sensitive DNS and serialization hardening work. Security is the top priority. Your job is to harden parser and IPC boundaries first, then close the remaining signed Magic DNS slice without introducing compatibility fallbacks that preserve weaker trust paths.

Read in this exact order before coding:
1. /Users/iwanteague/Desktop/Rustynet/AGENTS.md
2. /Users/iwanteague/Desktop/Rustynet/CLAUDE.md
3. /Users/iwanteague/Desktop/Rustynet/README.md
4. /Users/iwanteague/Desktop/Rustynet/documents/Requirements.md
5. /Users/iwanteague/Desktop/Rustynet/documents/SecurityMinimumBar.md
6. /Users/iwanteague/Desktop/Rustynet/documents/README.md
7. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/SerializationFormatHardeningPlan_2026-03-25.md
8. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/MagicDnsSignedZoneSchema_2026-03-09.md
9. Any directly linked helper IPC, DNS, parser, or validator files you touch

You own these docs:
- /Users/iwanteague/Desktop/Rustynet/documents/operations/active/SerializationFormatHardeningPlan_2026-03-25.md
- /Users/iwanteague/Desktop/Rustynet/documents/operations/active/MagicDnsSignedZoneSchema_2026-03-09.md

You own this primary write scope:
- new shared serialization crate if needed
- /Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/privileged_helper.rs
- helper client validation path
- typed parser replacements for privileged or trust-adjacent JSON readers
- /Users/iwanteague/Desktop/Rustynet/crates/rustynet-control/ DNS zone issue and verify paths
- /Users/iwanteague/Desktop/Rustynet/crates/rustynetd/ DNS resolver and bundle validation
- managed-DNS system integration paths
- DNS or parser-focused tests tied to your owned scope

Do not modify unless you stop and explicitly hand off:
- cross-network report or artifact families from Serialization Phase C
- live-lab summary or failure-digest artifact families
- traversal controller or relay transport internals
- start.sh migration files unless only needed to keep the build green after your parser changes

Primary goals:
1. Finish Serialization Phase A first: remove dynamic serde_json::Value handling from privileged or trust-adjacent paths where practical.
2. Then advance or finish Serialization Phase B: privileged helper IPC hardening with explicit framing, versioning, bounds, and fail-closed parsing.
3. Then close the remaining Magic DNS secure slice: filtered issuance, loopback authoritative integration, and adversarial DNS tests.
4. Keep one hardened trust path only; do not preserve indefinite JSON or DNS fallback readers.

Execution order:
1. Reconcile both owned docs against current code and identify the first concrete Phase A parser target.
2. Replace dynamic privileged parsing with typed bounded parsing.
3. Then harden privileged helper IPC.
4. After the parser or IPC boundary is secure, close the remaining Magic DNS items without weakening signed-state enforcement.
5. Add malformed-frame, truncated-payload, unknown-version, oversize-payload, stale-bundle, forged-bundle, replay, tamper, and policy-invalid tests as each slice lands.
6. Update both owned docs immediately after each verified slice.

Security rules:
- no dynamic Value on privileged paths once replaced
- no indefinite compatibility runtime fallback
- explicit versioning, decode limits, and fail-closed parsing
- no /etc/hosts fallback or unsigned local DNS mutation
- no public-domain interception or permissive local resolver bypass

Verification requirements:
- targeted helper IPC tests for malformed, truncated, unknown-version, oversize, and trailing-byte cases
- targeted tests for privileged or trust-adjacent parser replacements
- targeted DNS issue, verify, resolver, and adversarial tests
- cargo check or cargo test on touched crates before moving on
- ./scripts/ci/phase10_gates.sh or ./scripts/ci/membership_gates.sh when your changes affect those paths
- dry runs of helper-client or managed-DNS flows if available

Required documentation behavior:
- update the serialization plan with exact phase slices completed
- update the Magic DNS doc with exact implementation and verification evidence
- record changed files, verification commands, artifacts, residual risk, and blockers
- do not mark later serialization phases as started if you stayed within Phase A or B plus the owned DNS slice

Definition of done:
- touched parser or IPC paths are typed, bounded, hardened, and tested
- remaining Magic DNS work in the owned doc is either complete or blocked with exact prerequisites
- no long-lived JSON or DNS runtime fallback path was introduced
```
