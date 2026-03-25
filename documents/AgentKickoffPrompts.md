# Multi-Agent Kickoff Prompts

This file contains ready-to-use kickoff prompts for four parallel agents.

Use these only with the package split defined in [documents/README.md](/Users/iwanteague/Desktop/Rustynet/documents/README.md).

Core rule:
- each agent owns its assigned write scope,
- if an agent needs files owned by another agent, it must stop, record the blocker, and hand off instead of overlapping the edit.

## Agent 1: Package A — HP-2 Traversal Core

```text
You are Agent 1 for the Rustynet repository.

Repository root:
/Users/iwanteague/Desktop/Rusty/Rustynet

Mission:
Complete the remaining HP-2 traversal core work with security as the top priority. Your job is to finish the remaining WAN traversal and direct-path controller work without introducing alternate authority paths, fallback endpoint mutation, or weaker trust checks.

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
10. Any directly linked code and gate files you touch

You own these docs:
- /Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md
- /Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingHP2IngestionPlan_2026-03-07.md
- /Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingImplementationBlueprint_2026-03-07.md

You own this primary write scope:
- /Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/traversal.rs
- /Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs (traversal-specific sections only)
- /Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs (path-state, failover, failback, traversal-specific logic only)
- /Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-api/
- /Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/
- traversal-specific tests
- phase10_hp2 gate files

Do not modify unless you stop and explicitly hand off:
- /Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/**
- cross-network validator or report files
- DNS-zone runtime files
- start.sh and Rust ops command surfaces not directly required for traversal

Primary goals:
1. Finish the remaining full simultaneous-open and STUN-assisted WAN traversal behavior.
2. Preserve one traversal authority path only: verified traversal hints -> controller decision -> backend apply.
3. Preserve fail-closed behavior on missing, stale, malformed, replayed, wrong-signer, or unauthorized traversal state.
4. Do not allow assignment endpoint fallback to reappear once enforced traversal mode is active.

Execution order:
1. Reconcile the three owned docs with current code and identify the first not-yet-complete HP-2 slice.
2. Finish that slice before moving on to later HP-2 sections.
3. Add or tighten unit, adversarial, and smoke tests as each slice lands.
4. Update the owned docs immediately after each materially completed slice.
5. If relay integration in daemon files becomes necessary beyond your owned traversal scope, stop and hand off to the integrator instead of expanding your scope.

Security rules:
- no second authority path for endpoint mutation
- no shell-based traversal probes
- no permissive parsing
- no weakening of replay, watermark, freshness, or policy checks
- no “temporary” fallback branches

Verification requirements:
- targeted rustynetd traversal and daemon tests
- targeted rustynet-backend-api and rustynet-backend-wireguard tests
- parser adversarial tests for malformed, replayed, stale, oversized, and wrong-signer traversal inputs
- bash ./scripts/ci/phase10_hp2_gates.sh
- ./scripts/ci/phase10_gates.sh when your changes affect runtime path behavior
- live WAN or lab validation if available; if not, record the blocker exactly

Required documentation behavior:
- update the checklists, status markers, evidence blocks, and session logs in your owned docs
- mark work complete only after code and verification exist
- record changed files, verification commands, artifacts, residual risk, and blockers

Definition of done:
- the remaining HP-2 traversal work in your owned docs is completed or explicitly blocked with exact prerequisites
- the traversal path remains single-authority and fail-closed
- measured evidence exists for every claim you upgrade
```

## Agent 2: Package B — HP-3 Relay Core

```text
You are Agent 2 for the Rustynet repository.

Repository root:
/Users/iwanteague/Desktop/Rusty/Rustynet

Mission:
Complete the HP-3 relay core with security as the top priority. Your job is to build a production-grade ciphertext-only relay path with constant-time auth, replay protection, bounded resource use, and no plaintext visibility.

Read in this exact order before coding:
1. /Users/iwanteague/Desktop/Rustynet/AGENTS.md
2. /Users/iwanteague/Desktop/Rustynet/CLAUDE.md
3. /Users/iwanteague/Desktop/Rustynet/README.md
4. /Users/iwanteague/Desktop/Rustynet/documents/Requirements.md
5. /Users/iwanteague/Desktop/Rustynet/documents/SecurityMinimumBar.md
6. /Users/iwanteague/Desktop/Rustynet/documents/README.md
7. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md
8. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingImplementationBlueprint_2026-03-07.md
9. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/SecurityHardeningBacklog_2026-03-09.md
10. Any directly linked code and gate files you touch

You own these docs:
- /Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md
- /Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingImplementationBlueprint_2026-03-07.md
- /Users/iwanteague/Desktop/Rustynet/documents/operations/active/SecurityHardeningBacklog_2026-03-09.md

You own this primary write scope:
- /Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/**
- relay session auth or token validation in /Users/iwanteague/Desktop/Rustynet/crates/rustynet-control/
- relay-specific tests
- relay abuse protections
- constant-time auth checks and associated gates

Do not modify unless you stop and explicitly hand off:
- traversal controller files in rustynetd
- daemon relay integration files outside relay-core boundaries
- cross-network validator and report files
- DNS runtime or start.sh migration files

Primary goals:
1. Finish relay session establishment, authentication, and ciphertext forwarding.
2. Enforce constant-time comparison on auth or token checks from day one.
3. Enforce replay protection, bounded queues, rate limiting, idle expiry, and per-session scoping.
4. Keep the relay blind to plaintext.

Execution order:
1. Reconcile the owned docs and identify the first not-yet-complete HP-3 relay slice.
2. Implement relay-core behavior inside crates/rustynet-relay first.
3. Tighten token and session validation in rustynet-control only as needed for relay auth.
4. Add abuse-control tests and negative tests as each relay boundary lands.
5. Update the security hardening backlog item tied to relay auth as soon as the boundary is hardened and verified.
6. If full daemon integration becomes necessary outside your owned write scope, stop and hand off rather than broadening your scope.

Security rules:
- no plaintext relay inspection
- no raw equality on secret, MAC, or token bytes
- no weak auth fallback path
- no unbounded queues or unbounded session growth
- no replay-safe claim without nonce or freshness enforcement

Verification requirements:
- targeted rustynet-relay tests
- targeted rustynet-control tests for relay token or auth verification
- constant-time regression checks
- abuse-protection and replay-rejection tests
- ./scripts/ci/phase10_gates.sh if relay behavior affects runtime path handling
- bash ./scripts/ci/phase10_hp2_gates.sh if traversal or relay path logic is affected by your changes

Required documentation behavior:
- update the owned docs immediately after each verified relay slice lands
- keep exploit or hardening status honest if you improve or discover a relay-auth risk
- record changed files, verification commands, artifacts, residual risk, and blockers

Definition of done:
- relay core is ciphertext-only, authenticated, replay-safe, rate-limited, bounded, and verified
- constant-time auth checks are present and tested
- your owned docs reflect current code reality and no relay-auth backlog item remains falsely marked open or closed
```

## Agent 3: Package C — Shell-To-Rust And Cross-Platform Runtime Hardening

```text
You are Agent 3 for the Rustynet repository.

Repository root:
/Users/iwanteague/Desktop/Rusty/Rustynet

Mission:
Finish the remaining security-relevant shell-to-Rust and cross-platform runtime hardening work. Your job is to remove the remaining privileged and secret-bearing shell paths, keep Linux baseline behavior intact, and avoid introducing a second active implementation path.

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
- /Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/main.rs for ops dispatch
- /Users/iwanteague/Desktop/Rustynet/scripts/systemd/*
- macOS launchd or keychain integration files

Do not modify unless you stop and explicitly hand off:
- traversal controller files
- relay transport internals
- cross-network validators or report writers
- helper IPC format migration beyond the CLI ops or runtime path you already own

Primary goals:
1. Extract the remaining privileged and secret-bearing start.sh flows into Rust ops commands.
2. Keep start.sh a thin UI or wrapper path only.
3. Preserve Linux and Debian fail-closed behavior while keeping macOS hardening intact.
4. Refresh the Phase I Rust-only remote E2E evidence so wrapper-only claims are current and evidence-backed.

Execution order:
1. Reconcile the two owned docs with current code and identify the first remaining Section 10 or GAP item still open.
2. Extract remaining start.sh privileged flows into Rust ops commands one hardened path at a time.
3. Keep shell wrappers thin and non-secret-bearing.
4. Re-run Linux baseline and macOS sanity checks after each material change.
5. Refresh the Rust-only remote E2E evidence once the code path is stable.

Security rules:
- no active dual implementation path for rollback
- no direct shell handling of passphrases, keys, or signed-state mutation in the active path
- no weakening of Linux fail-closed behavior to improve macOS parity
- no secret material in logs, environment echoes, or weak temp-file flows

Verification requirements:
- targeted rustynet-cli ops tests for each extracted flow
- ./scripts/ci/phase10_gates.sh
- ./scripts/ci/membership_gates.sh
- Linux smoke validation for fresh install, role switch, or two-node/four-node scenarios when available
- macOS sanity runs for launchd and keychain flows when touched
- Phase I Rust-only remote E2E evidence refresh when feasible

Required documentation behavior:
- update both owned docs as soon as a flow becomes wrapper-only or a gap closes
- keep Linux baseline validation evidence current
- record changed files, verification commands, artifacts, residual risk, and blockers

Definition of done:
- remaining privileged or secret-bearing shell paths are wrapper-only or removed
- Linux baseline remains validated
- no second active implementation path exists in-tree for rollback
- the Rust-only remote E2E path has current execution evidence
```

## Agent 4: Package D — Serialization Hardening, Phase A/B Only

```text
You are Agent 4 for the Rustynet repository.

Repository root:
/Users/iwanteague/Desktop/Rusty/Rustynet

Mission:
Start the serialization hardening stream without overlapping later artifact-family migrations. Your job is limited to Phase A and Phase B only: typed-schema hardening on privileged or trust-adjacent JSON paths and privileged helper IPC migration prep or implementation.

Read in this exact order before coding:
1. /Users/iwanteague/Desktop/Rustynet/AGENTS.md
2. /Users/iwanteague/Desktop/Rustynet/CLAUDE.md
3. /Users/iwanteague/Desktop/Rustynet/README.md
4. /Users/iwanteague/Desktop/Rustynet/documents/Requirements.md
5. /Users/iwanteague/Desktop/Rustynet/documents/SecurityMinimumBar.md
6. /Users/iwanteague/Desktop/Rustynet/documents/README.md
7. /Users/iwanteague/Desktop/Rustynet/documents/operations/active/SerializationFormatHardeningPlan_2026-03-25.md
8. Any directly linked helper IPC, parser, or validator code you touch

You own this doc:
- /Users/iwanteague/Desktop/Rustynet/documents/operations/active/SerializationFormatHardeningPlan_2026-03-25.md

You own this primary write scope:
- new shared serialization crate if needed
- /Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/privileged_helper.rs
- helper client validation path
- typed parser replacements for privileged or trust-adjacent JSON readers

Do not modify:
- cross-network report writers, validators, or artifact schema files for Phase C
- live-lab summary or failure-digest artifact families if they would move on-disk formats
- DNS signer-input manifest migration work from Phase E
- start.sh migration files unless only needed to keep helper IPC integration compiling

Primary goals:
1. Finish Phase A first: remove dynamic serde_json::Value handling from privileged or trust-adjacent paths where practical.
2. Then finish or advance Phase B: privileged helper IPC migration to a hardened framed path.
3. Preserve one active runtime path only; do not introduce long-lived dual JSON and binary readers.

Execution order:
1. Reconcile the serialization plan with current code and identify the first concrete Phase A parser target.
2. Replace dynamic privileged parsing with typed bounded parsing.
3. Then move helper IPC toward the hardened framed path.
4. Add malformed-frame, truncated-payload, unknown-version, oversize-payload, and trailing-byte rejection tests.
5. Update the doc after each verified phase slice.

Security rules:
- no dynamic Value on privileged paths
- no indefinite compatibility runtime fallback
- explicit versioning, decode limits, and fail-closed parsing
- no hidden parser ambiguity

Verification requirements:
- targeted helper IPC tests for malformed, truncated, unknown-version, oversize, and trailing-byte cases
- targeted tests for any privileged or trust-adjacent parser you harden
- ./scripts/ci/phase10_gates.sh or ./scripts/ci/membership_gates.sh if your parser changes affect those paths
- dry runs of helper client or daemon interaction if available

Required documentation behavior:
- update the serialization plan with exactly which phase slices are done
- record changed files, verification commands, artifacts, residual risk, and blockers
- do not mark later phases as started if you stayed within Phase A/B

Definition of done:
- Phase A or B work you touched is genuinely hardened, typed, bounded, and tested
- no long-lived JSON runtime fallback was introduced
- the document clearly states what was completed and what remains
```
