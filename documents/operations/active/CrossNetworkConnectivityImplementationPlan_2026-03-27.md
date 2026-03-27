# Rustynet Cross-Network Connectivity Implementation Plan (2026-03-27)
**Last Updated:** 2026-03-27T11:15:00Z

## AI Implementation Prompt

```text
You are the implementation agent for the remaining work in this document.
Repository root: .
All paths in this document are repo-root-relative. Do not rewrite them as machine-absolute paths.

Mission:
Implement the missing RustyNet code required for secure cross-network communication between nodes on different networks. Complete the work in one uninterrupted execution if feasible. Security is the top priority. Do not stop at planning if you can still write, test, verify, and document code safely.

Mandatory reading order:
1. AGENTS.md
2. CLAUDE.md
3. README.md
4. documents/Requirements.md
5. documents/SecurityMinimumBar.md
6. documents/phase10.md
7. documents/operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md
8. documents/operations/active/UdpHolePunchingImplementationBlueprint_2026-03-07.md
9. documents/operations/active/CrossNetworkRemoteExitNodePlan_2026-03-16.md
10. This document
11. The code you touch

Non-negotiables:
- Keep one hardened execution path per security-sensitive workflow.
- Fail closed on missing, stale, invalid, replayed, or unauthorized state.
- Do not add legacy branches, insecure fallback modes, or "temporary" bypasses.
- Do not weaken tests or gates to make results pass.
- Do not mark work complete until code, tests, and evidence exist.
- Keep all status reporting honest. A programmed path is not the same thing as a live path.

Document-specific execution order:
1. First fix fresh-install sequencing if it is still wrong:
   - inspect crates/rustynet-cli/src/ops_install_systemd.rs
   - if rustynetd is started before signed assignment/trust priming when refresh services are configured, fix that before any other cross-network work
   - the secure requirement is: signed refresh artifacts are seeded before first daemon activation when those refresh paths are enabled
2. Harden path-state truthfulness:
   - split "programmed/configured" from "live/proven" for direct and relay paths
   - rustynet status and rustynet netcheck must not report relay-active or direct-active without fresh liveness proof
3. Finish the usable relay-first cross-network path:
   - relay candidates must resolve to reachable relay infrastructure, not peer-private addresses
   - relay session establishment, token refresh, and runtime liveness must be fully enforced before the path is considered live
   - fix the retained-relay periodic reprobe/failback regression
4. Finish public candidate acquisition and publication:
   - gather host, srflx, and relay candidates
   - refresh signed traversal inputs on startup, network change, pre-expiry, and path change
   - do not treat foreign-network RFC1918 host candidates as acceptable remote-exit transport proof
5. Finish real WAN simultaneous-open:
   - direct path claims require coordinated simultaneous-open behavior and fresh backend handshake proof
   - no claim of cross-network direct success is allowed from a one-sided programmed endpoint alone
6. Finish managed DNS correctness for remote-exit operation:
   - stale signed DNS-zone state must remain fail-closed
   - full remote-exit readiness requires a deterministic signed DNS-zone refresh/install path, not hope that stale state will self-heal
7. Finish gates and evidence:
   - update cross-network reports, validators, and phase10 gates so they hard-fail on "configured but not live" states
   - generate or validate the six canonical cross-network reports named in this document

Exact output requirements:
- Updated Rust code
- Updated gates/tests
- Updated this document with completion status and evidence
- No unresolved TODO/FIXME placeholders for in-scope deliverables

Scope-specific validation:
- cargo fmt --all -- --check
- cargo clippy --workspace --all-targets --all-features -- -D warnings
- cargo check --workspace --all-targets --all-features
- cargo test --workspace --all-targets --all-features
- cargo audit --deny warnings
- cargo deny check bans licenses sources advisories
- ./scripts/ci/phase10_gates.sh
- ./scripts/ci/membership_gates.sh
- ./scripts/ci/phase10_hp2_gates.sh
- targeted rustynetd, rustynet-relay, rustynet-control, backend, and cross-network report tests for touched code
- live cross-network validation if the environment exists

If a command or gate fails:
1. stop forward progress,
2. fix the root cause,
3. rerun the impacted tests and gates,
4. record the result in this document.

Definition of done for this document:
- Fresh install no longer produces avoidable daemon bootstrap failure when signed refresh services are configured.
- rustynet status / rustynet netcheck distinguish programmed path from live path honestly.
- relay path can become live across networks with authenticated relay sessions and measured liveness proof.
- direct path can become live across networks only when simultaneous-open plus fresh backend handshake evidence succeeds.
- cross-network reports and gates fail closed on unproven path states.
- the six canonical cross-network reports validate successfully when live evidence exists.
- no insecure fallback endpoint mutation path exists anywhere in active runtime.

If live cross-network hardware is unavailable, still finish all code, local tests, and gate work you can complete, then mark the exact remaining live evidence step as blocked with the missing prerequisite.
```

## Current Open Work

`Open scope`
- Fresh-install sequencing can still produce an avoidable first-daemon-start failure if signed refresh ordering is wrong.
- Current runtime can report `path_mode=relay_active path_reason=relay_endpoint_programmed` even when the path is not proven live.
- Current live evidence shows valid signed state but no real cross-network dataplane proof:
  - `srflx_candidates=0`
  - `wg latest-handshakes=0`
  - remote endpoint still private
- Managed DNS can remain fail-closed due to stale signed DNS-zone state during otherwise healthy daemon runtime.
- The six canonical cross-network reports still need to fail on unproven paths and pass only on measured proof.

`Do first`
- Fix any remaining fresh-install sequencing bug in `crates/rustynet-cli/src/ops_install_systemd.rs`.
- Then make runtime path-state reporting honest before touching the user-facing cross-network claim surface.

`Completion proof`
- Cross-network relay path becomes live with authenticated relay-session proof and fresh backend handshake evidence.
- Cross-network direct path becomes live only after real simultaneous-open success and fresh backend handshake evidence.
- `rustynet status` and `rustynet netcheck` expose both programmed state and live/proven state.
- Phase 10 cross-network reports validate only measured live proof.

`Do not do`
- Do not claim "connect from anywhere" until direct or relay live evidence exists.
- Do not use manual router port forwarding as the correctness path.
- Do not classify a foreign-network RFC1918 endpoint as a valid remote cross-network path.
- Do not add endpoint mutation code that bypasses signed traversal verification.

`Clarity note`
- This document is narrower and more execution-focused than the broader traversal and remote-exit plans. If those broader documents contain optimistic status that conflicts with current code or evidence, follow the stricter interpretation in this document and then update the broader document honestly.

## 1. Objective

Deliver secure cross-network communication for RustyNet so that:
- a node on network A can securely reach or use an authorized node on network B,
- relay transport works when direct path is unavailable,
- direct path works only when simultaneous-open and fresh handshake evidence prove it,
- DNS and routing remain fail-closed,
- user-visible status and gates describe what is actually live, not just what is configured.

## 2. Evidence-Based Current State

The current repository and live Fedora diagnostics show:

1. Signed control state is healthy.
- `assignment verify` passes.
- `traversal verify` passes.
- `rustynetd` can run after forced refresh.

2. Cross-network transport is not yet proven.
- The reported path can be `relay_active` while the live handshake remains zero.
- The current `path_reason` can be `relay_endpoint_programmed`, which is a configured-state signal, not a live-state signal.
- Current relay/direct proof is therefore too optimistic for cross-network readiness.

3. Public candidate acquisition is not yet sufficient in practice.
- Live evidence showed `srflx_candidates=0`.
- Without a valid public reflexive or reachable relay path, a node cannot traverse between unrelated LANs securely.

4. Managed DNS is still correctly fail-closed when stale.
- This is the right security behavior.
- It is not sufficient for remote-exit readiness because it leaves managed names unavailable until a fresh signed DNS-zone bundle is installed.

5. Fresh-install ordering needs to be correct.
- A first install must not start the daemon before required signed state is primed if the refresh services are configured to provide that state.
- Avoidable startup failure is not acceptable in a hardened default path.

## 3. Security Constraints That Must Stay True

These constraints are mandatory while implementing this work:

1. Signed traversal authority remains the only source of endpoint mutation.
2. Missing, stale, tampered, replayed, or wrong-signer traversal or DNS artifacts must fail closed.
3. Relay remains ciphertext-only and token-scoped.
4. Default-deny ACL, leak prevention, kill-switch, and DNS fail-close must remain intact across every path transition.
5. Status and gates must never claim success from configuration state alone.
6. No legacy endpoint mutation path may be reintroduced.

## 4. Exact Code Work Required

### 4.1 Fresh-Install Sequencing Hardening

**Files**
- `crates/rustynet-cli/src/ops_install_systemd.rs`
- `scripts/systemd/rustynetd-assignment-refresh.service`
- `scripts/systemd/rustynetd-trust-refresh.service`

**Required behavior**
- If assignment or trust auto-refresh is enabled, the install path must seed those signed artifacts before the first daemon activation.
- Post-refresh daemon state refresh must remain socket-aware and fail closed when appropriate.
- Do not treat refresh-service failure as best-effort success during initial secure bring-up.

**Done means**
- A fresh install no longer produces an avoidable first-daemon-start failure caused by missing primed signed artifacts.
- Installer tests assert the correct ordering.

### 4.2 Honest Runtime Path-State Semantics

**Files**
- `crates/rustynetd/src/daemon.rs`
- `crates/rustynetd/src/phase10.rs`
- `crates/rustynet-backend-api/src/lib.rs`
- `crates/rustynet-backend-wireguard/src/lib.rs`

**Required behavior**
- Separate configured/programmed path state from live/proven path state.
- `rustynet status` and `rustynet netcheck` must expose enough fields to tell:
  - configured direct path
  - configured relay path
  - live direct path
  - live relay path
  - last fresh handshake evidence
  - relay-session live state and expiry when applicable
- A relay path is not live just because the controller path is `Relay`.
- A direct path is not live just because an endpoint was programmed.
- Live path claims require fresh backend handshake evidence or an equally strong runtime liveness proof.

**Minimum acceptance**
- Current optimistic output such as `path_mode=relay_active path_reason=relay_endpoint_programmed` is replaced or extended so the output cannot be misread as live proof.
- Existing tests are updated so unproven states fail gates.

### 4.3 Relay-First Cross-Network Usability

**Files**
- `crates/rustynetd/src/relay_client.rs`
- `crates/rustynetd/src/daemon.rs`
- `crates/rustynetd/src/phase10.rs`
- `crates/rustynet-relay/src/transport.rs`
- `crates/rustynet-control/src/lib.rs`

**Required behavior**
- Relay candidates used for cross-network paths must resolve to actual relay infrastructure, not peer-private addresses.
- Relay session establishment must be mandatory before the relay path is treated as available.
- Relay token expiry refresh must update sessions without reopening any unsigned endpoint-mutation path.
- Retained-relay periodic reprobe must be able to recover direct when fresh direct handshake evidence appears.
- Relay failure must fail closed, not silently degrade to an untrusted path.

**Done means**
- Cross-network relay path can be selected, established, refreshed, and reported as live only when the authenticated relay session exists and traffic proof is present.
- The retained-relay failback regression is fixed with tests.

### 4.4 Public Candidate Acquisition And Signed Traversal Inputs

**Files**
- `crates/rustynetd/src/traversal.rs`
- `crates/rustynetd/src/daemon.rs`
- `crates/rustynet-control/src/lib.rs`

**Required behavior**
- Gather host, server-reflexive (`srflx`), and relay candidates.
- Keep candidate validation strict:
  - bounded count
  - bounded size
  - type allowlist
  - no duplicate tuples
  - no invalid special addresses
- Refresh candidate publication on:
  - startup
  - underlay IP change
  - traversal pre-expiry
  - relay/direct transition events
- Signed traversal bundles must contain the actual candidate set needed for cross-network decision-making.
- Do not treat a peer RFC1918 host candidate on a foreign network as sufficient cross-network path proof.

**Done means**
- Live candidate gathering can produce non-empty `srflx` or relay candidates when the environment allows.
- Signed traversal input refresh is deterministic and tied to runtime state changes.

### 4.5 Real WAN Simultaneous-Open

**Files**
- `crates/rustynetd/src/traversal.rs`
- `crates/rustynetd/src/daemon.rs`
- `crates/rustynet-backend-api/src/lib.rs`
- `crates/rustynet-backend-wireguard/src/lib.rs`

**Required behavior**
- Direct cross-network path establishment must use coordinated simultaneous-open behavior, not a one-sided optimistic probe model.
- The implementation must preserve all traversal signature, replay, freshness, and policy checks before any backend endpoint mutation.
- Direct path success must require fresh backend handshake proof.

**Done means**
- A direct cross-network path is only reported as live after simultaneous-open and fresh handshake evidence succeed.
- Negative tests prove that unsigned, replayed, stale, or tampered traversal inputs cannot trigger endpoint mutation.

### 4.6 Managed DNS Readiness For Remote Exit

**Files**
- `crates/rustynetd/src/daemon.rs`
- `crates/rustynet-cli/src/main.rs`
- `crates/rustynet-cli/src/ops_install_systemd.rs`
- `scripts/systemd/rustynetd-managed-dns.service`
- any new DNS refresh unit or helper added by the agent

**Required behavior**
- Stale signed DNS-zone state remains fail-closed.
- Full remote-exit readiness must include a deterministic signed DNS-zone refresh/install path.
- The runtime must not imply that trust/assignment refresh automatically fixes stale DNS-zone state unless a real DNS-zone refresh path exists in code.

**Done means**
- Managed DNS for remote-exit operation is either:
  - refreshed automatically through a real signed path, or
  - explicitly and honestly left blocked with the exact missing prerequisite.

### 4.7 Cross-Network Reports, Validators, And Gates

**Files**
- `crates/rustynet-cli/src/ops_cross_network_reports.rs`
- `crates/rustynet-cli/src/bin/phase10_cross_network_exit_gates.rs`
- `crates/rustynet-cli/src/bin/phase10_gates.rs`
- `scripts/e2e/live_linux_lab_orchestrator.sh`
- any touched live validator binaries under `crates/rustynet-cli/src/bin/`

**Canonical report files that must remain authoritative**
- `artifacts/phase10/cross_network_direct_remote_exit_report.json`
- `artifacts/phase10/cross_network_relay_remote_exit_report.json`
- `artifacts/phase10/cross_network_failback_roaming_report.json`
- `artifacts/phase10/cross_network_traversal_adversarial_report.json`
- `artifacts/phase10/cross_network_remote_exit_dns_report.json`
- `artifacts/phase10/cross_network_remote_exit_soak_report.json`

**Required behavior**
- Validators must hard-fail if a report claims success while the new live/proven path fields indicate only configured state.
- Reports must carry measured evidence tied to the current commit.
- Phase 10 readiness must reject missing, stale, invalid, or overly optimistic cross-network evidence.

**Done means**
- The report schema and gates enforce live proof rather than configuration proof.
- Existing placeholder success paths are removed.

## 5. Exact Acceptance Criteria

The work in this document is not complete unless all of the following are true:

1. Fresh install
- first-daemon-start ordering is correct when assignment/trust refresh is configured
- no avoidable bootstrap failure remains in the hardened install path

2. Status truthfulness
- `rustynet status` and `rustynet netcheck` distinguish programmed vs live path
- no direct or relay path is labeled live without proof

3. Relay cross-network operation
- relay session is authenticated, refreshed, and measured live
- relay failure stays fail-closed

4. Direct cross-network operation
- simultaneous-open is real
- direct success requires fresh backend handshake evidence

5. DNS correctness
- stale DNS-zone state remains fail-closed
- remote-exit DNS readiness has a real signed refresh/install path or an explicit documented blocker

6. Gate integrity
- cross-network reports fail on optimistic/unproven state
- the six canonical reports validate only on measured proof

## 6. Required Tests And Commands

Run these for substantial completion of this scope:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo audit --deny warnings
cargo deny check bans licenses sources advisories
./scripts/ci/phase10_hp2_gates.sh
./scripts/ci/phase10_gates.sh
./scripts/ci/membership_gates.sh
```

Run targeted tests for every touched slice. At minimum, that means:

```bash
cargo test -p rustynetd
cargo test -p rustynet-relay
cargo test -p rustynet-control
cargo test -p rustynet-backend-wireguard
cargo test -p rustynet-cli --bin phase10_cross_network_exit_gates
cargo test -p rustynet-cli --bin rustynet-cli
```

If live cross-network hardware exists, also run the relevant live validators and cross-network report generation/verification path. If live hardware does not exist, do not fake success; record the blocker.

## 7. Agent Output Requirements

When the agent updates this document, it must include:

- `Changed files:` exact repo-root-relative paths
- `Verification:` exact commands run
- `Artifacts:` exact repo-root-relative artifact paths, if any
- `Residual risk:` what remains
- `Blocker / prerequisite:` only when truly blocked

## 8. Definition Of Done

This document is complete only when all are true:

- the fresh-install sequencing bug is fixed or verified absent
- runtime status and netcheck are honest about configured vs live path state
- relay path is truly usable across networks with authenticated sessions and liveness proof
- direct path is truly usable across networks only when simultaneous-open and fresh handshake proof succeed
- DNS remains fail-closed and remote-exit DNS has a real signed refresh/install story
- phase10 cross-network evidence rejects optimistic claims and validates only measured proof
- no insecure fallback path was added to achieve any of the above

## 9. Session Log

### 2026-03-27T11:15:00Z
- Document created to give a single AI agent an explicit, execution-ready cross-network connectivity scope.
- Basis for this document:
  - current repo state
  - current traversal and relay plans
  - live Fedora diagnostics showing signed-state health but no real cross-network handshake proof
  - fresh-install sequencing issue observed during secure redeploy work

## Agent Update Rules

1. Update this document immediately after each materially completed slice.
2. Mark items complete only after code and verification exist.
3. Keep all paths repo-root-relative.
4. Do not record optimistic status that is not backed by code and evidence.
5. If live validation is unavailable, say so explicitly and stop at the real blocker.
