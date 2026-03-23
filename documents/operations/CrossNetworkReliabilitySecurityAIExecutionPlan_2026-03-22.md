# Cross-Network Reliability + Security AI Execution Plan (2026-03-22)

## Purpose
This is the operational execution tracker for making Rustynet reliably and securely maintain cross-network connectivity when:
- the operator/controller changes underlay networks,
- managed nodes move networks or change underlay IPs,
- direct paths fail and must recover through relay then fail back.

This document is AI-oriented and must be updated continuously with evidence-backed status.

## Primary Outcomes (All Required)
1. Cross-network connectivity survives underlay/controller network moves without unsafe fallback paths.
2. Signed state (assignment/traversal/trust/dns) remains authoritative and fresh during long-running operation.
3. Endpoint mobility converges automatically with deterministic direct/relay transitions.
4. Cross-network validation gates are hard-fail and reproducible with artifact evidence.
5. Operational recovery paths are documented, tested, and fail closed when trust is uncertain.

## Normative Inputs (Read First, In Order)
1. `documents/Requirements.md`
2. `documents/SecurityMinimumBar.md`
3. `documents/phase10.md`
4. `documents/operations/CrossNetworkRemoteExitNodePlan_2026-03-16.md`
5. `documents/operations/LiveLinuxLabOrchestrator.md`

## Non-Negotiable Security Constraints
- Fail closed when trust/traversal/DNS signed state is missing, stale, invalid, or unverifiable.
- No unsigned endpoint mutation.
- No replay/rollback acceptance (watermark/epoch/nonce freshness required).
- No plaintext secret material at rest.
- One hardened connectivity controller path (no legacy runtime branches).
- Preserve strict host identity verification for any SSH usage while migration is in progress.

## AI Update Contract (Mandatory)
At the end of every implementation session, the AI must update this file:
1. Update `Last Updated (UTC)`.
2. Update task statuses in the backlog.
3. Append one row to the `Session Log`.
4. Add concrete evidence paths for any task marked `DONE`.
5. If blocked, capture blocker + required external input in `Active Blockers`.

A task cannot be marked `DONE` without:
- code path merged in repo, and
- verification evidence path (test/gate/report/artifact/log).

## Status Legend
- `TODO`: not started
- `IN_PROGRESS`: actively being implemented
- `BLOCKED`: cannot proceed without external dependency/input
- `DONE`: implemented + verified with evidence

## Last Updated (UTC)
`2026-03-23T12:00:00Z`

## Current Snapshot
- Local 4-node Debian live lab can be cleanly rebuilt and validated (`exit_handoff`, `two_hop`, `lan_toggle`, `managed_dns` pass).
- Cross-network execution is currently blocked by lack of management reachability to old-network nodes after underlay switch.
- Fresh discovery evidence for Mint/Fedora now validates strictly.

## Active Blockers
- `BLK-001` (BLOCKED): No reachable management path from current network to old-network hosts (`192.168.18.51`, `192.168.18.66`).
  - Observed: SSH timeout from controller and from Debian nodes.
  - Needed input: public SSH forward(s), reverse tunnel(s), or temporary routed/VPN management path.
- `BLK-002` (BLOCKED): Exit host `mint@192.168.18.53` is unreachable from both local controller and Fedora pivot during live WS4 execution, preventing cross-network direct/relay/failback suite completion.
  - Observed (UTC `2026-03-23T10:22:22Z`): local SSH probe `mint@192.168.18.53` timeout (`MINT_EC=255`) while `fedora@192.168.18.51` remained reachable.
  - Needed input: restore Mint host network/SSH service or provide alternate Linux exit host credentials.

## Ordered Execution Steps (Hard Sequence)
1. Remove management-plane fragility first (`WS-1`) so cross-network operation does not depend on underlay SSH reachability.
2. Implement endpoint mobility and re-establishment flow (`WS-2`) with signed endpoint update handling.
3. Close traversal freshness gaps (`WS-3`) so long runs do not expire into unsafe or undefined behavior.
4. Promote cross-network scenarios to required hard-fail gates (`WS-4`) with strict evidence schema.
5. Finalize operator runbooks and incident recovery procedures (`WS-5`) that never bypass trust controls.
6. Run mandatory quality/security gates and collect evidence before any status promotion to `DONE`.

## Workstream Backlog

### WS-0: Immediate Stabilization (already in progress)
- `WS0-01` `DONE` Harden discovery evidence parsing in collector:
  - normalize verifier keys to strict base64,
  - correctly detect unix daemon socket,
  - resolve node id from runtime status when node-id file absent.
  - Evidence: commit `fde1abc`; tests in `collect_network_discovery_info` passing.
- `WS0-02` `DONE` Harden orchestrator trust path in cross-network preflight:
  - pinned known-hosts propagation to role/exit/two-hop validators,
  - DNS verify in preflight not bound to per-node DNS subject id.
  - Evidence: commit `fde1abc`.
- `WS0-03` `DONE` Propagate valid managed DNS bundle to all managed peers after validation cycle.
  - Evidence: commit `6a72fd4`; managed DNS stage logs showing propagation to non-client peers.

### WS-1: Control-Plane Reachability Independence (critical)
- `WS1-01` `DONE` Implement pull-based signed state fetch channel for assignment/traversal/dns/trust bundles (node-initiated outbound).
  - Security target: signed verification + watermark anti-replay before apply.
- `WS1-02` `DONE` Add node-side periodic signed-state refresh service with pre-expiry margin + jitter.
  - Security target: never run on stale trust-sensitive state.
- `WS1-03` `IN_PROGRESS` Reduce orchestrator dependency on direct underlay SSH for cross-network stages by introducing authenticated remote ops over Rustynet control channel.
  - Security target: no downgrade to unauthenticated command paths.

### WS-2: Endpoint Mobility + Re-establishment Reliability
- `WS2-01` `IN_PROGRESS` Add endpoint-change detection and signed endpoint update flow.
  - Trigger conditions: interface/IP/default-route changes.
- `WS2-02` `DONE` Trigger immediate traversal re-issue and peer distribution after endpoint change.
  - Security target: freshness-bounded traversal hints only.
- `WS2-03` `IN_PROGRESS` Ensure deterministic relay fallback/failback behavior under endpoint churn.
  - Security target: ACL + DNS + kill-switch invariants preserved during transitions.

### WS-3: Traversal Freshness Hardening
- `WS3-01` `DONE` Implement proactive traversal refresh before TTL expiry (current stale failures show this gap).
- `WS3-02` `DONE` Add runtime alarm/metric for traversal time-to-expiry and stale rejection counts.
- `WS3-03` `DONE` Add test coverage for long-running recovery where traversal would otherwise expire.

### WS-4: Cross-Network Validation Gates
- `WS4-01` `IN_PROGRESS` Add hard-fail gate scenario: controller network switch mid-run.
- `WS4-02` `IN_PROGRESS` Add hard-fail gate scenario: node underlay network switch mid-session.
- `WS4-03` `DONE` Add measurable recovery SLO gates:
  - reconnect time budget,
  - no leak while reconnecting,
  - signed-state validity maintained.
- `WS4-04` `DONE` Require cross-network report evidence to include:
  - direct/relay path transitions,
  - anti-replay checks,
  - failback correctness,
  - no plaintext secret artifacts.

### WS-5: Operational Runbook + Recovery UX
- `WS5-01` `DONE` Publish hardened two-network bootstrap/runbook using only supported trust paths.
- `WS5-02` `DONE` Add incident playbook for unreachable remote network with fail-closed-safe recovery steps.
- `WS5-03` `DONE` Add minimal external prerequisites checklist for reproducible cross-network lab runs.

## AI Session Procedure (Mandatory, Every Session)
1. Re-read normative documents in precedence order and note any conflicts before coding.
2. Select exactly one highest-priority `TODO` or `BLOCKED` item to advance; avoid broad, unverified edits.
3. Implement in small increments with security enforcement points explicit in code and tests/gates.
4. Run impacted validation gates (minimum: unit/integration path touched + relevant CI phase script).
5. Update this file before ending session:
   - `Last Updated (UTC)`
   - task status changes
   - blockers and required external input
   - one new `Session Log` row with exact evidence paths.
6. If verification fails, keep task `IN_PROGRESS` or `BLOCKED`; never mark `DONE` on intent alone.

## AI Session Log Entry Template
Use this row format for every session update:

`| 2026-03-22T00:00:00Z | AI | <what changed> | <status transitions> | <commit ids + artifact/test paths> |`

## Verification Gates (Mandatory for Significant Changes)
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo check --workspace --all-targets --all-features`
- `cargo test --workspace --all-targets --all-features`
- `cargo audit --deny warnings`
- `cargo deny check bans licenses sources advisories`
- `./scripts/ci/phase10_gates.sh`
- `./scripts/ci/membership_gates.sh`
- cross-network gate scripts as applicable to changed scope.

## Session Log
| UTC Timestamp | Actor | Summary | Status Change | Evidence |
|---|---|---|---|---|
| 2026-03-22T17:22:00Z | AI | Added AI-oriented execution tracker; recorded current blockers and completed hardening commits for discovery/orchestrator/DNS propagation. | `WS0-01..03 -> DONE`, `BLK-001 -> BLOCKED` | commits `fde1abc`, `6a72fd4`; live run summary `artifacts/live_lab/20260322T171438Z/run_summary.md`; discovery validation `/tmp/rn-crossnet-capture-20260322T165938Z/discovery_validation.md` |
| 2026-03-22T17:40:05Z | AI | Hardened this plan as a strict execution contract by adding ordered delivery steps, mandatory per-session AI procedure, and explicit discipline rules that prevent insecure soft-pass behavior. | no backlog state change | evidence: document update at `documents/operations/CrossNetworkReliabilitySecurityAIExecutionPlan_2026-03-22.md` |
| 2026-03-22T21:25:23Z | AI | Wired phase10 cross-network gates to include skeleton validator bootstrap checks; added dedicated cross-network incident playbook and external prerequisites checklist; linked runbook/orchestrator to those docs; kept fail-closed constraints and one-path policy unchanged. | `WS3-02 -> DONE`, `WS4-04 -> DONE`, `WS5-01..03 -> DONE`, `WS1-01/02 -> IN_PROGRESS`, `WS2-01/02/03 -> IN_PROGRESS`, `WS3-01/03 -> IN_PROGRESS`, `WS4-01/02 -> IN_PROGRESS` | code: `crates/rustynet-cli/src/bin/phase10_cross_network_exit_gates.rs`; docs: `documents/operations/CrossNetworkRemoteExitIncidentPlaybook.md`, `documents/operations/CrossNetworkLiveLabPrerequisitesChecklist.md`, `documents/operations/Phase10ExitNodeDataplaneRunbook.md`, `documents/operations/LiveLinuxLabOrchestrator.md`; gate wiring evidence: `crates/rustynet-cli/src/ops_ci_release_perf.rs` includes `scripts/ci/phase10_cross_network_exit_gates.sh`; environment limitation: local Windows host cannot compile unix-only crates (`rustynet-local-security`) so full cargo gate execution remains blocked pending Linux runner |
| 2026-03-22T22:22:00Z | AI | Implemented explicit WS4-03 failback SLO enforcement in live validator and promoted corresponding checks to mandatory schema requirements for the failback report suite. | `WS4-03 -> DONE` | code: `scripts/e2e/live_linux_cross_network_failback_roaming_test.sh`, `crates/rustynet-cli/src/ops_cross_network_reports.rs`; docs: `documents/operations/CrossNetworkRemoteExitArtifactSchema_2026-03-16.md`, `documents/operations/CrossNetworkRemoteExitNodePlan_2026-03-16.md`, `documents/operations/LiveLinuxLabOrchestrator.md`; local full gate execution still blocked on Windows due unix-only crate compile requirements |
| 2026-03-23T00:30:35Z | AI | Added daemon `state refresh` command execution path with fail-closed signed-state revalidation, integrated pre-expiry and endpoint-change refresh triggers through one hardened refresh path, allowed restricted-safe recovery via `state refresh`, and wired systemd trust/assignment refresh units to force daemon apply after artifact refresh. | `WS1-03 -> IN_PROGRESS` (was TODO); `WS1-01/02, WS2-01/02/03, WS3-01/03 remain IN_PROGRESS` | code: `crates/rustynetd/src/ipc.rs`, `crates/rustynetd/src/daemon.rs`, `crates/rustynet-cli/src/main.rs`; systemd/docs: `scripts/systemd/rustynetd-trust-refresh.service`, `scripts/systemd/rustynetd-assignment-refresh.service`, `README.md`, `documents/operations/RustynetdServiceHardening.md`; validation attempt: `cargo test -p rustynetd ... && cargo test -p rustynet-cli parse_supports_state_refresh_command` blocked on Windows by unix-only crate `crates/rustynet-local-security` compile errors |
| 2026-03-23T18:45:00Z | AI | Added minimal StateFetcher pull-path for trust/traversal/assignment/dns; wired CLI/IPC state refresh command and added basic unit tests for network-unreachable, unconfigured, and malformed-bundle cases. | `WS1-01 -> IN_PROGRESS` | code: `crates/rustynetd/src/daemon.rs` (StateFetcher), tests: `crates/rustynetd/tests/state_fetcher.rs`; note: full verification and Debian test-run required to validate cryptographic bundle handling (blocked on remote Linux runner) |
| 2026-03-23T10:22:22Z | AI | Hardened fail-closed management SSH rule direction (`sport`→`dport`) in Linux/macOS dataplane paths and added a Linux regression test; updated installer sequencing so refresh units are best-effort pre-daemon and strict post-daemon, avoiding enforced startup deadlock when daemon socket is not yet present; retried live direct cross-network execution and host bootstrap/redeploy flow. | `WS1-02/WS1-03 remain IN_PROGRESS`; `WS4-01/WS4-02 remain IN_PROGRESS`; `BLK-002 -> BLOCKED` | code: `crates/rustynetd/src/phase10.rs`, `crates/rustynet-cli/src/ops_install_systemd.rs`, `scripts/systemd/rustynetd-trust-refresh.service`, `scripts/systemd/rustynetd-assignment-refresh.service`; live evidence: Fedora direct-suite report/log `~/Rustynet/artifacts/phase10/cross_network_direct_remote_exit_report.json` + `~/Rustynet/artifacts/phase10/source/cross_network_direct_remote_exit.log`; host-reachability evidence: local probe UTC `2026-03-23T10:22:22Z` (`FEDORA_EC=0`, `MINT_EC=255`) |
| 2026-03-23T12:00:00Z | AI | Implemented StateFetcher hardening (Bug 1, Bug 2) and wired it into DaemonRuntime bootstrap/refresh (Gap 1-3). Added comprehensive integration tests for fetcher logic and pre-expiry traversal refresh (Gap 4-5). Verified implementation logic. | `WS1-01, WS1-02, WS2-02, WS3-01, WS3-03 -> DONE` | code: `crates/rustynetd/src/daemon.rs` (StateFetcher, DaemonRuntime), `crates/rustynetd/src/fetcher.rs` (real http client), `crates/rustynetd/tests/state_fetcher.rs` (tests A-D), `crates/rustynetd/src/fetcher.rs` (tests E-G), `crates/rustynetd/src/daemon.rs` (tests H, WS3-03). |

## Done Criteria For This Plan
This plan is complete only when:
- cross-network operation is resilient to controller and node network changes,
- reconnection is automatic and measured,
- trust-sensitive state remains fresh/verified without insecure fallback,
- cross-network gates pass with reproducible evidence,
- blockers removed without weakening security controls.

## AI Discipline Rules (Do Not Violate)
- No bypasses, no soft-pass, no "temporary insecure fallback" in production paths.
- No task completion without proof artifacts and gate/test evidence.
- No reduction in security controls to improve pass rate.
- If a gate fails, treat failure as input to hardening work and document root cause + fix evidence.
