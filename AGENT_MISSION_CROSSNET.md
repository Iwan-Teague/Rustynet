# Rustynet Cross-Network Mission — AI Agent Execution Prompt

## MISSION STATEMENT

You are executing the final completion sprint for Rustynet Phase 10 cross-network remote exit capabilities. Your job is to implement all remaining IN_PROGRESS workstream items, run all mandatory CI and security gates on real Linux hardware, generate verifiable evidence artifacts, and update the project execution tracker. You must do this entirely in one session, implementing and testing as you go.

**CRITICAL**: You are running on a Linux machine or have access to Linux machines. This project has unix-only crates (`rustynet-local-security`) that CANNOT compile on Windows. All cargo commands and live tests MUST be run on Linux. Two lab machines are available via SSH.

---

## LAB MACHINES

| Role | SSH Target | Password (ssh + sudo) |
|------|-----------|----------------------|
| Device 1 (Debian) | `debian@192.168.18.51` | `tempo` |
| Device 2 (Mint/Ubuntu-based) | `mint@192.168.18.53` | `tempo` |

**IMPORTANT CONSTRAINT**: Both lab machines are on the SAME physical LAN (`192.168.18.0/24`). True cross-network isolation requires network namespace simulation. You MUST use Linux network namespaces (ip netns) to create isolated virtual networks on one or both hosts so that cross-network tests are topologically distinct. Specifically:
- Create a network namespace on one host (e.g., the Debian host) that routes through a different virtual subnet
- Use IP aliasing on different interfaces to create distinct `network_id` labels that prove topology isolation
- The `classify-cross-network-topology` CLI command determines if two IPs are distinct-network; if running on same-subnet hosts, you may need to use virtual interfaces (veth pairs + netns) to create genuinely distinct IP spaces

**Password entry for sudo**: Use `echo "tempo" | sudo -S <cmd>` or configure passwordless sudo via `echo "debian ALL=(ALL) NOPASSWD:ALL" | sudo -S tee /etc/sudoers.d/rustynet-ci` on each host.

---

## PRIMARY REFERENCE DOCUMENTS — READ THESE FIRST IN ORDER

Before writing any code, read these documents from the repository:

1. `documents/Requirements.md`
2. `documents/SecurityMinimumBar.md`
3. `documents/phase10.md`
4. `documents/operations/CrossNetworkRemoteExitNodePlan_2026-03-16.md`
5. `documents/operations/CrossNetworkReliabilitySecurityAIExecutionPlan_2026-03-22.md`
6. `documents/operations/LiveLinuxLabOrchestrator.md`
7. `documents/operations/CrossNetworkRemoteExitArtifactSchema_2026-03-16.md`

**Precedence rule**: If documents conflict, choose the strictest secure interpretation.

---

## NON-NEGOTIABLE SECURITY CONSTRAINTS (NEVER VIOLATE)

1. **Fail-closed always**: Any missing/stale/invalid/unverifiable trust/traversal/DNS signed state → deny connection, never permit with degraded security
2. **No unsigned endpoint mutation**: Endpoint updates require verified signed traversal bundles with nonce/freshness check
3. **No replay/rollback**: Watermark/epoch/nonce freshness required at every state boundary
4. **No plaintext secrets at rest**: Keys encrypted at rest, systemd credentials for passphrases
5. **One hardened path**: EXACTLY ONE implementation path for each security-sensitive operation. No `if legacy_mode`, no `try_secure.or_else(insecure_fallback)`, no feature flags on security controls
6. **No task marked DONE without proof**: Every completed item needs: (a) code path in repo, (b) test/gate/artifact evidence path
7. **No bypasses, no soft-passes, no temporary insecure fallbacks** — ever
8. **`#![forbid(unsafe_code)]`** must remain on all crates

---

## FLEET STRATEGY — USE PARALLEL SUBAGENTS

Launch independent workstreams in parallel using the Task/fleet capability. After reading the normative documents, divide work as follows:

### Fleet Agent A — WS-1: Control-Plane Reachability Independence
Responsible for implementing daemon-side pull-based signed state refresh so the daemon does not depend on underlay SSH reachability from the operator.

Items:
- **WS1-01**: Implement pull-based signed state fetch channel in `rustynetd` for assignment/traversal/DNS/trust bundles. The node initiates outbound fetch; verifies signatures + watermark anti-replay before applying. No unauthenticated fetch path.
- **WS1-02**: Add node-side periodic signed-state refresh service with pre-expiry margin + jitter. Wire into the systemd timer units already stubbed at `scripts/systemd/rustynetd-trust-refresh.service` and `scripts/systemd/rustynetd-assignment-refresh.service`. The daemon must NEVER run on stale trust-sensitive state.
- **WS1-03**: Fully wire the `state refresh` IPC command (daemon already has skeleton in `crates/rustynetd/src/daemon.rs` and `crates/rustynetd/src/ipc.rs`) so that authenticated remote ops can trigger a signed-state refresh over the Rustynet control channel. Security target: no downgrade to unauthenticated command paths.

Code files to examine and modify:
- `crates/rustynetd/src/daemon.rs`
- `crates/rustynetd/src/ipc.rs`
- `crates/rustynetd/src/phase10.rs`
- `crates/rustynetd/src/traversal.rs`
- `crates/rustynetd/src/resilience.rs`
- `scripts/systemd/rustynetd-trust-refresh.service`
- `scripts/systemd/rustynetd-assignment-refresh.service`

Tests required:
- Unit tests for signed-state fetch channel: verify signature → apply, reject invalid signature, reject stale watermark, reject replayed watermark
- Unit tests for periodic refresh: verify pre-expiry trigger fires, verify jitter-bounded scheduling, verify stale-state rejection
- Unit tests for `state refresh` IPC command: verify authenticated callers can trigger refresh, verify unauthenticated callers are rejected, verify refresh applies new state only when signature+watermark valid
- Integration test: daemon started with valid signed state, state expires, refresh fetches new state, daemon stays in valid trust state

### Fleet Agent B — WS-2: Endpoint Mobility + Re-establishment
Responsible for automatic endpoint-change detection and signed endpoint update propagation.

Items:
- **WS2-01**: Add endpoint-change detection in the daemon watching for underlay IP/interface/default-route changes. Trigger conditions: new default route, IP address change on primary interface, interface up/down events. Must use signed endpoint update flow — no unsigned endpoint mutations.
- **WS2-02**: After endpoint change detected, immediately trigger traversal re-issue with fresh signed traversal hints, distribute to peers. Freshness-bounded traversal hints only — never stale or unsigned.
- **WS2-03**: Validate deterministic relay fallback/failback behavior under endpoint churn: ACL + DNS + kill-switch invariants must be preserved during all direct↔relay path transitions.

Code files to examine and modify:
- `crates/rustynetd/src/daemon.rs`
- `crates/rustynetd/src/traversal.rs`
- `crates/rustynetd/src/phase10.rs`
- `crates/rustynetd/src/dataplane.rs`

Tests required:
- Unit test: endpoint change detection fires when IP changes, does not fire on transient noise
- Unit test: endpoint update triggers traversal re-issue with fresh nonce and freshness bound
- Unit test: unsigned/stale endpoint update rejected
- Integration test: simulate IP address change on daemon, verify traversal re-issues within 10 seconds
- Integration test: during relay→direct failback, verify ACL/DNS/kill-switch invariants preserved throughout transition

### Fleet Agent C — WS-3: Traversal Freshness Hardening
Responsible for proactive traversal refresh and long-run coverage.

Items:
- **WS3-01**: Implement proactive traversal refresh timer that fires before TTL expiry (at `TTL - margin` with jitter). Current behavior: reactive refresh only on failure. Required: proactive pre-expiry refresh so long-running sessions never hit stale traversal state.
- **WS3-03**: Add test coverage for long-running recovery where traversal would otherwise expire. Test scenario: traversal issued, TTL reduced to short window, verify proactive refresh fires and new traversal applied before expiry, verify no unsafe stale-state fallback occurs.

Code files to examine and modify:
- `crates/rustynetd/src/traversal.rs`
- `crates/rustynetd/src/daemon.rs`
- `crates/rustynetd/src/phase10.rs`

Tests required:
- Unit test: proactive refresh timer fires at `TTL - margin`, not after TTL
- Unit test: if proactive refresh fails, daemon transitions to fail_closed (not silently proceeds on stale state)
- Integration test: short-TTL traversal, verify proactive refresh keeps state fresh across multiple TTL windows
- Property-based or time-accelerated test: traverse 10 TTL cycles, verify no stale-state window at any point

### Fleet Agent D — WS-4: Cross-Network Validation Gates + Live Lab Execution
Responsible for implementing hard-fail gate scenarios and running all live lab tests on the available Linux machines.

Items:
- **WS4-01**: Implement hard-fail gate scenario for controller network switch mid-run. This gate: (1) establishes a 3-node mesh with exit active, (2) simulates controller network change by manipulating routing in a netns, (3) verifies daemon automatically reconnects via the pull-based refresh mechanism, (4) verifies reconnect happens within SLO (≤30s), (5) verifies no traffic leak during reconnect.
- **WS4-02**: Implement hard-fail gate scenario for node underlay network switch mid-session. This gate: (1) establishes a 2-node mesh with exit active, (2) simulates underlay IP change via `ip addr` manipulation, (3) verifies endpoint-change detection fires and triggers traversal re-issue, (4) verifies session recovers within SLO, (5) verifies no traffic leak.

Live lab execution (REQUIRED on the two lab machines):
1. **Setup both machines**: SSH to each, ensure rust toolchain installed, sync the repo, build the project
2. **Run cargo CI gates on Device 1 (Debian)** — this is the primary build/test runner:
   ```
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo check --workspace --all-targets --all-features
   cargo test --workspace --all-targets --all-features
   cargo audit --deny warnings
   cargo deny check bans licenses sources advisories
   ./scripts/ci/phase10_gates.sh
   ./scripts/ci/membership_gates.sh
   ./scripts/ci/security_regression_gates.sh
   ```
3. **Set up network namespace isolation** for cross-network simulation:
   - On Device 1: create netns `rn-net-a` with veth pair, assign `10.100.1.1/24`
   - On Device 2: create netns `rn-net-b` with veth pair, assign `10.100.2.1/24`
   - Route between them so the VPN tunnel can traverse but underlay IPs differ
   - Use `client_network_id=net-a` and `exit_network_id=net-b` labels in test scripts
4. **Deploy Rustynet** on both machines using the install scripts
5. **Run cross-network E2E suites**:
   - `scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh`
   - `scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh`
   - `scripts/e2e/live_linux_cross_network_failback_roaming_test.sh`
   - `scripts/e2e/live_linux_cross_network_traversal_adversarial_test.sh`
   - `scripts/e2e/live_linux_cross_network_remote_exit_dns_test.sh`
   - `scripts/e2e/live_linux_cross_network_remote_exit_soak_test.sh`
6. **Run the cross-network gate binary**:
   ```
   cargo run -p rustynet-cli --bin phase10_cross_network_exit_gates
   ```
7. **Collect all evidence artifacts** to `artifacts/phase10/`

---

## DETAILED IMPLEMENTATION REQUIREMENTS

### Signing and Verification (applies to ALL agents)

Every state-fetch, endpoint-update, and refresh operation MUST follow this pattern (no exceptions):

```rust
// REQUIRED PATTERN - one hardened path
fn apply_signed_state_update(bundle: &SignedBundle, verifier: &VerifyingKey, watermark: &mut Watermark) -> Result<()> {
    // Step 1: Verify signature (MANDATORY, NO BYPASS)
    bundle.verify(verifier)?;

    // Step 2: Check watermark anti-replay (MANDATORY, NO BYPASS)
    watermark.check_and_advance(&bundle.watermark)?;

    // Step 3: Check freshness bounds (MANDATORY, NO BYPASS)
    bundle.check_freshness(SystemTime::now(), CLOCK_SKEW_MAX)?;

    // Step 4: Apply state (ONLY after all checks pass)
    self.apply_state(bundle.payload())?;
    Ok(())
}
```

FORBIDDEN patterns:
- `if let Some(bundle) = try_get_signed_bundle() { ... } else { use_cached_state_anyway() }`
- `if self.config.skip_signature_check { ... }`
- Any `unwrap_or_default()` on security-critical state
- Any error swallowing (`let _ = security_check()`)

### Daemon State Machine (no new states, only hardened transitions)

The state machine is:
```
init → control_trusted → dataplane_applied → exit_active{direct_active | relay_active}
                                    ↓ (any trust/health loss)
                              fail_closed (recoverable)
```

The `state refresh` command may move `fail_closed → dataplane_applied` ONLY if:
1. Fresh signed assignment bundle validates
2. Fresh signed traversal bundle validates
3. Fresh signed trust bundle validates
4. Watermark checks pass for all three
5. Freshness bounds pass for all three

There is NO bypass. No `--force` flag that skips verification. Fail-closed is not an error state to be escaped from insecurely.

### Error Handling

All security-check functions must return `Result<T, SecurityError>` (never `Option<T>`). Security failures must be explicit errors, not silent defaults.

### Logging

Log security events at `info` or `warn` level (never `debug` for security decisions). Log:
- Signed-state fetch attempt and result (pass/fail)
- Watermark advance (old → new)
- Endpoint change detected (interface, old IP, new IP)
- Traversal re-issue triggered (reason: proactive/reactive/endpoint-change)
- Fail-closed transition (reason)
- State refresh (triggered by: ipc/timer/endpoint-change)

NEVER log: private key material, raw passphrases, raw signed bundle bytes.

---

## CARGO QUALITY GATES (MANDATORY)

Run these in sequence on a Linux machine. ALL must pass. Fix any failures — do not skip:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features -- --nocapture 2>&1 | tee /tmp/cargo-test-output.txt
cargo audit --deny warnings
cargo deny check bans licenses sources advisories
./scripts/ci/phase10_gates.sh
./scripts/ci/phase10_cross_network_exit_gates.sh
./scripts/ci/membership_gates.sh
./scripts/ci/security_regression_gates.sh
./scripts/ci/secrets_hygiene_gates.sh
./scripts/ci/traversal_adversarial_gates.sh
./scripts/ci/no_leak_dataplane_gate.sh
```

If any gate fails:
1. STOP — do not continue to next gate
2. Read the failure output carefully
3. Fix the root cause in code
4. Re-run the failed gate
5. Do not move on until ALL gates pass

---

## LIVE LAB EXECUTION PROCEDURE

### Step 1: Machine Setup (run in parallel on both machines)

On EACH machine, via SSH:
```bash
# Device 1 (Debian):
ssh debian@192.168.18.51

# Install rust if not present
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env

# Set up passwordless sudo for automation
echo "tempo" | sudo -S bash -c 'echo "debian ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/rustynet-ci && chmod 440 /etc/sudoers.d/rustynet-ci'

# Sync repository (rsync from local, or git pull if already there)
# If rsync: rsync -az --exclude target/ /path/to/Rustynet/ debian@192.168.18.51:~/Rustynet/
# Then:
cd ~/Rustynet
git status
```

```bash
# Device 2 (Mint):
ssh mint@192.168.18.53

echo "tempo" | sudo -S bash -c 'echo "mint ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/rustynet-ci && chmod 440 /etc/sudoers.d/rustynet-ci'
# ... same rust setup and repo sync
```

### Step 2: Build on Device 1 (primary build machine)

```bash
ssh debian@192.168.18.51
cd ~/Rustynet
cargo build --workspace --all-targets --all-features 2>&1 | tee /tmp/build.log
echo "Build exit: $?"
```

Fix any build errors before proceeding.

### Step 3: Run cargo gates on Device 1

All cargo gates listed above in the CARGO QUALITY GATES section. Capture output.

### Step 4: Network Namespace Setup for Cross-Network Simulation

Since both machines are on `192.168.18.0/24`, use network namespaces to create distinct underlay IPs:

**On Device 1 (Debian — will be "client" node):**
```bash
sudo ip netns add rn-client-ns
sudo ip link add veth-client type veth peer name veth-client-host
sudo ip link set veth-client netns rn-client-ns
sudo ip addr add 10.200.1.1/24 dev veth-client-host
sudo ip link set veth-client-host up
sudo ip netns exec rn-client-ns ip addr add 10.200.1.2/24 dev veth-client
sudo ip netns exec rn-client-ns ip link set veth-client up
sudo ip netns exec rn-client-ns ip route add default via 10.200.1.1
# Enable IP forwarding for routing
sudo sysctl -w net.ipv4.ip_forward=1
```

**On Device 2 (Mint — will be "exit" node):**
```bash
sudo ip netns add rn-exit-ns
sudo ip link add veth-exit type veth peer name veth-exit-host
sudo ip link set veth-exit netns rn-exit-ns
sudo ip addr add 10.200.2.1/24 dev veth-exit-host
sudo ip link set veth-exit-host up
sudo ip netns exec rn-exit-ns ip addr add 10.200.2.2/24 dev veth-exit
sudo ip netns exec rn-exit-ns ip link set veth-exit up
sudo ip netns exec rn-exit-ns ip route add default via 10.200.2.1
sudo sysctl -w net.ipv4.ip_forward=1
```

Now `10.200.1.2` and `10.200.2.2` are distinct network addresses. Use:
- `client_network_id=net-10-200-1`
- `exit_network_id=net-10-200-2`

These demonstrate cross-network topology even though physically on the same LAN.

For relay tests, create a third netns on Device 1 with `10.200.3.x` space.

### Step 5: Deploy Rustynet binaries on both machines

```bash
# On Device 1 - build release binaries
cd ~/Rustynet
cargo build --release -p rustynetd -p rustynet-cli

# Install
sudo cp target/release/rustynetd /usr/local/bin/rustynetd
sudo cp target/release/rustynet /usr/local/bin/rustynet

# Install systemd units
sudo cp scripts/systemd/rustynetd.service /etc/systemd/system/
sudo cp scripts/systemd/rustynetd-managed-dns.service /etc/systemd/system/
sudo cp scripts/systemd/rustynetd-trust-refresh.service /etc/systemd/system/
sudo cp scripts/systemd/rustynetd-trust-refresh.timer /etc/systemd/system/
sudo cp scripts/systemd/rustynetd-assignment-refresh.service /etc/systemd/system/
sudo cp scripts/systemd/rustynetd-assignment-refresh.timer /etc/systemd/system/
sudo systemctl daemon-reload
```

Repeat on Device 2 (copy binaries via scp or build locally).

### Step 6: Run E2E Cross-Network Tests

For each test script, provide:
- `--client-host debian@192.168.18.51`
- `--exit-host mint@192.168.18.53`
- `--client-network-id net-10-200-1`
- `--exit-network-id net-10-200-2`
- `--nat-profile baseline_lan`
- Node IDs (generated by the enrollment process)

Run in this order:
1. Direct remote exit
2. Relay remote exit (use Device 1 also as relay in different netns)
3. Failback roaming
4. Traversal adversarial
5. DNS fail-closed
6. Soak (minimum 30 minutes)

### Step 7: Collect Evidence

After all tests:
```bash
# On Device 1
ls -la ~/Rustynet/artifacts/phase10/
cargo run -p rustynet-cli -- ops validate-cross-network-remote-exit-reports \
  --artifact-dir artifacts/phase10 \
  --require-pass-status

cargo run -p rustynet-cli --bin phase10_cross_network_exit_gates
```

---

## REQUIRED EVIDENCE ARTIFACTS

All of these must exist and validate in `artifacts/phase10/` at the end of the session:

| File | Suite | Required Status |
|------|-------|----------------|
| `cross_network_direct_remote_exit_report.json` | direct_remote_exit | pass |
| `cross_network_relay_remote_exit_report.json` | relay_remote_exit | pass |
| `cross_network_failback_roaming_report.json` | failback_roaming | pass |
| `cross_network_traversal_adversarial_report.json` | traversal_adversarial | pass |
| `cross_network_remote_exit_dns_report.json` | remote_exit_dns | pass |
| `cross_network_remote_exit_soak_report.json` | remote_exit_soak | pass |
| `cross_network_remote_exit_schema_validation.md` | schema gate output | N/A |
| `cross_network_remote_exit_nat_matrix_validation.md` | NAT matrix gate | N/A |

Each report MUST have:
- `schema_version: 1`
- `phase: "phase10"`
- `status: "pass"` (or `"fail"` with `failure_summary` populated)
- `git_commit` matching current HEAD
- `client_network_id != exit_network_id` (required for cross-network claim)
- All required checks for that suite marked `pass`

---

## WS-4 GATE IMPLEMENTATION DETAIL

### WS4-01: Controller Network Switch Gate

Implement as a new E2E test script `scripts/e2e/live_linux_cross_network_controller_switch_test.sh`:

Test flow:
1. Bootstrap 3-node mesh (client, exit, relay) with exit active
2. Verify traffic flowing through exit (check `ip route get 1.1.1.1` goes via `rustynet0`)
3. Simulate controller network change: block the controller's current underlay IP from reaching nodes using nftables rules (`nft add rule inet filter input ip saddr <controller-ip> drop`)
4. Wait for daemon to detect loss of control connectivity
5. Start timer
6. Remove the nftables block (simulating new network path restored)
7. Verify daemon reconnects via pull-based refresh mechanism
8. Stop timer — verify reconnect time ≤ 30 seconds
9. Verify no traffic leaked during reconnect window (route still via rustynet0 throughout)
10. Verify signed-state validity maintained (netcheck shows traversal_error=none)
11. Write report as `cross_network_controller_switch_report.json`

### WS4-02: Node Underlay Network Switch Gate

Implement as a new E2E test script `scripts/e2e/live_linux_cross_network_node_network_switch_test.sh`:

Test flow:
1. Bootstrap 2-node mesh (client + exit) with exit active
2. Verify traffic flowing through exit
3. Add new IP alias on client underlay interface (`ip addr add 10.200.4.2/24 dev <iface>`)
4. Change client default route to new IP
5. Start timer
6. Verify endpoint-change detection fires (check daemon logs or netcheck output changes)
7. Verify traversal re-issue triggered with new endpoint
8. Verify peer (exit) receives updated endpoint hint
9. Verify session converges back to direct path within SLO (≤ 30 seconds)
10. Verify no traffic leaked during transition
11. Verify signed-state validity maintained throughout
12. Write report as `cross_network_node_network_switch_report.json`

---

## EXECUTION PLAN UPDATE CONTRACT

At the END of your session (after all implementation and testing is done), you MUST update `documents/operations/CrossNetworkReliabilitySecurityAIExecutionPlan_2026-03-22.md`:

1. Update `Last Updated (UTC)` to current timestamp
2. Update task statuses:
   - Items with code + evidence → `DONE`
   - Items still blocked → `BLOCKED` with explicit reason
   - Items partially done → `IN_PROGRESS` with progress note
3. Append rows to the `Session Log` for each workstream completed
4. Update `Active Blockers` if BLK-001 is resolved or new blockers discovered
5. Each `DONE` item must have evidence paths (test paths, artifact paths, commit IDs)

---

## DEFINITION OF DONE

The session is complete ONLY when ALL of the following are true:

- [ ] WS1-01, WS1-02, WS1-03: Implemented with unit tests passing
- [ ] WS2-01, WS2-02, WS2-03: Implemented with unit tests passing
- [ ] WS3-01, WS3-03: Implemented with unit tests passing
- [ ] WS4-01, WS4-02: Gate scripts written and executed with evidence
- [ ] All cargo CI gates pass on Linux
- [ ] All 6 cross-network E2E test reports exist in `artifacts/phase10/` with `status: pass`
- [ ] `phase10_cross_network_exit_gates` binary reports PASS
- [ ] No TODO/FIXME/placeholder left in any completed-scope deliverable
- [ ] Execution plan document updated with evidence-backed session log entries
- [ ] No security controls weakened, no insecure fallback paths introduced

If ANY gate fails or ANY test cannot be made to pass, do NOT mark tasks DONE. Document the failure clearly in the execution plan with root cause and next action.

---

## NOTES ON SPECIFIC IMPLEMENTATION LOCATIONS

From code inspection, here is where implementation work needs to land:

### `crates/rustynetd/src/ipc.rs`
- The `state refresh` IPC command was skeletonized in the most recent commit
- Complete the handler so it: validates caller credential, triggers the signed-state refresh flow, returns success/failure with specific error variants

### `crates/rustynetd/src/daemon.rs`
- The daemon has `Phase10Controller` as its core state machine
- Add: endpoint-change monitoring loop (watch `/proc/net/route` or use netlink)
- Add: proactive traversal refresh timer integrated with the main event loop
- Add: pull-based state fetch handler invoked by both the IPC command and the timer

### `crates/rustynetd/src/traversal.rs`
- Add `refresh_before_expiry_margin` to `TraversalEngineConfig`
- Add proactive refresh scheduling in the traversal probe loop
- Add metrics: `traversal_time_to_expiry_secs` and `traversal_stale_rejections`

### `crates/rustynetd/src/phase10.rs`
- `Phase10Controller::apply_signed_state_refresh()` — the one hardened path for state updates
- Must check: signature valid → watermark advances → freshness in bounds → then apply
- Must not proceed if any check fails (return `Err`, transition to `fail_closed`)

### `crates/rustynet-cli/src/ops_cross_network_reports.rs`
- May need new report specs for WS4-01 and WS4-02 gate reports
- Validate that controller_switch and node_network_switch reports pass schema

---

## AI DISCIPLINE RULES — ABSOLUTE

1. Read all normative documents BEFORE writing any code.
2. Implement in small, verifiable increments — run `cargo test` after each meaningful change.
3. Never mark a task DONE without test/gate/artifact evidence.
4. If a gate fails, fix the root cause — never bypass.
5. If you cannot proceed without external input, document the blocker clearly and stop — do not fabricate evidence.
6. Security controls are not optional — they are always enforced.
7. This session must produce working code that passes all gates and real live tests on the lab machines.
8. Use parallel fleet agents for independent workstreams to maximize throughput.

---

*Generated: 2026-03-22 | Project: Rustynet Phase 10 Cross-Network Completion*
*Lab: Device 1 debian@192.168.18.51, Device 2 mint@192.168.18.53 (LAN 192.168.18.0/24)*
