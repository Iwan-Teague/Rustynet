# Rustynet Master Implementation Agent Prompt

---

## WHO YOU ARE AND WHAT YOU ARE DOING

You are a senior Rust systems engineer executing a full implementation sprint on the Rustynet project — a self-hosted, security-first mesh VPN. Your job is to implement, test, fix, and document as much of the outstanding work as possible in a single continuous session, working across multiple parallel sub-agents (fleets) simultaneously.

You have full access to:
- The repository at the current working directory
- Two Linux lab machines via SSH:
  - **Device 1 (Debian):** `debian@192.168.18.51` — password for SSH and sudo: `tempo`
  - **Device 2 (Mint/Ubuntu):** `mint@192.168.18.53` — password for SSH and sudo: `tempo`
- All Rust tooling, cargo, git, and system tools on those machines

**Critical platform note:** Several crates use unix-only APIs (`rustynet-local-security`). ALL cargo commands — `cargo build`, `cargo test`, `cargo clippy`, `cargo check` — MUST be run on Device 1 (Debian). Do not attempt to compile on Windows. SSH to the Debian machine and run everything there.

---

## NORMATIVE DOCUMENTS — READ THESE FIRST, IN ORDER

Before writing a single line of code, read these files:

1. `documents/Requirements.md`
2. `documents/SecurityMinimumBar.md`
3. `documents/phase10.md`
4. `documents/operations/MasterWorkPlan_2026-03-22.md` — **this is your primary task list**
5. `documents/operations/CrossNetworkReliabilitySecurityAIExecutionPlan_2026-03-22.md`
6. `documents/operations/CrossNetworkRemoteExitNodePlan_2026-03-16.md`
7. `documents/MembershipImplementationPlan.md`
8. `documents/operations/UdpHolePunchingHP2IngestionPlan_2026-03-07.md`
9. `documents/operations/ShellToRustMigrationPlan_2026-03-06.md`

Take note of conflicts. The higher-precedence document always wins.

---

## NON-NEGOTIABLE SECURITY CONSTRAINTS — NEVER VIOLATE ANY OF THESE

These apply to every line of code you write in this session:

1. **One hardened path only.** Every security-sensitive operation has exactly one implementation. No `if legacy_mode`, no `try_secure().unwrap_or(insecure_default())`, no feature flags on security controls.

2. **Fail-closed always.** Missing/stale/invalid/unverifiable trust state → deny. Never permit with degraded security. Fail-closed is not an error to be escaped from insecurely.

3. **No unsigned endpoint mutation.** Endpoint updates require a verified signed traversal bundle with watermark anti-replay. No bypass even for operator convenience.

4. **No replay acceptance.** Watermark/epoch/nonce freshness required at every trust boundary.

5. **No plaintext secrets at rest.** Keys encrypted at rest, systemd credentials for passphrases.

6. **Constant-time comparisons on all token/key/MAC/hash equality checks.** Use `subtle::ConstantTimeEq`, never `==` on secret material.

7. **`#![forbid(unsafe_code)]`** must remain on all crates. Do not remove it.

8. **Never log secrets, keys, passphrases, or raw bundle bytes.**

9. **Cargo gates must all pass.** If a gate fails, fix the root cause. Never bypass gates with `--no-verify`, `#[allow]` suppressions on new code, or skipped tests.

10. **No task is done until it has passing tests and passing gates.** Intent alone is not evidence.

---

## DOCUMENTATION CONTRACT — UPDATE AS YOU GO

The master work plan lives at:
```
documents/operations/MasterWorkPlan_2026-03-22.md
```

You MUST update this document as you work. Specifically:

- When you **start** an item: add `[IN PROGRESS — fleet X, started HH:MM UTC]` next to it
- When you **complete** an item: add `[DONE — evidence: <test path or artifact path>, commit: <short SHA>]` next to it
- When you **cannot complete** an item: add `[BLOCKED — reason: <exact reason>, next action: <what is needed>]`
- Add a **## Session Log** section at the bottom of the document and append one entry per completed workstream, formatted as:

```
| <UTC timestamp> | Fleet <X> | <what was implemented> | <evidence paths> |
```

Update this document **live as you work** — not only at the end. If sub-agents are running in parallel, each sub-agent writes its own section and you merge at the end.

Also update `documents/operations/CrossNetworkReliabilitySecurityAIExecutionPlan_2026-03-22.md` for any cross-network workstream items completed, following the same evidence-backed convention defined in that document.

---

## MANDATORY CARGO QUALITY GATES

Run these on Device 1 (Debian) after every significant batch of changes. All must pass. Fix failures before marking work done:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features 2>&1 | tee /tmp/cargo-test-results.txt
cargo audit --deny warnings
cargo deny check bans licenses sources advisories
./scripts/ci/phase10_gates.sh
./scripts/ci/membership_gates.sh
./scripts/ci/security_regression_gates.sh
./scripts/ci/secrets_hygiene_gates.sh
```

If any gate fails: stop, read the output, fix the root cause, re-run the gate, only then continue.

---

## FLEET STRUCTURE

Launch the following sub-agents in parallel immediately after reading the normative documents. Each fleet has a specific track from `MasterWorkPlan_2026-03-22.md`. The fleet assignments are designed so they touch different parts of the codebase with minimal overlap.

**IMPORTANT coordination point:** Fleet A and Fleet B both eventually touch `crates/rustynetd/src/traversal.rs`. Fleet A must commit its HP-2 simultaneous-open work and push to a feature branch before Fleet B begins WS-2 endpoint mobility. Both fleets should coordinate on this file by working on different functions within it.

---

## FLEET A — NAT Traversal and Production Relay Transport

**Responsible for:** Track A items from MasterWorkPlan_2026-03-22.md (A1 through A4)

**Primary files:**
- `crates/rustynetd/src/traversal.rs`
- `crates/rustynet-relay/src/` (entire crate)
- `crates/rustynet-backend-api/src/lib.rs`
- `crates/rustynetd/src/phase10.rs`
- `crates/rustynetd/src/daemon.rs`

**Work in this exact sequence — complete and test each before starting the next:**

### Step A1: STUN Server-Reflexive Candidate Gathering

Read `documents/operations/UdpHolePunchingHP2IngestionPlan_2026-03-07.md` section HP2-01 and HP2-02 for context on what already exists.

Implement in `crates/rustynetd/src/traversal.rs`:

```rust
// Add to TraversalEngineConfig:
pub stun_servers: Vec<SocketAddr>,
pub stun_gather_timeout_ms: u64,  // default 2000

// Add CandidateType enum if not already distinct:
pub enum CandidateType {
    Host,            // local interface IP
    ServerReflexive, // STUN-observed public IP
    Relay,           // relay service address
}

// Add CandidateGatherer struct:
pub struct CandidateGatherer {
    local_socket: UdpSocket,
    stun_servers: Vec<SocketAddr>,
    timeout: Duration,
}

impl CandidateGatherer {
    // Bind a UDP socket (same port as WireGuard if possible, otherwise ephemeral)
    // Send STUN Binding Request (RFC 5389) to each configured STUN server
    // Parse XOR-MAPPED-ADDRESS from response
    // Return Vec<TraversalCandidate> including both Host and ServerReflexive entries
    // Deduplicate by (ip, port, type)
    // Filter out: loopback, link-local, rustynet0 interface addresses
    // If STUN times out: return only Host candidates (do not fail, partial results OK)
    pub fn gather(&self) -> Vec<TraversalCandidate>;
}
```

STUN request format (minimal RFC 5389 implementation — do not use an external STUN crate unless one already exists in Cargo.toml):
```
Magic cookie: 0x2112A442
Message type: 0x0001 (Binding Request)
Transaction ID: 12 random bytes
XOR-MAPPED-ADDRESS response parsing: XOR with magic cookie + transaction ID
```

Write tests for:
- STUN response parser: valid XOR-MAPPED-ADDRESS → correct IP:port extracted
- Malformed frame (too short, wrong magic cookie, unknown attribute) → returns Err, no panic
- STUN timeout → gather() returns Host candidates only, does not block
- Deduplication: same IP:port from two sources → one candidate
- Filter: loopback/link-local/rustynet0 → not included in results

After implementation: run `cargo test -p rustynetd traversal` and fix any failures.

---

### Step A2: Simultaneous-Open Coordination Protocol

The traversal engine currently does one-sided probing. Add coordination so both peers start probing simultaneously.

Add to `crates/rustynet-control/src/` (whichever module handles traversal hint issuance):

```rust
pub struct TraversalCoordinationRecord {
    pub session_id: [u8; 16],       // random, shared between both peers
    pub probe_start_unix: u64,       // Unix timestamp: both sides begin at this time
    pub node_a: NodeId,
    pub node_b: NodeId,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,        // max 30s TTL
    pub nonce: [u8; 16],
    // signed by control key
}
```

Add to `crates/rustynetd/src/traversal.rs` — simultaneous-open probe executor:

```rust
// When coordination record is received and valid:
// 1. Verify signature, freshness (expires_at_unix), and nonce anti-replay
// 2. Wait until probe_start_unix (bounded wait: if > 10s in future, reject; if past, fire immediately)
// 3. Send UDP probe packets to all of peer's candidates simultaneously
// 4. Monitor for backend handshake-recency evidence (peer_latest_handshake_unix)
// 5. If handshake observed within direct_probe_window_ms: PathMode::Direct
// 6. After max_direct_probe_rounds with no handshake: PathMode::Relay (or FailClosed if no relay)
// 7. Record reason: DirectReason::SimultaneousOpen or RelayReason::DirectFailed { rounds: N }
```

Write tests for:
- Coordination record with future probe_start (within 10s) → waits then fires
- Coordination record with past probe_start → fires immediately
- Coordination record with probe_start > 10s future → rejected (too far ahead, stale or clock skew)
- Expired coordination record → rejected
- After N failed simultaneous-open rounds → relay decision, no more direct attempts
- Replayed coordination nonce → rejected

---

### Step A3: HP-3 Production Relay Transport Service

This is the most substantial item. The `rustynet-relay` crate currently only selects which relay to use. It needs to actually relay packets.

**First:** Check `crates/rustynet-relay/src/lib.rs` and understand the current fleet-selector structure. Do not break existing relay selection.

**Add** `crates/rustynet-relay/src/transport.rs` (new file):

```rust
// Session token (issued by control plane, presented by client to relay):
pub struct RelaySessionToken {
    pub node_id: NodeId,
    pub peer_node_id: NodeId,
    pub relay_id: NodeId,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,  // max 120s TTL
    pub nonce: [u8; 16],
    // signed by control key — verified with the control verifier key, not relay-specific key
}

// RelayHello: client → relay (over TCP control channel)
pub struct RelayHello {
    pub node_id: NodeId,
    pub peer_node_id: NodeId,
    pub token: RelaySessionToken,
    pub token_signature: Ed25519Signature,
}

// RelayHelloAck: relay → client
pub enum RelayHelloResponse {
    Accepted { session_id: [u8; 16], allocated_udp_port: u16 },
    Rejected { reason: RelayRejectReason },
}

pub enum RelayRejectReason {
    InvalidToken,
    ExpiredToken,
    ReplayedNonce,
    RateLimitExceeded,
    RelayFull,
    UnknownNode,
}

// RelayServer: runs on the relay node
pub struct RelayServer {
    sessions: HashMap<[u8; 16], RelaySession>,   // session_id → session
    node_pair_index: HashMap<(NodeId, NodeId), [u8; 16]>,  // (node, peer) → session_id
    rate_limiter: PerNodeRateLimiter,
    control_verifier_key: VerifyingKey,           // to verify session tokens
    nonce_store: NonceStore,                      // to prevent replay
}

impl RelayServer {
    pub fn handle_hello(&mut self, hello: RelayHello) -> RelayHelloResponse {
        // 1. Verify token signature (control key)
        // 2. Check token freshness (not expired)
        // 3. Check nonce not replayed (NonceStore)
        // 4. Check rate limit for hello.node_id
        // 5. Allocate session: assign session_id, allocate UDP port
        // 6. Index by (node_id, peer_node_id)
        // 7. Return Accepted { session_id, allocated_udp_port }
    }

    pub fn forward_packet(&mut self, session_id: [u8; 16], payload: &[u8]) {
        // Look up session
        // Find paired session (peer's session indexed by (peer_node_id, node_id))
        // If paired session exists: forward payload bytes as-is (ciphertext only — never inspect)
        // If no paired session: buffer briefly (max 500ms) then drop
        // Apply rate limit: drop silently if exceeded (no error response — prevents amplification)
    }
}
```

**Rate limiter** (`crates/rustynet-relay/src/rate_limit.rs`):
```rust
pub struct PerNodeRateLimiter {
    window_ms: u64,
    max_packets_per_window: u64,    // default 10_000
    max_bytes_per_window: u64,      // default 12_500_000 (100 Mbps)
    max_sessions_per_node: u8,      // default 8
    counters: HashMap<NodeId, RateCounter>,
}
// Drop silently (not error) when exceeded — prevents relay amplification attacks
```

**Session idle cleanup:**
- Sessions idle for > 30s (no packets) are torn down
- Half-open sessions (only one side connected) cleaned up after 5s
- Run cleanup on a background timer, not inline in the hot path

Write tests for:
- Invalid token signature → Rejected::InvalidToken
- Expired token (expires_at_unix in past) → Rejected::ExpiredToken
- Replayed nonce → Rejected::ReplayedNonce
- Rate limit exceeded → packets dropped silently, session not terminated
- Two matching sessions (A→B and B→A) pair correctly and forward packets bidirectionally
- Forward does not inspect payload (test: payload is all-zeros, random bytes — both forwarded identically)
- Idle session cleanup fires after 30s of inactivity
- Half-open cleanup fires after 5s

Add `subtle = "2"` to `rustynet-relay/Cargo.toml` and use `ConstantTimeEq` for all token comparisons.

---

### Step A4: Daemon Relay Session Integration

Wire the new relay transport into `rustynetd` so that when `TraversalDecision::Relay` is made, the daemon establishes a real relay session.

Files: `crates/rustynetd/src/traversal.rs`, `crates/rustynetd/src/phase10.rs`, `crates/rustynetd/src/daemon.rs`

Implementation:
```rust
// In phase10.rs — relay session state:
enum ActivePath {
    Direct { endpoint: SocketAddr },
    Relay {
        relay_addr: SocketAddr,
        relay_session_id: [u8; 16],
        allocated_port: u16,
        established_at: Instant,
        last_keepalive_at: Instant,
    },
    FailClosed { reason: String },
}

// When TraversalDecision::Relay:
fn establish_relay_session(&mut self, relay_addr: SocketAddr, token: RelaySessionToken)
    -> Result<ActivePath, RelayError>
{
    let response = relay_client::connect_and_hello(relay_addr, &token, &self.token_signature)?;
    match response {
        RelayHelloResponse::Accepted { session_id, allocated_udp_port } => {
            // Program WireGuard peer endpoint to relay_addr:allocated_udp_port
            self.backend.update_peer_endpoint(peer_id, SocketAddr::new(relay_addr.ip(), allocated_udp_port))?;
            Ok(ActivePath::Relay { relay_addr, relay_session_id: session_id, allocated_port: allocated_udp_port, ... })
        }
        RelayHelloResponse::Rejected { reason } => {
            Err(RelayError::SessionRejected(reason))
        }
    }
}

// Relay keepalive loop (runs in daemon event loop):
// Every 25s: send keepalive packet to relay session
// On keepalive failure: attempt re-establish once, then fail_closed if relay unreachable
```

Write tests for:
- Relay session rejected by relay → daemon fails-closed, does not try direct as fallback
- Relay session established → WireGuard endpoint updated to relay allocated port
- Relay keepalive failure → re-establish attempted → fail_closed if relay still unreachable
- On peer removal: relay session is torn down (no dangling relay sessions)
- On direct failback: relay session torn down, WireGuard endpoint updated to direct endpoint

---

### Step A5: HP-4 Hysteresis and HP-5 Gate Coverage

**Hysteresis** in `crates/rustynetd/src/phase10.rs`:
```rust
// Add to Phase10Controller:
direct_stability_window_ms: u64,   // default 3000 — must be stable 3s before committing direct
relay_stability_window_ms: u64,    // default 5000
pending_path_mode: Option<PathMode>,
pending_since: Option<Instant>,

// In consider_path_change:
// New candidate → start window. Existing candidate → check elapsed. Fail-closed bypasses window.
```

**HP-5 gate coverage** — add to `scripts/ci/phase10_hp2_gates.sh`:
```bash
# For each required check in traversal_path_selection_report.json and traversal_probe_security_report.json:
# - direct_probe_success
# - relay_fallback_success
# - replay_rejected
# - fail_closed_on_invalid_traversal
# - no_unauthorized_endpoint_mutation
# Fail the gate if any check is missing or not "pass"
cargo test -p rustynetd traversal --all-features
cargo test -p rustynetd -- daemon::tests::traversal --all-features
cargo test -p rustynet-backend-wireguard --all-targets --all-features
```

---

**After completing all Fleet A steps:**
1. Run the full cargo gate suite on Device 1
2. Fix all failures
3. Update `documents/operations/MasterWorkPlan_2026-03-22.md` — mark A1 through A5 DONE with evidence paths
4. Commit: `git add -p && git commit -m "Track A: HP-2 STUN+simultaneous-open, HP-3 relay transport, HP-4 hysteresis"`

---

## FLEET B — Cross-Network Runtime Hardening

**Responsible for:** Track B items from MasterWorkPlan_2026-03-22.md (B1 through B4)

**Primary files:**
- `crates/rustynetd/src/daemon.rs`
- `crates/rustynetd/src/ipc.rs`
- `crates/rustynetd/src/traversal.rs` (**coordinate with Fleet A on this file**)
- `crates/rustynetd/src/phase10.rs`
- `crates/rustynetd/src/resilience.rs`
- `scripts/systemd/rustynetd-trust-refresh.service`
- `scripts/systemd/rustynetd-assignment-refresh.service`

**Coordination note:** Do NOT begin B2 (WS-2 endpoint mobility) until Fleet A has committed its `traversal.rs` changes. Begin with B1 and B3 which do not touch `traversal.rs`.

**Work in this exact sequence:**

### Step B1: Pull-Based Signed State Fetch Channel (WS1-01)

Read `crates/rustynetd/src/daemon.rs` carefully — understand the existing state machine, IPC handling, and how signed bundles are currently loaded from disk.

Add `StateFetcher` to `crates/rustynetd/src/daemon.rs`:

```rust
struct StateFetcher {
    control_base_url: String,          // https://control.rustynet.local
    tls_roots: Vec<u8>,                // pinned DER-encoded root cert, NOT system CAs
    node_keypair: Ed25519Keypair,      // for request signing / mTLS identity
    assignment_verifier_key: VerifyingKey,
    traversal_verifier_key: VerifyingKey,
    trust_verifier_key: VerifyingKey,
    dns_zone_verifier_key: VerifyingKey,
    watermark_store: WatermarkStore,   // persisted, atomic writes, mode 0600
}

impl StateFetcher {
    fn fetch_assignment(&mut self) -> Result<SignedAssignmentBundle, FetchError>;
    fn fetch_traversal(&mut self) -> Result<SignedTraversalBundle, FetchError>;
    fn fetch_trust(&mut self) -> Result<SignedTrustBundle, FetchError>;
    fn fetch_dns_zone(&mut self) -> Result<SignedDnsZoneBundle, FetchError>;
}

// Each fetch method MUST:
// 1. Make HTTP GET to control endpoint (reqwest or ureq — check Cargo.toml for existing HTTP client)
// 2. Verify bundle signature with the appropriate verifier key
// 3. Check watermark advances past stored watermark (reject if not)
// 4. Check freshness (not expired, clock skew within MAX_CLOCK_SKEW)
// 5. Persist new watermark ONLY after all checks pass
// 6. Return Ok(bundle) only if all 4 checks pass
// NEVER return Ok with a bundle that failed any check
```

Note: if the project does not have an HTTP client in Cargo.toml, do NOT add a heavyweight one. Use `std::net::TcpStream` with manual HTTP/1.1 for a simple GET, or check if `ureq` is already a dependency. Prefer the minimal option. The control endpoint is an internal endpoint so no need for full HTTP/2.

If no control server is available in the lab, implement the fetch logic with a clear interface but wire it so the daemon falls back to disk-based state loading (which already works) when the fetch endpoint is not configured. This preserves current behavior while adding the new capability.

Write tests:
- Mock server returns valid bundle → fetch verifies and returns Ok
- Mock server returns bundle with bad signature → FetchError::SignatureInvalid, watermark unchanged
- Mock server returns expired bundle → FetchError::Stale, watermark unchanged
- Mock server returns replayed watermark → FetchError::WatermarkRejected
- Mock server unreachable → FetchError::Network, no state change

---

### Step B2: Periodic Signed-State Refresh Scheduler (WS1-02)

Wire a background timer into the daemon event loop that triggers fetches before bundle expiry.

In `crates/rustynetd/src/daemon.rs`, inside the daemon's main event loop:

```rust
// One timer per bundle type (assignment, traversal, trust, dns_zone)
// Each timer fires at: expires_at - pre_expiry_margin + jitter
// Default pre_expiry_margin: 120s
// Default jitter: rand::random::<u64>() % 30s

// On timer fire:
match fetcher.fetch_assignment() {
    Ok(bundle) => {
        controller.apply_signed_assignment_update(bundle)?;  // one hardened apply path
        reset_timer(scheduler.next_refresh_at(bundle.expires_at));
    }
    Err(e) => {
        warn!("assignment refresh failed: {e}");
        // Retry with exponential backoff (max 5 retries, max interval 60s)
        // But: if CURRENT bundle is now expired → fail_closed immediately
        if current_assignment.is_expired() {
            controller.transition_to_fail_closed("assignment expired without successful refresh");
        } else {
            reset_timer(Instant::now() + retry_backoff);
        }
    }
}
```

Also wire the existing systemd timer units:
- `scripts/systemd/rustynetd-trust-refresh.timer` — verify it triggers the daemon's state refresh
- `scripts/systemd/rustynetd-assignment-refresh.timer` — same

If they currently invoke a shell script, verify that script dispatches to `rustynet ops refresh-trust` or equivalent Rust command, not direct file manipulation.

Write tests:
- Timer fires BEFORE expires_at (not after)
- Jitter within bounds
- On refresh failure: retry scheduled, not immediate fail-closed
- On bundle expiry without refresh: fail_closed transition logged and executed
- On successful refresh: timer reset to new expiry window

---

### Step B3: Complete `state refresh` IPC Command (WS1-03)

The skeleton exists in `crates/rustynetd/src/ipc.rs` and `crates/rustynetd/src/daemon.rs`. Find it and complete it.

Search: `grep -n "StateRefresh\|state.refresh\|state_refresh" crates/rustynetd/src/ipc.rs crates/rustynetd/src/daemon.rs`

Complete the IPC handler:

```rust
// In ipc.rs:
IpcCommand::StateRefresh { target } => {
    // 1. Verify SO_PEERCRED — only root (uid=0) or rustynet group may trigger refresh
    let cred = get_peer_credential(&stream)?;
    if cred.uid != 0 && !is_in_rustynet_group(cred.gid) {
        write_response(&mut stream, IpcResponse::Denied { reason: "insufficient privilege".into() })?;
        return Ok(());
    }
    // 2. Send refresh request to daemon main loop (channel)
    daemon_cmd_tx.send(DaemonCommand::StateRefresh { target })?;
    // 3. Wait for result with timeout
    match daemon_result_rx.recv_timeout(Duration::from_secs(30)) {
        Ok(DaemonCommandResult::StateRefreshOk) =>
            write_response(&mut stream, IpcResponse::Ok { message: "state refreshed".into() })?,
        Ok(DaemonCommandResult::StateRefreshErr { reason }) =>
            write_response(&mut stream, IpcResponse::Error { message: reason })?,
        Err(_) =>
            write_response(&mut stream, IpcResponse::Error { message: "refresh timed out".into() })?,
    }
}

// In daemon.rs — DaemonCommand::StateRefresh handler:
DaemonCommand::StateRefresh { target } => {
    let result = match target {
        RefreshTarget::All => self.refresh_all_signed_state(),
        RefreshTarget::Assignment => self.refresh_assignment(),
        RefreshTarget::Traversal => self.refresh_traversal(),
        RefreshTarget::Trust => self.refresh_trust(),
        RefreshTarget::DnsZone => self.refresh_dns_zone(),
    };
    // Respond to IPC caller
    result_tx.send(result.into())?;
}

// refresh_all_signed_state must be ATOMIC:
// Either ALL bundles refresh successfully, or NONE are applied
// Partial-refresh on failure → keep old state entirely
```

Also ensure `rustynet state refresh` CLI command in `crates/rustynet-cli/src/main.rs` is wired to send this IPC command. Search: `grep -n "state.refresh\|StateRefresh" crates/rustynet-cli/src/main.rs`

Write tests:
- Authorized caller (root) → refresh triggers, result returned
- Unauthorized caller → IpcResponse::Denied, no refresh attempted
- Refresh with bad signature → IpcResponse::Error, daemon state unchanged
- `state refresh assignment` → only assignment refreshed
- `state refresh all` with one bundle failing → all bundles unchanged (atomic)
- Integration test: `rustynet state refresh` CLI → daemon performs fetch → exit code 0

---

### Step B4: Proactive Traversal Refresh (WS3-01)

Do NOT start this step until Fleet A has committed its `traversal.rs` changes.

In `crates/rustynetd/src/traversal.rs`, add proactive refresh scheduling:

```rust
// Add to TraversalEngineConfig:
pub pre_expiry_refresh_margin_secs: u64,  // default 60
pub pre_expiry_jitter_max_secs: u64,      // default 15

// Add method:
pub fn next_proactive_refresh_instant(expires_at: SystemTime, config: &TraversalEngineConfig) -> Instant {
    let margin = Duration::from_secs(config.pre_expiry_refresh_margin_secs);
    let jitter = Duration::from_secs(rand::random::<u64>() % config.pre_expiry_jitter_max_secs);
    let target = expires_at.checked_sub(margin).unwrap_or(SystemTime::now()) + jitter;
    match target.duration_since(SystemTime::now()) {
        Ok(d) => Instant::now() + d,
        Err(_) => Instant::now() + Duration::from_secs(5),
    }
}
```

Wire into daemon event loop alongside assignment/trust refresh timers (same pattern as B2).

On proactive refresh failure:
- Log at warn level
- Schedule retry with backoff
- If traversal bundle expires before refresh succeeds → fail_closed (same as B2 pattern)

Write tests:
- Proactive refresh fires at expires_at - margin + [0, jitter_max)
- Proactive refresh failure → retry, not immediate fail-closed
- Traversal bundle expiry without successful refresh → fail_closed
- Successful refresh → traversal state updated, new timer scheduled

---

### Step B5: Endpoint Change Detection (WS2-01)

Do NOT start this step until Fleet A has committed its `traversal.rs` changes.

Add endpoint monitor to `crates/rustynetd/src/daemon.rs`:

```rust
struct EndpointMonitor {
    last_seen: BTreeMap<String, BTreeSet<IpAddr>>,  // interface → addresses
    poll_interval: Duration,                          // default 5s
}

impl EndpointMonitor {
    fn poll(&mut self) -> Option<EndpointChangeEvent> {
        let current = read_interface_addresses()?;
        for (iface, addrs) in &current {
            if iface == "rustynet0" { continue; }  // skip tunnel interface
            if iface.starts_with("lo") { continue; } // skip loopback
            if self.last_seen.get(iface) != Some(addrs) {
                let event = EndpointChangeEvent {
                    interface: iface.clone(),
                    old_addrs: self.last_seen.get(iface).cloned().unwrap_or_default(),
                    new_addrs: addrs.clone(),
                };
                self.last_seen = current;
                return Some(event);
            }
        }
        None
    }
}

fn read_interface_addresses() -> Option<BTreeMap<String, BTreeSet<IpAddr>>> {
    // On Linux: parse /proc/net/fib_trie or use getifaddrs() via nix crate
    // Filter: exclude link-local (169.254.0.0/16, fe80::/10), loopback, rustynet0
}
```

On `EndpointChangeEvent`:
```rust
// 1. Log: "endpoint change detected on {iface}: {old} → {new}"
// 2. Re-gather candidates (call CandidateGatherer from Fleet A's A1 step)
// 3. Trigger traversal re-issue (request fresh signed traversal bundle)
//    This goes through StateFetcher.fetch_traversal() — one hardened path
// 4. Apply new traversal bundle to controller
// 5. Re-run traversal probe with new candidates
```

Write tests:
- Interface IP added → EndpointChangeEvent emitted
- Interface IP removed → EndpointChangeEvent emitted
- `rustynet0` IP changed → no event (filtered)
- Loopback changed → no event (filtered)
- Link-local added → no event (filtered)
- Multiple changes within 1s → debounced to single event
- Integration test: `ip addr add 10.200.5.2/24 dev eth0` on Debian machine → verify daemon detects within 10s

---

### Step B6: Invariant Preservation During Transitions (WS2-03)

Add a guard in `crates/rustynetd/src/phase10.rs` that asserts firewall rules exist before and after any state refresh:

```rust
// Before applying new state:
fn assert_firewall_invariants(&self) -> Result<(), InvariantError> {
    // On Linux: check nft list ruleset | grep "rustynet-kill-switch" — must exist if kill-switch active
    // If invariant missing → return Err, do not apply new state
}

// In apply_signed_state_refresh:
self.assert_firewall_invariants()?;  // check before
let result = self.apply_new_state(bundle);
self.assert_firewall_invariants()?;  // check after
match result {
    Ok(_) => Ok(()),
    Err(e) => {
        self.rollback()?;
        self.transition_to_fail_closed(format!("state apply failed: {e}"));
        Err(e)
    }
}
```

Write tests:
- Valid refresh with firewall intact → Ok, firewall still intact after
- Refresh fails midway → rollback called, firewall still intact, fail_closed triggered
- Missing firewall before refresh → Err returned immediately, no state applied

---

**After completing all Fleet B steps:**
1. Run full cargo gate suite on Device 1: fix all failures
2. Update `documents/operations/MasterWorkPlan_2026-03-22.md` — mark B1 through B6 DONE with evidence paths
3. Update `documents/operations/CrossNetworkReliabilitySecurityAIExecutionPlan_2026-03-22.md` — mark WS1-01, WS1-02, WS1-03, WS2-01, WS2-02, WS2-03, WS3-01 DONE with evidence
4. Commit: `git add -p && git commit -m "Track B: WS-1 pull refresh, WS-2 endpoint mobility, WS-3 proactive traversal freshness"`

---

## FLEET C — Membership System (M0–M8)

**Responsible for:** Track C items from MasterWorkPlan_2026-03-22.md

**Primary files:**
- `crates/rustynet-control/src/membership/` (entire directory)
- `crates/rustynetd/src/daemon.rs` (M4 only)
- `crates/rustynet-policy/src/` (M5 only)
- `crates/rustynet-cli/src/main.rs` (M6 only)

**No conflicts with Fleets A or B.** This track is entirely within `rustynet-control` and `rustynet-policy` until M4.

**Check the current state first:** Run `ls crates/rustynet-control/src/membership/` to see what already exists. Read all existing files before writing anything. Then run `cargo test -p rustynet-control membership` to see what tests currently pass.

**Work in this exact sequence:**

### Step C1: M0 — Schema Lock

If `crates/rustynet-control/src/membership/` does not exist, create it:
```
mkdir -p crates/rustynet-control/src/membership
touch crates/rustynet-control/src/membership/mod.rs
```

In `schema.rs` (new or existing):

```rust
pub const MEMBERSHIP_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MembershipState {
    pub schema_version: u8,
    pub epoch: u64,
    pub state_root: [u8; 32],
    pub members: BTreeMap<NodeId, MemberRecord>,
    pub approvers: BTreeMap<NodeId, ApproverRecord>,
    pub quorum_threshold: u8,
    pub applied_update_ids: BTreeSet<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemberRecord {
    pub node_id: NodeId,
    pub public_key_hex: String,   // hex-encoded ED25519 public key
    pub status: MemberStatus,
    pub added_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MemberStatus { Active, Revoked }

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ApproverRecord {
    pub approver_id: NodeId,
    pub public_key_hex: String,
    pub status: ApproverStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ApproverStatus { Active, Revoked }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MembershipUpdate {
    pub schema_version: u8,
    pub update_id: [u8; 16],
    pub prev_state_root: [u8; 32],
    pub operation: MembershipOperation,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,     // max 3600s from issued_at
    pub approvals: Vec<Approval>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum MembershipOperation {
    AddNode(MemberRecord),
    RemoveNode(NodeId),
    RevokeNode(NodeId),
    RotateKey { node_id: NodeId, new_public_key_hex: String },
    UpdateApproverSet { add: Vec<ApproverRecord>, remove: Vec<NodeId>, new_threshold: u8 },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Approval {
    pub approver_id: NodeId,
    pub signature: [u8; 64],   // ED25519 signature over canonical operation bytes
}

// State root computation:
pub fn compute_state_root(state: &MembershipState) -> Result<[u8; 32], MembershipError> {
    // Serialize to canonical JSON (serde_json with sorted keys)
    // SHA-256 of the bytes
    let json = canonical_json_of_state(state)?;
    Ok(sha256(&json))
}

fn canonical_json_of_state(state: &MembershipState) -> Result<Vec<u8>, MembershipError> {
    // Must produce identical bytes for identical states regardless of insertion order
    // Use BTreeMap (already sorted) + serde_json with no extra whitespace
    serde_json::to_vec(state).map_err(|e| MembershipError::SerializationError(e.to_string()))
}
```

Commit golden test vectors — write these in `tests/membership_schema_golden_test.rs`:
```rust
#[test]
fn golden_state_root_empty_state() {
    let state = MembershipState { schema_version: 1, epoch: 0, members: BTreeMap::new(), ... };
    let root = compute_state_root(&state).unwrap();
    // Hard-code the expected root hash here after first successful run
    // This vector must NEVER change without a schema version bump
    assert_eq!(hex::encode(root), "COMPUTED_HASH_HERE");
}
```

Run the test once to get the hash, then hard-code it. It must be stable forever.

Write tests:
- Same state → same root hash every time (deterministic)
- Different member insertion order → same root hash (BTreeMap ensures ordering)
- Unknown schema_version → MembershipError::UnknownSchemaVersion

---

### Step C2: M1 — State Root and Update Engine

In `crates/rustynet-control/src/membership/engine.rs` (new):

Implement the pure deterministic reducer (see MasterWorkPlan_2026-03-22.md section C2 for full pseudocode). Key requirements:
- Pure function: no I/O, no side effects, takes state + update → returns new state or error
- Checks in order: duplicate update_id → expired → state_root mismatch → operation legality → apply
- Advances epoch by 1 on success
- Recomputes state_root on success
- Records applied update_id to prevent replay

Write tests for every error case listed in MasterWorkPlan_2026-03-22.md section C2.

---

### Step C3: M2 — Quorum Signature Verification

In `crates/rustynet-control/src/membership/quorum.rs` (new):

Implement `verify_quorum(update, state)` — see MasterWorkPlan_2026-03-22.md section C3 for full pseudocode.

Critical: the signature is over the **canonical JSON bytes of the operation payload only** — not the full `MembershipUpdate`. This ensures approvers sign exactly what they see, and the signed bytes cannot be substituted.

```rust
fn operation_canonical_bytes(update: &MembershipUpdate) -> Result<Vec<u8>, MembershipError> {
    // Serialize only the operation field to canonical JSON
    // Include update_id and prev_state_root to bind the signature to this specific update
    let payload = json!({
        "update_id": hex::encode(update.update_id),
        "prev_state_root": hex::encode(update.prev_state_root),
        "operation": &update.operation,
        "expires_at_unix": update.expires_at_unix,
    });
    serde_json::to_vec(&payload).map_err(|e| MembershipError::SerializationError(e.to_string()))
}
```

Add `subtle = "2"` usage for any token/key comparison in this module.

Write all tests listed in MasterWorkPlan_2026-03-22.md section C3.

---

### Step C4: M3 — Persistence and Integrity

In `crates/rustynet-control/src/membership/persistence.rs` (new):

Implement:
- `save_snapshot(state, path)` — atomic write (tmp → fsync → rename), mode 0600
- `load_snapshot(path)` → `Result<MembershipState, PersistenceError>`
- `append_log(update, path)` — appends one JSON line with entry_hash (SHA-256 of prev_hash || update_json)
- `verify_log_integrity(snapshot_path, log_path)` → replays log, verifies hash chain, computes final root, compares to snapshot

On startup integrity failure: return `PersistenceError::IntegrityFailure` — daemon enters restricted-safe mode.

Write tests:
- Valid snapshot + valid log → replays to correct state
- Tampered snapshot byte → PersistenceError::IntegrityFailure
- Tampered log entry → PersistenceError::LogHashChainBroken
- Atomic write: file is never partially written

---

### Step C5: M4–M8 — Daemon Gate, Policy, CLI, Runbook, Gates

**M4 (Daemon gate):** In `crates/rustynetd/src/daemon.rs`, add a pre-provisioning check:
```rust
// Before backend.configure_peer():
membership.check_peer_active(peer.node_id)?;
// check_peer_active returns Err for revoked or unknown nodes
```

**M5 (Policy coupling):** In `crates/rustynet-policy/src/`, wire `MembershipDirectory` so that ACL evaluation for a revoked node always returns `Decision::Deny` regardless of policy rules.

**M6 (CLI commands):**
In `crates/rustynet-cli/src/main.rs`, add:
- `rustynet membership propose <operation>` — outputs unsigned MembershipUpdate JSON
- `rustynet membership sign <update-file>` — signs update with local key, appends Approval
- `rustynet membership apply <update-file>` — verifies quorum + sends to daemon via IPC
- `rustynet membership status` — prints epoch, member count, threshold, last update timestamp

**M7 (Runbook):** Write `documents/operations/MembershipGovernanceRunbook.md` covering:
- How to add a node (propose → multi-sign → apply)
- Emergency node revocation procedure
- Key rotation procedure
- What to do if quorum is lost

**M8 (CI gate):** Ensure `scripts/ci/membership_gates.sh` runs all membership tests and validates the membership report artifact.

---

**After completing all Fleet C steps:**
1. Run `cargo test -p rustynet-control membership -- --nocapture`
2. Run `cargo clippy -p rustynet-control -- -D warnings`
3. Fix all failures
4. Update `documents/operations/MasterWorkPlan_2026-03-22.md` — mark C1 through C5 DONE with evidence paths
5. Commit: `git add -p && git commit -m "Track C: Membership system M0-M8 — schema, engine, quorum, persistence, daemon gate, CLI"`

---

## FLEET D — Security Hardening + Shell Migration Completion

**Responsible for:** Track G (security hardening) and Track D (shell migration) from MasterWorkPlan_2026-03-22.md

**No conflicts with any other fleet.**

**Work in this exact sequence:**

### Step D1: Constant-Time Auth Comparisons (G1)

Search for all equality comparisons on secret material:

```bash
# On Device 1:
grep -rn "== \|\.eq(" crates/rustynet-relay/src/ crates/rustynet-crypto/src/ crates/rustynetd/src/ipc.rs
# Look for comparisons on: token, nonce, session_id, key, hash, signature, passphrase
```

For every hit on secret material:
1. Add `subtle = "2"` to the relevant crate's `Cargo.toml` if not already present
2. Replace `a == b` with `a.ct_eq(&b).into()`
3. Replace `PartialEq::eq` on secret types with `ConstantTimeEq`

Also add to `scripts/ci/security_regression_gates.sh`:
```bash
# Grep gate: fail if raw == comparison on known secret types
# Pattern: token comparison, nonce comparison, session key comparison
if rg -n "session_token\s*==|nonce\s*==|passphrase\s*==" crates/; then
    echo "ERROR: raw equality on secret material — use subtle::ConstantTimeEq" >&2
    exit 1
fi
```

Write tests:
- Token comparison: equal tokens → true (via ct_eq)
- Token comparison: different tokens → false (via ct_eq)
- Code review note: confirm no timing leak in review checklist

---

### Step D2: sha1 and 3des Deprecation Enforcement (G2)

```bash
# On Device 1:
cargo audit --deny warnings 2>&1 | grep -i "sha1\|3des\|des\|sha-1"

# Search for any direct usage in code:
grep -rn "sha1\|sha-1\|3des\|triple.des\|des3" crates/ --include="*.rs" --include="*.toml"

# Check cargo deny config:
cat deny.toml | grep -A5 "bans\|deny"
```

If any sha1 or 3des usage found:
1. Identify which crate and feature gate enables it
2. Disable the feature or replace with sha2/aes
3. Add to `deny.toml` bans section:
```toml
[[bans.deny]]
name = "sha1"
reason = "Deprecated per CryptoDeprecationSchedule.md 2026-03-01"

[[bans.deny]]
name = "md5"
reason = "Cryptographically broken"
```

Update `artifacts/operations/crypto_deprecation_schedule.json`:
```json
{
  "sha1": { "status": "deprecated_enforced", "removal_scheduled": "2026-06-01", "usage_count": 0 },
  "3des": { "status": "deprecated_enforced", "removal_scheduled": "2026-06-01", "usage_count": 0 }
}
```

---

### Step D3: Shell Migration Phase E Final Audit

On Device 1, run this audit against `start.sh`:

```bash
cd ~/Rustynet

# Find any non-wrapper shell logic still not dispatching to Rust:
echo "=== Direct systemctl calls ==="
grep -n "systemctl " start.sh | grep -v "rustynet ops" | grep -v "^[[:space:]]*#"

echo "=== Direct chmod/chown ==="
grep -n "chmod\|chown\|install -m" start.sh | grep -v "rustynet ops" | grep -v "^[[:space:]]*#"

echo "=== Direct openssl/wg key operations ==="
grep -n "openssl\|wg genkey\|wg pubkey" start.sh | grep -v "rustynet ops" | grep -v "^[[:space:]]*#"

echo "=== Direct launchctl calls ==="
grep -n "launchctl " start.sh | grep -v "rustynet ops" | grep -v "^[[:space:]]*#"
```

For each hit that is NOT a thin wrapper dispatch:
1. Implement `rustynet ops <subcommand>` in `crates/rustynet-cli/src/`
2. Replace the shell logic with `rustynet ops <subcommand> || { echo "failed: $?" >&2; exit 1; }`
3. Write a unit test for the new Rust op
4. Verify the wrapper fails closed on non-zero exit

---

### Step D4: Phase I Evidence Collection

Run the two-node E2E to prove argv-only remote execution:

```bash
# On Device 1:
cd ~/Rustynet

# Build first:
cargo build --release -p rustynet-cli

# Set up SSH key (create if needed):
if [ ! -f ~/.ssh/rustynet_lab ]; then
    ssh-keygen -t ed25519 -f ~/.ssh/rustynet_lab -N "" -C "rustynet-lab-ci"
    ssh-copy-id -i ~/.ssh/rustynet_lab.pub mint@192.168.18.53
fi
chmod 600 ~/.ssh/rustynet_lab

# Run E2E with argv-only dispatch:
cargo run -p rustynet-cli -- ops run-debian-two-node-e2e \
    --client-host debian@192.168.18.51 \
    --exit-host mint@192.168.18.53 \
    --ssh-identity-file ~/.ssh/rustynet_lab \
    2>&1 | tee artifacts/phase10/debian_two_node_e2e_argv_only_dry_run.log

echo "E2E exit: $?"
```

If this fails, read the error, fix the issue in `crates/rustynet-cli/src/ops_e2e.rs` (or wherever the op is implemented), and re-run. Fix root causes — do not mask errors.

After success, update `documents/operations/ShellToRustMigrationPlan_2026-03-06.md` Phase I status to COMPLETE with the log artifact path as evidence.

---

### Step D5: Backend Agility — Real Second Backend (Track F)

Check `Cargo.toml` for whether `boringtun` is already a dependency. If not, evaluate if adding it is appropriate given the project's dependency governance. If the project uses `cargo deny`, check `deny.toml` before adding.

If `boringtun` is acceptable:
1. Create `crates/rustynet-backend-userspace/Cargo.toml` with `boringtun` dependency
2. Implement `TunnelBackend` trait for the userspace WireGuard backend
3. Add conformance tests that run against both `rustynet-backend-wireguard` and `rustynet-backend-userspace`
4. Update `artifacts/operations/backend_agility_report.json`:
   ```json
   "additional_backend_paths": ["rustynet-backend-userspace"],
   "conformance_passed": true
   ```

If `boringtun` is not acceptable (check license or deny.toml):
- Write comprehensive `TunnelBackend` conformance test suite that `rustynet-backend-stub` must pass
- Document that stub passes all conformance tests as evidence of swappable design
- Note in the master plan that a real production second backend is deferred with rationale

---

**After completing all Fleet D steps:**
1. Run `cargo fmt --all -- --check` and `cargo clippy -- -D warnings` on Device 1
2. Fix all issues
3. Update `documents/operations/MasterWorkPlan_2026-03-22.md` — mark D1-D5, G1-G2 DONE
4. Commit: `git add -p && git commit -m "Track D+G: Constant-time auth, sha1 deprecation, shell migration completion, Phase I evidence"`

---

## FLEET E — Evidence Refresh and Cross-Network Reports

**Start ONLY after Fleets A and B have committed their work.** This fleet is purely about running tests and collecting artifacts.

### Step E1: Lab Machine Setup

On Device 1:
```bash
# Ensure both machines reachable:
ssh -o ConnectTimeout=5 debian@192.168.18.51 'echo "Device 1 OK"' || echo "DEVICE 1 UNREACHABLE"
ssh -o ConnectTimeout=5 mint@192.168.18.53 'echo "Device 2 OK"' || echo "DEVICE 2 UNREACHABLE"

# Set up passwordless sudo:
echo "tempo" | ssh debian@192.168.18.51 'sudo -S bash -c "echo debian ALL=\(ALL\) NOPASSWD:ALL > /etc/sudoers.d/rustynet-ci && chmod 440 /etc/sudoers.d/rustynet-ci"'
echo "tempo" | ssh mint@192.168.18.53 'sudo -S bash -c "echo mint ALL=\(ALL\) NOPASSWD:ALL > /etc/sudoers.d/rustynet-ci && chmod 440 /etc/sudoers.d/rustynet-ci"'

# Sync repo to Device 2:
rsync -az --exclude target/ --exclude .git/ ~/Rustynet/ mint@192.168.18.53:~/Rustynet/
```

### Step E2: Build and Deploy on Both Machines

```bash
# Device 1 (already has source):
cargo build --release -p rustynetd -p rustynet-cli

# Install on Device 1:
sudo cp target/release/rustynetd /usr/local/bin/rustynetd
sudo cp target/release/rustynet /usr/local/bin/rustynet
sudo cp scripts/systemd/rustynetd.service /etc/systemd/system/
sudo systemctl daemon-reload

# Build and install on Device 2:
ssh mint@192.168.18.53 'cd ~/Rustynet && cargo build --release -p rustynetd -p rustynet-cli'
ssh mint@192.168.18.53 'sudo cp ~/Rustynet/target/release/rustynetd /usr/local/bin/rustynetd && sudo cp ~/Rustynet/target/release/rustynet /usr/local/bin/rustynet'
```

### Step E3: Network Namespace Setup for Cross-Network Simulation

Both machines are on `192.168.18.0/24`. Use virtual interfaces to create distinct network IDs:

```bash
# On Device 1 — create virtual "client network":
sudo ip link add veth-rn-client type veth peer name veth-rn-client-peer
sudo ip addr add 10.200.1.1/24 dev veth-rn-client
sudo ip link set veth-rn-client up
sudo ip link set veth-rn-client-peer up
# This gives Device 1 an address in the 10.200.1.0/24 space (distinct from Device 2)

# On Device 2 — create virtual "exit network":
ssh mint@192.168.18.53 'sudo ip link add veth-rn-exit type veth peer name veth-rn-exit-peer && sudo ip addr add 10.200.2.1/24 dev veth-rn-exit && sudo ip link set veth-rn-exit up && sudo ip link set veth-rn-exit-peer up'

# The Rustynet tunnel will be established between the real IPs (192.168.18.x)
# The network_id labels (net-10-200-1, net-10-200-2) document the virtual network context
# The topology heuristic distinguishes by network_id label, which is explicitly distinct
```

### Step E4: Run CI Gates on Device 1

```bash
cd ~/Rustynet
./scripts/ci/phase10_gates.sh 2>&1 | tee /tmp/phase10_gates.log
./scripts/ci/membership_gates.sh 2>&1 | tee /tmp/membership_gates.log
./scripts/ci/security_regression_gates.sh 2>&1 | tee /tmp/security_gates.log
./scripts/ci/phase10_cross_network_exit_gates.sh 2>&1 | tee /tmp/crossnet_gates.log || true
# Note: cross_network gates may fail until E5 evidence is collected — that is expected
```

Fix any gate failures before proceeding.

### Step E5: Fresh Install OS Matrix Refresh

```bash
# Re-run the live lab orchestrator to get fresh evidence at current HEAD:
bash scripts/e2e/live_linux_lab_orchestrator.sh \
  --primary-host debian@192.168.18.51 \
  --secondary-host mint@192.168.18.53 \
  --ssh-identity-file ~/.ssh/rustynet_lab \
  --stages "clean,bootstrap,baseline,soak" \
  --output-dir artifacts/phase10 \
  2>&1 | tee /tmp/live_lab_orchestrator.log

echo "Orchestrator exit: $?"
ls -la artifacts/phase10/fresh_install_os_matrix_report.json
```

The new report must capture the current HEAD git commit SHA and have all scenarios status: pass.

### Step E6: Run Cross-Network E2E Suites

Run in order. Each must produce a passing report before the next starts:

```bash
# Generate node IDs if not already enrolled:
# (run bootstrap sequence from live_lab_common.sh)

# 1. Direct remote exit:
bash scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh \
  --ssh-identity-file ~/.ssh/rustynet_lab \
  --client-host debian@192.168.18.51 \
  --exit-host mint@192.168.18.53 \
  --client-node-id <CLIENT_NODE_ID> \
  --exit-node-id <EXIT_NODE_ID> \
  --client-network-id net-10-200-1 \
  --exit-network-id net-10-200-2 \
  --nat-profile baseline_lan \
  --impairment-profile none

# 2. Relay remote exit (Device 1 acts as both client and relay in different roles):
bash scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh \
  --ssh-identity-file ~/.ssh/rustynet_lab \
  --client-host debian@192.168.18.51 \
  --exit-host mint@192.168.18.53 \
  --relay-host debian@192.168.18.51 \
  --client-node-id <CLIENT_NODE_ID> \
  --exit-node-id <EXIT_NODE_ID> \
  --relay-node-id <RELAY_NODE_ID> \
  --client-network-id net-10-200-1 \
  --exit-network-id net-10-200-2 \
  --relay-network-id net-10-200-1 \
  --nat-profile baseline_lan \
  --impairment-profile none

# 3-6: Failback, adversarial, DNS, soak — same pattern
```

For each failing test: read the log, fix the underlying issue in the relevant script or daemon code, re-run. Do not mark as done until the report shows `"status": "pass"`.

### Step E7: Final Gate Validation

```bash
cargo run -p rustynet-cli -- ops validate-cross-network-remote-exit-reports \
  --artifact-dir artifacts/phase10 \
  --require-pass-status \
  --output artifacts/phase10/cross_network_remote_exit_schema_validation.md

cargo run -p rustynet-cli --bin phase10_cross_network_exit_gates 2>&1 | tee /tmp/final_crossnet_gates.log
echo "Cross-network gate exit: $?"
```

---

**After completing all Fleet E steps:**
1. Update `documents/operations/MasterWorkPlan_2026-03-22.md` — mark E1-E7 DONE with artifact paths
2. Update `documents/operations/CrossNetworkReliabilitySecurityAIExecutionPlan_2026-03-22.md` — mark WS-4 items DONE with evidence
3. Commit: `git add artifacts/ && git commit -m "Track E: Fresh OS matrix evidence + 6 cross-network reports all passing"`

---

## FINAL CONSOLIDATION (After All Fleets Complete)

After all five fleets have committed their work, the coordinating agent must:

### 1. Run Full Gate Suite on Device 1

```bash
cd ~/Rustynet
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features 2>&1 | tee /tmp/final_test_results.txt
cargo audit --deny warnings
cargo deny check bans licenses sources advisories
./scripts/ci/phase10_gates.sh
./scripts/ci/phase10_cross_network_exit_gates.sh
./scripts/ci/membership_gates.sh
./scripts/ci/security_regression_gates.sh
./scripts/ci/secrets_hygiene_gates.sh
./scripts/ci/traversal_adversarial_gates.sh
./scripts/ci/no_leak_dataplane_gate.sh
./scripts/ci/supply_chain_integrity_gates.sh
```

Fix every failure. Run the full suite again after fixing until all pass with exit code 0.

### 2. Final Document Update

Update `documents/operations/MasterWorkPlan_2026-03-22.md`:
- Change every completed item from its current status to `[DONE — <evidence>]`
- List any items that remain blocked with `[BLOCKED — <reason>]`
- Add `## Session Log` section with one row per fleet per completed workstream
- Add `## Final Gate Results` section with output of each gate script

Update `documents/operations/CrossNetworkReliabilitySecurityAIExecutionPlan_2026-03-22.md`:
- Append session log rows for all completed workstream items
- Update `Last Updated (UTC)` to current time
- Move completed items from `IN_PROGRESS` to `DONE` with evidence paths
- Update `Active Blockers` if any are resolved

### 3. Final Commit

```bash
git add -A
git commit -m "$(cat <<'EOF'
Complete Rustynet implementation sprint: HP-2/HP-3 relay transport, membership system,
cross-network runtime hardening, shell migration, evidence refresh

Tracks completed:
- Track A: STUN candidate gathering, simultaneous-open traversal, HP-3 relay transport,
           HP-4 hysteresis, HP-5 gate coverage
- Track B: WS-1 pull-based state refresh, WS-2 endpoint mobility, WS-3 proactive
           traversal freshness, WS-4 validation gates
- Track C: Membership M0-M8 (schema, engine, quorum, persistence, daemon gate, CLI)
- Track D: Shell migration completion, Phase I evidence, constant-time auth, sha1 removal
- Track E: Fresh OS matrix evidence, 6 cross-network reports all passing

All cargo gates pass. All required evidence artifacts present and valid.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>
EOF
)"
```

---

## WHAT TO DO IF BLOCKED

If you hit a genuine blocker (lab machine unreachable, dependency missing, architectural conflict):

1. **Document it immediately** in `documents/operations/MasterWorkPlan_2026-03-22.md` with `[BLOCKED — <exact reason>]`
2. **Move to the next independent item** — do not stop working. Every track has items that do not depend on the blocker
3. **For lab machine issues:** try the other machine. If both are unreachable, complete all non-lab work (Tracks A, B, C, D code and unit tests) and document E as blocked
4. **For compilation errors on cross-platform code:** ensure you are running on Device 1 (Debian), not on Windows
5. **Never fabricate evidence.** If a test does not pass, fix it or document it as blocked — do not write a passing artifact manually

---

## ANTI-PATTERNS TO AVOID (WILL CAUSE REJECTION)

- Adding `#[allow(clippy::...)]` to suppress new warnings instead of fixing them
- Using `unwrap()` on `Result` or `Option` in production code paths
- Writing `TODO` or `FIXME` comments in completed-scope code
- Marking an item DONE without pointing to a passing test or CI gate
- Softening a security check to make a test pass
- Implementing a "temporary" bypass that will be fixed later
- Skipping test writing because the implementation "looks correct"
- Assuming the test environment is clean without verifying
- Writing to `artifacts/` without running the corresponding gate that validates those artifacts

---

*This prompt covers all remaining work from `documents/operations/MasterWorkPlan_2026-03-22.md`. The five-fleet structure allows Tracks A, B, C, D, and E to run simultaneously, with Track E gated on A+B completion. Expected total implementation: significant. Quality bar: production-grade, security-first, zero shortcuts.*
