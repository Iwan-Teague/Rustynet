# Rustynet Master Work Plan — 2026-03-22

## Purpose

This document is the single authoritative reference for all remaining implementation work across the entire Rustynet project. It is organized into parallel development tracks so that multiple agents or developers can work simultaneously with minimal interference. Each item includes specific files to touch, interfaces to implement, tests to write, and acceptance criteria.

**Precedence:** `Requirements.md` > `SecurityMinimumBar.md` > scope docs > this document. If this plan conflicts with those, the higher-precedence document wins.

---

## Quick-Reference: Parallel Track Map

```
┌─────────────────────────────────────────────────────────────────────┐
│  TRACK A          TRACK B          TRACK C      TRACK D    TRACK E  │
│  NAT Traversal    Cross-Network    Membership   Shell→Rust Evidence  │
│  & Relay          Runtime Hard.    System       Migration  Refresh   │
│                                                                      │
│  HP-2 remaining   WS-1 refresh     M0 schema    Phase E    OS Matrix │
│  HP-3 relay svc   WS-2 mobility    M1 reducer   Phase I    Crossnet  │
│  HP-4 controller  WS-3 freshness   M2 quorum    evidence   reports   │
│  HP-5 gates       WS-4 gates       M3 persist               ↑       │
│       ↓                ↓           M4 daemon     (no deps) DEPENDS  │
│  BLOCKS WS-2     BLOCKS Track E   M5 policy                on A+B   │
└─────────────────────────────────────────────────────────────────────┘
```

**Can run fully in parallel from day one:**
- Track A and Track C (Membership) — zero shared files
- Track A and Track D (Shell migration) — zero shared files
- Track C and Track D — zero shared files
- Track A (HP-3 relay) and Track B (WS-1, WS-3) — different subsystems

**Has ordering constraints:**
- Track B (WS-2 endpoint mobility) should start after HP-2 simultaneous-open probing exists in Track A — they touch the same `traversal.rs` file
- Track E (evidence refresh) must wait for Track A and Track B to be substantially complete
- Track B (WS-4 validation gates) must wait for WS-1/WS-2/WS-3 to be done

---

## TRACK A — NAT Traversal and Production Relay Transport

**Owner area:** `crates/rustynetd/src/traversal.rs`, `crates/rustynet-relay/`, `crates/rustynet-backend-api/`

**Why this matters:** The whole point of Rustynet is to connect devices "from anywhere" without manual port forwarding. Without HP-3 (real relay transport) and the remaining HP-2 (simultaneous-open WAN traversal), the relay path is just a routing label — no actual packets are relayed. Direct connection only works when both sides happen to have reachable IPs.

**Safe to run in parallel with:** Track C, Track D, and Track B (WS-1/WS-3 only).

**Conflicts with:** Track B (WS-2) — both touch `traversal.rs`. Coordinate so they are not editing the same functions simultaneously.

---

### A1 — HP-2 Remaining: Full Simultaneous-Open WAN Traversal

**Status:** Partial. One-sided probe executor exists. Full simultaneous-open (both sides send simultaneously to each other's candidates) is missing.

**What exists already:**
- `TraversalEngine` in `crates/rustynetd/src/traversal.rs` runs a bounded one-sided probe loop
- Backend handshake-recency evidence (`peer_latest_handshake_unix`) exists
- `TraversalAuthorityMode::EnforcedV1` is active — assignment endpoints cannot override traversal
- Signed traversal hint validation, watermark, freshness all work

**What is missing:**

**A1-a: STUN server-reflexive candidate gathering**

Currently the daemon only knows about local candidates (interface IPs). To punch through NAT, it needs server-reflexive candidates (the public IP:port that a STUN server observes). Without this, two NATed nodes cannot discover each other's public-facing endpoints.

Files to modify:
- `crates/rustynetd/src/traversal.rs` — add `CandidateGatherer` struct
- `crates/rustynetd/src/daemon.rs` — invoke gatherer during bootstrap

Implementation:
```
1. Add a CandidateGatherer that:
   - binds the WireGuard UDP socket (or a dedicated probe socket)
   - sends STUN Binding Request to a configured STUN server (RFC 5389)
   - parses STUN Binding Response to extract XOR-MAPPED-ADDRESS
   - records the server-reflexive candidate (ip, port, type=srflx)
   - applies a deadline so it never blocks startup
2. Add config fields to daemon/traversal config:
   - stun_servers: Vec<SocketAddr>  (configurable, defaults to well-known public STUN)
   - stun_gather_timeout_ms: u64    (default 2000)
3. Integrate with TraversalCandidate types:
   - CandidateType::Host (local interface)
   - CandidateType::ServerReflexive (STUN-observed)
   - CandidateType::Relay (relay service)
4. Signed endpoint-hint bundles issued by control must include srflx candidates
   so peers receive the public endpoint to try
```

Tests required:
- Unit test: STUN response parser handles valid XOR-MAPPED-ADDRESS, malformed frames, truncated input, wrong magic cookie — no panic, returns Err
- Unit test: candidates are deduplicated (same IP:port from two sources = one entry)
- Unit test: gather times out correctly and returns partial results (not zero results on STUN failure)
- Integration test (netns): create a netns with NAT masquerade, bind a mock STUN server inside, verify gatherer extracts the post-NAT address

Acceptance: `traversal_path_selection_report.json` must gain a `stun_reflexive_candidates_gathered: pass` check.

---

**A1-b: Simultaneous-Open Coordination**

Currently, only the client side sends probe packets. True simultaneous-open requires both sides to start sending at approximately the same time so that both NAT tables have entries before the first packet arrives.

Files to modify:
- `crates/rustynetd/src/traversal.rs` — add simultaneous-open orchestration
- `crates/rustynet-control/` — add traversal coordination signal (both sides need to start probing at the same time)

Implementation:
```
1. Add a TraversalCoordinationRecord issued by control containing:
   - session_id: [u8; 16]  (random, shared between both peers)
   - probe_start_unix: u64 (Unix timestamp, both sides begin at this time)
   - peer_a: NodeId
   - peer_b: NodeId
   - signed by control key, short TTL (30s max)

2. In rustynetd traversal engine:
   - receive coordination record
   - wait until probe_start_unix (bounded wait, max 10s)
   - at that moment, send UDP probe packets to all of peer's candidates
   - simultaneously, peer does the same
   - first handshake observed = direct path established

3. Bounded retry policy:
   - max 5 simultaneous-open rounds
   - 500ms between rounds
   - if no handshake within rounds*spacing + grace, declare direct failed
   - fall through to relay (A2)

4. Record transition reason:
   - PathMode::Direct { reason: DirectReason::SimultaneousOpen }
   - PathMode::Relay { reason: RelayReason::DirectFailed { rounds: N } }
```

Tests required:
- Unit test: coordination record with future probe_start waits, then fires; past probe_start fires immediately
- Unit test: expired coordination record (> 30s old) is rejected
- Unit test: after N failed rounds, transitions to relay decision — no additional attempts
- Integration test (two netns with iptables NAT): verify two nodes establish direct path through simulated NAT using simultaneous-open

---

### A2 — HP-3: Production Relay Transport Service

**Status:** Not built. `rustynet-relay` is a fleet selector only — it chooses a relay but cannot forward packets.

**What needs to be built:**

This is the most substantial remaining code item in the entire project. The relay service must:
1. Accept authenticated node sessions over a control channel
2. Forward encrypted WireGuard UDP packets between two authenticated sessions
3. Never decrypt — only forward ciphertext
4. Apply per-node rate limits and abuse controls
5. Integrate with regional relay selection from `rustynet-relay`

**A2-a: Relay Session Protocol**

Files to create/modify:
- `crates/rustynet-relay/src/transport.rs` (new) — session auth and packet forwarding
- `crates/rustynet-relay/src/session.rs` (new) — per-session state
- `crates/rustynet-relay/src/rate_limit.rs` (new) — per-node rate and abuse controls
- `crates/rustynet-relay/src/lib.rs` — wire everything together

Protocol design (keep it minimal and auditable):
```
Client → Relay: RelayHello {
    node_id: NodeId,          // who is connecting
    peer_node_id: NodeId,     // who they want to reach
    session_token: [u8; 32],  // short-lived token from control plane, signed
    nonce: [u8; 16],          // replay prevention
}

Relay → Client: RelayHelloAck {
    session_id: [u8; 16],     // assigned session id
    allocated_port: u16,      // UDP port for this session on relay
} | RelayHelloReject { reason: RejectReason }

Client → Relay: RelayPacket { session_id, payload: [u8] }  // ciphertext only
Relay → Client: RelayPacket { session_id, payload: [u8] }  // forwarded from peer
```

Security requirements:
- Session token must be validated against control key signature before session is accepted (no unsigned sessions)
- Session token must have a short TTL (≤ 120s from issuance)
- session_token must include the peer_node_id in its signed payload — cannot be reused to reach a different peer
- Reject immediately if session_token is stale, signature invalid, or nonce replayed
- Relay never reads payload bytes for routing — only session_id determines forwarding destination
- After session auth: relay matches two sessions (A→B and B→A) by (node_id, peer_node_id) pair, then bidirectionally forwards packets

Rate limiting per session:
- max packet rate: 10,000 pps (configurable)
- max bandwidth: 100 Mbps (configurable)
- max concurrent sessions per node: 8 (configurable)
- on limit exceeded: drop packets silently (not RST/reject — avoid amplification)

Implementation steps:
```
1. Add relay session token type to rustynet-control:
   - RelaySessionToken { node_id, peer_node_id, relay_id, issued_at_unix, expires_at_unix, nonce }
   - signed by control key (same signer as traversal hints)
   - issued on demand when a node needs a relay session

2. Add relay server binary or integrate into rustynetd:
   - binds UDP port for relay traffic
   - binds TCP control port for session auth
   - session lifecycle: Hello → verify token → allocate → active → timeout/teardown

3. Integrate into rustynetd relay path:
   - when TraversalDecision::Relay is made, daemon contacts relay control port
   - sends RelayHello with token
   - receives allocated UDP port
   - programs WireGuard peer endpoint to relay_addr:allocated_port
   - sets up keepalive to maintain relay session

4. Session cleanup:
   - idle sessions (no packets for 30s) are torn down
   - on WireGuard peer removal, tear down associated relay session
   - relay server garbage collects half-open sessions
```

Tests required:
- Unit test: invalid session token (bad signature) → rejected, no session allocated
- Unit test: expired session token → rejected
- Unit test: replayed nonce → rejected
- Unit test: session token for wrong peer → rejected
- Unit test: two matching sessions (A→B, B→A) correctly pair and forward packets bidirectionally
- Unit test: rate limit enforcement — packets above limit are silently dropped, session not terminated
- Unit test: session idle timeout — session is cleaned up after idle period
- Integration test: two nodes in separate netns with direct UDP blocked by iptables; verify they can exchange WireGuard packets through relay, decrypt successfully on the other side

---

**A2-b: Daemon Relay Session Integration**

Files to modify:
- `crates/rustynetd/src/traversal.rs` — add relay session establishment
- `crates/rustynetd/src/phase10.rs` — integrate relay session into path controller
- `crates/rustynetd/src/daemon.rs` — add relay session state tracking

Implementation:
```
1. When TraversalDecision::Relay:
   a. Request relay session token from control (or load pre-issued token)
   b. Connect to relay control port, send RelayHello
   c. Receive allocated port (relay_addr:allocated_port)
   d. Update WireGuard peer endpoint to relay_addr:allocated_port
   e. Record: PathMode::Relay { relay_addr, relay_session_id, established_at }

2. Relay session keepalive:
   - send keepalive packet every 25s to prevent idle timeout
   - on keepalive failure (relay unreachable), re-establish or fail-closed

3. Relay session teardown on path change:
   - when direct path is re-established (failback):
     a. update WireGuard endpoint to direct endpoint
     b. send relay session teardown to relay
     c. record: PathMode::Direct { reason: DirectReason::RelayFailback }

4. Status/netcheck must reflect relay session:
   - relay_session_id, relay_addr, relay_session_age_secs
   - distinct from traversal probe state
```

Tests required:
- Integration test: direct path blocked → relay session established → direct path unblocked → relay failback occurs, relay session torn down, direct path active
- Unit test: relay session keepalive failure → re-establish attempted, then fail-closed if relay unreachable
- Unit test: on peer removal, relay session is torn down (no dangling sessions)

---

### A3 — HP-4: Seamless Path Controller Completion

**Status:** The `Phase10Controller` in `crates/rustynetd/src/phase10.rs` acts as the path controller but lacks hysteresis (stability window before committing to a path change) and full live-handoff-under-load proof.

**What is needed:**

**A3-a: Hysteresis for Direct→Relay and Relay→Direct transitions**

Without hysteresis, a flapping network causes rapid path switching that can disrupt active connections. Hysteresis requires a path to be stable for a minimum duration before committing.

Files to modify:
- `crates/rustynetd/src/phase10.rs` — add hysteresis policy to path controller
- `crates/rustynetd/src/traversal.rs` — expose stability window

Implementation:
```
Add to Phase10Controller:
  direct_stability_window_ms: u64    // how long direct must be healthy before committing (default: 3000)
  relay_stability_window_ms: u64     // how long relay must be healthy before committing (default: 5000)
  last_path_change_at: Option<Instant>
  pending_path_mode: Option<PathMode>  // candidate mode not yet committed

Path change logic:
  fn consider_path_change(&mut self, candidate: PathMode) {
      if candidate == self.current_path { return; }
      if self.pending_path_mode != Some(candidate) {
          // New candidate — start stability window
          self.pending_path_mode = Some(candidate);
          self.pending_since = Instant::now();
          return;
      }
      // Existing candidate — check if stability window elapsed
      let stability_window = match candidate {
          PathMode::Direct => self.direct_stability_window_ms,
          PathMode::Relay  => self.relay_stability_window_ms,
      };
      if self.pending_since.elapsed() >= Duration::from_millis(stability_window) {
          self.commit_path_change(candidate);  // one hardened commit path
      }
  }
```

Tests required:
- Unit test: path does not switch when candidate flaps within stability window
- Unit test: path switches after candidate is stable for full window duration
- Unit test: fail-closed transition bypasses hysteresis (security > stability)
- Integration test: induce flapping NAT condition, verify path changes < 3 times in 60s window

---

**A3-b: Live Handoff Under Load Evidence**

The phase10.md exit criteria requires "live handoff under load with no policy bypass and no leak." This needs an explicit test and artifact.

Files to create:
- `scripts/e2e/live_linux_path_handoff_under_load_test.sh` — test script

Test flow:
```
1. Bootstrap two-node mesh with direct exit active
2. Start iperf3 or netperf traffic through exit node (sustained load)
3. Block direct UDP path using iptables
4. Measure:
   a. time until relay path active (reconnect_ms)
   b. packet loss during transition (sampled by ping -c 60 to exit)
   c. absence of unprotected egress during transition (no route via non-rustynet0 interface)
   d. ACL/DNS/kill-switch invariants maintained (check nftables rules still present)
5. Unblock direct path, measure:
   a. time until failback to direct (failback_ms)
   b. same leak checks
6. Write report: live_linux_path_handoff_under_load_report.json
   Required checks:
   - direct_to_relay_reconnect_ms <= 30000
   - relay_to_direct_failback_ms <= 30000
   - no_unprotected_egress_during_transition: pass
   - acl_invariants_maintained: pass
   - dns_fail_closed_maintained: pass
```

---

### A4 — HP-5: Hardening and Gate Coverage

**Status:** Not started as a formal gate. Some individual tests exist.

**A4-a: Traversal Adversarial Test Suite**

Files: `scripts/e2e/live_linux_cross_network_traversal_adversarial_test.sh` (exists, needs full implementation)

Required test scenarios:
```
1. Forged endpoint hint (wrong signature):
   - Inject a traversal bundle with invalid ED25519 signature
   - Verify daemon rejects it and remains on current path (does not fail-closed on first reject)
   - Verify rejection is logged at warn level

2. Replayed endpoint hint (stale nonce):
   - Capture a valid bundle, wait for it to expire, re-present it
   - Verify daemon rejects based on watermark/freshness check

3. Rogue endpoint injection (valid signature, wrong candidate set):
   - Issue bundle with an IP that the node does not actually own
   - Verify daemon does not program that IP as the peer endpoint

4. Candidate flooding:
   - Issue bundle with MAX_CANDIDATES + 1 entries
   - Verify daemon rejects or truncates, does not panic/OOM

5. Control-surface exposure:
   - Verify rustynetd does not expose an HTTP/RPC port on any interface
   - Verify daemon socket is owner-only (0600)
   - Verify no privileged helper binary is world-executable
```

**A4-b: Path Transition ACL Preservation**

This gate must prove that during any direct↔relay transition, the ACL/firewall/kill-switch rules never relax.

Implementation:
```
In scripts/ci/traversal_adversarial_gates.sh, add:
1. Snapshot nftables ruleset before path transition
2. Trigger path transition
3. Snapshot nftables ruleset at every 500ms interval during transition
4. Compare each snapshot to baseline — any rule removal = fail
5. Verify final ruleset equals baseline after transition completes
```

**A4-c: VM Matrix Gate (HP-5)**

The HP-5 acceptance requires gate coverage on Debian, Ubuntu, Fedora, Mint, and macOS. The fresh_install_os_matrix already covers these for basic connectivity. HP-5 specifically needs traversal/relay path evidence on each OS.

Add to `scripts/ci/phase10_hp2_gates.sh`:
```
For each OS in the VM matrix:
- Run traversal_path_selection test (direct probe decision correct)
- Run relay_fallback test (relay path entered when direct blocked)
- Run replay_rejected test (stale bundle rejected)
- Run fail_closed_on_invalid_traversal test
- Collect per-OS traversal report
```

---

## TRACK B — Cross-Network Runtime Hardening

**Owner area:** `crates/rustynetd/src/daemon.rs`, `crates/rustynetd/src/traversal.rs`, `crates/rustynetd/src/phase10.rs`, `crates/rustynetd/src/ipc.rs`

**Why this matters:** Even with working relay transport (Track A), the daemon currently loses connectivity if the controller changes networks or the node's underlay IP changes. Track B makes connectivity self-healing without operator intervention.

**Safe to run in parallel with:** Track C, Track D, Track A (HP-3 relay, HP-4). Coordinate with Track A on `traversal.rs` changes (WS-2 and HP-2 touch the same file).

---

### B1 — WS-1: Control-Plane Reachability Independence

**Goal:** The daemon must not depend on the operator's current underlay network to stay alive. It fetches signed state independently over the Rustynet control channel.

**B1-a: Pull-Based Signed State Fetch Channel (WS1-01)**

Currently: the daemon loads signed state from disk at startup and on explicit IPC command. There is no autonomous outbound fetch.

Files to modify:
- `crates/rustynetd/src/daemon.rs` — add `StateFetcher` component
- `crates/rustynetd/src/phase10.rs` — wire fetcher into refresh flow

Implementation:
```rust
// New component: StateFetcher
struct StateFetcher {
    control_endpoint: Url,          // https endpoint of control plane
    tls_trust_roots: RootCertStore, // pinned trust roots, not system roots
    node_identity: Ed25519Keypair,  // for mTLS client auth
    watermarks: WatermarkStore,     // tracks last-seen watermarks per bundle type
}

impl StateFetcher {
    /// Fetch one signed bundle from control. Verifies signature + watermark before returning.
    fn fetch_assignment(&self) -> Result<SignedAssignmentBundle, FetchError> {
        let raw = self.http_get("/v1/assignment")?;       // HTTP GET with mTLS
        let bundle = parse_signed_assignment_bundle(&raw)
            .map_err(FetchError::ParseError)?;
        bundle.verify(&self.assignment_verifier_key)       // signature check
            .map_err(FetchError::SignatureInvalid)?;
        self.watermarks.advance_assignment(&bundle.watermark) // anti-replay
            .map_err(FetchError::WatermarkRejected)?;
        bundle.check_freshness(SystemTime::now(), MAX_CLOCK_SKEW) // freshness
            .map_err(FetchError::Stale)?;
        Ok(bundle)
    }

    // Same pattern for: fetch_traversal, fetch_trust, fetch_dns_zone
    // Each has its own verifier key and watermark namespace
}
```

Important security constraints:
- TLS trust roots must be pinned at install time, not loaded from system CA store
- mTLS client certificate derived from node's identity key (same key as WireGuard identity)
- If fetch fails (network unreachable, cert invalid, signature bad), return `Err` — never return stale state
- Watermark store persisted atomically to disk with strict permissions (0600)

Tests required:
- Unit test: valid bundle returned from mock server → parsed, verified, watermark advanced → Ok
- Unit test: invalid signature from server → `FetchError::SignatureInvalid`, watermark not advanced
- Unit test: stale bundle (expired freshness) → `FetchError::Stale`, watermark not advanced
- Unit test: replayed watermark (watermark ≤ current) → `FetchError::WatermarkRejected`
- Unit test: network unreachable → `FetchError::Network`, existing on-disk state unchanged
- Unit test: two concurrent fetches → second fetch sees watermark already advanced by first, rejects (idempotency via watermark)

---

**B1-b: Node-Side Periodic Refresh (WS1-02)**

The daemon needs a background loop that periodically refreshes signed state before it expires.

Files to modify:
- `crates/rustynetd/src/daemon.rs` — add refresh scheduler to daemon event loop

Implementation:
```rust
struct RefreshScheduler {
    assignment_ttl_secs: u64,    // from current bundle
    traversal_ttl_secs: u64,
    trust_ttl_secs: u64,
    pre_expiry_margin_secs: u64, // default: 120s before expiry
    jitter_max_secs: u64,        // default: 30s (prevent thundering herd)
}

impl RefreshScheduler {
    fn next_refresh_at(&self, bundle_expires_at: SystemTime) -> Instant {
        let margin = Duration::from_secs(self.pre_expiry_margin_secs);
        let jitter = Duration::from_secs(rand::random::<u64>() % self.jitter_max_secs);
        let target = bundle_expires_at - margin + jitter;
        // Never schedule in the past
        let now = SystemTime::now();
        if target <= now {
            Instant::now() + Duration::from_secs(5)  // fire soon
        } else {
            Instant::now() + target.duration_since(now).unwrap()
        }
    }
}

// In daemon event loop:
loop {
    select! {
        _ = assignment_refresh_timer => {
            match fetcher.fetch_assignment() {
                Ok(bundle) => {
                    controller.apply_signed_assignment(bundle)?; // one hardened apply path
                    assignment_refresh_timer.reset(scheduler.next_refresh_at(bundle.expires_at));
                }
                Err(e) => {
                    log::warn!("assignment refresh failed: {e}");
                    // Do NOT fail-closed on first failure — retry with backoff
                    assignment_refresh_timer.reset(Instant::now() + RETRY_BACKOFF);
                    // If expiry passes without successful refresh → fail-closed
                    if SystemTime::now() > current_assignment.expires_at {
                        controller.transition_fail_closed("assignment expired without refresh");
                    }
                }
            }
        }
        // Same for traversal, trust, dns_zone timers
    }
}
```

Tests required:
- Unit test: refresh fires at `expires_at - margin + jitter`, not after `expires_at`
- Unit test: jitter is bounded (never exceeds `jitter_max_secs`)
- Unit test: on failed refresh, daemon retries without fail-closing immediately
- Unit test: if refresh fails and bundle expires, daemon transitions to fail_closed
- Unit test: successful refresh resets timer to new bundle's expiry window
- Integration test: daemon with short-TTL bundle (10s), verify refresh fires before expiry, daemon never enters fail_closed

---

**B1-c: Complete `state refresh` IPC Command (WS1-03)**

The skeleton IPC command exists in `ipc.rs` and `daemon.rs`. It needs to be fully wired to the signed-state refresh flow.

Files to modify:
- `crates/rustynetd/src/ipc.rs` — complete IPC command parser/handler
- `crates/rustynetd/src/daemon.rs` — implement `handle_state_refresh_command`

Implementation:
```rust
// In ipc.rs — command is already parsed, handler needs completion:
IpcCommand::StateRefresh { target: RefreshTarget } => {
    // Verify caller credential (SO_PEERCRED)
    let cred = get_peer_credential(&stream)?;
    if !is_authorized_for_refresh(&cred) {
        return Ok(IpcResponse::Denied { reason: "insufficient privilege" });
    }
    // Dispatch to daemon
    daemon_tx.send(DaemonMessage::TriggerStateRefresh { target })?;
    // Wait for result (bounded timeout)
    match daemon_rx.recv_timeout(Duration::from_secs(30)) {
        Ok(DaemonMessage::StateRefreshComplete { result }) => {
            IpcResponse::StateRefreshResult { result }
        }
        Ok(_) | Err(_) => IpcResponse::Error { message: "refresh timed out" }
    }
}

// In daemon.rs — the actual refresh:
fn handle_state_refresh(&mut self, target: RefreshTarget) -> RefreshResult {
    // ONE path: fetch → verify → apply
    // Never applies unverified state even if caller is root
    match target {
        RefreshTarget::All => {
            self.refresh_assignment()?;
            self.refresh_traversal()?;
            self.refresh_trust()?;
            self.refresh_dns_zone()?;
        }
        RefreshTarget::Assignment => self.refresh_assignment()?,
        // etc.
    }
    // If any refresh fails → return Err, caller gets failure reason
    // Daemon stays in current state (does not partially apply)
    RefreshResult::Success
}
```

Tests required:
- Unit test: authorized caller (uid=root or rustynet group) → refresh triggers, result returned
- Unit test: unauthorized caller (non-root, non-rustynet) → Denied response, no refresh attempted
- Unit test: refresh returns Err (bad signature) → IpcResponse indicates failure, daemon state unchanged
- Unit test: `state refresh assignment` only refreshes assignment, not traversal/trust/dns
- Integration test (Linux): `rustynet state refresh` CLI command → daemon performs fetch → CLI prints result

---

### B2 — WS-2: Endpoint Mobility and Re-establishment

**Goal:** When the daemon's underlay IP changes (interface up/down, DHCP renewal, VPN reconnect), it automatically detects this and issues updated traversal hints so peers can reach it at the new address.

**Coordinate with Track A** — WS-2 touches `traversal.rs` and the probe executor. Work on B2 after HP-2 simultaneous-open (A1-b) is in a stable state.

**B2-a: Endpoint Change Detection (WS2-01)**

Files to modify:
- `crates/rustynetd/src/daemon.rs` — add netlink watcher or poll-based monitor
- `crates/rustynetd/src/traversal.rs` — add endpoint change notification type

Implementation:
```rust
// Option 1: poll-based (simpler, Linux + macOS compatible)
struct EndpointMonitor {
    last_seen_addrs: BTreeMap<String, Vec<IpAddr>>, // interface → addresses
    poll_interval: Duration,                         // default: 5s
}

impl EndpointMonitor {
    fn poll(&mut self) -> Option<EndpointChangeEvent> {
        let current = get_all_interface_addresses()?; // reads /proc/net/if_inet6 + getifaddrs
        for (iface, addrs) in &current {
            if self.last_seen_addrs.get(iface) != Some(addrs) {
                // Change detected
                let event = EndpointChangeEvent {
                    interface: iface.clone(),
                    old_addrs: self.last_seen_addrs.get(iface).cloned().unwrap_or_default(),
                    new_addrs: addrs.clone(),
                    detected_at: SystemTime::now(),
                };
                self.last_seen_addrs = current;
                return Some(event);
            }
        }
        None
    }
}

// Option 2: netlink (Linux-only, lower latency)
// Subscribe to RTM_NEWADDR / RTM_DELADDR netlink events
// On event: extract new address, compare to last known, emit EndpointChangeEvent
```

Security constraint: the endpoint monitor must filter out:
- The `rustynet0` WireGuard interface itself (IP changes on the tunnel are not underlay changes)
- Loopback (`127.0.0.0/8`, `::1`)
- Link-local addresses (`169.254.0.0/16`, `fe80::/10`) — these are not routable

Tests required:
- Unit test: interface address added → EndpointChangeEvent emitted with correct old/new
- Unit test: interface goes down (all addresses removed) → event emitted
- Unit test: `rustynet0` address change → no event emitted (filtered)
- Unit test: loopback address change → no event emitted
- Unit test: debounce — multiple events within 1s window coalesced into one

---

**B2-b: Traversal Re-Issue After Endpoint Change (WS2-02)**

When an endpoint change is detected, the daemon must immediately issue new signed traversal hints and distribute to peers.

Files to modify:
- `crates/rustynetd/src/daemon.rs` — wire EndpointChangeEvent to traversal re-issue
- `crates/rustynet-control/` — ensure traversal hint issuance API accepts refresh trigger

Implementation:
```
On EndpointChangeEvent:
1. Gather fresh candidates with new IP (+ re-run STUN if available)
2. Request new signed traversal hint bundle from control
   (or: if node is its own control, self-sign with local key)
3. Verify the new bundle (signature, freshness, watermark) before applying
4. Distribute to all active peers via the control channel
5. Re-run traversal probe with new candidates
6. Log: "endpoint change detected on {iface}: {old} → {new}, traversal re-issued"
```

Security constraint: fresh traversal hints must be issued with a new nonce and a watermark that advances past the previous bundle. Old bundle must not be re-distributed.

Tests required:
- Unit test: endpoint change → traversal re-issue triggered within 10s
- Unit test: re-issued bundle has higher watermark than previous bundle
- Unit test: unsigned re-issued bundle rejected (signature check still applies even on self-trigger)
- Integration test: change IP on client interface → verify exit node receives updated endpoint within 30s

---

**B2-c: Invariant Preservation During Transitions (WS2-03)**

This is about proving that during the endpoint-change-induced traversal re-issue, ACL/DNS/kill-switch rules remain intact.

Files to modify:
- `crates/rustynetd/src/phase10.rs` — ensure apply_signed_state_refresh does not relax firewall
- `scripts/e2e/` — add transition invariant test

Implementation:
```
In phase10.rs apply_signed_state_refresh:
  1. Assert current firewall rules exist (fail-closed if they don't before applying changes)
  2. Apply new state
  3. Assert firewall rules still exist after apply
  4. If firewall assertion fails at any point → rollback + fail_closed

In test:
  1. Active exit session with nftables kill-switch applied
  2. Trigger endpoint change (ip addr add alias)
  3. Poll nftables every 500ms for 60 iterations
  4. Assert kill-switch rule never disappears during re-establishment
```

Tests required:
- Unit test: apply_signed_state_refresh with valid new state → firewall rules unchanged
- Unit test: apply fails midway → rollback restores original rules, daemon enters fail_closed
- Integration test: live endpoint change → nftables snapshot never shows missing kill-switch rule

---

### B3 — WS-3: Traversal Freshness Hardening

**B3-a: Proactive Traversal Refresh (WS3-01)**

**Status:** Only reactive refresh (on probe failure). Proactive pre-expiry refresh not implemented.

Files to modify:
- `crates/rustynetd/src/traversal.rs` — add TTL-driven refresh scheduling
- `crates/rustynetd/src/daemon.rs` — wire traversal refresh timer

Implementation:
```rust
// In TraversalEngineConfig:
pub struct TraversalEngineConfig {
    // existing fields...
    pub pre_expiry_refresh_margin_secs: u64,  // default: 60 (refresh 60s before TTL)
    pub pre_expiry_jitter_max_secs: u64,      // default: 15
}

// In traversal engine loop:
fn schedule_proactive_refresh(expires_at: SystemTime, config: &TraversalEngineConfig) -> Instant {
    let margin = Duration::from_secs(config.pre_expiry_refresh_margin_secs);
    let jitter_secs = rand::random::<u64>() % config.pre_expiry_jitter_max_secs;
    let jitter = Duration::from_secs(jitter_secs);
    let target_system_time = expires_at - margin + jitter;
    // Convert to Instant safely
    match target_system_time.duration_since(SystemTime::now()) {
        Ok(d) => Instant::now() + d,
        Err(_) => Instant::now() + Duration::from_secs(5), // already past — fire soon
    }
}

// On proactive refresh trigger:
match fetcher.fetch_traversal() {
    Ok(bundle) => {
        controller.apply_signed_traversal_update(bundle); // ONE apply path, same as always
        schedule_proactive_refresh(bundle.expires_at, config);
    }
    Err(e) => {
        warn!("proactive traversal refresh failed: {e}, will retry");
        // Retry at shorter interval, but do NOT fail-closed immediately
        // Fail-closed only when expiry passes
    }
}
```

Tests required:
- Unit test: `schedule_proactive_refresh` fires before `expires_at`, never after
- Unit test: jitter is within `[0, jitter_max_secs)`
- Unit test: proactive refresh applies bundle via same path as reactive (no bypass)
- Unit test: failed proactive refresh → retry scheduled, fail_closed only after expiry
- Integration test: short-TTL traversal (20s), verify proactive refresh fires at ~10s remaining, daemon never enters fail_closed

---

**B3-b: Long-Running Recovery Test Coverage (WS3-03)**

Files to create:
- `scripts/e2e/live_linux_cross_network_remote_exit_soak_test.sh` (exists, needs full traversal freshness assertions)

Add to soak test:
```
In soak monitoring loop, every sample interval:
1. Check traversal_alarm_state from netcheck output
2. Check traversal_time_to_expiry_secs
3. Assert traversal_alarm_state == "ok" (never "critical", "error", or "missing")
4. Assert traversal_time_to_expiry_secs > 0 (never expired)
5. Record min/max/avg TTL remaining across samples
6. Assert min TTL remaining >= 0 (proactive refresh kept it fresh)
7. Record in soak report: traversal_freshness_maintained_throughout_soak: pass/fail
```

---

### B4 — WS-4: Cross-Network Validation Gates

These can only be implemented after B1/B2/B3 are substantially done and lab machines are reachable.

**B4-a: Controller Network Switch Gate (WS4-01)**

Files to create:
- `scripts/e2e/live_linux_cross_network_controller_switch_test.sh`

Test flow:
```
1. Bootstrap 2-node mesh (client + exit) with direct exit active
2. Record current signed-state validity (netcheck output)
3. Simulate controller network change:
   - On exit host: add nftables rule blocking control plane source IP
     sudo nft add rule inet filter input ip saddr <controller_ip> drop
4. Start timer
5. Wait 35s (one refresh cycle with margin)
6. Remove the nftables block (new network path restored)
7. Wait for daemon to detect and re-fetch signed state (max 30s)
8. Verify:
   - reconnect_secs <= 30 (from block removal to valid state)
   - no traffic leaked while reconnecting (route still via rustynet0)
   - signed_state_valid (netcheck shows traversal_alarm_state=ok after recovery)
9. Write report: cross_network_controller_switch_report.json
```

**B4-b: Node Network Switch Gate (WS4-02)**

Files to create:
- `scripts/e2e/live_linux_cross_network_node_network_switch_test.sh`

Test flow:
```
1. Bootstrap 2-node mesh with exit active
2. On client host, add a secondary IP alias on a different subnet:
   sudo ip link add dummy0 type dummy
   sudo ip link set dummy0 up
   sudo ip addr add 10.200.4.2/24 dev dummy0
3. Change default route to new interface:
   sudo ip route replace default via 10.200.4.1 dev dummy0
4. Start timer
5. Verify endpoint-change detection fires (check daemon log for "endpoint change detected")
6. Verify traversal re-issue triggered (netcheck shows new candidate IPs)
7. Verify exit peer receives updated endpoint (wg show endpoints)
8. Verify session recovers (route still via rustynet0, exit still active) within 30s
9. Clean up: restore original default route, remove alias
10. Write report: cross_network_node_network_switch_report.json
```

---

## TRACK C — Membership System (M0–M8)

**Owner area:** `crates/rustynet-control/src/membership/`

**Why this matters:** Node add/remove/revoke operations currently happen through signed assignment bundles. The membership system adds quorum governance — a threshold of admin keys must sign any membership change. This prevents a single compromised admin key from adding a rogue node.

**Safe to run fully in parallel with:** All other tracks. Membership code lives entirely in `rustynet-control` and `rustynet-policy`. Only M4 touches `rustynetd`.

---

### C1 — M0: Foundations and Schema Lock

Files to modify:
- `crates/rustynet-control/src/membership/schema.rs` (new or extend)

Tasks:
```
1. Define canonical membership schema types:
   - MembershipState { epoch: u64, state_root: [u8; 32], members: BTreeMap<NodeId, MemberRecord> }
   - MemberRecord { node_id, public_key, status: Active|Revoked, added_at_unix, updated_at_unix }
   - MembershipUpdate { update_id: [u8; 16], prev_state_root: [u8; 32], operation: Operation,
                        expires_at_unix: u64, approvals: Vec<Approval> }
   - Operation: AddNode | RemoveNode | RevokeNode | RotateKey | UpdateApproverSet
   - Approval { approver_id: NodeId, signature: Ed25519Signature }

2. Choose canonical encoding: CBOR (use ciborium crate) or canonical JSON (use serde_json with
   sorted keys + no extra whitespace). Decision: canonical JSON is simpler to audit, use that.

3. Define root hash computation:
   - Serialize MembershipState to canonical JSON
   - SHA-256 of the bytes = state_root
   - This is deterministic: same state always → same root

4. Add schema version constant: MEMBERSHIP_SCHEMA_VERSION = 1
   - Updates with unknown schema version are rejected with MembershipError::UnknownSchemaVersion

5. Add golden test vectors:
   - Known state → known canonical JSON → known root hash
   - These vectors must be committed and never change without a schema version bump
```

Tests required:
- Unit test: known state serializes to exact expected JSON bytes
- Unit test: known JSON computes to exact expected SHA-256 root hash
- Unit test: state with unknown schema version → rejected
- Unit test: two states with same members but different order → same root hash (canonical ordering)

---

### C2 — M1: State Root and Update Engine

Files to modify:
- `crates/rustynet-control/src/membership/engine.rs` (new)

Tasks:
```rust
// Pure deterministic reducer (no side effects, pure function):
fn apply_update(state: &MembershipState, update: &MembershipUpdate)
    -> Result<MembershipState, MembershipError>
{
    // Anti-replay check
    if state.applied_update_ids.contains(&update.update_id) {
        return Err(MembershipError::DuplicateUpdateId);
    }

    // Freshness check
    if SystemTime::now() > SystemTime::UNIX_EPOCH + Duration::from_secs(update.expires_at_unix) {
        return Err(MembershipError::UpdateExpired);
    }

    // Rollback protection: prev_state_root must match current root
    if update.prev_state_root != state.state_root {
        return Err(MembershipError::StateRootMismatch {
            expected: update.prev_state_root,
            actual: state.state_root
        });
    }

    // Apply operation
    let mut new_state = state.clone();
    match &update.operation {
        Operation::AddNode(record) => {
            if new_state.members.contains_key(&record.node_id) {
                return Err(MembershipError::NodeAlreadyExists(record.node_id));
            }
            new_state.members.insert(record.node_id, record.clone());
        }
        Operation::RemoveNode(node_id) => {
            if !new_state.members.contains_key(node_id) {
                return Err(MembershipError::NodeNotFound(*node_id));
            }
            new_state.members.remove(node_id);
        }
        Operation::RevokeNode(node_id) => {
            let member = new_state.members.get_mut(node_id)
                .ok_or(MembershipError::NodeNotFound(*node_id))?;
            member.status = MemberStatus::Revoked;
        }
        // ... other operations
    }

    // Advance epoch and recompute root
    new_state.epoch += 1;
    new_state.applied_update_ids.insert(update.update_id);
    new_state.state_root = compute_state_root(&new_state)?;

    Ok(new_state)
}
```

Tests required:
- Unit test: AddNode valid → new state has member, epoch+1, new root
- Unit test: AddNode duplicate → MembershipError::NodeAlreadyExists
- Unit test: RemoveNode unknown → MembershipError::NodeNotFound
- Unit test: wrong prev_state_root → MembershipError::StateRootMismatch
- Unit test: expired update → MembershipError::UpdateExpired
- Unit test: replayed update_id → MembershipError::DuplicateUpdateId
- Unit test: epoch is strictly increasing

---

### C3 — M2: Quorum Signature Verification

Files to modify:
- `crates/rustynet-control/src/membership/quorum.rs` (new)

Tasks:
```rust
fn verify_quorum(
    update: &MembershipUpdate,
    state: &MembershipState,   // current state contains approver set + threshold
) -> Result<(), QuorumError> {
    let canonical_payload = canonical_json(update.operation_payload())?;

    let mut valid_signers: BTreeSet<NodeId> = BTreeSet::new();

    for approval in &update.approvals {
        // Check approver is active in current state
        let approver = state.approvers.get(&approval.approver_id)
            .ok_or(QuorumError::UnknownApprover(approval.approver_id))?;

        if approver.status != ApproverStatus::Active {
            return Err(QuorumError::ApproverNotActive(approval.approver_id));
        }

        // Verify signature over exact canonical payload bytes
        let verifying_key = VerifyingKey::from_bytes(&approver.public_key)
            .map_err(|_| QuorumError::InvalidApproverKey)?;

        verifying_key.verify_strict(&canonical_payload, &approval.signature)
            .map_err(|_| QuorumError::InvalidSignature(approval.approver_id))?;

        // Enforce uniqueness (duplicate approver_id = attack attempt)
        if !valid_signers.insert(approval.approver_id) {
            return Err(QuorumError::DuplicateSigner(approval.approver_id));
        }
    }

    // Check threshold
    let threshold = state.quorum_threshold; // e.g. 2 out of 3
    if valid_signers.len() < threshold as usize {
        return Err(QuorumError::InsufficientSignatures {
            got: valid_signers.len(),
            required: threshold as usize
        });
    }

    Ok(())
}
```

Tests required:
- Unit test: 2-of-3 quorum with 2 valid signatures → Ok
- Unit test: 2-of-3 quorum with 1 valid signature → InsufficientSignatures
- Unit test: duplicate signer → DuplicateSigner
- Unit test: inactive approver → ApproverNotActive
- Unit test: unknown approver → UnknownApprover
- Unit test: bad signature (payload modified) → InvalidSignature
- Unit test: modifying payload bytes after signing → InvalidSignature (not a different error)

---

### C4 — M3: Persistence and Integrity

Files to modify:
- `crates/rustynet-control/src/membership/persistence.rs` (new)

Tasks:
```
Snapshot file: /var/lib/rustynet/membership.snapshot
  - Canonical JSON of MembershipState
  - mode: 0600, owner: rustynet user

Log file: /var/lib/rustynet/membership.log
  - Append-only, one MembershipUpdate per line (JSON)
  - mode: 0600, owner: rustynet user

Startup integrity verification:
1. Load snapshot → decode → compute root hash
2. Replay each log entry through apply_update()
3. Compute final root hash
4. Compare to snapshot root hash + all applied updates
5. If mismatch → enter restricted-safe mode (no peer/route apply until resolved)

Atomic write strategy:
1. Write to snapshot.tmp
2. fsync
3. rename snapshot.tmp → snapshot
4. This ensures no partial-write corruption

Log integrity metadata (per entry):
- entry_hash: SHA-256 of (prev_entry_hash || update_json)
- This forms a hash chain — any tampering breaks the chain
```

Tests required:
- Unit test: valid snapshot + valid log → replays to correct state
- Unit test: tampered snapshot (byte flip) → detected at startup → restricted-safe
- Unit test: tampered log entry → hash chain broken → detected → restricted-safe
- Unit test: atomic write — if process killed during write, snapshot is uncorrupted
- Unit test: strict permissions enforced on all written files (0600)

---

### C5 — M4: Daemon Enforcement Gate

Files to modify:
- `crates/rustynetd/src/daemon.rs` — add membership check before peer apply
- `crates/rustynetd/src/phase10.rs` — gate peer provisioning on membership status

Tasks:
```rust
// Before provisioning any peer:
fn check_peer_membership(
    node_id: NodeId,
    membership: &MembershipState,
) -> Result<(), MembershipError> {
    match membership.members.get(&node_id) {
        Some(record) if record.status == MemberStatus::Active => Ok(()),
        Some(record) if record.status == MemberStatus::Revoked => {
            Err(MembershipError::NodeRevoked(node_id))
        }
        None => Err(MembershipError::NodeNotFound(node_id)),
    }
}

// In apply_dataplane_generation, before backend.configure_peer():
for peer in &peers {
    check_peer_membership(peer.node_id, &self.membership)?;
    // Only reaches here if peer is Active
    self.backend.configure_peer(peer)?;
}

// On membership update (revocation):
// Immediately remove revoked peer from backend
fn apply_revocation(&mut self, node_id: NodeId) -> Result<()> {
    self.backend.remove_peer(node_id)?;
    // Also remove any routes granted to that peer
    self.dataplane.remove_routes_for_peer(node_id)?;
    log::info!("peer {} revoked and removed from dataplane", node_id);
    Ok(())
}
```

Tests required:
- Unit test: active member → provisioned
- Unit test: revoked member → provisioning denied, existing peer removed
- Unit test: unknown member → provisioning denied
- Integration test: revoke a node → within 10s, WireGuard peer is removed, routes removed

---

### C6 — M5 through M8: Policy, CLI, Runbooks, and Gates

**M5 (Policy coupling):** Wire `MembershipDirectory` in `rustynet-policy` to reject ACL decisions for revoked nodes. A revoked node's traffic must be denied even if an old ACL rule would permit it.

**M6 (CLI):** Implement:
- `rustynet membership propose <operation>` — creates unsigned update, prints for signing
- `rustynet membership sign <update-file>` — signs update with local admin key, appends approval
- `rustynet membership apply <update-file>` — verifies quorum, applies to daemon
- `rustynet membership status` — shows current epoch, member count, threshold

**M7 (Runbooks):** Write `documents/operations/MembershipGovernanceRunbook.md`:
- How to add a new node (propose → sign (N admins) → apply)
- How to revoke a compromised node (emergency vs. planned)
- How to rotate admin keys
- Incident drill procedure

**M8 (CI gates):** `scripts/ci/membership_gates.sh` must run:
- `cargo test -p rustynet-control membership::*`
- Schema golden vector tests
- Quorum verification tests
- Daemon enforcement gate tests
- Verify `artifacts/phase10/membership_report.json` exists and passes schema validation


Track C — Status & Evidence (updated):

- M0 (Schema lock): Implemented in `crates/rustynet-control/src/membership.rs`. MEMBERSHIP_SCHEMA_VERSION = 1 and canonical payload/root functions exist (canonical_payload, state_root_hex). Golden/determinism tests present (canonical_state_and_root_are_deterministic, unknown_schema_version_is_rejected_fail_closed). Status: Implemented.

- M1 (Deterministic reducer/engine): Deterministic reducer and preview/apply paths implemented (reduce_membership_state, preview_next_state, apply_signed_update). Ordered checks present: network id, created/expiry checks, prev_state_root verification, epoch chain, signature verification, legality checks, epoch advance, recompute root, and replay protection via MembershipReplayCache. Tests: add_node_update_requires_valid_signatures_and_root_chain, replay_and_rollback_are_rejected, replay_cache_not_updated_on_failed_update. Status: Implemented.

- M2 (Quorum verification): Implemented in `verify_membership_signatures`. Enforces active approver membership, threshold, duplicate signer detection, owner-signature requirement for sensitive ops. Uses ed25519_dalek verifying APIs. Tests present for threshold, duplicate signer, owner signature required. Status: Implemented.

- M3 (Persistence & integrity): Snapshot and append-only log implemented: persist_membership_snapshot, load_membership_snapshot, append_membership_log_entry, load_membership_log, replay_membership_snapshot_and_log, atomic_write with tmp+fsync+rename and permission checks on Unix. Tests: snapshot_and_log_roundtrip_integrity, loading_empty_membership_log_is_supported. Status: Implemented.

- M4–M8 (Integration, daemon gate, CLI, runbooks, CI gates): Parts are present: `crates/rustynetd/src/daemon.rs` references membership load/replay functions and default paths; scripts for CI gating and incident drill exist (`scripts/ci/membership_gates.sh`, `scripts/operations/membership_incident_drill.sh`). CLI wiring and runbook document are partly missing or require additional integration testing on Debian hosts. Status: Partial — integration and CI gate execution on Linux required to finalize.

Test execution note:
- I attempted to run `cargo test -p rustynet-control membership -- --nocapture` in this Windows environment. The build failed due to unrelated compilation errors in `crates/rustynet-control/src/lib.rs` (missing `NodeId` and related functions), preventing running the membership tests here. See test attempt log for details.

Recommended validation steps (run on Debian build host as requested):

- cargo test -p rustynet-control membership -- --nocapture
- cargo clippy -p rustynet-control -- -D warnings

If those pass on a Linux host, the `fleet-c-track` todo can be marked done. If not, fix the unrelated compile errors in `crates/rustynet-control/src/lib.rs` that block the test harness.

Files of interest / tests added:
- crates/rustynet-control/src/membership.rs (core implementation and unit tests)
- Key tests (inside membership.rs test module):
  - canonical_state_and_root_are_deterministic
  - unknown_schema_version_is_rejected_fail_closed
  - signed_update_requires_threshold_and_owner_for_quorum_change
  - add_node_update_requires_valid_signatures_and_root_chain
  - replay_and_rollback_are_rejected
  - duplicate_signer_is_rejected
  - owner_signature_required_for_rotate_approver
  - replay_cache_not_updated_on_failed_update
  - loading_empty_membership_log_is_supported
  - snapshot_and_log_roundtrip_integrity

Next steps to finish Track C:
1. Run full test/gate on Debian host and fix any platform-specific build errors (e.g., missing types in lib.rs).
2. Implement CLI glue (rustynet membership ...) in `crates/rustynet-cli` and wire apply to daemon IPC.
3. Author `documents/operations/MembershipGovernanceRunbook.md` and add CI gate evidence artifacts.

---

## TRACK D — Shell-to-Rust Migration Completion

**Owner area:** `start.sh`, `scripts/e2e/debian_two_node_clean_install_and_tunnel_test.sh`

**Safe to run fully in parallel with:** All other tracks.

**Current state from migration plan:**
- Phases A, B, C, F, G, H: **COMPLETE**
- Phase E: **Nearly complete** — service lifecycle, key custody, trust install, macOS paths all migrated. Minor remaining wiring tasks.
- Phase I: **Code done, evidence needed** — orchestrator uses argv-only dispatch, but no fresh lab dry-run evidence has been collected

---

### D1 — Phase E Completion

Audit `start.sh` for any remaining direct shell operations that are not dispatching to a Rust op. Specifically check:

```bash
# Search for any of these patterns still in active (non-wrapper) paths:
grep -n "systemctl " start.sh | grep -v "rustynet ops"
grep -n "launchctl " start.sh | grep -v "rustynet ops"
grep -n "install -m\|chmod \|chown " start.sh | grep -v "rustynet ops"
grep -n "openssl\|wg genkey\|wg pubkey" start.sh | grep -v "rustynet ops"
```

Any hit that is NOT inside a thin wrapper function dispatching to `rustynet ops <cmd>` is a remaining Phase E task.

For each hit:
1. Implement the equivalent `rustynet ops <subcommand>` in `crates/rustynet-cli/src/`
2. Replace the shell logic with `rustynet ops <subcommand> || exit 1`
3. Add unit test for the new Rust op
4. Verify the wrapper fails closed on error (non-zero exit from the Rust op must propagate)

---

### D2 — Phase I: Evidence Collection

The code exists. What is needed is a successful dry-run in the lab to prove the argv-only remote execution path works end-to-end.

```bash
# On a Linux machine with both lab nodes reachable:
cargo run -p rustynet-cli -- ops run-debian-two-node-e2e \
  --client-host debian@192.168.18.51 \
  --exit-host mint@192.168.18.53 \
  --ssh-identity-file ~/.ssh/rustynet_lab \
  2>&1 | tee artifacts/phase10/debian_two_node_e2e_argv_only_dry_run.log

# The report must show no "bash -se" or "bash -c" execution paths
# All remote commands must be argv arrays (not shell strings)
```

After successful run, update `ShellToRustMigrationPlan_2026-03-06.md` Phase I status to COMPLETE with evidence path.

---

## TRACK E — Evidence Freshness (Depends on A and B)

**Do not start Track E until:** Track A (at minimum HP-2 completion + HP-3 baseline) and Track B (WS-1/WS-2/WS-3) are substantially done. Track E is purely about running tests and collecting artifacts.

---

### E1 — Fresh Install OS Matrix Refresh

**Problem:** Current report (`fresh_install_os_matrix_report.json`) was captured on 2026-03-08 at commit `4500e38`. The gate has a max age of 7 days. It will fail freshness checks against current HEAD.

**Solution:** Re-run the live lab orchestrator with the current HEAD commit on the lab machines.

```bash
# On Device 1 (Debian) with access to both machines:
bash scripts/e2e/live_linux_lab_orchestrator.sh \
  --nodes "debian@192.168.18.51,mint@192.168.18.53" \
  --ssh-identity-file ~/.ssh/rustynet_lab \
  --stages "clean,bootstrap,baseline" \
  --output-dir artifacts/phase10

# The report must capture current git commit SHA
# Scenarios required: clean_install, one_hop, two_hop, role_switch for each OS
# Security assertions: all five must be true
```

If macOS is not available in the lab, update the gate to mark macOS as `"status": "skipped", "reason": "no macOS lab hardware available"` and document this as a known gap with the requirement that macOS evidence must be collected before stable release.

---

### E2 — Six Cross-Network Reports

**Problem:** All six required cross-network reports are missing. Previous attempts failed at lab initialization.

**Prerequisite:**
- Track B (WS-1/WS-2/WS-3) done — so the daemon is self-healing
- Lab machines reachable (check SSH connectivity before starting)
- Network namespace setup complete (see AGENT_MISSION_CROSSNET.md for netns setup procedure)

**Run in order:**
```bash
# 1. Direct remote exit
bash scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh \
  --client-host debian@192.168.18.51 \
  --exit-host mint@192.168.18.53 \
  --client-node-id <id> --exit-node-id <id> \
  --client-network-id net-10-200-1 --exit-network-id net-10-200-2 \
  --nat-profile baseline_lan --impairment-profile none

# 2. Relay remote exit (use Device 1 as relay in separate netns)
# 3. Failback roaming
# 4. Traversal adversarial
# 5. DNS fail-closed
# 6. Soak (minimum 30 minutes)

# Then validate all reports:
cargo run -p rustynet-cli -- ops validate-cross-network-remote-exit-reports \
  --artifact-dir artifacts/phase10 \
  --require-pass-status

cargo run -p rustynet-cli --bin phase10_cross_network_exit_gates
```

---

## TRACK F — Backend Agility (Second Real Backend)

**Owner area:** `crates/rustynet-backend-api/`, potential new crate `rustynet-backend-userspace`

**Why this matters:** The `FinalLaunchChecklist.md` explicitly flags that the current `backend_agility_report.json` is weak — it only lists `rustynet-backend-api` (the interface) as the "additional backend", not an actual implementation. The launch checklist requires a second non-simulated backend.

**Safe to run fully in parallel with:** All tracks. New crate, no conflicts.

**Option 1 (Recommended): WireGuard userspace backend using boringtun**

`boringtun` is a pure-Rust, production-ready WireGuard userspace implementation by Cloudflare. Using it as a second backend demonstrates real backend swappability.

Files to create:
- `crates/rustynet-backend-userspace/` (new crate)
- `crates/rustynet-backend-userspace/src/lib.rs`

Implementation:
```
1. Add crate to workspace Cargo.toml
2. Implement TunnelBackend trait using boringtun:
   - add_peer, remove_peer, configure_peer
   - update_peer_endpoint, current_peer_endpoint
   - peer_latest_handshake_unix
   - get_stats, list_peers
   - capabilities(): BackendCapabilities { userspace: true, kernel_wireguard: false }
3. Keep all WireGuard-specific code inside this crate (no leakage to control/policy)
4. Run conformance tests against both backends to prove TunnelBackend contract
```

Gate update:
```
In backend_agility_report.json:
  "additional_backend_paths": ["rustynet-backend-userspace"],
  "conformance_passed": true   (only if conformance tests pass for both)
```

**Option 2 (Alternative): Stub backend with full conformance tests**

If boringtun is out of scope, at minimum write comprehensive conformance tests for the `TunnelBackend` trait and demonstrate that `rustynet-backend-stub` passes all of them (so any future backend just needs to pass the same suite).

---

## TRACK G — Security Hardening Completion

**Safe to run fully in parallel with:** All tracks.

### G1 — HP-3 Relay Transport Constant-Time Auth Prep

**Status:** Flagged as PENDING in `SecurityHardeningBacklog_2026-03-09.md`.

Before implementing HP-3 relay transport (Track A, A2), the auth token comparison in the relay session protocol must use constant-time comparison to avoid timing side-channels.

Files to implement in:
- `crates/rustynet-relay/src/transport.rs` — when validating session tokens

Implementation:
```rust
// WRONG — timing leak:
if session_token == expected_token { ... }

// CORRECT — constant time:
use subtle::ConstantTimeEq;
if session_token.ct_eq(&expected_token).into() { ... }
```

Add `subtle = "2"` to `rustynet-relay/Cargo.toml`.

Also apply to:
- Any MAC/HMAC comparison in auth flows
- Any token/nonce equality check in relay session handling

Test:
- Unit test: tokens of same length, different bytes → always takes the same code path (cannot be observed, but can be verified in code review)
- Gate: add grep gate in `security_regression_gates.sh` that fails if any equality comparison on token/key/hash bytes uses `==` directly (must use `ct_eq` or `verify_slices_are_equal`)

---

### G2 — sha1 and 3des Deprecation Enforcement

**From `CryptoDeprecationSchedule.md`:** sha1 and 3des deprecated 2026-03-01, removal 2026-06-01.

Current date 2026-03-22 — we are in the deprecation window. The scheduled removal is in ~10 weeks.

Tasks:
```
1. Search codebase for any sha1 or 3des usage:
   cargo audit --deny warnings  (should already catch this)
   grep -r "sha1\|sha-1\|3des\|triple.des\|des3" Cargo.toml crates/

2. If found in any dependency:
   - Identify which feature gate enables it
   - Disable the feature or find an alternative crate
   - Add to cargo deny config to ban these algorithms

3. Update crypto_deprecation_schedule.json:
   - sha1: { status: "deprecated", removal_scheduled: "2026-06-01", usage_count: 0 }
   - 3des: { status: "deprecated", removal_scheduled: "2026-06-01", usage_count: 0 }

4. Add CI gate: fail if sha1 or 3des usage count > 0 (counted by cargo audit)
```

---

## FINAL LAUNCH CHECKLIST — What Needs Sign-Off

These are the human-approval items that cannot be automated. They should happen after all technical tracks are complete.

| Item | Who | Prerequisite |
|------|-----|-------------|
| Engineering Owner sign-off | Engineering lead | All cargo gates green, all evidence artifacts valid and fresh |
| Security Owner sign-off | Security lead | `SecurityMinimumBar.md` all controls verified, adversarial tests pass |
| Operations Owner sign-off | Ops lead | Runbooks complete, incident drills passed, DR report fresh |
| Release artifact signing | CI system | All above sign-offs recorded |
| SBOM generation | CI system | After final build |
| Provenance attestation | CI system | After SBOM |

---

## Dependency Graph (Execution Order)

```
Phase 1 (can all start immediately, fully parallel):
  Track A: HP-2 simultaneous-open (A1-a STUN, A1-b simultaneous-open)
  Track C: M0 schema lock
  Track D: Phase E audit and Phase I evidence
  Track G: G1 constant-time auth prep, G2 deprecation enforcement

Phase 2 (start after Phase 1 milestone):
  Track A: HP-3 relay transport (A2) — needs G1 done first
  Track C: M1 engine, M2 quorum (independent of A)
  Track B: WS-1 refresh (B1-a, B1-b, B1-c) — independent of A

Phase 3 (start after Phase 2 milestone):
  Track A: HP-4 hysteresis (A3), HP-5 gates (A4)
  Track B: WS-2 endpoint mobility (B2) — coordinate with A on traversal.rs
  Track C: M3 persistence, M4 daemon gate, M5-M8
  Track F: Second backend (independent)

Phase 4 (after Phase 3 — all major features complete):
  Track B: WS-3 freshness (B3), WS-4 validation gates (B4)
  Track E: Fresh install OS matrix refresh (E1)
  Track E: Six cross-network reports (E2)

Phase 5 (final):
  Fresh cargo CI gate run on Linux (all gates green)
  Human sign-offs
  Release artifact signing, SBOM, provenance
```

---

## Summary Table

| Track | Items | Parallel-Safe With | Blocks |
|-------|-------|-------------------|--------|
| A: NAT Traversal + Relay | HP-2 remaining, HP-3, HP-4, HP-5 | C, D, G, B(WS-1/WS-3) | Track E |
| B: Cross-Net Hardening | WS-1, WS-2, WS-3, WS-4 | C, D, G, A(HP-3/HP-4) | Track E |
| C: Membership | M0–M8 | A, B, D, F, G | Nothing |
| D: Shell Migration | Phase E, Phase I evidence | A, B, C, F, G | Nothing |
| E: Evidence Refresh | OS Matrix, 6 cross-net reports | Nothing | Launch |
| F: Backend Agility | Second real backend | A, B, C, D, G | Launch |
| G: Security Hardening | Const-time auth, sha1/3des removal | A, B, C, D, F | Track A (HP-3) |

**Largest remaining code work (by effort):**
1. HP-3 Production Relay Transport — new protocol, new service, full test suite
2. HP-2 Simultaneous-Open WAN — STUN integration, coordination protocol
3. Membership System M0–M8 — full quorum-signed governance system
4. Cross-Network WS-1/WS-2/WS-3 — daemon self-healing refresh and endpoint mobility

**Quickest wins (low effort, high value):**
1. G1 + G2 — constant-time auth prep and sha1/3des audit (1–2 hours)
2. D2 — Phase I evidence collection (run one lab session, ~2 hours)
3. B1-c — complete `state refresh` IPC command wiring (skeleton already exists, ~4 hours)
4. B3-a — proactive traversal refresh timer (well-defined, ~4 hours)
