# Rustynet Cross-Network Remote Exit Node Plan (2026-03-16)
**Last Updated:** 2026-03-25T18:00:31Z

## AI Implementation Prompt

```text
You are the implementation agent for the remaining work in this document.
Repository root: /Users/iwanteague/Desktop/Rustynet

Mission:
Complete the remaining in-scope work in this file in one uninterrupted execution if feasible. Security is the top priority. Do not stop at planning if you can still write, test, and verify code safely.

Mandatory reading order:
1. /Users/iwanteague/Desktop/Rustynet/AGENTS.md
2. /Users/iwanteague/Desktop/Rustynet/CLAUDE.md
3. /Users/iwanteague/Desktop/Rustynet/README.md
4. /Users/iwanteague/Desktop/Rustynet/documents/Requirements.md
5. /Users/iwanteague/Desktop/Rustynet/documents/SecurityMinimumBar.md
6. This document
7. Directly linked scope/design docs and the code you will touch

Non-negotiables:
- one hardened execution path for each security-sensitive workflow
- fail closed on missing, stale, invalid, replayed, or unauthorized state
- no insecure compatibility paths, no legacy fallback branches, and no weakening of tests to make results pass
- no TODO/FIXME/placeholders for in-scope deliverables
- do not mark work complete until code, tests, and evidence exist

Execution workflow:
1. Read this document fully and convert every unchecked, open, pending, partial, or blocked item into a concrete checklist.
2. Execute the remaining work in the ordered sequence listed below.
3. Implement in small, verifiable increments, but continue until the remaining in-scope slice is complete or a real external blocker stops you.
4. After every material code change:
   - run targeted unit and integration tests for touched crates and modules
   - run smoke tests, dry runs, or CLI/service validators for the exact workflow you changed
   - rerun the most relevant gate before moving on
5. After every completed item:
   - update this document immediately instead of maintaining a separate private checklist
   - mark checkboxes and status blocks complete only after verification
   - append concise evidence: files changed, tests run, artifacts produced, residual risk, and blocker state if any
   - keep any existing session log, evidence table, acceptance checklist, or status summary current
6. Before claiming completion:
   - run repository-standard gates when the scope is substantial:
     cargo fmt --all -- --check
     cargo clippy --workspace --all-targets --all-features -- -D warnings
     cargo check --workspace --all-targets --all-features
     cargo test --workspace --all-targets --all-features
     cargo audit --deny warnings
     cargo deny check bans licenses sources advisories
   - run the scope-specific validations listed below
   - if live or lab validation is available, run it; if it is not available, do not fake success and record the blocker precisely
7. If a test or gate fails, fix the root cause. Never weaken the check, bypass the security control, or mark a synthetic path as good enough.

Document-specific execution order:
1. First reconcile stale status or over-optimistic claims with current code and evidence so the document stays honest.
2. Then finish Section 8 Phase 1 candidate acquisition and signed traversal input work that is not yet implemented or verified.
3. Then finish Section 8 Phase 2 HP-2 real WAN simultaneous-open behavior with signed authority, replay protection, and no endpoint-fallback path.
4. Then finish Section 8 Phase 3 HP-3 production relay transport with constant-time auth, replay protection, rate limiting, bounded queues, idle expiry, and ciphertext-only forwarding.
5. Then finish Section 8 Phase 4 remote exit-node dataplane integration, including failover, failback, roaming, managed DNS, leak prevention, and route-scope enforcement.
6. Then finish Section 8 Phase 5 testing, gates, artifacts, and release enforcement, including the six cross-network reports and the hard-pass gate path described later in the document.
7. Close Section 12 immediate next code work and Section 9 artifact and gate requirements before claiming remote-exit readiness.

Scope-specific validation for this document:
- Targeted tests for rustynetd, rustynet-relay, rustynet-control, and any touched CLI/report modules.
- ./scripts/ci/phase10_gates.sh
- ./scripts/ci/membership_gates.sh
- bash ./scripts/ci/phase10_hp2_gates.sh if that gate exists in the tree after your changes.
- All cross-network validators and live scripts named in Sections 9 and 12 when the environment is available.
- Commit-bound live artifacts under artifacts/phase10 or the documented live-lab paths.

Definition of done for this document:
All remaining in-scope items in this document are marked complete or explicitly blocked with exact prerequisites, the six cross-network report paths are real and validated, and Rustynet has measured evidence for secure cross-network remote-exit behavior instead of design-only claims.

If full completion is impossible in one execution, continue until you hit a real external blocker, then mark the exact remaining items as blocked with the reason, the missing prerequisite, and the next concrete step.
```

## Current Open Work

This block is the quick source of truth for what remains in this document.
If historical notes later in the file conflict with this block, the AI prompt, or current code reality, update the stale section instead of following the stale note.

`Open scope`
- Finish honest, measured cross-network remote-exit capability from candidate acquisition through live gates.
- Remaining code-heavy work is HP-2 real WAN simultaneous-open behavior, HP-3 production relay transport, remote-exit dataplane integration, and the final cross-network gate/report path.
- The six required cross-network evidence reports and the phase10 cross-network hard-pass gate are still part of the remaining proof burden.
- Phase 10 readiness no longer gets to ignore the six canonical cross-network reports in code, but the measured artifacts are still missing and the current `rustynetd` runtime compile break blocks end-to-end verification of that gate slice.

`Do first`
- Reconcile any stale optimism in this document with current code and evidence.
- Then finish the remaining Phase 1 and Phase 2 traversal input and WAN simultaneous-open work before extending relay or remote-exit claims.

`Completion proof`
- Measured code and artifact evidence for direct remote exit, relay remote exit, failback/roaming, adversarial traversal rejection, managed DNS, and soak behavior.
- Hard-pass cross-network gate output and commit-bound artifacts under the documented paths.

`Do not do`
- Do not claim Rustynet can securely connect from anywhere until the cross-network reports and hard gate evidence exist.
- Do not add alternate endpoint-mutation or remote-exit fallback logic.

`Clarity note`
- If historical status text later in this file conflicts with current code reality, update the stale section immediately instead of working from the stale assumption.

## Document Status: CRITICAL SECURITY REFERENCE
This document defines the complete, production-grade architecture for establishing secure cross-network tunnels between Rustynet nodes across the Internet. Every implementation choice must be traceable to a security requirement or threat mitigation in this document.

**Implementation Tracking:** Use the checklist markers `[ ]` throughout this document to track completion. Mark items `[x]` only when implemented + verified with test evidence.

## 1. Objective
Deliver Tailscale-like remote exit-node behavior for Rustynet:
- a device on one network can securely use an authorized Rustynet exit node on a different network,
- direct UDP is used when NAT conditions allow,
- encrypted relay is used when direct UDP cannot be established,
- fail-closed behavior is preserved for traffic, DNS, routing, and control-plane trust.

This document is implementation-oriented. It starts from the repository's current state and defines the remaining work in phases.

## 2. Document Relationship and Precedence
This plan extends, but does not replace:
- [Requirements.md](/Users/iwanteague/Desktop/Rustynet/documents/Requirements.md)
- [SecurityMinimumBar.md](/Users/iwanteague/Desktop/Rustynet/documents/SecurityMinimumBar.md)
- [phase10.md](/Users/iwanteague/Desktop/Rustynet/documents/phase10.md)
- [UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md](/Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md)
- [UdpHolePunchingHP2IngestionPlan_2026-03-07.md](/Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingHP2IngestionPlan_2026-03-07.md)

If any conflict exists, the stricter security interpretation wins.

## 3. User Outcome
The target user experience is:
1. A user enrolls a device on network A.
2. Another enrolled device on network B is authorized as an exit node.
3. The client selects that remote exit node.
4. Rustynet establishes the tunnel automatically:
   - direct UDP if possible,
   - encrypted relay if direct UDP is not possible.
5. Full-tunnel traffic and managed DNS flow through the selected remote exit node without manual consumer-router port forwarding.

The phrase "from anywhere" is not acceptable as a claim until the direct path and relay path are both proven under real cross-network conditions.

## 3A. The One Hardened Path Principle (MANDATORY)

**Core Philosophy:** Every security-sensitive operation has EXACTLY ONE implementation path. That path is hardened, tested, and enforced at runtime. No legacy branches, no fallback modes, no "temporary" insecure alternatives.

### 3A.1 What This Means in Practice

**✅ CORRECT: One Secure Path**
```rust
fn apply_endpoint_update(peer: PeerId, endpoint: SocketAddr) -> Result<()> {
    // STEP 1: Verify signed traversal bundle (MANDATORY, NO BYPASS)
    let traversal = self.verify_signed_traversal(peer)?;
    
    // STEP 2: Verify endpoint in candidate set (MANDATORY, NO BYPASS)
    if !traversal.candidates.contains(&endpoint) {
        return Err(Error::UnauthorizedEndpoint);
    }
    
    // STEP 3: Apply to backend (ONLY path)
    self.backend.set_peer_endpoint(peer, endpoint)?;
    Ok(())
}
```

**❌ FORBIDDEN: Multiple Paths / Legacy Branches**
```rust
fn apply_endpoint_update(peer: PeerId, endpoint: SocketAddr) -> Result<()> {
    // WRONG: Has fallback to weaker path
    if let Some(traversal) = self.try_verify_signed_traversal(peer) {
        // Modern secure path
        if traversal.candidates.contains(&endpoint) {
            self.backend.set_peer_endpoint(peer, endpoint)?;
        }
    } else if self.config.legacy_mode {  // ❌ FORBIDDEN
        // "Legacy" unsecured path - NEVER DO THIS
        warn!("Using legacy endpoint update");
        self.backend.set_peer_endpoint(peer, endpoint)?;
    }
    Ok(())
}
```

### 3A.2 Mandatory Enforcement Rules

**RULE 1: No Runtime Branch Selection for Security-Critical Operations**

Security-critical operations include:
- Endpoint mutation (direct/relay path changes)
- Route installation (exit-node, LAN access, bypass routes)
- DNS configuration (managed zone, fail-closed mode)
- Firewall rule management (kill-switch, ACL enforcement)
- Key material handling (generation, storage, loading, zeroization)
- Trust state verification (signature checks, freshness, anti-replay)
- Privileged helper invocation (argv construction, validation)

For these operations:
- ✅ ONE hardened implementation
- ❌ NO `if legacy_mode` branches
- ❌ NO `if feature_flag_enabled` for security controls
- ❌ NO `try_secure_path().or_else(|| insecure_fallback())`

**RULE 2: Migration Strategy Must Remove Old Paths**

When migrating from less secure to more secure implementation:

```rust
// WRONG: Keeps both paths
fn apply_route(route: IpNet) -> Result<()> {
    if self.config.use_new_route_engine {
        self.new_signed_route_engine.apply(route)  // Secure
    } else {
        self.old_shell_route_engine.apply(route)   // ❌ Insecure, but still present
    }
}

// CORRECT: Old path removed, only secure path exists
fn apply_route(route: IpNet) -> Result<()> {
    // Old shell-based implementation has been DELETED
    // Only signed route engine exists
    self.signed_route_engine.apply(route)
}
```

**Migration Process:**
1. Implement new secure path with tests
2. Verify new path meets all security requirements
3. Add migration gate that enforces new path usage
4. **DELETE old implementation** (not just deprecate)
5. Remove any configuration flags that selected old path

**RULE 3: Feature Flags for Capability, NOT Security**

```rust
// ✅ CORRECT: Feature flag for capability
if self.config.enable_relay {
    // Relay is a feature - can be enabled/disabled
    self.attempt_relay_connection(peer)?;
}

// ❌ FORBIDDEN: Feature flag for security control
if self.config.enforce_signed_traversal {  // ❌ NO!
    // Security controls are NOT optional
    self.verify_signature()?;
}
```

**Security controls are ALWAYS enforced, never behind feature flags.**

**RULE 4: No Graceful Degradation for Security**

```rust
// ❌ FORBIDDEN: Graceful degradation
fn establish_connection(peer: PeerId) -> Result<Connection> {
    if let Ok(conn) = self.try_secure_connection(peer) {
        return Ok(conn);
    }
    // WRONG: Falls back to less secure
    warn!("Falling back to insecure connection");
    self.insecure_connection(peer)
}

// ✅ CORRECT: Fail closed
fn establish_connection(peer: PeerId) -> Result<Connection> {
    // Either secure connection succeeds, or we fail
    self.secure_connection(peer)
    // No fallback, no degradation
}
```

### 3A.3 Code Review Rejection Criteria

Any pull request MUST be rejected if it:

1. **Adds a second implementation path** for security-critical operations
2. **Adds `if legacy_mode` or `if insecure_mode`** branches
3. **Weakens existing security checks** to improve compatibility
4. **Adds optional security enforcement** via feature flags
5. **Implements "temporary" bypass** for debugging/testing that could reach production
6. **Adds graceful degradation** that falls back to weaker security

**Code Review Checklist:**
- [ ] Does this PR add a new code path for an existing security-critical operation?
  - If YES → Reject unless old path is deleted in same PR
- [ ] Does this PR add a feature flag that disables security enforcement?
  - If YES → Reject unconditionally
- [ ] Does this PR add error recovery that bypasses security checks?
  - If YES → Reject unless it fails closed
- [ ] Does this PR keep deprecated/legacy security code "just in case"?
  - If YES → Reject, require deletion

### 3A.4 Runtime Enforcement

The daemon MUST enforce one-path at runtime:

```rust
// Example: Runtime assertion that no legacy branches exist
#[cfg(test)]
mod one_path_verification {
    #[test]
    fn no_legacy_endpoint_mutation_path() {
        // Verify only one code path exists for endpoint mutation
        let config = Config::default();
        
        // There should be NO configuration option to enable legacy behavior
        assert!(!config.has_field("legacy_endpoint_mode"));
        assert!(!config.has_field("insecure_mode"));
        assert!(!config.has_field("bypass_signature_checks"));
    }
    
    #[test]
    fn all_security_controls_mandatory() {
        let daemon = Daemon::new_test_instance();
        
        // Security controls CANNOT be disabled
        assert!(daemon.signature_verification_enabled());  // Must be true
        assert!(daemon.replay_protection_enabled());       // Must be true
        assert!(daemon.fail_closed_mode_active());         // Must be true
        
        // These should not even be functions - they should be const true
    }
}
```

### 3A.5 Examples: One Hardened Path Applied

**Endpoint Mutation:**
- ❌ OLD: Unsigned endpoint changes allowed "for debugging"
- ✅ NEW: ONLY signed traversal bundles trigger endpoint changes
- 🗑️ DELETED: Debug mode that bypassed signature checks

**Route Installation:**
- ❌ OLD: Shell script that parsed user input with `sh -c`
- ✅ NEW: Rust argv array builder with strict validation
- 🗑️ DELETED: Shell-based route management entirely

**DNS Configuration:**
- ❌ OLD: Falls back to system DNS if managed DNS unavailable
- ✅ NEW: Fails closed with SERVFAIL if managed DNS state invalid
- 🗑️ DELETED: System DNS fallback code path

**Relay Authentication:**
- ❌ OLD: Variable-time string comparison
- ✅ NEW: Constant-time HMAC verification only
- 🗑️ DELETED: Any non-constant-time comparison code

**Key Storage:**
- ❌ OLD: Plaintext key file as fallback if keychain unavailable
- ✅ NEW: OS keychain or encrypted file with startup permission check
- 🗑️ DELETED: Plaintext fallback code

### 3A.6 Verification: Proving One Path

Every security-critical module MUST have these tests:

```rust
#[cfg(test)]
mod one_path_verification_tests {
    use super::*;

    #[test]
    fn only_one_endpoint_mutation_function() {
        // Use reflection/compile-time checks to verify
        // only ONE public function exists for endpoint mutation
        let module = std::module_path!();
        let endpoint_mutation_fns = get_public_functions_matching(
            module,
            "endpoint|peer_endpoint|set_peer"
        );
        
        // Should be exactly ONE function
        assert_eq!(endpoint_mutation_fns.len(), 1,
            "Found multiple endpoint mutation paths: {:?}",
            endpoint_mutation_fns
        );
    }
    
    #[test]
    fn no_config_flags_for_security() {
        let config_schema = Config::schema();
        
        // These fields should NOT exist
        assert!(!config_schema.has_field("insecure_mode"));
        assert!(!config_schema.has_field("skip_signature_verification"));
        assert!(!config_schema.has_field("allow_unsigned_endpoints"));
        assert!(!config_schema.has_field("legacy_route_engine"));
    }
    
    #[test]
    fn security_functions_have_no_optional_behavior() {
        // verify_signature() should not take "skip_if_unavailable" parameter
        // apply_route() should not take "fallback_to_shell" parameter
        // etc.
        
        // This is verified at compile time by function signatures
    }
}
```

### 3A.7 Benefits of One Hardened Path

1. **Reduced Attack Surface:** No legacy code paths to exploit
2. **Simplified Auditing:** Only one path to review and verify
3. **Easier Testing:** No combinatorial explosion of path combinations
4. **Clearer Reasoning:** Behavior is deterministic and predictable
5. **No Accidental Bypass:** Cannot accidentally fall back to insecure path
6. **Better Performance:** No runtime checks for which path to use
7. **Confident Deployment:** No "what if legacy mode is still enabled?" worries

### 3A.8 Exception: Crypto Agility (Planned, Future)

The ONE exception to one-path rule is cryptographic agility for algorithm migration:

```rust
// ALLOWED: Multiple crypto algorithms for migration
enum CipherSuite {
    ChaCha20Poly1305,  // Current
    AesGcm256,         // Future post-quantum hybrid
}

// BUT: Only ONE algorithm active per session
// AND: Downgrade attacks prevented by protocol negotiation
// AND: Weak algorithms removed after migration complete
```

This is acceptable because:
- Crypto algorithms need to be upgraded over time
- Each algorithm is still fully secure (no "weak" option)
- Migration is protocol-negotiated, not runtime-configurable
- Old algorithms are DELETED after migration period

**This is NOT an excuse for:**
- ❌ Having both "secure" and "insecure" mode
- ❌ Allowing downgrade attacks
- ❌ Keeping deprecated crypto "just in case"

## 4. Current Repository Reality
### 4.1 What already exists
- Signed traversal bundle verification, freshness enforcement, and replay/rollback protection.
- Traversal-authoritative endpoint control in `rustynetd`.
- Bounded direct-probe logic with relay fallback decisions.
- Periodic reprobe for relay-backed sessions and relay-to-direct failback using live handshake evidence.
- Structured traversal diagnostics in `status` and `netcheck`.
- Phase 10 HP2 CI artifacts showing passing traversal path-selection and traversal-security checks.

Primary source references:
- [README.md:48](/Users/iwanteague/Desktop/Rustynet/README.md#L48)
- [phase10.md](/Users/iwanteague/Desktop/Rustynet/documents/phase10.md)
- [traversal_path_selection_report.json](/Users/iwanteague/Desktop/Rustynet/artifacts/phase10/traversal_path_selection_report.json)
- [traversal_probe_security_report.json](/Users/iwanteague/Desktop/Rustynet/artifacts/phase10/traversal_probe_security_report.json)

### 4.2 What does not exist yet
- Full WAN simultaneous-open traversal behavior.
- Production relay transport service.
- End-to-end live proof that a client on one network can use a remote exit node on a different network under real NAT conditions.

Primary source references:
- [README.md:48](/Users/iwanteague/Desktop/Rustynet/README.md#L48)
- [phase10.md](/Users/iwanteague/Desktop/Rustynet/documents/phase10.md)
- [UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md:17](/Users/iwanteague/Desktop/Rustynet/documents/operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md#L17)

### 4.3 Important architecture truth
- [rustynet-relay](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/lib.rs) currently contains relay fleet selection primitives, not a production ciphertext relay transport.
- The traversal controller is partially complete, but it still operates on a one-sided proof model rather than full WAN simultaneous-open behavior.

## 5. Complete Encryption Architecture

This section defines the **complete end-to-end encryption model** for all cross-network traffic. Every byte transmitted between Rustynet nodes across the Internet must be protected according to this specification.

### 5.1 Encryption Layer Model

Rustynet employs a **defense-in-depth encryption architecture** with three independent protection layers:

```
┌─────────────────────────────────────────────────────────────────┐
│ Layer 3: Application Payload (User Data)                       │
│   - User's actual network traffic (TCP/UDP/ICMP)               │
│   - DNS queries                                                 │
│   - Already protected by end-application TLS where applicable   │
└─────────────────────────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Layer 2: WireGuard Tunnel Encryption (MANDATORY, ALWAYS ON)    │
│   Protocol: WireGuard (RFC-draft, Noise Protocol Framework)    │
│   Cipher: ChaCha20-Poly1305 AEAD (RFC 8439)                    │
│   Key Exchange: Curve25519 (RFC 7748)                          │
│   Hash: BLAKE2s                                                 │
│   Authentication: Per-packet AEAD tag                          │
│   Anti-Replay: 64-bit counter-based                            │
│   Perfect Forward Secrecy: Automatic key rotation every 2 min  │
│   Confidentiality: 256-bit effective security                  │
└─────────────────────────────────────────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ Layer 1: Transport Path (Direct UDP OR Relay)                  │
│   DIRECT PATH:                                                  │
│     - Raw UDP packets containing WireGuard ciphertext           │
│     - NAT traversal via STUN/ICE-like probing                  │
│     - No additional encryption (WireGuard is sufficient)        │
│                                                                 │
│   RELAY PATH (when direct UDP fails):                          │
│     - Nested encryption model (see Section 5.3)                │
│     - Relay cannot decrypt Layer 2 (WireGuard) traffic         │
│     - Relay-specific session encryption prevents correlation   │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Direct Path Encryption (Peer-to-Peer)

**[ ] 5.2.1 WireGuard Protocol Enforcement**

When nodes communicate via direct UDP path:

1. **Protocol:** WireGuard 1.0 specification (noise-ik-psk pattern)
2. **Implementation:** `rustynet-backend-wireguard` crate wraps kernel WireGuard or userspace wireguard-rs
3. **Cipher Suite:** ChaCha20-Poly1305 AEAD (non-negotiable, no cipher downgrade)
4. **Key Material:**
   - Static Curve25519 keypair per node (generated at enrollment, stored in OS keychain)
   - Ephemeral session keys derived via Noise protocol handshake
   - Pre-shared key (PSK) support for post-quantum hardening (OPTIONAL, future Phase 11)
5. **Handshake:**
   - 1-RTT handshake using Noise_IK pattern
   - Identity hiding: responder identity is encrypted
   - No handshake amplification (protects against DDoS)
6. **Packet Protection:**
   - Every packet authenticated with Poly1305 MAC (128-bit tag)
   - Counter-based replay protection (64-bit counter, sliding window)
   - Padding to conceal packet lengths (optional, configurable per-flow)
7. **Key Rotation:**
   - Automatic session rekey every 2 minutes
   - Automatic rekey after 2^64-1 packets (never reached in practice)
   - Perfect forward secrecy: compromise of long-term key doesn't decrypt old sessions

**Security Properties:**
- ✅ Confidentiality: AES-256 equivalent (ChaCha20 uses 256-bit keys)
- ✅ Authenticity: Unforgeable MACs (Poly1305)
- ✅ Integrity: AEAD prevents tampering
- ✅ Anti-Replay: Sliding window prevents packet replay
- ✅ Perfect Forward Secrecy: Session keys rotated, not derivable from static keys
- ✅ Identity Privacy: Responder identity encrypted in handshake

**Verification Tests:**
```bash
# Verify WireGuard encryption is always active on direct paths
cargo test -p rustynetd phase10::tests::direct_path_requires_wireguard_handshake_success

# Verify no plaintext packets are ever sent
cargo test -p rustynetd phase10::tests::direct_path_never_sends_cleartext

# Verify replay protection
cargo test -p rustynetd phase10::tests::direct_path_rejects_replayed_packets
```

**[ ] 5.2.2 Key Distribution and Trust Model**

- **Key Generation:** Each node generates its own Curve25519 keypair at enrollment time
- **Public Key Distribution:** Control plane distributes public keys via signed "assignment bundles"
- **Trust Anchor:** Control plane's signing key is the root of trust
- **Key Verification:** Nodes MUST verify signature on assignment bundle before accepting peer public keys
- **No Key Escrow:** Control plane never sees private keys (zero-trust model)

**Implementation Location:**
- Key generation: `crates/rustynet-crypto/src/keypair.rs`
- Assignment bundle verification: `crates/rustynetd/src/assignment.rs`
- Backend integration: `crates/rustynet-backend-wireguard/src/peer_config.rs`

**[ ] 5.2.3 Direct Path Endpoint Mutation Security**

Critical constraint: **Only signed traversal bundles may trigger endpoint changes.**

```rust
// Pseudocode enforcement pattern
fn apply_endpoint_change(peer_id: NodeId, new_endpoint: SocketAddr) -> Result<()> {
    // STEP 1: Require signed traversal bundle (MANDATORY)
    let traversal = self.get_verified_traversal_bundle(peer_id)?
        .ok_or(Error::NoSignedTraversal)?;
    
    // STEP 2: Verify signature and freshness
    traversal.verify_signature(&self.control_plane_public_key)?;
    traversal.verify_fresh(MAX_TRAVERSAL_AGE)?;
    traversal.verify_nonce_not_replayed(&self.nonce_store)?;
    
    // STEP 3: Verify endpoint is in allowed candidate set
    if !traversal.candidates.contains(&new_endpoint) {
        return Err(Error::EndpointNotInCandidateSet);
    }
    
    // STEP 4: Only now may we mutate backend
    self.backend.update_peer_endpoint(peer_id, new_endpoint)?;
    
    // STEP 5: Record nonce to prevent replay
    self.nonce_store.record_used(traversal.nonce)?;
    
    Ok(())
}
```

**Attack Mitigations:**
- **Unsigned endpoint injection:** Blocked by signature verification
- **Replay attacks:** Blocked by nonce tracking
- **Rollback attacks:** Blocked by watermark/epoch counters
- **Stale traversal:** Blocked by TTL enforcement (MAX_TRAVERSAL_AGE = 60 seconds)

**Verification Tests:**
```bash
# Verify unsigned endpoint changes are rejected
cargo test -p rustynetd traversal::tests::unsigned_endpoint_mutation_rejected

# Verify replay protection
cargo test -p rustynetd traversal::tests::replayed_traversal_bundle_rejected

# Verify stale traversal rejection
cargo test -p rustynetd traversal::tests::stale_traversal_bundle_rejected
```

### 5.3 Relay Path Encryption (Zero-Trust Relay Model)

**[ ] 5.3.1 Architectural Principle: Zero-Knowledge Relay**

When direct UDP is impossible (hard NAT, firewall), Rustynet uses encrypted relay:

**Core Principle:** Relay infrastructure is **zero-trust**. Relay operators:
- ❌ Cannot decrypt WireGuard traffic (Layer 2 remains encrypted)
- ❌ Cannot see user application data
- ❌ Cannot correlate flows beyond session lifetime
- ✅ Can only forward opaque ciphertext between authenticated sessions

**Encryption Model: Nested Protection**

```
User Data
   └─> WireGuard Encrypted (ChaCha20-Poly1305)
       └─> Relay Session Encrypted (TLS 1.3 or Noise)
           └─> TCP/QUIC Transport
               └─> Internet
```

**Why Nested?**
1. **Defense in Depth:** Even if relay is compromised, WireGuard layer protects data
2. **Traffic Analysis Resistance:** Relay-layer encryption prevents correlation by external observers
3. **Session Isolation:** Relay session keys are ephemeral, distinct from WireGuard keys

**[ ] 5.3.2 Relay Session Establishment Protocol**

When a node needs relay service:

1. **Client → Control Plane:** Request relay allocation
   ```json
   {
     "request_type": "relay_allocation",
     "source_node_id": "node-abc123",
     "target_node_id": "node-xyz789",
     "signed_request": "<signature over (timestamp, node_ids, nonce)>"
   }
   ```

2. **Control Plane → Client:** Return signed relay credential
   ```json
   {
     "relay_url": "relay.rustynet.example.com:443",
     "relay_public_key": "<relay's X25519 public key>",
     "session_token": "<opaque session identifier>",
     "session_auth_key": "<HMAC key for session authentication>",
     "ttl": 300,
     "signed_bundle": "<control plane signature over entire payload>"
   }
   ```

3. **Client → Relay:** Establish encrypted session
   - Protocol: TLS 1.3 with relay's certificate (pinned public key)
   - OR: Noise_XX handshake for more control
   - Session bound to `session_token`
   - Every relay packet includes `HMAC-SHA256(session_auth_key, packet_data)` for authentication

4. **Relay Behavior:**
   - Relay maintains **two** concurrent encrypted sessions (client A ↔ relay ↔ client B)
   - Relay decrypts relay-layer envelope, extracts session_token, forwards to peer session
   - Relay **never** decrypts WireGuard layer (doesn't have keys)
   - Relay enforces rate limits, abuse detection, and session TTL

**[ ] 5.3.3 Relay Transport Protocol Specification**

**Option A: TLS 1.3-Based Relay (Recommended for MVP)**

```
Client                    Relay                    Target
  |                         |                         |
  |--- TLS 1.3 Handshake -->|                         |
  |<-- Server Certificate --|                         |
  |    (pin relay pubkey)   |                         |
  |                         |--- TLS 1.3 Handshake -->|
  |                         |<-- Server Certificate --|
  |                         |                         |
  |-- Relay Frame --------->|                         |
  |   [session_token]       |                         |
  |   [HMAC tag]            |                         |
  |   [WireGuard ciphertext]|-- Relay Frame --------->|
  |                         |   [WireGuard ciphertext]|
```

**Relay Frame Format:**
```
+----------------+----------------+------------------+-----------------+
| session_token  | sequence_num   | hmac_sha256      | wireguard_data  |
|   (16 bytes)   |   (8 bytes)    |   (32 bytes)     | (variable)      |
+----------------+----------------+------------------+-----------------+
```

- **session_token:** Opaque identifier from control plane
- **sequence_num:** Anti-replay counter (per-session)
- **hmac_sha256:** HMAC-SHA256(session_auth_key, session_token || sequence_num || wireguard_data)
- **wireguard_data:** Encrypted WireGuard packet (relay cannot decrypt)

**Security Properties:**
- ✅ Confidentiality: TLS 1.3 encryption (AES-128-GCM or ChaCha20-Poly1305)
- ✅ Relay Authentication: Certificate pinning prevents MitM
- ✅ Frame Authentication: HMAC prevents tampering
- ✅ Anti-Replay: Sequence numbers + HMAC binding
- ✅ Session Isolation: Each relay session has unique auth keys

**Constant-Time Comparison Requirement:**
```rust
// MANDATORY: Prevents timing attacks on session_token validation
fn verify_hmac(computed: &[u8; 32], provided: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    computed.ct_eq(provided).into()
}
```

**Implementation References:**
- Relay server: `crates/rustynet-relay/src/server.rs`
- Relay client: `crates/rustynetd/src/relay_client.rs`
- HMAC validation: `crates/rustynet-crypto/src/hmac.rs`

**Verification Tests:**
```bash
# Verify relay cannot decrypt WireGuard layer
cargo test -p rustynet-relay relay::tests::relay_cannot_decrypt_payload

# Verify constant-time HMAC comparison
cargo test -p rustynet-crypto hmac::tests::hmac_verification_constant_time

# Verify anti-replay protection
cargo test -p rustynet-relay relay::tests::replayed_sequence_rejected
```

**[ ] 5.3.4 Relay Abuse Protections**

To prevent relay from becoming an attack vector:

1. **Rate Limiting:**
   - Per-session: 10 MB/s sustained, 50 MB/s burst
   - Per-source-IP: 50 new sessions/minute
   - Global: Configurable capacity ceiling

2. **Session Lifecycle:**
   - Max TTL: 300 seconds (5 minutes)
   - Idle timeout: 60 seconds without traffic
   - Automatic cleanup on expiry

3. **Authentication Failures:**
   - 3 consecutive HMAC failures → session terminated
   - Source IP banned for 60 seconds after 10 failed authentications/minute

4. **Resource Bounds:**
   - Bounded session table (max 10,000 concurrent sessions)
   - Bounded queue depth per session (max 100 packets)
   - Memory limits enforced via bounded allocators

**Implementation:** `crates/rustynet-relay/src/abuse_prevention.rs`

### 5.4 Encryption Continuity During Path Transitions

**[ ] 5.4.1 Direct ↔ Relay Failover Without Re-keying**

Critical security property: **WireGuard session keys NEVER change during path transitions.**

```
Time:  T0              T1              T2              T3
       |               |               |               |
Path:  Direct UDP ---> Relay --------> Direct UDP
       |               ↑               ↑
Keys:  [WG Session 1]  |               |
                       [same keys]     [same keys]
                       
Effect: User experiences path change, but encryption is continuous
```

**Why This Matters:**
- No brief window of unencrypted traffic during failover
- No re-handshake latency
- No risk of handshake failure during network instability

**Implementation Approach:**
1. WireGuard session established once during initial peer connection
2. Traversal controller changes **transport path only** (UDP socket vs relay connection)
3. WireGuard backend continues using same session keys regardless of transport

**Code Path:**
```rust
// Pseudocode
fn transition_to_relay(peer_id: NodeId) -> Result<()> {
    // Get current WireGuard session state (DON'T destroy it)
    let wg_session = self.backend.get_session(peer_id)?;
    
    // Establish relay connection
    let relay_conn = self.relay_client.connect(peer_id).await?;
    
    // Redirect WireGuard packets to relay transport
    self.backend.set_transport(peer_id, Transport::Relay(relay_conn))?;
    
    // WireGuard session continues unchanged
    // No re-handshake, no key rotation
    Ok(())
}
```

**Verification Tests:**
```bash
# Verify no re-handshake during failover
cargo test -p rustynetd phase10::tests::direct_to_relay_transition_preserves_session

# Verify no packet loss window
cargo test -p rustynetd phase10::tests::failover_continuous_traffic_no_gap

# Verify same session keys before/after
cargo test -p rustynetd phase10::tests::failover_session_key_unchanged
```

**[ ] 5.4.2 Path Transition Security Invariants**

During any path transition (direct→relay, relay→direct, relay A→relay B):

1. **Encryption MUST remain active** - no cleartext packets ever sent
2. **ACL enforcement MUST remain active** - policy not bypassed during transition
3. **DNS fail-closed MUST remain active** - no DNS leaks during transition
4. **Kill-switch MUST remain active** - no underlay bypass during transition
5. **Traversal state MUST be signed** - no unsigned path changes

**Live Lab Test:**
```bash
# TunnelCrack-style bypass test during transition
scripts/e2e/live_linux_transition_leak_test.sh
```

### 5.5 Cryptographic Parameter Choices and Rationale

**[ ] 5.5.1 Algorithm Selection**

| Component | Algorithm | Rationale |
|-----------|-----------|-----------|
| Symmetric Encryption | ChaCha20 | Faster than AES on ARM, constant-time, no timing side-channels |
| Authentication | Poly1305 | Fast, provably secure, pairs with ChaCha20 |
| Key Exchange | Curve25519 | Industry standard, fast, side-channel resistant |
| Hash Function | BLAKE2s | Faster than SHA-256, cryptographically secure |
| Signature (Control Plane) | Ed25519 | Small keys, fast verification, deterministic |

**No Custom Cryptography:** All algorithms are **proven, standardized, audited implementations**:
- WireGuard: Extensively audited, formally verified in some implementations
- ChaCha20-Poly1305: RFC 8439, IETF standard
- Curve25519: RFC 7748, widely deployed (Signal, TLS 1.3)
- Ed25519: RFC 8032, NIST recommended

**[ ] 5.5.2 Key Lengths and Security Levels**

| Key Type | Length | Security Level | Post-Quantum Resistant? |
|----------|--------|----------------|-------------------------|
| WireGuard Static Key | 256 bits | 128-bit security | ❌ No (Curve25519) |
| WireGuard Session Key | 256 bits | 128-bit security | ❌ No |
| Control Plane Signing Key | 256 bits | 128-bit security | ❌ No (Ed25519) |
| Relay Session Auth Key | 256 bits | 128-bit security | ✅ Symmetric |
| PSK (Optional) | 256 bits | 256-bit security | ✅ Yes |

**Post-Quantum Strategy:**
- Current: Pre-shared key (PSK) mode adds post-quantum protection (future Phase 11)
- Future: Hybrid key exchange (Curve25519 + Kyber) when WireGuard spec stabilizes

**[ ] 5.5.3 Cryptographic Implementation Hygiene**

**MANDATORY REQUIREMENTS:**

1. **Memory Zeroization:**
   ```rust
   use zeroize::{Zeroize, ZeroizeOnDrop};
   
   #[derive(Zeroize, ZeroizeOnDrop)]
   struct PrivateKey([u8; 32]);
   
   // Automatically zeroed when dropped
   ```

2. **Constant-Time Comparison:**
   ```rust
   use subtle::ConstantTimeEq;
   
   fn compare_macs(a: &[u8], b: &[u8]) -> bool {
       a.ct_eq(b).into()
   }
   ```

3. **No Key Logging:**
   ```rust
   // NEVER do this
   println!("Private key: {:?}", private_key); // ❌ FORBIDDEN
   
   // Use redacted debug
   #[derive(Debug)]
   struct PrivateKey {
       #[debug("<redacted>")]
       key: [u8; 32]
   }
   ```

4. **Secure Random Number Generation:**
   ```rust
   use rand::rngs::OsRng;
   
   let mut key = [0u8; 32];
   OsRng.fill_bytes(&mut key); // Use OS entropy
   ```

**Verification Tests:**
```bash
# Verify no secret logging
cargo test -p rustynet-control operations::tests::structured_logger_never_writes_cleartext_secrets

# Verify zeroization
cargo test -p rustynet-crypto keypair::tests::private_key_zeroized_on_drop

# Verify constant-time operations
cargo test -p rustynet-crypto constant_time::tests::no_timing_leaks
```

### 5.6 Control Plane Transport Security

**[ ] 5.6.1 TLS 1.3 Enforcement**

All communication between nodes and control plane MUST use TLS 1.3:

- **Minimum Version:** TLS 1.3 (no fallback to 1.2 or earlier)
- **Cipher Suites:** 
  - `TLS_CHACHA20_POLY1305_SHA256` (preferred)
  - `TLS_AES_128_GCM_SHA256` (acceptable)
- **Certificate Validation:** Full chain validation + hostname verification
- **Certificate Pinning:** Optional for high-security deployments

**Why TLS 1.3 Only:**
- ✅ Eliminates downgrade attacks
- ✅ Mandatory perfect forward secrecy
- ✅ Encrypts more handshake data
- ✅ Faster handshake (1-RTT)

**[ ] 5.6.2 Signed State Bundle Verification**

Every control plane response (assignment, traversal, DNS, trust) MUST be signed:

```rust
struct SignedBundle {
    payload: Vec<u8>,           // JSON-serialized state
    signature: [u8; 64],        // Ed25519 signature
    signing_key_id: String,     // Which key signed this
    timestamp: u64,             // Unix timestamp
    nonce: [u8; 16],            // Anti-replay nonce
}

fn verify_bundle(bundle: &SignedBundle, trusted_key: &Ed25519PublicKey) -> Result<()> {
    // 1. Verify signature
    let message = [&bundle.payload, &bundle.timestamp.to_le_bytes(), &bundle.nonce].concat();
    trusted_key.verify(&message, &bundle.signature)?;
    
    // 2. Verify freshness (max 60 seconds old)
    if SystemTime::now() - bundle.timestamp > Duration::from_secs(60) {
        return Err(Error::Stale);
    }
    
    // 3. Verify nonce not replayed
    if nonce_store.seen(&bundle.nonce)? {
        return Err(Error::Replay);
    }
    nonce_store.record(&bundle.nonce)?;
    
    Ok(())
}
```

**Anti-Replay Strategy:**
- Nonce store: In-memory LRU cache (last 10,000 nonces)
- Persistence: Write-ahead log for crash recovery
- Cleanup: Automatic expiry after 120 seconds (2x max bundle age)

## 6. Known Vulnerability Classes and Mitigations

This section catalogs **known attacks against VPN systems** and Rustynet's specific defenses. This is **MANDATORY reading** before implementing any cross-network feature.

### 6.1 TunnelCrack (2023) - LocalNet and ServerIP Bypass

**Vulnerability:** Attackers create bypass routes that leak traffic outside VPN tunnel.

**Attack Vectors:**
1. **LocalNet Attack:** Attacker controls local router, injects routes for victim's destination IPs via local gateway
2. **ServerIP Attack:** Traffic to VPN server IP itself bypasses tunnel, attacker observes DNS/control traffic

**Rustynet Mitigations:**

**[ ] 6.1.1 Strict Route Ownership**
- ALL routes managed by Rustynet MUST be explicitly added via signed route advertisements
- No automatic "trust local gateway" behavior
- Operating system bypass routes ONLY for narrow control-plane IPs (exact /32 or /128)

**Implementation:**
```rust
// crates/rustynetd/src/routing.rs
fn apply_bypass_route(destination: IpAddr) -> Result<()> {
    // ONLY allow /32 (IPv4) or /128 (IPv6) - NO subnet bypass
    if !is_host_route(destination) {
        return Err(Error::BroadBypassNotAllowed);
    }
    
    // ONLY allow control plane IPs
    if !self.control_plane_ips.contains(&destination) {
        return Err(Error::UnauthorizedBypass);
    }
    
    // Add route
    self.route_table.add_bypass(destination)?;
    Ok(())
}
```

**Verification Tests:**
```bash
# Verify broad bypasses rejected
cargo test -p rustynetd routing::tests::subnet_bypass_rejected

# Live lab test
scripts/e2e/live_linux_server_ip_bypass_test.sh
```

**[ ] 6.1.2 Network Namespace Isolation (Linux)**

On Linux, use network namespaces for strongest isolation:
- Rustynet interface in separate namespace
- Only authorized sockets can access VPN namespace
- Physical interface isolated from VPN namespace

**Future Enhancement:** Phase 11 namespace hardening

### 6.2 TunnelVision (CVE-2024-3661) - DHCP Option 121 Injection

**Vulnerability:** Attacker on local network sends DHCP option 121 (classless static routes) that bypass VPN.

**Attack Vector:**
```
Attacker DHCP server → Client
  Option 121: 0.0.0.0/0 via attacker_gateway
  
Result: All traffic bypasses VPN, routes via attacker's gateway
```

**Rustynet Mitigations:**

**[ ] 6.2.1 Kill-Switch Route Lock**

When VPN is active in protected mode:
1. Install iptables/nftables rules BEFORE configuring interface
2. Default DENY all traffic except through VPN interface
3. DHCP changes cannot override iptables rules

**Implementation:**
```rust
// crates/rustynetd/src/firewall.rs
fn enable_killswitch(vpn_interface: &str) -> Result<()> {
    // 1. Block all output by default
    nftables::add_rule("output", "policy drop")?;
    
    // 2. Allow only through VPN interface
    nftables::add_rule("output", &format!("oifname {} accept", vpn_interface))?;
    
    // 3. Allow localhost
    nftables::add_rule("output", "oifname lo accept")?;
    
    // 4. Allow DHCP/DNS for bootstrap (narrow)
    nftables::add_rule("output", "udp dport 67-68 accept")?;
    
    Ok(())
}
```

**Verification Tests:**
```bash
# Verify DHCP option 121 cannot bypass
cargo test -p rustynetd dataplane::tests::dhcp_option_121_bypass_blocked

# Live lab test with malicious DHCP server
scripts/e2e/live_linux_dhcp_injection_test.sh
```

**[ ] 6.2.2 Network Namespace Alternative (Strongest)**

- Place WireGuard interface in dedicated network namespace
- DHCP runs in default namespace, cannot affect VPN namespace
- Physical isolation prevents option 121 from affecting VPN

### 6.3 Tailscale TS-2025-008 - Missing State Fail-Open

**Vulnerability:** When trust state files are missing (deleted, corrupted, unmounted), system fails OPEN instead of fail-closed.

**Attack Vector:**
```
1. Attacker compromises system
2. Attacker deletes /var/lib/tailscale/tailnet-lock.json
3. System boots without trust verification
4. Attacker can now push malicious config
```

**Rustynet Mitigations:**

**[ ] 6.3.1 Mandatory Trust State Verification**

```rust
// crates/rustynetd/src/daemon.rs
fn initialize_runtime() -> Result<RuntimeState> {
    // 1. Load trust state (signed membership/assignment)
    let trust_state = match TrustState::load()? {
        Some(state) => state,
        None => {
            // CRITICAL: Missing state is FAIL-CLOSED
            warn!("Trust state missing - entering restricted safe mode");
            return Ok(RuntimeState::RestrictedSafeMode);
        }
    };
    
    // 2. Verify signature and freshness
    trust_state.verify_signature(&self.control_plane_key)?;
    trust_state.verify_not_stale(MAX_TRUST_AGE)?;
    
    // 3. Only now allow normal operation
    Ok(RuntimeState::Normal(trust_state))
}
```

**Verification Tests:**
```bash
cargo test -p rustynetd daemon::tests::daemon_runtime_enters_restricted_safe_mode_without_trust_evidence
```

### 6.4 Tailscale TS-2026-001 - Shell Injection to Root

**Vulnerability:** Passing unsanitized input to shell commands allows privilege escalation.

**Attack Vector:**
```bash
# Vulnerable code (DON'T DO THIS)
command = format!("ip route add {} via {}", user_input, gateway);
system(command);  // ❌ Shell injection if user_input = "; rm -rf /"
```

**Rustynet Mitigations:**

**[ ] 6.4.1 Argv-Only Command Execution**

**MANDATORY RULE:** ALL privileged helper invocations MUST use argv arrays, NEVER shell construction.

```rust
// ✅ CORRECT
fn add_route(destination: IpNet, gateway: IpAddr) -> Result<()> {
    let output = Command::new("/sbin/ip")
        .arg("route")
        .arg("add")
        .arg(destination.to_string())
        .arg("via")
        .arg(gateway.to_string())
        .output()?;
    
    if !output.status.success() {
        return Err(Error::CommandFailed);
    }
    Ok(())
}

// ❌ FORBIDDEN
fn add_route_wrong(destination: &str, gateway: &str) -> Result<()> {
    let command = format!("ip route add {} via {}", destination, gateway);
    system(&command)?;  // NEVER DO THIS
    Ok(())
}
```

**[ ] 6.4.2 Input Validation Schema**

ALL external inputs MUST be validated against strict schemas:

```rust
fn validate_cidr(input: &str) -> Result<IpNet> {
    // Reject shell metacharacters
    if input.contains(&[';', '&', '|', '$', '`', '\n', '\r']) {
        return Err(Error::InvalidInput);
    }
    
    // Parse as IP network (strict)
    let net: IpNet = input.parse()
        .map_err(|_| Error::InvalidCidr)?;
    
    Ok(net)
}
```

**Verification Tests:**
```bash
cargo test -p rustynetd privileged_helper::tests::fuzzgate_rejects_unknown_tokens_and_shell_metacharacters
```

### 6.5 Tailscale TS-2024-005 - Exit Node Inbound Filtering Bypass

**Vulnerability:** Exit node forwards inbound internet traffic into mesh, not just outbound.

**Attack Vector:**
```
1. Client enables exit node
2. Attacker on internet sends packets to exit node's public IP
3. Packets forwarded into Rustynet mesh
4. Client receives unrequested traffic from internet
```

**Rustynet Mitigations:**

**[ ] 6.5.1 Strict Inbound Filtering on Exit Nodes**

```rust
// crates/rustynetd/src/exit_node.rs
fn configure_exit_nat(interface: &str) -> Result<()> {
    // 1. Enable forwarding
    sysctl("net.ipv4.ip_forward", "1")?;
    
    // 2. NAT outbound only (SNAT)
    nftables::add_rule("nat", "postrouting", 
        &format!("oifname {} masquerade", interface))?;
    
    // 3. CRITICAL: Block inbound forwarding from internet
    nftables::add_rule("filter", "forward",
        &format!("iifname {} oifname rustynet-* drop", interface))?;
    
    // 4. Allow outbound forwarding from mesh to internet
    nftables::add_rule("filter", "forward",
        &format!("iifname rustynet-* oifname {} accept", interface))?;
    
    Ok(())
}
```

**Verification Tests:**
```bash
cargo test -p rustynetd phase10::tests::exit_node_blocks_inbound_internet_to_mesh

# Live lab: External host tries to reach mesh via exit node
scripts/e2e/live_linux_exit_inbound_filter_test.sh
```

### 6.6 WireGuard Endpoint Mobility Attack

**Vulnerability:** WireGuard accepts endpoint changes from any source IP (by design for NAT roaming).

**Attack Vector:**
```
1. Attacker observes WireGuard handshake (knows public keys)
2. Attacker sends spoofed handshake from attacker's IP
3. WireGuard changes endpoint to attacker's IP
4. Traffic now routes through attacker (MitM)
```

**Rustynet Mitigations:**

**[ ] 6.6.1 Signed Endpoint Hints Only**

Rustynet **adds an authorization layer on top of WireGuard:**

```rust
fn process_wireguard_handshake(peer_id: NodeId, source_ip: IpAddr) -> Result<()> {
    // 1. WireGuard will accept handshake (we can't prevent this)
    
    // 2. BUT: Check if source_ip is in our signed candidate set
    let traversal = self.get_verified_traversal(peer_id)?
        .ok_or(Error::NoTraversal)?;
    
    if !traversal.candidates.contains(&source_ip) {
        // 3. Endpoint changed to unauthorized IP - REJECT
        warn!("Handshake from unauthorized endpoint: {}", source_ip);
        
        // 4. Restore last-known-good endpoint
        self.backend.reset_endpoint(peer_id, traversal.last_verified_endpoint)?;
        
        return Err(Error::UnauthorizedEndpoint);
    }
    
    // 5. Authorized endpoint - allow change
    Ok(())
}
```

**Detection:** Monitor WireGuard endpoint changes via netlink/status API

**Verification Tests:**
```bash
# Live lab: Attacker sends handshake from unexpected IP
scripts/e2e/live_linux_endpoint_hijack_test.sh
```

### 6.7 Additional Attack Classes

**[ ] 6.7.1 DNS Rebinding (Tailscale TS-2022-004/005)**
- **Mitigation:** No HTTP control API on localhost
- **Rustynet:** Unix socket only (not accessible via network)

**[ ] 6.7.2 Timing Side-Channels (Tailscale TS-2025-003)**
- **Mitigation:** Constant-time comparison for all auth tokens/HMACs
- **Verification:** `cargo test constant_time::tests::no_timing_leaks`

**[ ] 6.7.3 Auth Key Reuse Race (Tailscale TS-2025-007)**
- **Mitigation:** Atomic TOCTOU-resistant credential consumption
- **Implementation:** `crates/rustynet-control/src/credential_store.rs`
- **Verification:** `cargo test credential::tests::concurrent_enrollment_single_use_enforced`

**[ ] 6.7.4 Secrets in Logs (Tailscale TS-2025-005)**
- **Mitigation:** Structured logging with automatic secret redaction
- **Verification:** `cargo test operations::tests::structured_logger_never_writes_cleartext_secrets`

**[ ] 6.7.5 Protocol Filter Omission (Tailscale TS-2025-006)**
- **Mitigation:** ACL protocol filters preserved end-to-end
- **Verification:** `cargo test acl::tests::protocol_specific_acl_enforced_on_exit_node`

## 7. Non-Negotiable Security Invariants

These must hold throughout every phase:

1. **[ ] One hardened path only for endpoint mutation.**
   - `verified signed traversal state -> deterministic controller decision -> backend apply`
   
2. **[ ] No unsigned endpoint mutation.**
   - All endpoint changes MUST have corresponding signed traversal bundle
   - Verification: Lines in code + test paths
   
3. **[ ] No silent fallback to weaker path logic.**
   - No "legacy" runtime branches
   - No "temporary" insecure fallbacks
   
4. **[ ] No plaintext visibility at the relay.**
   - Relay sees only WireGuard ciphertext
   - Verification: Relay server tests + adversarial audit
   
5. **[ ] No unprotected egress if no valid direct or relay path exists.**
   - Kill-switch enforced in protected mode
   - Fail-closed on trust state loss
   
6. **[ ] Replay, rollback, stale-state, and wrong-signer artifacts must fail closed.**
   - Nonce tracking prevents replay
   - Watermark/epoch prevents rollback
   - TTL enforcement prevents stale acceptance
   - Signature verification prevents wrong-signer
   
7. **[ ] Route and DNS protections must survive direct/relay transitions.**
   - No leak window during failover
   - Continuous kill-switch enforcement
   
8. **[ ] Exit-node selection must never widen LAN or underlay access beyond explicit policy.**
   - Exit node advertising MUST be signed
   - Route ACLs strictly enforced
   
9. **[ ] Local control surfaces remain Unix-socket or root-only system integration surfaces.**
   - No HTTP API on localhost (prevents DNS rebinding)
   - No LAN-accessible management ports
   
10. **[ ] Every new cross-network behavior must land with measured gate evidence.**
    - Not just unit tests
    - Live lab validation required

## 8. Minimum Functional Definition of Done

Rustynet can claim cross-network remote exit-node support only when all of the following are true:

**[ ] 8.1 Direct Path Capabilities**
1. A client behind NAT can use a remote exit node behind a different NAT via direct UDP when NAT conditions allow.
2. WireGuard encryption active end-to-end (ChaCha20-Poly1305 AEAD verified).
3. Signed traversal bundle required for initial connection and all endpoint changes.
4. Anti-replay, anti-rollback, and freshness protections operational.

**[ ] 8.2 Relay Path Capabilities**
1. A client can use the same remote exit node via encrypted relay when direct UDP does not work.
2. Nested encryption: WireGuard layer + relay session layer both active.
3. Relay cannot decrypt WireGuard payload (zero-trust relay verified).
4. Relay authentication uses constant-time comparison.
5. Relay abuse protections enforced (rate limits, session TTL, bounded resources).

**[ ] 8.3 Path Transition Safety**
1. Direct-to-relay and relay-to-direct transitions preserve:
   - WireGuard session keys (no re-handshake)
   - ACL enforcement
   - Kill-switch behavior
   - DNS fail-closed behavior
   - Narrow server-IP bypass semantics (only /32 or /128 for control plane)
2. No packet loss or cleartext window during transition.
3. Continuous encryption verified during failover.

**[ ] 8.4 Security Properties**
1. All known vulnerability classes from Section 6 mitigated and tested:
   - TunnelCrack (LocalNet/ServerIP bypass)
   - TunnelVision (DHCP option 121 injection)
   - Tailscale fail-open bugs (TS-2025-008)
   - Tailscale shell injection (TS-2026-001)
   - Tailscale exit filtering (TS-2024-005)
   - WireGuard endpoint mobility attacks
2. Adversarial test suite passes (forged/replayed/stale traversal rejected).
3. No secret leakage in logs, metrics, or error messages.

**[ ] 8.5 Operational Resilience**
1. System remains functional after endpoint roaming (IP address change).
2. System survives control plane temporary unavailability (uses cached signed state).
3. System fails closed when trust state is missing/corrupted/expired.

**[ ] 8.6 Measured Evidence**
1. Live validation artifacts exist and pass on a multi-network Linux lab.
2. All artifacts follow schema in CrossNetworkRemoteExitArtifactSchema_2026-03-16.md.
3. Evidence is commit-bound, not stale, and reproducible.

## 7. Gap Summary
The remaining work falls into four technical gaps:
1. Candidate acquisition:
   - Rustynet needs real public/reflexive candidate discovery, not just signed endpoint hints carrying static or pre-known addresses.
2. WAN simultaneous-open behavior:
   - Rustynet needs shared-socket, real NAT traversal behavior rather than only one-sided bounded probe logic.
3. Relay transport:
   - Rustynet needs a real ciphertext relay service and client integration.
4. Cross-network exit-path validation:
   - Rustynet needs measured live evidence that full-tunnel routing and DNS remain secure across direct and relay paths.

## 8. Implementation Phases
### Phase 0: Truth Lock and Threat Model Baseline
Goal:
- Align all remaining work under one current-state plan and stop overstating completion.

Tasks:
1. Keep current docs explicit that WAN simultaneous-open and production relay are still open.
2. Maintain the exploit-comparison and live-auditing skill outputs as release inputs for traversal and relay work.
3. Treat HP2 and HP3 as release-blocking for cross-network remote-exit claims.

Primary touchpoints:
- [README.md](/Users/iwanteague/Desktop/Rustynet/README.md)
- [phase10.md](/Users/iwanteague/Desktop/Rustynet/documents/phase10.md)
- [tools/skills/rustynet-security-auditor](/Users/iwanteague/Desktop/Rustynet/tools/skills/rustynet-security-auditor/SKILL.md)

Acceptance:
- No repo document claims "connect from anywhere" without measured evidence.

### Phase 1: Candidate Acquisition and Signed Traversal Inputs
Goal:
- Complete the authenticated candidate-discovery foundation required for real cross-network connectivity.

Tasks:
1. Add real candidate acquisition for:
   - local interface candidates,
   - public reflexive candidates,
   - relay candidates.
2. Keep the signed traversal artifact model:
   - source node,
   - target node,
   - candidate list,
   - short TTL,
   - nonce,
   - watermark/replay protection,
   - signature.
3. Ensure candidate acquisition does not create an alternate runtime authority path.
4. Bind every candidate the daemon consumes to:
   - a signed artifact,
   - freshness window,
   - authorization scope.

Primary touchpoints:
- [crates/rustynet-control/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-control/src/lib.rs)
- [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)
- [crates/rustynetd/src/traversal.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/traversal.rs)
- [crates/rustynet-cli/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/main.rs)

Security constraints:
- No raw peer endpoint gossip.
- No unsigned STUN-like observations used directly for endpoint mutation.
- Candidate TTLs must remain short and bounded.
- Oversized or malformed candidate artifacts must fail closed.

Acceptance:
- Measured artifact proving:
  - signed candidate publication,
  - replay rejection,
  - wrong-signer rejection,
  - stale candidate rejection,
  - no endpoint mutation without signed traversal authority.

### Phase 2: Complete HP2 for Real WAN Simultaneous-Open
Goal:
- Turn the current one-sided probe model into a real cross-network direct-path engine.

Tasks:
1. Ensure traversal attempts use the same UDP socket and port behavior as the actual WireGuard transport path.
2. Implement simultaneous-open scheduling suitable for unrelated NATs.
3. Extend endpoint-roam handling to real WAN path changes.
4. Keep bounded, deterministic probe fanout and pacing from daemon config.
5. Preserve direct/relay decision control in one state machine only.

Primary touchpoints:
- [crates/rustynetd/src/traversal.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/traversal.rs)
- [crates/rustynetd/src/phase10.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs)
- [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)
- [crates/rustynet-backend-wireguard/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/lib.rs)

Security constraints:
- No manual or operator-driven endpoint override as a production path.
- No path transition without signed traversal proof and deterministic controller approval.
- Direct-path establishment must not disable kill-switch or route-leak protections.
- Direct-path success criteria must be based on bounded authenticated runtime evidence, not optimistic assumption.

Acceptance:
- Live measured evidence showing:
  - two nodes on different networks establish direct UDP when NAT conditions allow,
  - direct path survives endpoint roaming,
  - direct-path failure falls back safely without leak.

### Phase 3: Build HP3 Production Relay Transport
Goal:
- Provide a secure fallback path when direct UDP is impossible.

Tasks:
1. Convert [rustynet-relay](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/lib.rs) from selector-only logic into a real ciphertext relay service.
2. Add authenticated relay session setup and expiry.
3. Add per-session replay protection.
4. Use constant-time comparison for relay auth/token validation.
5. Add abuse protections:
   - rate limiting,
   - bounded queues,
   - idle expiry,
   - per-node/session scoping.
6. Keep relay blind to payload plaintext.

Primary touchpoints:
- [crates/rustynet-relay/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/lib.rs)
- [crates/rustynet-relay/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/main.rs)
- [crates/rustynetd/src/phase10.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs)
- [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)
- [crates/rustynet-control/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-control/src/lib.rs)

Security constraints:
- Relay sees only ciphertext and minimal routing metadata.
- No plaintext session negotiation outside the existing trust model.
- Relay token/session validation must be constant-time.
- Relay path use must still obey assignment/trust/ACL policy.

Acceptance:
- Measured evidence showing:
  - direct-blocked peers can still connect through relay,
  - relay transport does not expose plaintext,
  - auth failures, stale sessions, and replay attempts fail closed.

### Phase 4: Remote Exit-Node Dataplane Integration
Goal:
- Make remote exit-node use work over either direct or relay path without weakening policy.

Tasks:
1. Ensure the client can select a remote exit node on another network and use it as:
   - full-tunnel egress,
   - managed DNS path,
   - optional LAN toggle path where authorized.
2. Preserve narrow server-IP bypass semantics for control traffic.
3. Ensure the exit node enforces:
   - route scope,
   - forwarding/NAT policy,
   - DNS policy,
   - ACL constraints.
4. Ensure path changes do not cause transient underlay leaks.

Primary touchpoints:
- [crates/rustynetd/src/phase10.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs)
- [crates/rustynetd/src/dataplane.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/dataplane.rs)
- [crates/rustynet-cli/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/main.rs)
- [start.sh](/Users/iwanteague/Desktop/Rustynet/start.sh)

Security constraints:
- Exit selection remains signed-state-driven.
- No raw route mutation fallback in `start.sh` or daemon control flow.
- DNS must remain managed-zone fail-closed.
- LAN access remains explicit and policy-limited.

Acceptance:
- Live measured evidence showing:
  - client on network A uses exit on network B,
  - DNS remains protected,
  - no route leak or underlay bypass occurs during steady state or path transition.

### Phase 5: Testing, Security Gates, and Release Enforcement
Goal:
- Convert the feature from "implemented in code" to "proven secure in the lab".

Tasks:
1. Extend the existing live validation skill and orchestrator coverage to include:
   - direct cross-network exit-node success,
   - relay-backed cross-network exit-node success,
   - relay-to-direct failback,
   - endpoint roaming recovery,
   - stale/forged traversal rejection during active sessions.
2. Bind those results into canonical tracked artifacts under `artifacts/phase10/`.
3. Extend Phase 10 readiness to require those artifacts.
4. Keep comparative exploit coverage honest:
   - do not promote partially covered classes without measured live evidence.
5. Add a dedicated cross-network exit-node gate bundle rather than relying on generic traversal success alone.

Primary touchpoints:
- [scripts/ci/phase10_hp2_gates.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/phase10_hp2_gates.sh)
- [scripts/ci/check_phase10_readiness.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/check_phase10_readiness.sh)
- [scripts/e2e/live_linux_lab_orchestrator.sh](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_lab_orchestrator.sh)
- [tools/skills/rustynet-security-auditor](/Users/iwanteague/Desktop/Rustynet/tools/skills/rustynet-security-auditor/SKILL.md)

Security constraints:
- No release gate may be weakened to compensate for missing WAN evidence.
- Evidence must remain commit-bound and measured.
- Stale child evidence must fail closed.
- A passing local/unit gate is not sufficient to claim cross-network readiness.

Acceptance:
- Phase 10 gates require and pass on:
  - cross-network direct remote-exit evidence,
  - cross-network relay remote-exit evidence,
  - fail-closed adversarial traversal evidence.

## 8A. Comprehensive Rust Testing Requirements

This section defines MANDATORY testing requirements for all cross-network functionality. Every feature must have multi-layered test coverage before it can be considered complete.

### 8A.1 Test Pyramid Structure

Rustynet follows a strict test pyramid:

```
                    ▲
                   ╱ ╲
                  ╱   ╲
                 ╱ E2E ╲         10% - Live Lab Tests (hours)
                ╱───────╲
               ╱         ╲
              ╱Integration╲      20% - Integration Tests (minutes)
             ╱─────────────╲
            ╱               ╲
           ╱   Unit Tests    ╲   70% - Unit & Property Tests (seconds)
          ╱___________________╲
```

**Ratios:**
- **70% Unit Tests:** Fast, isolated, deterministic
- **20% Integration Tests:** Multi-component, in-process
- **10% E2E Tests:** Full system, live network

### 8A.2 Unit Test Requirements (Rust)

#### 8A.2.1 Core Principles

Every Rust module MUST have:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    // REQUIRED: Test module for every implementation module
}
```

**Coverage Requirements:**
- **Minimum:** 80% line coverage for security-critical modules
- **Target:** 90% line coverage for all modules
- **Mandatory:** 100% coverage for crypto/signature verification code

**Tools:**
```bash
# Generate coverage report
cargo tarpaulin --out Html --output-dir coverage/

# Enforce minimum coverage in CI
cargo tarpaulin --fail-under 80
```

#### 8A.2.2 Signature Verification Tests

Every function that verifies signatures MUST have these tests:

```rust
#[cfg(test)]
mod signature_tests {
    use super::*;
    
    #[test]
    fn valid_signature_accepted() {
        let (public_key, secret_key) = generate_test_keypair();
        let payload = b"test payload";
        let signature = sign(payload, &secret_key);
        
        assert!(verify_signature(payload, &signature, &public_key).is_ok());
    }
    
    #[test]
    fn invalid_signature_rejected() {
        let (public_key, _) = generate_test_keypair();
        let payload = b"test payload";
        let bad_signature = [0u8; 64]; // Wrong signature
        
        assert!(verify_signature(payload, &bad_signature, &public_key).is_err());
    }
    
    #[test]
    fn wrong_key_signature_rejected() {
        let (public_key1, secret_key1) = generate_test_keypair();
        let (public_key2, _) = generate_test_keypair();
        let payload = b"test payload";
        let signature = sign(payload, &secret_key1);
        
        // Signed with key1, verified with key2 -> reject
        assert!(verify_signature(payload, &signature, &public_key2).is_err());
    }
    
    #[test]
    fn modified_payload_rejected() {
        let (public_key, secret_key) = generate_test_keypair();
        let original = b"original payload";
        let modified = b"modified payload";
        let signature = sign(original, &secret_key);
        
        assert!(verify_signature(modified, &signature, &public_key).is_err());
    }
    
    #[test]
    fn empty_signature_rejected() {
        let (public_key, _) = generate_test_keypair();
        let payload = b"test payload";
        let empty_sig = [];
        
        assert!(verify_signature(payload, &empty_sig, &public_key).is_err());
    }
}
```

#### 8A.2.3 Anti-Replay Tests

Every nonce/replay protection mechanism MUST have:

```rust
#[cfg(test)]
mod replay_protection_tests {
    use super::*;
    
    #[test]
    fn fresh_nonce_accepted() {
        let mut store = NonceStore::new();
        let nonce = generate_nonce();
        
        assert!(store.check_and_record(&nonce).is_ok());
    }
    
    #[test]
    fn replayed_nonce_rejected() {
        let mut store = NonceStore::new();
        let nonce = generate_nonce();
        
        // First use: OK
        assert!(store.check_and_record(&nonce).is_ok());
        
        // Second use: REJECTED
        assert!(store.check_and_record(&nonce).is_err());
    }
    
    #[test]
    fn expired_nonce_cleaned_up() {
        let mut store = NonceStore::new();
        let nonce = generate_nonce();
        
        store.check_and_record(&nonce).unwrap();
        
        // Fast-forward time past expiry
        store.advance_time(Duration::from_secs(121)); // 2x max age
        
        // Cleanup should remove old nonces
        store.cleanup_expired();
        
        // Old nonce is gone, but we still reject to be safe
        assert!(store.check_and_record(&nonce).is_err());
    }
    
    #[test]
    fn concurrent_nonce_recording_safe() {
        use std::sync::Arc;
        use std::thread;
        
        let store = Arc::new(Mutex::new(NonceStore::new()));
        let nonce = Arc::new(generate_nonce());
        
        // Two threads try to use same nonce
        let handles: Vec<_> = (0..2).map(|_| {
            let store = Arc::clone(&store);
            let nonce = Arc::clone(&nonce);
            thread::spawn(move || {
                store.lock().unwrap().check_and_record(&nonce)
            })
        }).collect();
        
        let results: Vec<_> = handles.into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        
        // Exactly ONE should succeed, ONE should fail
        let successes = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(successes, 1, "Concurrent nonce check failed atomicity");
    }
}
```

#### 8A.2.4 Constant-Time Operation Tests

All timing-sensitive operations MUST have constant-time verification:

```rust
#[cfg(test)]
mod constant_time_tests {
    use super::*;
    use std::time::Instant;
    
    #[test]
    fn hmac_verification_constant_time() {
        let key = [42u8; 32];
        let correct_hmac = compute_hmac(&key, b"test data");
        let wrong_hmac = [0u8; 32];
        
        // Measure timing for correct HMAC
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = verify_hmac(&correct_hmac, &correct_hmac, &key);
        }
        let correct_duration = start.elapsed();
        
        // Measure timing for wrong HMAC
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = verify_hmac(&wrong_hmac, &correct_hmac, &key);
        }
        let wrong_duration = start.elapsed();
        
        // Timing difference should be negligible (< 5%)
        let ratio = if correct_duration > wrong_duration {
            correct_duration.as_nanos() as f64 / wrong_duration.as_nanos() as f64
        } else {
            wrong_duration.as_nanos() as f64 / correct_duration.as_nanos() as f64
        };
        
        assert!(ratio < 1.05, 
            "HMAC verification has timing leak: ratio={}", ratio);
    }
    
    #[test]
    fn token_comparison_constant_time() {
        use subtle::ConstantTimeEq;
        
        let token1 = [1u8; 16];
        let token2 = [2u8; 16];
        
        // This should compile (uses constant-time comparison)
        let _ = token1.ct_eq(&token2);
        
        // This should NOT compile if we've forbidden variable-time comparison
        // (enforced via clippy lint)
        // let _ = token1 == token2;  // Should trigger clippy::op_ref_non_const_eq
    }
}
```

#### 8A.2.5 Memory Safety Tests

Sensitive data MUST be zeroized:

```rust
#[cfg(test)]
mod memory_safety_tests {
    use super::*;
    use zeroize::Zeroize;
    
    #[test]
    fn private_key_zeroized_on_drop() {
        let key_ptr: *const u8;
        let key_value: u8;
        
        {
            let key = PrivateKey::generate();
            let key_bytes = key.as_bytes();
            key_ptr = key_bytes.as_ptr();
            key_value = key_bytes[0];
            
            // Key exists and has non-zero value
            assert_ne!(key_value, 0);
        }
        // Key dropped here - should be zeroized
        
        // SAFETY: This is a test verification that zeroization occurred
        // In production, this memory may be reallocated
        unsafe {
            let potentially_zeroized = std::ptr::read(key_ptr);
            // Note: This test is best-effort, as memory may have been reused
            // Better approach: Use memory sanitizers in CI
        }
    }
    
    #[test]
    fn session_keys_not_in_debug_output() {
        let session = Session::new_test();
        let debug_output = format!("{:?}", session);
        
        // Debug output should NOT contain raw key bytes
        assert!(!debug_output.contains("key"));
        assert!(debug_output.contains("<redacted>") || 
                debug_output.contains("***"));
    }
    
    #[test]
    fn no_key_material_in_error_messages() {
        let key = PrivateKey::generate();
        let result: Result<(), _> = Err(Error::InvalidKey(key));
        
        let error_message = format!("{}", result.unwrap_err());
        
        // Error message should NOT expose key material
        assert!(!error_message.contains(&format!("{:?}", key.as_bytes())));
    }
}
```

#### 8A.2.6 Property-Based Testing (Mandatory for Parsers)

Use `proptest` for all parsing/validation code:

```rust
#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    
    proptest! {
        #[test]
        fn parse_cidr_never_panics(s in "\\PC*") {
            // Any string input should not panic
            let _ = parse_cidr(&s);
        }
        
        #[test]
        fn valid_cidr_roundtrips(ip in any::<IpAddr>(), prefix_len in 0u8..=128) {
            let cidr = format!("{}/{}", ip, prefix_len);
            if let Ok(parsed) = parse_cidr(&cidr) {
                assert_eq!(parsed.to_string(), cidr);
            }
        }
        
        #[test]
        fn signature_verification_never_panics(
            payload in proptest::collection::vec(any::<u8>(), 0..1024),
            signature in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let (public_key, _) = generate_test_keypair();
            
            // Should never panic, even with garbage input
            let _ = verify_signature(&payload, &signature, &public_key);
        }
        
        #[test]
        fn nonce_check_never_panics(
            nonce in proptest::collection::vec(any::<u8>(), 0..32)
        ) {
            let mut store = NonceStore::new();
            let _ = store.check_and_record(&nonce);
        }
    }
}
```

#### 8A.2.7 Fuzzing Requirements

Security-critical parsers MUST have fuzz tests:

```rust
// fuzz/fuzz_targets/traversal_bundle_parser.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use rustynet_control::TraversalBundle;

fuzz_target!(|data: &[u8]| {
    // Should never panic or crash
    let _ = TraversalBundle::parse(data);
});
```

**Fuzzing commands:**
```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run fuzzer for 10 minutes minimum
cargo fuzz run traversal_bundle_parser -- -max_total_time=600

# Run all fuzzers in CI
cargo fuzz list | xargs -I {} cargo fuzz run {} -- -max_total_time=60
```

**Mandatory fuzz targets:**
- [ ] Traversal bundle parser
- [ ] Assignment bundle parser
- [ ] DNS zone parser
- [ ] ACL policy parser
- [ ] Relay frame parser

### 8A.3 CI/CD Gate Requirements

Every PR must pass these gates:

```yaml
# .github/workflows/security_gates.yml
name: Security Gates

on: [pull_request]

jobs:
  unit_tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: cargo test --all-features --all-targets
      - run: cargo tarpaulin --fail-under 80
      
  property_tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: cargo test --release -- --ignored proptest
      
  fuzz_tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: cargo install cargo-fuzz
      - run: |
          for target in $(cargo fuzz list); do
            cargo fuzz run $target -- -max_total_time=60 -rss_limit_mb=2048
          done
          
  integration_tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: cargo test --test '*' --all-features
      
  clippy_security_lints:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: cargo clippy --all-targets --all-features -- -D warnings
      - run: cargo clippy --all-targets --all-features -- -W clippy::unwrap_used
      - run: cargo clippy --all-targets --all-features -- -W clippy::expect_used
      - run: cargo clippy --all-targets --all-features -- -D clippy::panic
      
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: cargo audit --deny warnings
      - run: cargo deny check bans licenses sources advisories
      
  miri:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: rustup component add miri
      - run: cargo miri test --package rustynet-crypto
      
  live_lab_tests:
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request' && contains(github.event.pull_request.labels.*.name, 'security-critical')
    steps:
      - uses: actions/checkout@v3
      - run: ./scripts/e2e/run_all_live_tests.sh
      - uses: actions/upload-artifact@v3
        with:
          name: live-test-evidence
          path: artifacts/live_lab/
```

### 8A.4 Test Evidence Requirements

Every test MUST generate structured evidence:

```rust
// In test code
#[test]
fn signature_verification_blocks_invalid() {
    let test_id = uuid::Uuid::new_v4();
    let evidence_path = PathBuf::from(format!(
        "artifacts/test_evidence/{}.json",
        test_id
    ));
    
    // Run test
    let result = verify_signature(/* invalid */);
    assert!(result.is_err());
    
    // Generate evidence
    let evidence = TestEvidence {
        test_id: test_id.to_string(),
        test_name: "signature_verification_blocks_invalid",
        timestamp: SystemTime::now(),
        result: "pass",
        git_commit: env!("GIT_COMMIT"),
        details: json!({
            "verification_result": "rejected",
            "error_type": "InvalidSignature",
        }),
    };
    
    std::fs::create_dir_all(evidence_path.parent().unwrap()).unwrap();
    std::fs::write(evidence_path, serde_json::to_string_pretty(&evidence).unwrap()).unwrap();
}
```

## 9. Mandatory Test and Gate Contract for "Connect From Anywhere"
This is release-blocking. Rustynet must not claim cross-network remote-exit capability until all required tests and gates below exist and pass on the target commit.

### 9.1 Required test classes
1. Unit and property tests
   - signed candidate parsing and verification
   - replay, rollback, stale-state, wrong-signer rejection
   - bounded simultaneous-open scheduling
   - relay session token/auth validation
   - constant-time auth/token comparison for relay control surfaces
   - route and DNS fail-closed transitions during path changes
2. Local integration tests
   - backend endpoint rotation on valid traversal decision only
   - direct-path establishment success when handshake evidence advances
   - safe fallback to relay when direct cannot be proven
   - safe failback from relay to direct when direct becomes healthy
   - exit-node routing and DNS enforcement under path transitions
3. Live multi-network lab tests
   - direct remote-exit success across different networks
   - relay-backed remote-exit success across different networks
   - relay-to-direct failback after reprobe
   - endpoint roaming recovery
   - reboot recovery while remote-exit path remains policy-safe
4. Adversarial live tests
   - forged traversal state during active session
   - stale traversal state during active session
   - replayed traversal state during active session
   - rogue endpoint injection
   - route-bypass / TunnelCrack-style leak attempts during path change
   - control-surface exposure checks while cross-network exit path is active
5. Soak and resilience tests
   - long-running direct session across networks
   - long-running relay session across networks
   - repeated direct/relay flaps without policy leak

### 9.2 Required measured artifacts
At minimum, the following tracked measured artifacts must exist under `artifacts/phase10/` and be required by readiness checks:
- `cross_network_direct_remote_exit_report.json`
- `cross_network_relay_remote_exit_report.json`
- `cross_network_failback_roaming_report.json`
- `cross_network_traversal_adversarial_report.json`
- `cross_network_remote_exit_dns_report.json`
- `cross_network_remote_exit_soak_report.json`

Each artifact must be:
- `evidence_mode = measured`
- commit-bound to the current `HEAD`
- tagged with `nat_profile` and `impairment_profile`
- sourced from canonical tracked inputs, not gitignored run-only paths
- rejected if stale, incomplete, or schema-invalid

Canonical schema reference:
- [CrossNetworkRemoteExitArtifactSchema_2026-03-16.md](/Users/iwanteague/Desktop/Rustynet/documents/operations/CrossNetworkRemoteExitArtifactSchema_2026-03-16.md)
- `cargo run --quiet -p rustynet-cli -- ops validate-cross-network-remote-exit-reports ...`

### 9.3 Required checks inside those artifacts
The measured reports must prove all of the following checks as `pass`:
1. `direct_remote_exit_success`
2. `relay_remote_exit_success`
3. `relay_to_direct_failback_success`
4. `endpoint_roam_recovery_success`
5. `failback_reconnect_within_slo`
6. `no_underlay_leak_while_reconnecting`
7. `signed_state_valid_while_reconnecting`
8. `remote_exit_dns_fail_closed`
9. `remote_exit_no_underlay_leak`
10. `remote_exit_server_ip_bypass_is_narrow`
11. `forged_traversal_rejected`
12. `stale_traversal_rejected`
13. `replayed_traversal_rejected`
14. `rogue_endpoint_rejected`
15. `control_surface_exposure_blocked`
16. `long_soak_stable`
17. `cross_network_topology_heuristic`
18. `direct_remote_exit_ready`
19. `post_soak_bypass_ready`
20. `no_plaintext_passphrase_files`

### 9.4 Required gate wiring
The repo should add or extend gate entry points so this evidence is enforced automatically:
1. Add a dedicated gate bundle:
   - [phase10_cross_network_exit_gates.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/phase10_cross_network_exit_gates.sh)
   - include `cargo run --quiet -p rustynet-cli -- ops validate-cross-network-nat-matrix ...` as a hard-fail matrix coverage check
2. Keep `scripts/ci/phase10_hp2_gates.sh` for traversal engine correctness, but do not treat it as sufficient evidence for remote exit-node readiness.
3. Extend [check_phase10_readiness.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/check_phase10_readiness.sh) to require every cross-network remote-exit artifact and its mandatory checks.
   - that readiness path must invoke `cargo run --quiet -p rustynet-cli -- ops validate-cross-network-remote-exit-reports ...` before interpreting pass/fail checks
4. Extend [live_linux_lab_orchestrator.sh](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_lab_orchestrator.sh) so the cross-network exit suite is a distinct hard-fail stage.
5. Extend the Rustynet security auditor skill so coverage promotion only happens when those measured reports pass schema validation and required checks.

### 9.5 Failure policy
If any required test or artifact fails:
1. Rustynet must not claim "connect from anywhere".
2. Coverage remains `partially_covered`.
3. Release readiness must fail closed.
4. The fix must land with a regression test or measured validator that proves the failure class is covered.

### 9.6 Security interpretation of pass/fail
- A passing direct-path test without relay proof is insufficient.
- A passing relay-path test without direct-path proof is insufficient.
- A passing happy-path test without adversarial rejection proof is insufficient.
- A passing unit/integration suite without measured live evidence is insufficient.

## 10. Recommended Build Order
The correct implementation order from the current repo state is:
1. Finish candidate acquisition and signed traversal input completeness.
2. Finish true WAN simultaneous-open behavior in HP2.
3. Implement real relay transport in HP3.
4. Bind exit-node full-tunnel semantics to those paths.
5. Add live measured evidence and gate enforcement.

This order matters. Shipping relay before the direct-path controller is secure enough would multiply trust surfaces unnecessarily. Shipping direct-path claims before live cross-network validation would overstate the feature and weaken release integrity.

## 11. What Must Not Be Done
1. Do not add a second endpoint mutation path.
2. Do not accept unsigned or locally guessed external endpoints.
3. Do not rely on manual port forwarding as the product correctness path.
4. Do not treat a public-IP exit node as proof that hole punching is complete.
5. Do not add "temporary" raw shell fallbacks for relay or traversal control.
6. Do not claim "works from anywhere" until live multi-network evidence exists.

## 12. Immediate Next Code Work
The highest-value next code steps are:
1. Finish the candidate acquisition side for real public/reflexive candidates.
2. Complete shared-socket simultaneous-open behavior in the traversal engine and backend integration.
3. Begin the real ciphertext relay transport implementation in `rustynet-relay`.
4. Define the cross-network remote-exit measured artifact schemas and readiness checks before implementation claims start to drift.

## 13. Exit Criteria for This Plan
This plan is complete only when:
1. Rustynet can securely connect a client on one network to an exit node on another network without manual port forwarding when direct NAT traversal is possible.
2. The same workflow securely succeeds via relay when direct traversal is not possible.
3. The measured live artifacts and Phase 10 gates prove that behavior on the current commit.
4. The required cross-network remote-exit tests and adversarial gates in Section 9 pass without weakening any release checks.

---

## APPENDIX A: Complete Implementation Master Checklist

This checklist consolidates ALL implementation requirements from this document. Mark items `[x]` only when:
1. Code is implemented and committed
2. Unit/integration tests pass
3. Relevant gates pass (if applicable)
4. Evidence artifact exists (if required)

### A.1 Encryption Architecture (Section 5)

#### Direct Path Encryption
- [ ] 5.2.1 WireGuard Protocol Enforcement
  - [ ] ChaCha20-Poly1305 AEAD cipher suite enforced (no downgrade)
  - [ ] Curve25519 key exchange implemented
  - [ ] Per-packet authentication with Poly1305 MAC
  - [ ] Counter-based replay protection (64-bit window)
  - [ ] Automatic key rotation every 2 minutes
  - [ ] Tests: `direct_path_requires_wireguard_handshake_success`
  - [ ] Tests: `direct_path_never_sends_cleartext`
  - [ ] Tests: `direct_path_rejects_replayed_packets`

- [ ] 5.2.2 Key Distribution and Trust Model
  - [ ] Curve25519 keypair generation at enrollment
  - [ ] Public key distribution via signed assignment bundles
  - [ ] Assignment bundle signature verification
  - [ ] Zero-trust model (control plane never sees private keys)
  - [ ] Implementation: `crates/rustynet-crypto/src/keypair.rs`
  - [ ] Implementation: `crates/rustynetd/src/assignment.rs`

- [ ] 5.2.3 Direct Path Endpoint Mutation Security
  - [ ] Signed traversal bundle requirement enforced
  - [ ] Signature verification on traversal bundles
  - [ ] Freshness check (MAX_TRAVERSAL_AGE = 60 seconds)
  - [ ] Nonce-based replay protection
  - [ ] Endpoint candidate set validation
  - [ ] Tests: `unsigned_endpoint_mutation_rejected`
  - [ ] Tests: `replayed_traversal_bundle_rejected`
  - [ ] Tests: `stale_traversal_bundle_rejected`

#### Relay Path Encryption
- [ ] 5.3.1 Zero-Knowledge Relay Architecture
  - [ ] Relay cannot decrypt WireGuard layer (verified)
  - [ ] Nested encryption model implemented
  - [ ] Session isolation with ephemeral keys

- [ ] 5.3.2 Relay Session Establishment Protocol
  - [ ] Control plane relay allocation API
  - [ ] Signed relay credential generation
  - [ ] Session token and auth key distribution
  - [ ] TTL enforcement (300 seconds max)

- [ ] 5.3.3 Relay Transport Protocol (TLS 1.3-Based)
  - [ ] TLS 1.3 handshake with relay server
  - [ ] Certificate pinning for relay public key
  - [ ] Relay frame format implementation (session_token + seq + HMAC + data)
  - [ ] Constant-time HMAC verification
  - [ ] Sequence number anti-replay protection
  - [ ] Implementation: `crates/rustynet-relay/src/server.rs`
  - [ ] Implementation: `crates/rustynetd/src/relay_client.rs`
  - [ ] Tests: `relay_cannot_decrypt_payload`
  - [ ] Tests: `hmac_verification_constant_time`
  - [ ] Tests: `replayed_sequence_rejected`

- [ ] 5.3.4 Relay Abuse Protections
  - [ ] Rate limiting (10 MB/s sustained, 50 MB/s burst per session)
  - [ ] Per-source-IP session creation limits (50/minute)
  - [ ] Global capacity ceiling configuration
  - [ ] Session TTL enforcement (300 seconds max)
  - [ ] Idle timeout (60 seconds without traffic)
  - [ ] HMAC failure limits (3 consecutive failures → terminate)
  - [ ] Source IP banning on auth abuse (10 failures/minute → 60s ban)
  - [ ] Bounded session table (max 10,000 concurrent)
  - [ ] Bounded queue depth (max 100 packets/session)
  - [ ] Implementation: `crates/rustynet-relay/src/abuse_prevention.rs`

#### Encryption Continuity
- [ ] 5.4.1 Direct ↔ Relay Failover Without Re-keying
  - [ ] WireGuard session keys preserved during path changes
  - [ ] Transport path switch without session destruction
  - [ ] No re-handshake during failover
  - [ ] Tests: `direct_to_relay_transition_preserves_session`
  - [ ] Tests: `failover_continuous_traffic_no_gap`
  - [ ] Tests: `failover_session_key_unchanged`

- [ ] 5.4.2 Path Transition Security Invariants
  - [ ] Continuous encryption during transitions
  - [ ] ACL enforcement during transitions
  - [ ] DNS fail-closed during transitions
  - [ ] Kill-switch active during transitions
  - [ ] Signed traversal state for path changes
  - [ ] Live test: `scripts/e2e/live_linux_transition_leak_test.sh`

#### Cryptographic Hygiene
- [ ] 5.5.3 Cryptographic Implementation Hygiene
  - [ ] Memory zeroization for private keys (use `zeroize` crate)
  - [ ] Constant-time comparison for MACs/tokens (use `subtle` crate)
  - [ ] No key material in logs (redacted debug impl)
  - [ ] Secure RNG (use `OsRng`)
  - [ ] Tests: `structured_logger_never_writes_cleartext_secrets`
  - [ ] Tests: `private_key_zeroized_on_drop`
  - [ ] Tests: `no_timing_leaks`

#### Control Plane Security
- [ ] 5.6.1 TLS 1.3 Enforcement
  - [ ] TLS 1.3 minimum version enforced (no downgrade)
  - [ ] Approved cipher suites only (ChaCha20-Poly1305, AES-128-GCM)
  - [ ] Full certificate chain validation
  - [ ] Hostname verification
  - [ ] Optional certificate pinning support

- [ ] 5.6.2 Signed State Bundle Verification
  - [ ] Ed25519 signature verification
  - [ ] Freshness check (max 60 seconds old)
  - [ ] Nonce-based replay protection
  - [ ] Nonce store with LRU cache (10,000 entries)
  - [ ] Write-ahead log for crash recovery
  - [ ] Automatic expiry (120 seconds)

### A.2 Vulnerability Mitigations (Section 6)

#### TunnelCrack Mitigations
- [ ] 6.1.1 Strict Route Ownership
  - [ ] Only /32 or /128 bypass routes allowed
  - [ ] Only control plane IPs allowed for bypass
  - [ ] Signed route advertisement requirement
  - [ ] Tests: `subnet_bypass_rejected`
  - [ ] Live test: `scripts/e2e/live_linux_server_ip_bypass_test.sh`

- [ ] 6.1.2 Network Namespace Isolation (Linux)
  - [ ] Rustynet interface in separate namespace
  - [ ] Physical interface isolation
  - [ ] (Future: Phase 11)

#### TunnelVision Mitigations
- [ ] 6.2.1 Kill-Switch Route Lock
  - [ ] iptables/nftables rules before interface config
  - [ ] Default DENY all traffic except VPN
  - [ ] Allow only through VPN interface
  - [ ] Localhost exemption
  - [ ] Bootstrap DHCP/DNS allowance (narrow)
  - [ ] Tests: `dhcp_option_121_bypass_blocked`
  - [ ] Live test: `scripts/e2e/live_linux_dhcp_injection_test.sh`

- [ ] 6.2.2 Network Namespace Alternative
  - [ ] WireGuard in dedicated namespace
  - [ ] DHCP isolation from VPN namespace
  - [ ] (Future: Phase 11)

#### Tailscale TS-2025-008 Mitigation
- [ ] 6.3.1 Mandatory Trust State Verification
  - [ ] Trust state load at startup
  - [ ] Fail-closed on missing state (RestrictedSafeMode)
  - [ ] Signature verification on trust state
  - [ ] Freshness verification on trust state
  - [ ] Tests: `daemon_runtime_enters_restricted_safe_mode_without_trust_evidence`

#### Tailscale TS-2026-001 Mitigation
- [ ] 6.4.1 Argv-Only Command Execution
  - [ ] All privileged helpers use argv arrays (never shell)
  - [ ] No Command::new with format!/shell construction
  - [ ] Strict enforcement in code review

- [ ] 6.4.2 Input Validation Schema
  - [ ] Shell metacharacter rejection
  - [ ] Strict parsing (IpNet, SocketAddr, etc.)
  - [ ] Tests: `fuzzgate_rejects_unknown_tokens_and_shell_metacharacters`

#### Tailscale TS-2024-005 Mitigation
- [ ] 6.5.1 Strict Inbound Filtering on Exit Nodes
  - [ ] Block inbound forwarding from internet to mesh
  - [ ] Allow outbound forwarding from mesh to internet
  - [ ] SNAT/masquerade for outbound only
  - [ ] Tests: `exit_node_blocks_inbound_internet_to_mesh`
  - [ ] Live test: `scripts/e2e/live_linux_exit_inbound_filter_test.sh`

#### WireGuard Endpoint Mobility Mitigation
- [ ] 6.6.1 Signed Endpoint Hints Only
  - [ ] Monitor WireGuard endpoint changes
  - [ ] Verify endpoint in signed candidate set
  - [ ] Restore last-known-good on unauthorized change
  - [ ] Live test: `scripts/e2e/live_linux_endpoint_hijack_test.sh`

#### Additional Attack Mitigations
- [ ] 6.7.1 DNS Rebinding (TS-2022-004/005)
  - [ ] No HTTP API on localhost
  - [ ] Unix socket only for control

- [ ] 6.7.2 Timing Side-Channels (TS-2025-003)
  - [ ] Constant-time comparison for all auth
  - [ ] Tests: `no_timing_leaks`

- [ ] 6.7.3 Auth Key Reuse Race (TS-2025-007)
  - [ ] Atomic credential consumption
  - [ ] TOCTOU-resistant design
  - [ ] Implementation: `crates/rustynet-control/src/credential_store.rs`
  - [ ] Tests: `concurrent_enrollment_single_use_enforced`

- [ ] 6.7.4 Secrets in Logs (TS-2025-005)
  - [ ] Structured logging with redaction
  - [ ] Tests: `structured_logger_never_writes_cleartext_secrets`

- [ ] 6.7.5 Protocol Filter Omission (TS-2025-006)
  - [ ] ACL protocol filters preserved end-to-end
  - [ ] Tests: `protocol_specific_acl_enforced_on_exit_node`

### A.3 Security Invariants (Section 7)

- [ ] Invariant 1: One hardened endpoint mutation path
- [ ] Invariant 2: No unsigned endpoint mutation
- [ ] Invariant 3: No silent fallback to weaker logic
- [ ] Invariant 4: No plaintext visibility at relay
- [ ] Invariant 5: No unprotected egress without valid path
- [ ] Invariant 6: Replay/rollback/stale/wrong-signer fail closed
- [ ] Invariant 7: Route/DNS protections survive transitions
- [ ] Invariant 8: Exit-node selection never widens access
- [ ] Invariant 9: Unix-socket control surfaces only
- [ ] Invariant 10: Measured gate evidence for all behaviors

### A.4 Functional Requirements (Section 8)

#### Direct Path Capabilities
- [ ] 8.1.1 NAT-to-NAT direct UDP connectivity
- [ ] 8.1.2 WireGuard encryption verified
- [ ] 8.1.3 Signed traversal bundle enforcement
- [ ] 8.1.4 Anti-replay/anti-rollback/freshness protections

#### Relay Path Capabilities
- [ ] 8.2.1 Relay fallback when direct fails
- [ ] 8.2.2 Nested encryption (WireGuard + relay layer)
- [ ] 8.2.3 Zero-trust relay (cannot decrypt)
- [ ] 8.2.4 Constant-time relay authentication
- [ ] 8.2.5 Relay abuse protections

#### Path Transition Safety
- [ ] 8.3.1 WireGuard session preservation
- [ ] 8.3.2 ACL enforcement during transitions
- [ ] 8.3.3 Kill-switch during transitions
- [ ] 8.3.4 DNS fail-closed during transitions
- [ ] 8.3.5 Narrow bypass semantics preserved
- [ ] 8.3.6 No packet loss window
- [ ] 8.3.7 Continuous encryption

#### Security Properties
- [ ] 8.4.1 All Section 6 vulnerabilities mitigated
- [ ] 8.4.2 Adversarial test suite passes
- [ ] 8.4.3 No secret leakage

#### Operational Resilience
- [ ] 8.5.1 Endpoint roaming recovery
- [ ] 8.5.2 Control plane unavailability handling
- [ ] 8.5.3 Fail-closed on trust state issues

#### Measured Evidence
- [ ] 8.6.1 Live lab artifacts exist and pass
- [ ] 8.6.2 Artifacts follow schema
- [ ] 8.6.3 Evidence is commit-bound and reproducible

### A.5 Testing and Gates (Section 9)

#### Unit and Property Tests
- [ ] 9.1.1 Signed candidate parsing and verification
- [ ] 9.1.2 Replay/rollback/stale/wrong-signer rejection
- [ ] 9.1.3 Bounded simultaneous-open scheduling
- [ ] 9.1.4 Relay session token/auth validation
- [ ] 9.1.5 Constant-time comparison for relay auth
- [ ] 9.1.6 Route/DNS fail-closed during transitions

#### Local Integration Tests
- [ ] 9.1.7 Backend endpoint rotation on valid traversal only
- [ ] 9.1.8 Direct-path establishment on handshake evidence
- [ ] 9.1.9 Safe fallback to relay when direct fails
- [ ] 9.1.10 Safe failback from relay to direct
- [ ] 9.1.11 Exit-node routing/DNS under path transitions

#### Live Multi-Network Lab Tests
- [ ] 9.1.12 Direct remote-exit success across networks
- [ ] 9.1.13 Relay-backed remote-exit across networks
- [ ] 9.1.14 Relay-to-direct failback after reprobe
- [ ] 9.1.15 Endpoint roaming recovery
- [ ] 9.1.16 Reboot recovery with policy-safe paths

#### Adversarial Live Tests
- [ ] 9.1.17 Forged traversal state rejection
- [ ] 9.1.18 Stale traversal state rejection
- [ ] 9.1.19 Replayed traversal state rejection
- [ ] 9.1.20 Rogue endpoint injection blocked
- [ ] 9.1.21 TunnelCrack-style bypass attempts blocked
- [ ] 9.1.22 Control surface exposure checks

#### Soak and Resilience Tests
- [ ] 9.1.23 Long-running direct session across networks
- [ ] 9.1.24 Long-running relay session across networks
- [ ] 9.1.25 Repeated direct/relay flaps without leak

#### Required Measured Artifacts
- [ ] 9.2.1 `cross_network_direct_remote_exit_report.json`
- [ ] 9.2.2 `cross_network_relay_remote_exit_report.json`
- [ ] 9.2.3 `cross_network_failback_roaming_report.json`
- [ ] 9.2.4 `cross_network_traversal_adversarial_report.json`
- [ ] 9.2.5 `cross_network_remote_exit_dns_report.json`
- [ ] 9.2.6 `cross_network_remote_exit_soak_report.json`

#### Required Checks in Artifacts
- [ ] 9.3.1 `direct_remote_exit_success`
- [ ] 9.3.2 `relay_remote_exit_success`
- [ ] 9.3.3 `relay_to_direct_failback_success`
- [ ] 9.3.4 `endpoint_roam_recovery_success`
- [ ] 9.3.5 `failback_reconnect_within_slo`
- [ ] 9.3.6 `no_underlay_leak_while_reconnecting`
- [ ] 9.3.7 `signed_state_valid_while_reconnecting`
- [ ] 9.3.8 `remote_exit_dns_fail_closed`
- [ ] 9.3.9 `remote_exit_no_underlay_leak`
- [ ] 9.3.10 `remote_exit_server_ip_bypass_is_narrow`
- [ ] 9.3.11 `forged_traversal_rejected`
- [ ] 9.3.12 `stale_traversal_rejected`
- [ ] 9.3.13 `replayed_traversal_rejected`
- [ ] 9.3.14 `rogue_endpoint_rejected`
- [ ] 9.3.15 `control_surface_exposure_blocked`
- [ ] 9.3.16 `long_soak_stable`
- [ ] 9.3.17 `cross_network_topology_heuristic`
- [ ] 9.3.18 `direct_remote_exit_ready`
- [ ] 9.3.19 `post_soak_bypass_ready`
- [ ] 9.3.20 `no_plaintext_passphrase_files`

#### Gate Wiring
- [ ] 9.4.1 Create `scripts/ci/phase10_cross_network_exit_gates.sh`
- [ ] 9.4.2 Add NAT matrix validation command
- [ ] 9.4.3 Extend `check_phase10_readiness.sh` for cross-network artifacts
- [ ] 9.4.4 Extend `live_linux_lab_orchestrator.sh` for cross-network stage
- [ ] 9.4.5 Extend security auditor skill for coverage promotion

### A.6 Implementation Phases (Section 8.x)

#### Phase 0: Truth Lock
- [ ] Explicit WAN simultaneous-open status in docs
- [ ] Explicit relay transport status in docs
- [ ] No "connect from anywhere" claims without evidence

#### Phase 1: Candidate Acquisition
- [ ] Local interface candidate discovery
- [ ] Public reflexive candidate discovery (STUN-like)
- [ ] Relay candidate discovery
- [ ] Signed traversal artifact model maintained
- [ ] Candidate acquisition doesn't create alternate authority
- [ ] Candidate binding to signed artifact
- [ ] Short TTL enforcement
- [ ] Nonce/watermark replay protection
- [ ] Acceptance artifact proving signed publication, replay rejection, stale rejection

#### Phase 2: HP2 WAN Simultaneous-Open
- [ ] Shared-socket UDP behavior (same as WireGuard transport)
- [ ] Simultaneous-open scheduling for unrelated NATs
- [ ] Endpoint roam handling for WAN path changes
- [ ] Bounded probe fanout and pacing
- [ ] Single state machine for direct/relay decisions
- [ ] Acceptance: Live evidence of direct UDP across networks

#### Phase 3: HP3 Production Relay Transport
- [ ] Real ciphertext relay service (not just selector logic)
- [ ] Authenticated relay session setup
- [ ] Session expiry enforcement
- [ ] Per-session replay protection
- [ ] Constant-time token/auth validation
- [ ] Rate limiting
- [ ] Bounded queues
- [ ] Idle expiry
- [ ] Per-node/session scoping
- [ ] Relay blind to plaintext
- [ ] Acceptance: Relay transport evidence, no plaintext exposure

#### Phase 4: Remote Exit-Node Dataplane
- [ ] Client can select remote exit node
- [ ] Full-tunnel egress routing
- [ ] Managed DNS path
- [ ] Optional LAN toggle (policy-authorized)
- [ ] Narrow server-IP bypass preserved
- [ ] Exit node route scope enforcement
- [ ] Exit node forwarding/NAT policy
- [ ] Exit node DNS policy
- [ ] Exit node ACL constraints
- [ ] No transient leaks during path changes
- [ ] Acceptance: Client on network A uses exit on network B, DNS protected, no leaks

#### Phase 5: Testing, Security Gates, Release Enforcement
- [ ] Extend live validation for cross-network scenarios
- [ ] Canonical artifacts under `artifacts/phase10/`
- [ ] Phase 10 readiness requires cross-network artifacts
- [ ] Comparative exploit coverage honest
- [ ] Dedicated cross-network exit-node gate bundle
- [ ] Acceptance: Cross-network gates pass with measured evidence

---

## APPENDIX B: Quick Reference - Security Decision Tree

Use this when making implementation decisions:

```
┌─────────────────────────────────────────────────────────────┐
│ "Should I implement feature X in way Y?"                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
        ┌─────────────────────────────────────────┐
        │ Does it require unsigned state mutation?│
        └─────────────────────────────────────────┘
           YES │                     │ NO
               │                     ▼
         ❌ REJECT            Does it bypass existing
                             signed-state requirements?
                                     │
                          YES │            │ NO
                              │            ▼
                        ❌ REJECT   Does it add shell
                                   command construction?
                                            │
                                 YES │           │ NO
                                     │           ▼
                               ❌ REJECT   Does it weaken
                                          fail-closed behavior?
                                                   │
                                        YES │            │ NO
                                            │            ▼
                                      ❌ REJECT   Does it expose
                                                 plaintext at relay?
                                                          │
                                               YES │           │ NO
                                                   │           ▼
                                             ❌ REJECT   Does it have
                                                        measured evidence?
                                                                 │
                                                      NO │            │ YES
                                                         │            ▼
                                                   ❌ DEFER    ✅ PROCEED
                                                   (Block on    (Implement with
                                                    evidence)    test coverage)
```

---

## APPENDIX C: Cryptographic Algorithm Quick Reference

| Purpose | Algorithm | Key Size | Standard | Rationale |
|---------|-----------|----------|----------|-----------|
| **Symmetric Encryption** | ChaCha20 | 256-bit | RFC 8439 | Faster than AES on ARM, constant-time |
| **Authentication (AEAD)** | Poly1305 | 256-bit | RFC 8439 | Fast, provably secure, pairs with ChaCha20 |
| **Key Exchange** | Curve25519 | 256-bit | RFC 7748 | Industry standard, fast, side-channel resistant |
| **Hash Function** | BLAKE2s | 256-bit | RFC 7693 | Faster than SHA-256, cryptographically secure |
| **Digital Signature** | Ed25519 | 256-bit | RFC 8032 | Small keys, fast verification, deterministic |
| **HMAC** | HMAC-SHA256 | 256-bit | RFC 2104 | Standard, secure, widely supported |
| **Random Number Generation** | OS-provided (`OsRng`) | N/A | N/A | Uses kernel entropy sources |

**Security Level:** All algorithms provide at least 128-bit security (equivalent to AES-256 against quantum computers).

**Post-Quantum Status:** Current algorithms are vulnerable to quantum computers. Future Phase 11 will add hybrid key exchange (Curve25519 + Kyber) and optional PSK mode.

---

## APPENDIX D: Common Implementation Pitfalls

### ❌ **DON'T: Shell Construction**
```rust
// WRONG - allows injection
let cmd = format!("ip route add {} via {}", user_dest, gateway);
std::process::Command::new("sh").arg("-c").arg(&cmd).spawn()?;
```

### ✅ **DO: Argv Arrays**
```rust
// CORRECT - no injection possible
std::process::Command::new("ip")
    .arg("route")
    .arg("add")
    .arg(user_dest)
    .arg("via")
    .arg(gateway)
    .spawn()?;
```

### ❌ **DON'T: Variable-Time Comparison**
```rust
// WRONG - timing attack possible
if computed_hmac == provided_hmac {
    return Ok(());
}
```

### ✅ **DO: Constant-Time Comparison**
```rust
// CORRECT - no timing leakage
use subtle::ConstantTimeEq;
if computed_hmac.ct_eq(&provided_hmac).into() {
    return Ok(());
}
```

### ❌ **DON'T: Logging Secrets**
```rust
// WRONG - leaks key to logs
debug!("Private key: {:?}", private_key);
```

### ✅ **DO: Redacted Debug**
```rust
// CORRECT - key not visible in logs
#[derive(Debug)]
struct PrivateKey {
    #[debug("<redacted>")]
    key: [u8; 32],
}
```

### ❌ **DON'T: Fail-Open on Missing State**
```rust
// WRONG - allows bypass when state file deleted
let trust_state = TrustState::load().unwrap_or_default();
```

### ✅ **DO: Fail-Closed on Missing State**
```rust
// CORRECT - enters safe mode when state missing
let trust_state = match TrustState::load()? {
    Some(s) => s,
    None => return Ok(RuntimeState::RestrictedSafeMode),
};
```

---

## Document Change Log

| Date | Change | Author |
|------|--------|--------|
| 2026-03-16 | Initial creation | Engineering |
| 2026-03-22T18:31 | Added comprehensive encryption architecture (Section 5) | AI + Security Review |
| 2026-03-22T18:31 | Added known vulnerability mitigations (Section 6) | AI + Security Review |
| 2026-03-22T18:31 | Added complete implementation checklist (Appendix A) | AI + Security Review |
| 2026-03-22T18:31 | Added security decision tree (Appendix B) | AI + Security Review |
| 2026-03-22T18:31 | Added cryptographic algorithm reference (Appendix C) | AI + Security Review |
| 2026-03-22T18:31 | Added common pitfalls guide (Appendix D) | AI + Security Review |
| 2026-03-22T18:43 | Added "One Hardened Path" principle (Section 3A) | AI + Security Review |
| 2026-03-22T18:43 | Added comprehensive Rust testing requirements (Section 8A) | AI + Security Review |
| 2026-03-22T18:43 | Added property-based testing, fuzzing, CI/CD gates | AI + Security Review |
| 2026-03-22T18:43 | Document now 2,299 lines (5.4x larger than original) | AI + Security Review |
| 2026-03-25T18:00 | Wired `ops verify-phase10-readiness` to fail closed on missing/invalid cross-network reports and NAT-matrix coverage; verification remains blocked by Agent 1 runtime compile failures and missing live artifacts | Agent 2 |

## Session Update — 2026-03-25T18:00:31Z

Status: partial

- Changed files: `crates/rustynet-cli/src/ops_cross_network_reports.rs`, `crates/rustynet-cli/src/ops_phase9.rs`
- What landed: Phase 10 readiness now reuses the cross-network schema validator and NAT-matrix validator, so canonical remote-exit evidence is required before readiness can pass.
- Verification:
  - `rustfmt --edition 2024 crates/rustynet-cli/src/ops_cross_network_reports.rs crates/rustynet-cli/src/ops_phase9.rs` `pass`
  - `cargo fmt --all -- --check` `blocked` by unrelated formatting diffs in Agent 1-owned and other out-of-scope files
  - `cargo test -p rustynet-cli validate_cross_network_remote_exit_readiness_accepts_complete_canonical_reports -- --nocapture` `blocked` by unrelated compile failures in `crates/rustynetd/src/daemon.rs`, `crates/rustynetd/src/dataplane.rs`, `crates/rustynetd/src/phase10.rs`, and `crates/rustynetd/src/relay_client.rs`
- Artifacts: none generated; `artifacts/phase10/` still lacks the six canonical `cross_network_*` reports required by Section 9.2.
- Residual risk: live proof for direct remote exit, relay remote exit, failback/roaming, adversarial traversal rejection, managed DNS, and soak behavior is still absent.
- Blocker / prerequisite: Agent 1 must clear the current runtime compile break before the readiness command, the dedicated cross-network gate, and any live-lab cross-network run can be re-validated end to end.
## Agent Update Rules

Use these rules every time you modify this document during implementation work.

1. Update the document immediately after each materially completed slice.
- Do not keep a private checklist that diverges from this file.
- This document must remain the public execution record.

2. Mark completion conservatively.
- Use `[x]` only after the code is implemented and verified.
- Use `Status: partial` when some hardening landed but real work remains.
- Use `Status: blocked` only for real external blockers; name the blocker precisely.

3. Record evidence under the section you touched, or in the existing session log/evidence table if the document already has one.
- Minimum evidence fields:
  - `Changed files:` exact paths
  - `Verification:` exact commands, tests, smoke runs, dry runs, gates
  - `Artifacts:` exact generated paths, if any
  - `Residual risk:` what still remains, if anything
  - `Blocker / prerequisite:` only when applicable

4. Use exact timestamps and commit references where possible.
- Prefer UTC timestamps in ISO-8601 format.
- If commits exist, record the commit SHA that contains the work.

5. Do not delete historical context that still matters.
- Correct stale claims when they are inaccurate.
- Do not erase previous findings, checklist items, or session history just to make the document look cleaner.

6. Keep security claims evidence-backed.
- Never write that a path is secure, complete, hardened, or production-ready without code and verification proof.
- If live validation is unavailable, state that explicitly and record the missing prerequisite.

7. If tests fail, record the failure honestly and fix the root cause.
- Do not weaken gates, remove checks, or relabel failures as acceptable.
- If a fix is incomplete, mark the item partial instead of complete.
