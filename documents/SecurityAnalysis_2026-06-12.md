# Rustynet Security Analysis — Weaknesses & Modern Mitigations

- **Date:** 2026-06-12
- **Baseline:** commit `d5ffee5` (post ITER-3 loop)
- **Scope:** Full workspace static analysis with focus on dataplane, crypto, trust, IPC, and supply chain
- **Methodology:** Combines findings from SecurityReview_2026-05-24 (§1–18, 38 findings), new static analysis of production paths, and modern defense-in-depth assessment

---

## 1. Executive Summary

Rustynet's security core is **strongly engineered** in several dimensions: the privileged helper is an exemplary argv-only allowlisted boundary; crypto uses vetted primitives with Argon2id, fail-closed CSPRNG, and redacting Debug; the signed-trust core verifies-before-mutates with watermark protection; and network parsers are bounded and panic-free. There are no pre-auth RCE paths.

However, the **dataplane fail-closed posture** — the project's central security guarantee — has a cluster of High-severity gaps where errors are silently discarded, controls are dead code, and the Windows killswitch is materially weaker than Linux. These are the **highest-residual-risk items** and should be fixed before any production deployment.

### Findings Tally

| Severity | Existing (SecurityReview) | New (this analysis) | Total Open |
|---|---|---|---|
| Critical | 0 | 0 | 0 |
| High | 7 (RN-01 fixed; 6 open) | 3 | 9 |
| Medium | 9 (RN-14/15 fixed; 7 open) | 5 | 12 |
| Low | 17 (RN-17/19/22/23/24 fixed; 12 open) | 4 | 16 |
| Info | 5 | 2 | 7 |

---

## 2. High-Severity Findings

### 2.1 Open from SecurityReview (prioritized)

#### RN-03 — `force_fail_closed` results silently discarded (fail-open)
- **Status:** OPEN (10 discard sites confirmed)
- **Risk:** On first bootstrap, if `block_all_egress` fails, the killswitch table is never created and all traffic egresses cleartext while the daemon believes it's restricted.
- **Modern fix:** Replace `let _ = self.controller.force_fail_closed(...)` with `force_fail_closed_or_terminate()` that either succeeds, retries with exponential backoff while refusing to serve, or calls `std::process::abort()` to let systemd's mandatory boot killswitch backstop.

#### RN-04 — Tunnel + routes come up before killswitch is programmed
- **Status:** OPEN
- **Fix:** Program the `policy drop` killswitch BEFORE `backend.start()` and route apply. Make the `ExecStartPre` boot killswitch mandatory in the shipped systemd unit.

#### RN-05 — Policy engine default-allows non-`node:` selectors (revocation bypass)
- **Status:** OPEN
- **Fix:** Resolve `group:`/`tag:`/`user:` selectors to their constituent node set; deny if any member is revoked/unknown. Reject unresolvable selectors for trust-sensitive rules.

#### RN-06 + RN-07 — Windows killswitch + IPv6 leak
- **Status:** OPEN
- **Fix:** Scope Windows LAN egress allow to exact bootstrap set (WG UDP + STUN + management). Add explicit IPv6 outbound block. Flush autoconfigured global IPv6 addresses.

#### RN-02 — Dead `dataplane.rs` module (assurance failure)
- **Status:** OPEN
- **Fix:** Delete `dataplane.rs` and point security-audit catalog at live `phase10.rs`.

#### RN-11 — Empty membership directory = allow-all (fail-open default)
- **Status:** OPEN
- **Fix:** Default to deny on empty unless `--membership-governance=disabled` is explicitly set.

---

### 2.2 New High-Severity Findings

#### RN-N1 — Production-path `expect()` panics in daemon runtime (DoS)
- **Severity:** High · **CWE-248 / CWE-754** · **Confidence: High**
- **Location:** `crates/rustynetd/src/daemon.rs`
  - L5905: `self.relay_client.take().expect("relay client should remain available")` — panics on double-call
  - L6154: `.values().next().expect("single traversal probe status")` — panics on empty map
  - L6300: `handshake_unix.expect("fresh handshake must carry timestamp")` — panics on None
  - L6341: Same pattern for relay handshake
  - L9238: `last_err.unwrap()` — panics on empty bind-attempt chain
- **Impact:** Any edge case that triggers these panics (empty traversal state, race on relay client, DNS bind exhaustion) crashes the daemon → tunnel drops → user traffic may egress cleartext if killswitch is not pre-programmed (RN-03/RN-04 chain).
- **Fix:** Replace every production `expect()`/`unwrap()` with proper error propagation (`map_err`/`ok_or_else`/`?`). The AGENTS.md §10.2 rule allows `expect()` only in tests, build scripts, CLI entry points, and locally-provable invariants. These sites are NOT locally provable.

#### RN-N2 — Control-plane has no TLS — plaintext IPC over Unix socket
- **Severity:** High · **CWE-319** · **Confidence: High**
- **Location:** `crates/rustynetd/src/ipc.rs` — `IpcCommand` is sent as plaintext over a `0o600` Unix socket.
- **Impact:** SecurityMinimumBar §3.2 requires "TLS 1.3 enforced for control-plane APIs." While the Unix socket provides filesystem ACL protection, there is no transport-layer encryption or server authentication. A local attacker who gains membership in the `rustynetd` group can connect and replay/forge IPC commands. The socket uses SO_PEERCRED for authn but has no anti-replay beyond the per-command structure.
- **Fix:** Add a per-command sequence number + HMAC or use a TLS 1.3 tunnel over the Unix socket for remote-admin paths. For local IPC, add a challenge-response nonce to prevent replay.

#### RN-N3 — No upper bound on concurrent IPC connections
- **Severity:** High · **CWE-770** · **Confidence: Medium**
- **Location:** `crates/rustynetd/src/ipc.rs` and `daemon.rs` IPC accept loop.
- **Impact:** Local DoS — unprivileged user can exhaust daemon file descriptors by opening many connections to the IPC socket. The daemon accepts connections in a loop without connection counting or rate limiting.
- **Fix:** Track active connection count; refuse new connections above `MAX_IPC_CONNECTIONS` (e.g., 16). Add per-UID connection limits.

---

## 3. Medium-Severity Findings

### 3.1 Open from SecurityReview

- **RN-08:** Key envelope lacks AAD binding (magic/version/salt/nonce not authenticated)
- **RN-09:** systemd-credential passphrase files may be group-readable
- **RN-10:** Corrupt rotation ledger silently resets to genesis
- **RN-12:** Linux DNS leak on exit nodes (broad accept precedes DNS drop)
- **RN-13:** No handshake flood guard in live path
- **RN-16:** GitHub Actions pinned to mutable tags (SHA-pinning needed)
- **RN-25:** Coordination replay window is in-memory only

### 3.2 New Medium-Severity Findings

#### RN-N4 — Gossip transport has no rate limiting
- **Severity:** Medium · **CWE-770** · **Confidence: Medium**
- **Location:** `crates/rustynetd/src/gossip_runtime.rs`, `gossip_transport.rs`
- **Description:** The gossip ingress path (`drain_gossip_inbound`) processes every received bundle in a tight loop. A rogue peer flooding forged bundles can consume CPU + memory with signature verification attempts.
- **Fix:** Add per-peer gossip rate limiting (token bucket, e.g., 10 bundles/sec). Drop bundles above the rate before signature verification.

#### RN-N5 — Enrollment token HMAC uses non-constant-time comparison for TTL check
- **Severity:** Medium · **CWE-208** · **Confidence: Low**
- **Location:** `crates/rustynet-control/src/enrollment.rs`
- **Description:** The enrollment token TTL check (`expires_at < now`) is done BEFORE the constant-time HMAC comparison. An attacker can learn when a token is expired by timing the response, narrowing the window for brute-force. This is a defense-in-depth gap — the token is 256-bit HMAC, so brute-force is impractical regardless.
- **Fix:** Move the TTL check to AFTER the constant-time HMAC verify. Always perform the full verify before any time-based rejection.

#### RN-N6 — No structured fuzzing harness for relay hello/session token
- **Severity:** Medium · **CWE-20** · **Confidence: Medium**
- **Location:** `crates/rustynet-relay/src/transport.rs`, `session.rs`
- **Description:** While the membership decoder has fuzz targets (per §18), the relay hello parser and session token verifier do not. The relay processes untrusted UDP from any source address.
- **Fix:** Add `cargo-fuzz` targets for `parse_relay_hello`, `verify_session_token`, and the rate-limiter state machine. Integrate into CI.

#### RN-N7 — Port mapper (UPnP/NAT-PMP/PCP) responses have no size cap for XML body
- **Severity:** Medium · **CWE-770** · **Confidence: Medium**
- **Location:** `crates/rustynetd/src/port_mapper.rs`
- **Description:** The UPnP IGD client fetches an XML device description over HTTP. The response body is read into a `String` without a size cap. A malicious/compromised router could return a multi-gigabyte XML document, causing memory exhaustion.
- **Fix:** Add `MAX_UPNP_DEVICE_DESC_BYTES` (e.g., 65536) and reject oversized responses. Mirror the cap on the SOAP response reader.

#### RN-N8 — DNS zone bundle has no maximum record count enforced at decode
- **Severity:** Medium · **CWE-770** · **Confidence: Low**
- **Location:** `crates/rustynet-dns-zone/src/lib.rs`
- **Description:** While the security review credits `dns-zone` with `MAX_RECORD_COUNT`, verification shows the cap exists at parse time. However, there is no cross-check that the parsed record count does not exceed a reasonable per-bundle limit for operational safety.
- **Fix:** Add `MAX_DNS_ZONE_RECORD_COUNT_PER_BUNDLE` at 1000 and reject larger bundles at decode.

---

## 4. Low-Severity Findings (New)

#### RN-N9 — `SystemTime::now()` used for security-sensitive expiry checks
- **Severity:** Low · **CWE-367** · **Confidence: Low**
- **Location:** Multiple sites in `daemon.rs`, `enrollment.rs`, `relay`
- **Description:** `SystemTime::now()` can be skewed by NTP adjustments, manual clock changes, or suspend/resume. Expiry checks using wall-clock time can be defeated by clock manipulation. The enrollment token ledger uses wall-clock TTL; relay session tokens use wall-clock expiry.
- **Fix:** Use `Instant` for monotonic timeouts where possible. For absolute expiry (TTL), document the acceptable clock-skew bound and add a skew-detection alarm (the cross-network preflight already has this — extend it to the daemon main loop).

#### RN-N10 — Relay session token nonce is 16 bytes (adequate but could use 32)
- **Severity:** Low · **CWE-330** · **Confidence: Low**
- **Location:** `crates/rustynet-control/src/lib.rs` — `RelaySessionToken.nonce: [u8; 16]`
- **Description:** The relay session token nonce is 128 bits, which is adequate for uniqueness but below the 256-bit recommendation for long-lived tokens in modern protocols.
- **Fix:** Extend `nonce` to `[u8; 32]`. This is a schema change — requires coordinated rollout.

#### RN-N11 — No audit log for IPC command execution
- **Severity:** Low · **CWE-778** · **Confidence: Low**
- **Location:** `daemon.rs` IPC command dispatch
- **Description:** IPC commands are executed without an audit trail. While the role-transition audit log exists (D12.e), day-to-day operations (status, key rotation, exit select) are not logged.
- **Fix:** Add structured audit events for security-relevant IPC commands (key rotate, exit select, route advertise/retract, enrollment consume).

#### RN-N12 — `cargo audit`/`cargo deny` not run as pre-commit hook
- **Severity:** Low · **CWE-1104** · **Confidence: Low**
- **Location:** Absent from `.git/hooks/` or documented pre-commit flow
- **Description:** Supply-chain checks run in CI but not locally before commit. An engineer can commit a dependency with a known CVE and only discover it in CI.
- **Fix:** Document the pre-commit gate in AGENTS.md §7. Add a `scripts/ci/precommit.sh` that runs `cargo deny check advisories` against changed `Cargo.lock`.

---

## 5. Modern Defense-in-Depth Recommendations

These are architectural improvements beyond fixing specific bugs.

### 5.1 Memory Safety — Migrate to `#[forbid(unsafe_code)]` everywhere
- **Current state:** 13/14 crates carry per-file `#![forbid(unsafe_code)]` (RL-2 landed). Only `rustynet-windows-native` (FFI) allows unsafe.
- **Recommendation:** Does not require changes — this is already best-in-class. Maintain this discipline.

### 5.2 Constant-Time Operations — Audit all secret-dependent branches
- **Current state:** `subtle` crate used for enrollment token comparison. Ed25519 `verify_strict` landed (RL-3).
- **Gap:** The encrypted key envelope path (`rustynet-crypto`) uses Argon2id with a derived key. The passphrase-to-key derivation timing reveals nothing about the passphrase (Argon2id is memory-hard and constant-time per block). Good.
- **Recommendation:** Add a CI gate (`scripts/ci/constant_time_gates.sh`) that greps for `==` or `!=` on types containing `Secret`, `Key`, `Passphrase`, `Token` outside of `subtle` blocks. This catches regressions.

### 5.3 Fuzzing Infrastructure — Continuous fuzzing in CI
- **Current state:** Membership decoder has fuzz targets. Relay, gossip, STUN, PCP, DNS zone are missing.
- **Recommendation:** Add `cargo-fuzz` targets for every network-facing parser. Run in OSS-Fuzz or a dedicated CI worker for 1 hour per commit.

### 5.4 Sandboxing — Strengthen the daemon's systemd unit
- **Current state:** `rustynetd.service` has `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, sandbox flags.
- **Gap:** `ProtectHome=true` is not set. The daemon does not need access to `/home`.
- **Recommendation:** Add `ProtectHome=true`, `ProtectProc=invisible`, `RestrictSUIDSGID=true`, `RemoveIPC=true` to the shipped unit. Use `systemd-analyze security rustynetd.service` as a CI gate.

### 5.5 Secrets Management — Migrate to TPM2 / SEV-SNP for key custody
- **Current state:** OS keychain (macOS Keychain, Windows DPAPI). Linux uses encrypted-at-rest with passphrase.
- **Recommendation:** For anchor/exit nodes, offer TPM2-backed sealing (bind the key to the PCR state — kernel, initrd, systemd). This prevents key exfiltration even with root access if the attacker cannot boot a modified kernel. This is a post-GA feature.

### 5.6 Formal Verification — Model the membership state machine
- **Current state:** The membership reducer (`apply_signed_update`) has tests but no formal model.
- **Recommendation:** Model the membership state machine in TLA+ or Stateright. Verify invariants: epoch monotonicity, quorum enforcement, replay-watermark correctness, no capability self-promotion. This is a post-GA research task.

---

## 6. Attack Surface Matrix

| Boundary | Protocol | Untrusted Input | Parsing Safety | AuthN/Z | Rate Limit |
|---|---|---|---|---|---|
| WireGuard peer | UDP:51820 | WG handshake + transport | Boringtun (audited) | WG preshared key | Boringtun cookie |
| Relay | UDP:51821 | Relay hello + session token | Bounded, no fuzz targets | Signed token | Token-bucket (10k pps) |
| Gossip | UDP:51821 | Signed membership bundle | Bounded 4KB, signature-verified | Ed25519 signature | **NONE** ⚠️ |
| STUN | UDP:19302→ | STUN binding response | Bounded 1024B, length-checked | None (public) | N/A |
| UPnP/PCP | UDP:1900/5351 | SSDP + SOAP / PCP MAP | Bounded but no XML size cap ⚠️ | None (LAN-only) | N/A |
| IPC | Unix socket | Newline-delimited JSON | Bounded 4KB, per-command | SO_PEERCRED | **NONE** ⚠️ |
| Anchor bundle-pull | TCP:51822 | HTTP GET with token header | Bounded response | HMAC token | N/A |
| Enrollment | TCP (via mesh) | Enrollment token | Constant-time HMAC | Token + TTL | Single-use ledger |
| DNS resolver | UDP:53 (loopback) | DNS question | Bounded, panic-free | None (local) | N/A |

---

## 7. Prioritized Remediation Roadmap

### P0 — Fix Now (fail-open / leak / DoS)
1. **RN-03 + RN-04:** Make `force_fail_closed` fatal + program killswitch before backend up
2. **RN-N1:** Remove all production `expect()`/`unwrap()` panics
3. **RN-06 + RN-07:** Windows killswitch parity + IPv6 block
4. **RN-05 + RN-11:** Close policy default-allow paths
5. **RN-02:** Delete dead `dataplane.rs`

### P1 — High-Value Integrity (next sprint)
6. **RN-10:** Corrupt ledger → fail closed
7. **RN-08:** AAD-bind key envelope
8. **RN-09:** Tighten systemd-credential group-read gate
9. **RN-16:** SHA-pin GitHub Actions
10. **RN-N2:** Control-plane anti-replay (nonce + HMAC over IPC)

### P2 — Defense-in-Depth (roadmap)
11. **RN-N4:** Gossip rate limiting
12. **RN-N7:** UPnP XML body size cap
13. **RN-N6:** Fuzz targets for relay + gossip + PCP
14. **RN-N12:** Pre-commit supply-chain gate
15. **RN-N3:** IPC connection limits
16. **RN-N5:** Enrollment TTL check after constant-time compare

### P3 — Modernization (post-GA)
17. §5.4: Harden systemd sandbox
18. §5.5: TPM2 key sealing
19. §5.6: Formal membership model
20. §5.3: Continuous fuzzing infrastructure

---

## 8. Compliance with SecurityMinimumBar

| Control (§3) | Status | Gap |
|---|---|---|
| 1. Proven crypto only | ✅ Upheld | No custom crypto |
| 2. TLS 1.3 for control-plane | ❌ **Gap** | IPC is plaintext (RN-N2) |
| 3. Auth/enrollment hardening | ⚠️ Partial | Rate limiting missing on IPC + gossip |
| 4. Secret/key handling | ⚠️ Partial | RN-08, RN-09, RN-33 open |
| 5. Host-OS boundary | ✅ Upheld | Platform enforcement present |
| 6. Default-deny ACL | ❌ **Gap** | RN-05, RN-11 open |
| 7. Web/admin security | ⚠️ N/A | No web UI yet; IPC needs hardening |
| 8. Data-plane leak prevention | ❌ **Gap** | RN-03/04/06/07/12 open |
| 9. Audit and forensics | ⚠️ Partial | Role audit exists; IPC audit missing |
| 10. Supply-chain integrity | ⚠️ Partial | RN-15 fixed; RN-16/30/31 open |

---

## 9. Recommendations for Immediate Action

1. **Fix RN-03/RN-04 before any production deployment.** The fail-open on first bootstrap is the highest-risk item — a transient nft helper failure during startup silently leaves the host unprotected.

2. **Delete `dataplane.rs` (RN-02) and point tests at `phase10.rs`.** Dead security code is worse than no code — it creates a false sense of assurance.

3. **Remove all `expect()`/`unwrap()` from `daemon.rs` production paths (RN-N1).** While individually low-probability, together they form a DoS surface that can be triggered by edge cases (empty gossip state, DNS bind exhaustion, relay client race).

4. **Add per-peer gossip rate limiting (RN-N4).** The gossip subsystem is the only network-facing path with no rate control. A single rogue peer can consume 100% CPU with forged bundles.

5. **Add CI fuzzing for relay + gossip parsers (RN-N6).** These process untrusted UDP from any source — they should have the same fuzzing coverage as the membership decoder.

---

## 10. Cross-Reference

- **Primary security review:** `documents/operations/active/SecurityReview_2026-05-24.md` (38 findings, §1–18)
- **Security baseline:** `documents/SecurityMinimumBar.md`
- **Agent contract:** `AGENTS.md` §3 (Non-Negotiable Engineering Constraints), §4 (Security Baseline Requirements), §10 (Common Patterns)
- **Dataplane plan:** `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md` §4.1 (residual traversal gaps)
- **Anchor design:** `documents/operations/active/AnchorNodeRoleDesign_2026-05-21.md`
- **Role taxonomy:** `documents/operations/active/NodeRoleTaxonomy_2026-05-21.md`
