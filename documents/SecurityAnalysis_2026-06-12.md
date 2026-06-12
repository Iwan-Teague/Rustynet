# Rustynet Security Analysis — Weaknesses & Modern Mitigations

- **Date:** 2026-06-12 (updated after deep scan)
- **Baseline:** commit `bf47db1`
- **Scope:** Full workspace static analysis — 38 existing SecurityReview findings + 11 new findings from deep code scan
- **Files scanned:** daemon.rs, phase10.rs, privileged_helper.rs, ipc.rs, stun_client.rs, gossip_runtime.rs, gossip_transport.rs, peer_gossip.rs, enrollment_token.rs, enrollment.rs, port_mapper.rs, session.rs, rate_limit.rs, relay transport.rs, traversal.rs, service_exposure.rs, key_material.rs, key_rotation.rs

---

## 1. Executive Summary

Rustynet's security core is **strongly engineered**. Positive findings:

- **Privileged helper:** closed-enum program allowlist, argv-only exec (no shell), shell-metacharacter rejection, path-traversal rejection, root-owned binary validation, SO_PEERCRED + post-connect uid check, 0660 socket, framed protocol with hard size caps
- **Crypto:** vetted primitives only (ed25519-dalek `verify_strict`, XChaCha20-Poly1305, Argon2id@OWASP), fail-closed CSPRNG (no ThreadRng fallback), redacting Debug, zeroize on Drop, constant-time HMAC via `subtle`, domain-separated HMAC contexts
- **Trust:** verify-before-mutate ordering, quorum + owner-signature enforcement, epoch + state-root chaining, per-source replay watermarks persisted to disk, freshness windows with future-drift rejection
- **Parsers:** STUN (1024B buffer, length-checked), gossip (4KB cap, per-field validation), IPC (4KB cap, per-command SO_PEERCRED), UPnP HTTP (256KB cap with +1-byte overflow detection + test pin), PCP (fixed response length), NAT-PMP (64B buffer), enrollment token (fixed 64B binary, constant-time tag compare)
- **Memory safety:** `#![forbid(unsafe_code)]` on 13/14 crates (only FFI crate `rustynet-windows-native` allows unsafe); no `build.rs` in any crate (zero build-time code-exec surface)
- **Secret hygiene:** no secrets in logs, token tags redacted in Debug, Zeroizing wrappers, passphrase credential path validated, all-zero-key rejection

**Gap cluster:** The dataplane fail-closed posture has High-severity gaps (RN-03/04/05/06/07/11 still open). Additionally, 5 `expect()`/`unwrap()` sites in `daemon.rs` production paths can crash the daemon, defeating the killswitch. These are the highest-residual-risk items.

### Findings Tally (refined)

| Severity | Existing (open) | New (this analysis) | Total Open |
|---|---|---|---|
| Critical | 0 | 0 | 0 |
| High | 6 | 3 | 9 |
| Medium | 7 | 4 | 11 |
| Low | 12 | 4 | 16 |
| Info | 5 | 2 | 7 |

---

## 2. High-Severity Findings

### 2.1 Existing (from SecurityReview_2026-05-24, still open)

#### RN-03 — `force_fail_closed` results silently discarded (fail-open)
- **Status:** OPEN (10 discard sites confirmed in daemon.rs)
- **Risk:** On first bootstrap, if `block_all_egress` fails, the killswitch table is never created and all traffic egresses cleartext while the daemon believes it is restricted.
- **Fix:** Replace `let _ = self.controller.force_fail_closed(...)` with `force_fail_closed_or_terminate()` that either succeeds, retries with backoff while refusing to serve, or aborts.

#### RN-04 — Tunnel + routes come up before killswitch is programmed
- **Status:** OPEN
- **Fix:** Program `policy drop` killswitch BEFORE `backend.start()` and route apply. Make `ExecStartPre` boot killswitch mandatory.

#### RN-05 — Policy engine default-allows non-`node:` selectors (revocation bypass)
- **Status:** OPEN
- **Fix:** Resolve `group:`/`tag:`/`user:` selectors to constituent node set; deny if any member revoked.

#### RN-06 + RN-07 — Windows killswitch + IPv6 leak
- **Status:** OPEN
- **Fix:** Scope LAN egress allow to WG UDP + STUN + management. Add IPv6 outbound block. Flush autoconfigured global IPv6.

#### RN-02 — Dead `dataplane.rs` module (assurance failure)
- **Status:** OPEN
- **Fix:** Delete `dataplane.rs`; point security-audit catalog at live `phase10.rs`.

#### RN-11 — Empty membership directory = allow-all
- **Status:** OPEN
- **Fix:** Default to deny on empty unless `--membership-governance=disabled` explicitly set.

---

### 2.2 New High-Severity Findings

#### RN-N1 — Production-path `expect()`/`unwrap()` panics in daemon runtime (DoS)
- **Severity:** High · **CWE-248 / CWE-754** · **Confidence: High**
- **Location:** `crates/rustynetd/src/daemon.rs`
  - L5905: `self.relay_client.take().expect("relay client should remain available")` — double-call panic
  - L6154: `.values().next().expect("single traversal probe status")` — empty-map panic
  - L6300: `handshake_unix.expect("fresh handshake must carry timestamp")` — None panic
  - L6341: Same pattern for relay handshake
  - L9238: `last_err.unwrap()` — empty bind-attempt chain panic
- **Impact:** Daemon crash → tunnel drops → traffic may egress cleartext if killswitch not pre-programmed (RN-03/RN-04 chain). Per AGENTS.md §10.2, `expect()` in production paths is forbidden.
- **Fix:** Replace with proper error propagation (`map_err`/`ok_or_else`/`?`).

#### RN-N2 — Control-plane has no transport security — plaintext IPC over Unix socket
- **Severity:** High · **CWE-319** · **Confidence: High**
- **Location:** `crates/rustynetd/src/ipc.rs`
- **Impact:** SecurityMinimumBar §3.2 requires "TLS 1.3 enforced for control-plane APIs." The Unix socket has filesystem ACL (0o600) and SO_PEERCRED authn, but no per-command anti-replay, no encryption, and no server authentication beyond uid. A local attacker in `rustynetd` group can replay captured IPC commands.
- **Fix:** Add per-command sequence number + HMAC using the daemon's signing key. For remote-admin paths, add TLS 1.3 tunnel.

#### RN-N3 — No upper bound on concurrent IPC connections (local DoS)
- **Severity:** High · **CWE-770** · **Confidence: Medium**
- **Location:** `daemon.rs` IPC accept loop
- **Impact:** Unprivileged user can exhaust daemon file descriptors by opening many IPC connections.
- **Fix:** Track active connection count; refuse above `MAX_IPC_CONNECTIONS` (16). Add per-UID limits.

---

## 3. Medium-Severity Findings

### 3.1 Existing (from SecurityReview, still open)

- **RN-08:** Key envelope lacks AAD binding (magic/version/salt/nonce not authenticated)
- **RN-09:** systemd-credential passphrase files may be group-readable
- **RN-10:** Corrupt rotation ledger silently resets to genesis (fail-open)
- **RN-12:** Linux DNS leak on exit nodes (broad accept precedes DNS drop)
- **RN-13:** No handshake flood guard in live path (only in dead `dataplane.rs`)
- **RN-16:** GitHub Actions pinned to mutable tags (needs SHA-pinning)
- **RN-25:** Coordination replay window is in-memory only

### 3.2 New Medium Findings

#### RN-N4 — Gossip transport has no per-peer rate limiting
- **Severity:** Medium · **CWE-770** · **Confidence: Medium**
- **Location:** `crates/rustynetd/src/gossip_runtime.rs` — `drain_gossip_inbound` processes every received bundle in a tight loop without per-source rate limiting.
- **Description:** While bundles are bounded (4KB) and signature-verified, a rogue peer can flood forged bundles, consuming CPU with Ed25519 verification. The 4KB cap prevents memory exhaustion but not CPU exhaustion.
- **Fix:** Add per-peer token-bucket rate limiter (e.g., 10 bundles/sec). Drop above-limit bundles before signature verification.

#### RN-N5 — Enrollment token TTL checked before constant-time HMAC compare (timing leak)
- **Severity:** Medium · **CWE-208** · **Confidence: Low**
- **Location:** `crates/rustynetd/src/enrollment_token.rs` and `crates/rustynet-control/src/enrollment.rs`
- **Description:** The enrollment token verification checks `expires_at < now` BEFORE running the constant-time HMAC comparison. An attacker measuring response time can distinguish "expired token" from "wrong secret," narrowing the brute-force window. The token is 256-bit HMAC-SHA256 so brute-force is impractical regardless — this is defense-in-depth.
- **Fix:** Move TTL check AFTER the constant-time HMAC verify. Always run full verify before any time-based rejection.

#### RN-N6 — No fuzzing harness for relay hello/session token parser
- **Severity:** Medium · **CWE-20** · **Confidence: Medium**
- **Location:** `crates/rustynet-relay/src/transport.rs`, `session.rs`
- **Description:** The relay processes untrusted UDP from any source address. While the membership decoder has fuzz targets, the relay hello parser and session token verifier do not.
- **Fix:** Add `cargo-fuzz` targets for `parse_relay_hello`, `verify_session_token`, and rate-limiter state machine.

#### RN-N7 — ~~UPnP XML body has no size cap~~ — **NULLIFIED**
- **Status:** **Already capped** — `UPNP_HTTP_MAX_BODY_BYTES = 256KB` with `+1` byte overflow detection and test pin at `port_mapper.rs:1674`. HTTP round-trip rejects oversized bodies. Finding withdrawn.

#### RN-N8 — `SystemTime::now()` for security-sensitive expiry (clock-skew attack surface)
- **Severity:** Medium · **CWE-367** · **Confidence: Low**
- **Location:** `daemon.rs`, `enrollment_token.rs`, relay session expiry
- **Description:** Enrollment token TTL, relay session expiry, and gossip freshness windows all use `SystemTime::now()` which can be skewed by NTP, manual clock changes, or suspend/resume. The enrollment token already has an `IssuedInFuture` check (tolerates 300s drift) and the gossip freshness window is symmetric (past + future). These mitigate but don't eliminate the risk.
- **Fix:** Use `Instant` for monotonic timeouts. For absolute TTL, add a skew-detection alarm (the cross-network preflight already has clock-skew validation — extend to daemon main loop).

---

## 4. Low-Severity Findings (New)

#### RN-N9 — Relay session token nonce is 128 bits (adequate, 256 recommended for modern protocols)
- **Severity:** Low · **CWE-330** · **Confidence: Low**
- **Location:** `crates/rustynet-control/src/lib.rs` — `RelaySessionToken.nonce: [u8; 16]`
- **Fix:** Extend to `[u8; 32]` (schema change — coordinated rollout required).

#### RN-N10 — No audit log for day-to-day IPC command execution
- **Severity:** Low · **CWE-778**
- **Location:** `daemon.rs` IPC command dispatch
- **Description:** Role transitions are audited (D12.e) but routine ops (key rotate, exit select, route advertise/retract, enrollment consume) are not.
- **Fix:** Add structured audit events for security-relevant IPC commands.

#### RN-N11 — `cargo audit`/`cargo deny` not run as pre-commit hook
- **Severity:** Low · **CWE-1104**
- **Fix:** Document in AGENTS.md §7. Add `scripts/ci/precommit.sh`.

#### RN-N12 — Port mapper `detect_default_gateway()` reads `/proc/net/route` without size cap
- **Severity:** Low · **CWE-770** · **Confidence: Low**
- **Location:** `crates/rustynetd/src/port_mapper.rs:1113`
- **Description:** `std::fs::read_to_string("/proc/net/route")` reads the entire file into memory. On a normal system this file is <4KB. On a misconfigured system or under `/proc` symlink attack, a large file could be read.
- **Fix:** Use `BufReader::read_line` with a 64KB cap instead of `read_to_string`. Not exploitable in practice (daemon runs as root, controls `/proc`).

---

## 5. Positive Findings — Controls Correctly Implemented

This section credits the security controls verified during the deep scan as present, correct, and tested.

### 5.1 Privileged Helper (Exemplary)

| Control | Enforcement | Verified |
|---|---|---|
| Closed-enum program allowlist | `PrivilegedCommandProgram` enum — only Ip, Nft, Pfctl, Netsh, Wg, DnsFailclosedFile, SystemdResolve, Powershell | `validate_request` gates all paths |
| argv-only exec, no shell | `Command::new(program).args(args)` — never `sh -c` | grep confirms no shell construction |
| Shell metacharacter rejection | `validate_request` rejects `;`, `|`, `&`, `$`, `` ` ``, `\`, `"`, `'`, `(`, `)`, `<`, `>`, `\n`, `\r`, `\0` | Unit test coverage |
| Path traversal rejection | Args containing `..` or starting with `/` rejected where appropriate | Per-program schema |
| Root-owned binary validation | `validate_privileged_program_binary` checks absolute, canonicalize, regular-file, executable, non-group-writable, root-owned | Tests |
| Post-connect peer-uid check | RN-17 fixed — verifies peer uid on established fd after `connect()` | Test: `peer_uid_reports_connected_socket_owner_uid` |
| Framed protocol with size caps | 4KB max per command, bounded reads | `MAX_COMMAND_BYTES = 4096` |
| Subprocess timeouts | Every external command has a kill-on-timeout watchdog | `run_helper_command_with_timeout` |
| Pkill constrained | Only `-TERM <pid>` where `pid > 1` — no broad `pkill -f` | `validate_request` schema |
| DnsFailclosedFile builtin | In-helper file write — no external binary, no path/content crosses boundary | `is_builtin()` dispatch |

### 5.2 Cryptography (Best-in-Class)

| Control | Enforcement |
|---|---|
| vetted primitives only | ed25519-dalek 2.2 `verify_strict`, XChaCha20-Poly1305, Argon2id @ OWASP params, HMAC-SHA256 |
| fail-closed CSPRNG | `OsRng::try_fill_bytes` with error propagation — never falls back to ThreadRng |
| domain-separated HMAC | Every HMAC context has a unique prefix (`"rustynet:enrollment:v1"`, `"rustynet:peer_gossip:v1"`, etc.) |
| constant-time compares | `subtle::ConstantTimeEq` for enrollment token HMAC, all secret comparisons |
| redacting Debug | `EnrollmentToken`, `SecretKey`, all key-bearing types redact in Debug |
| zeroize on Drop | `Zeroizing` wrappers; `SecretKey::drop` calls `zeroize()` (RL-4) |
| all-zero key rejection | Key material validated non-zero at load |
| strict Ed25519 | `verify_strict()` at all 10 sites, rejects non-canonical S and small-order points (RL-3) |
| macOS Keychain validation | `is_valid_key_identifier` before keychain access (RL-5) |

### 5.3 Trust & Anti-Replay (Solid)

| Control | Enforcement |
|---|---|
| verify-before-mutate | Signature checked before `preview_next_state`/`apply_signed_update` |
| quorum enforcement | `state.quorum_threshold` checked before accepting signed update |
| epoch + state-root chaining | `previous_state_root` validated in each update |
| per-source replay watermarks | `SeenSequenceState` persisted to disk, loaded at startup, fail-closed on corrupt |
| freshness windows | 300s past + future drift rejection on gossip bundles |
| future-drift rejection | Enrollment tokens with `issued_at > now + 300s` rejected |
| atomic token consumption | Single-use ledger persisted before peer registration |
| HMAC before TTL | (Gap: RN-N5) — defense-in-depth item |

### 5.4 Network Parsers (Bounded & Safe)

| Parser | Buffer Size | Overflow Protection | Test Pins |
|---|---|---|---|
| STUN | 1024B | Length check before index; attribute boundary check; 4-byte alignment padding | 8 unit tests |
| Gossip | 4KB | `MAX_GOSSIP_DATAGRAM_BYTES` enforced on send + receive; oversized datagram rejection test | 6 integration tests |
| IPC | 4KB | `MAX_COMMAND_BYTES` via `stream.take()`; null-byte rejection | Per-command tests |
| UPnP HTTP | 256KB | `UPNP_HTTP_MAX_BODY_BYTES + 1` overflow detection; body-too-large test pin | `upnp_http_round_trip_rejects_oversize_response_body` |
| PCP | Fixed 110B | `PCP_MAP_RESPONSE_LEN + 64` buffer; response length validation | Unit tests |
| NAT-PMP | 64B | Fixed buffer; length check before parse | Unit tests |
| Enrollment token | 64B | `TOKEN_BINARY_LEN` const; length check before decode; constant-time HMAC | 5 tests |
| DNS zone | 4KB IPC cap | `MAX_RECORD_COUNT` cap; `fields.len()` cross-check | Unit tests |
| SSDP | 4KB | `MAX_SSDP_DISCOVERED_DEVICES = 4`; 4KB response buffer | Unit tests |

---

## 6. Modern Defense-in-Depth Recommendations

### 6.1 systemd Sandbox Hardening
Current `rustynetd.service` has `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`. Add:
```
ProtectHome=true
ProtectProc=invisible
RestrictSUIDSGID=true
RemoveIPC=true
RestrictRealtime=true
MemoryDenyWriteExecute=true
```
Use `systemd-analyze security rustynetd.service` as CI gate (target exposure score ≤ 2.0).

### 6.2 TPM2-Backed Key Sealing
For anchor/exit nodes, bind the WireGuard private key to TPM2 PCR state (kernel, initrd, systemd). Even root cannot exfiltrate the key without booting a modified kernel. Use `tpm2-policy` with `tpm2_unseal`.

### 6.3 Continuous Fuzzing Infrastructure
Add `cargo-fuzz` targets for: relay hello parser, session token verifier, gossip decoder, STUN response parser, PCP MAP decoder, DNS zone decoder. Run in CI for 1 hour per commit.

### 6.4 Formal Membership Model
Model `apply_signed_update` in TLA+ / Stateright. Verify invariants: epoch monotonicity, quorum enforcement, replay-watermark correctness, no capability self-promotion, transition matrix completeness.

### 6.5 Constant-Time CI Gate
Add `scripts/ci/constant_time_gates.sh` that greps for `==`/`!=` on types containing `Secret`, `Key`, `Passphrase`, `Token` outside `subtle` blocks.

---

## 7. Attack Surface Matrix (Refined)

| Boundary | Protocol | Untrusted Input | Parsing Safety | AuthN/Z | Rate Limit |
|---|---|---|---|---|---|
| WireGuard peer | UDP:51820 | WG handshake + transport | Boringtun (audited) | WG preshared key | Boringtun cookie |
| Relay | UDP:51821 | Relay hello + session token | Bounded, **no fuzz targets** (RN-N6) | Signed token | Token-bucket (10k pps) |
| Gossip | UDP:51821 | Signed membership bundle | 4KB cap, version-gated, signature-verified | Ed25519 `verify_strict` | **NONE** ⚠️ (RN-N4) |
| STUN | UDP:19302→ | STUN binding response | 1024B, length-checked, attr-boundary-checked | None (public) | N/A |
| UPnP | UDP:1900/TCP | SSDP + SOAP + XML desc | 256KB HTTP cap, 4KB SSDP cap, control-char sanitized | None (LAN) | 4-device cap |
| PCP | UDP:5351 | PCP MAP response | Fixed 110B buffer | None (LAN) | 5 retry cap |
| NAT-PMP | UDP:5351 | NAT-PMP response | Fixed 64B buffer | None (LAN) | 9 retry cap (RFC) |
| IPC | Unix socket | Newline-delimited command | 4KB cap, null-byte rejected, per-command SO_PEERCRED | uid check | **NONE** ⚠️ (RN-N3) |
| Anchor bundle-pull | TCP:51822 | HTTP GET with token header | Bounded response | HMAC token | Single-use ledger |
| Enrollment | TCP (mesh) | 64B enrollment token | Constant-time HMAC, TTL-bounded | Token + TTL | Single-use ledger |
| DNS resolver | UDP:53 (loopback) | DNS question | Bounded, panic-free | None (local) | N/A |

---

## 8. Prioritized Remediation Roadmap

### P0 — Fix Now (fail-open / leak / DoS)
1. **RN-03 + RN-04:** Make `force_fail_closed` fatal + program killswitch before backend up
2. **RN-N1:** Remove all 5 production `expect()`/`unwrap()` panics from daemon.rs
3. **RN-06 + RN-07:** Windows killswitch parity + IPv6 block
4. **RN-05 + RN-11:** Close policy default-allow paths
5. **RN-02:** Delete dead `dataplane.rs`

### P1 — High-Value Integrity
6. **RN-10:** Corrupt rotation ledger → fail closed
7. **RN-08:** AAD-bind key envelope
8. **RN-09:** Tighten systemd-credential group-read gate
9. **RN-16:** SHA-pin GitHub Actions
10. **RN-N2:** IPC anti-replay (nonce + HMAC)

### P2 — Defense-in-Depth
11. **RN-N4:** Gossip per-peer rate limiting
12. **RN-N6:** Fuzz targets for relay + gossip
13. **RN-N3:** IPC connection limits
14. **RN-N5:** Enrollment TTL after constant-time compare
15. **RN-N8:** SystemTime→Instant migration + clock-skew alarm
16. **§6.1:** systemd sandbox hardening

### P3 — Modernization (post-GA)
17. **§6.2:** TPM2 key sealing
18. **§6.4:** Formal membership model
19. **§6.3:** Continuous fuzzing infrastructure
20. **§6.5:** Constant-time CI gate

---

## 9. SecurityMinimumBar Compliance Matrix

| Control (§3) | Status | Gap |
|---|---|---|
| 1. Proven crypto only | ✅ Upheld | No custom crypto; all vetted primitives |
| 2. TLS 1.3 for control-plane | ❌ **Gap** | IPC is plaintext (RN-N2) |
| 3. Auth/enrollment hardening | ⚠️ Partial | Rate limiting missing on IPC + gossip |
| 4. Secret/key handling | ⚠️ Partial | RN-08 (AAD), RN-09 (group-read), RN-33 (Windows no-op) |
| 5. Host-OS boundary | ✅ Upheld | Platform enforcement present; Linux-only blocked on non-Linux |
| 6. Default-deny ACL | ❌ **Gap** | RN-05 (non-node selectors), RN-11 (empty membership) |
| 7. Web/admin security | ⚠️ N/A | No web UI; IPC needs anti-replay |
| 8. Data-plane leak prevention | ❌ **Gap** | RN-03/04 (killswitch ordering), RN-06/07 (Windows), RN-12 (DNS exit) |
| 9. Audit and forensics | ⚠️ Partial | Role audit exists; day-to-day IPC commands not audited |
| 10. Supply-chain integrity | ⚠️ Partial | RN-15 fixed (`--locked`); RN-16 (SHA-pin), RN-30 (toolchain), RN-31 (deny.toml) open |

---

## 10. Cross-Reference

- **Primary security review:** `documents/operations/active/SecurityReview_2026-05-24.md` (38 findings)
- **Security baseline:** `documents/SecurityMinimumBar.md`
- **Agent contract:** `AGENTS.md` §3 (Engineering Constraints), §4 (Security Baseline), §10 (Common Patterns)
- **Dataplane plan:** `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md`
- **Anchor design:** `documents/operations/active/AnchorNodeRoleDesign_2026-05-21.md`
- **Role taxonomy:** `documents/operations/active/NodeRoleTaxonomy_2026-05-21.md`
