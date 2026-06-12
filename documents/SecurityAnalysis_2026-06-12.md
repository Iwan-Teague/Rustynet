# Rustynet Security Analysis — Verified Weaknesses & Hardening Patches

- **Date:** 2026-06-12 (verified against live code `bf47db1`)
- **Scope:** Cross-referenced SecurityReview (38 findings), HardeningAudit (Phase A+B), HardeningBacklog (HB-1..7), plus new deep code scan
- **Methodology:** Each finding verified against actual code at `file:line`; false positives removed; each has a concrete, harder-to-exploit patch

---

## 1. Verification Summary

### Already Fixed (8 findings): RN-01, RN-14, RN-15, RN-17, RN-19, RN-22, RN-23, RN-24

### Still Open — Verified REAL (30 review findings + 7 backlog items + 3 new)

---

## 2. P0 — Fix Now (fail-open / leak / DoS)

### RN-03 — `force_fail_closed` results silently discarded (fail-open on first bootstrap)
- **Source:** SecurityReview §3, re-verified HardeningBacklog §B `e01dd64`
- **Location:** `crates/rustynetd/src/daemon.rs` — 10 confirmed `let _ = …force_fail_closed(…)` sites
- **Verified:** `grep 'let _ =.*force_fail_closed' crates/rustynetd/src/daemon.rs` → 10 hits. Each discards the Result. If `block_all_egress` fails on first bootstrap (no prior killswitch table), the daemon proceeds as if protected but the host has no `policy drop`.
- **Exploitability:** HIGH. A transient nft helper failure during first boot → all traffic egresses cleartext. No attacker action needed — this is a reliability→security defect.
- **Patch:** Replace `let _ = self.controller.force_fail_closed(reason)` with:
  ```rust
  if let Err(e) = self.controller.force_fail_closed(reason) {
      tracing::error!(%e, reason, "force_fail_closed failed; aborting to let systemd boot killswitch backstop");
      std::process::abort();
  }
  ```
  This is strictly harder to exploit than swallowing the error: the daemon dies, systemd restarts it (or the boot killswitch stays active), and there's no window where the daemon thinks it's protected but isn't.

### RN-04 — Tunnel + routes up before killswitch programmed (bootstrap leak window)
- **Source:** SecurityReview §3
- **Location:** `crates/rustynetd/src/phase10.rs` — `apply_dataplane_generation` programs killswitch AFTER `backend.start()` and route apply
- **Verified:** Read `phase10.rs` apply order — `BackendStarted` state precedes killswitch programming. Comment confirms `ExecStartPre` is opt-in.
- **Patch:** 
  1. Program `policy drop` killswitch BEFORE `backend.start()` 
  2. Make `ExecStartPre` boot killswitch installer **mandatory** in shipped `rustynetd.service` unit
  3. Daemon refuses to start if boot killswitch table absent (existing verifier — just gate on it)

### RN-05 — Policy engine default-allows non-`node:` selectors (revocation bypass)
- **Source:** SecurityReview §3, re-verified HardeningBacklog §B
- **Location:** `crates/rustynet-policy/src/lib.rs:305-308` — `selector_membership_allowed` returns `true` for any selector not prefixed `node:`
- **Verified:** Read the function — confirmed. `group:`, `tag:`, `user:`, raw CIDR selectors skip the membership revocation gate.
- **Patch:** 
  ```rust
  fn selector_membership_allowed(selector: &str, membership: &MembershipState) -> bool {
      // Resolve non-node selectors to their constituent node set
      let node_ids = match resolve_selector_to_node_ids(selector, membership) {
          Some(ids) => ids,
          None => return false, // Unresolvable → deny (fail-closed)
      };
      node_ids.iter().all(|id| membership.is_active_member(id))
  }
  ```
  This closes the bypass: revoked nodes matching `group:`/`tag:`/`user:` rules are denied.

### RN-06 — Windows killswitch allows ALL non-DNS LAN egress
- **Source:** SecurityReview §3, re-verified HardeningBacklog §B
- **Location:** `crates/rustynetd/src/phase10.rs` — `windows_firewall_allow_interfacetype_args` emits unscoped `interfacetype=lan action=allow`
- **Verified:** Read the netsh args builder — confirmed unscoped allow.
- **Patch:** Replace the netsh `interfacetype=lan` allow with WFP filters (unified with E2 tunnel permit):
  - Permit: loopback + tunnel LUID + UDP to specific peer/relay endpoints + STUN + management/SSH
  - Block: everything else for BOTH IPv4 and IPv6
  - WFP sublayer with max weight so netsh rules cannot override
  - Re-verify in `assert_killswitch`

### RN-07 — Windows IPv6 leak (native IPv6 egress unblocked)
- **Source:** SecurityReview §3, HardeningBacklog §B (G8 in progress)
- **Location:** `crates/rustynetd/src/phase10.rs:3343` — only disables RA, not IPv6 egress
- **Verified:** G8 work added `RustyNetKS-BlockIpv6Lan` netsh rule, but: (a) not re-verified in `assert_killswitch`, (b) existing autoconfigured global addresses not flushed, (c) uses netsh not WFP.
- **Patch:** Unify with RN-06 WFP fix — single WFP block for both families. Flush autoconfigured global IPv6 addresses at enforcement time. Assert in `assert_killswitch`.

### RN-11 — Empty membership directory = allow-all (fail-open default)
- **Source:** SecurityReview §3, re-verified HardeningBacklog §B
- **Location:** `crates/rustynetd/src/phase10.rs:5005` — `if !membership.is_populated()` skips the enforcement gate
- **Verified:** Read the comment — "pre-membership escape hatch". Also `allowed_contexts` empty list matches all contexts at `policy/lib.rs:289`.
- **Patch:** 
  1. Default to deny when membership directory is empty
  2. Add explicit `--membership-governance=disabled` opt-in for pre-governance window
  3. Fail closed if snapshot path configured but failed to load
  4. Empty `allowed_contexts` → deny (not match-all)

### RN-02 — Dead `dataplane.rs` (assurance failure)
- **Source:** SecurityReview §3
- **Location:** `crates/rustynetd/src/dataplane.rs` — entire module is dead code
- **Verified:** `LinuxDataplane` referenced only in its own `#[cfg(test)]` block. Live path is `phase10.rs`.
- **Patch:** Delete `dataplane.rs`. Point `security_audit_catalog.rs` at `phase10.rs` enforcement. This removes the false assurance that someone reading `dataplane.rs` is validating the live killswitch.

---

## 3. New Verified Findings

### RN-N1 — Production `expect()` panic in daemon relay-client establish path (DoS)
- **Severity:** High · **CWE-248**
- **Location:** `crates/rustynetd/src/daemon.rs:5908`
  ```rust
  let mut relay_client = self
      .relay_client
      .take()
      .expect("relay client should remain available during establish");
  ```
- **Verified:** `self.relay_client` is `Option<RelayClient>`. If this code path executes twice (edge case: concurrent traversal probe + relay health check), the second `take()` returns `None` → panic → daemon crash → tunnel drops.
- **Patch:**
  ```rust
  let mut relay_client = self
      .relay_client
      .take()
      .ok_or_else(|| DaemonError::State("relay client already consumed".into()))?;
  ```
  This propagates the error instead of crashing, keeping the daemon alive with the tunnel intact.

### RN-N2 — Local IPC commands lack per-message anti-replay
- **Severity:** Medium · **CWE-294**
- **Location:** `crates/rustynetd/src/ipc.rs` — `IpcCommand::Local` dispatch path has no sequence number or nonce
- **Verified:** The `RemoteCommandEnvelope` has `nonce: u64` + Ed25519 signature. But `CommandEnvelope::Local` parsed from the Unix socket goes directly to command dispatch with only SO_PEERCRED for auth. A local attacker in the `rustynetd` group can capture and replay commands.
- **Patch:** Add a per-connection sequence counter to the local IPC path:
  ```rust
  // In the IPC accept handler:
  let mut conn_seq: u64 = 0;
  // On each command:
  if cmd_seq <= conn_seq {
      return Err("replay detected: sequence must be strictly increasing");
  }
  conn_seq = cmd_seq;
  ```
  For remote-admin, the existing `nonce` + signature mechanism is sufficient.

### RN-N3 — No IPC connection limit (local DoS via fd exhaustion)
- **Severity:** Medium · **CWE-770**
- **Location:** `crates/rustynetd/src/daemon.rs` IPC accept loop
- **Verified:** The daemon accepts IPC connections in a loop with no counting or rate limiting. Each connection consumes a file descriptor.
- **Patch:** 
  ```rust
  const MAX_IPC_CONNECTIONS: usize = 16;
  let mut active_connections: usize = 0;
  // In accept loop:
  if active_connections >= MAX_IPC_CONNECTIONS {
      // Accept and immediately close to drain the listen queue
      let _ = listener.accept();
      continue;
  }
  ```

---

## 4. Medium — Verified Open from SecurityReview

- **RN-08:** Key envelope lacks AAD binding — `rustynet-crypto/lib.rs:942` (empty AAD). Patch: bind `MAGIC || version || salt || nonce` as AAD.
- **RN-09:** systemd-credential passphrase group-readable — `key_material.rs:674` (wider mask on `/run/credentials/` prefix). Patch: require parent dir `0o700` + file group = 0 before widening.
- **RN-10:** Corrupt rotation ledger → genesis reset — `daemon.rs:8082` (returns `genesis()` on any error). Patch: distinguish absent (→genesis) from corrupt (→refuse to proceed).
- **RN-12:** DNS leak on exit nodes (broad accept precedes DNS drop) — `phase10.rs:1980` vs `:2020`. Patch: insert DNS drop with higher precedence.
- **RN-13:** No handshake flood guard in live path — only in dead `dataplane.rs`. Patch: implement in `phase10.rs` or rely on boringtun cookie mechanism (document decision).
- **RN-16:** GitHub Actions pinned to mutable tags — `.github/workflows/`. Patch: SHA-pin every `uses:`.
- **RN-25:** Coordination replay window in-memory only — `traversal.rs:833`. Patch: persist seen-nonce set.

---

## 5. Medium — New Verified

### RN-N4 — Gossip transport has no per-peer rate limiting (CPU DoS)
- **Location:** `crates/rustynetd/src/gossip_runtime.rs` — `drain_gossip_inbound` loop
- **Verified:** Bundles are 4KB-capped and signature-verified, but a rogue peer can flood forged bundles consuming CPU with Ed25519 verification. No per-source rate limiter exists.
- **Patch:** Token-bucket per source node_id (10 bundles/sec, burst 20). Drop above-limit BEFORE signature verification.

### RN-N5 — Enrollment token TTL checked before constant-time HMAC (timing side-channel)
- **Location:** `crates/rustynetd/src/enrollment_token.rs` — verify path checks `expires_at < now` before HMAC
- **Verified:** The token verification flow: decode → check expiry → check consumed-ledger → HMAC compare. The expiry check returns early with `Expired`, giving different response timing than `TagMismatch`. 256-bit HMAC makes brute-force impractical; defense-in-depth gap.
- **Patch:** Reorder: decode → HMAC compare (constant-time) → check consumed-ledger → check expiry. Always perform full constant-time verify before any time-based rejection.

### RN-N6 — No fuzzing harness for relay hello parser
- **Location:** `crates/rustynet-relay/src/transport.rs` — relay hello parse, `session.rs` — token verify
- **Verified:** Membership decoder has fuzz targets (`cargo-fuzz`). Relay hello parser processes untrusted UDP from any source — no fuzz target exists.
- **Patch:** Add `cargo-fuzz` targets for `parse_relay_hello`, `verify_session_token`, rate-limiter state machine.

---

## 6. Items from HardeningBacklog (2026-06-01) — Not Yet in SecurityReview

### HB-1 — Smoke harnesses use plain `remove_file` instead of secure scrub
- **Severity:** Low · **Location:** `windows_tunnel_smoke.rs`, `windows_killswitch_smoke.rs`
- **Patch:** Call `crate::key_material::remove_file_if_present(&key_path)` (overwrites-then-deletes) on all paths.

### HB-2 — `write_runtime_private_key` 0o600 is `cfg(unix)`-only
- **Severity:** Low · **Location:** `key_material.rs:739`
- **Patch:** On Windows, set explicit owner-only ACL via `SetNamedSecurityInfoW` or write to validated hardened dir.

### HB-3 — Killswitch-smoke recovery uses PATH-resolved `netsh` (RN-20 class)
- **Severity:** Low · **Location:** `windows_killswitch_smoke.rs` — `Command::new("netsh")`
- **Patch:** Use absolute `%SystemRoot%\System32\netsh.exe`.

### HB-4 — Killswitch-smoke Drop guard doesn't clean up IPv6 LAN block on panic
- **Severity:** Low · **Location:** `windows_killswitch_smoke.rs` — `FirewallRestoreGuard::drop`
- **Patch:** Add best-effort `netsh advfirewall firewall delete rule name=RustyNetKS-BlockIpv6Lan` to Drop guard.

### HB-5 — ipv6-smoke connects to hardcoded public third-party IPv6
- **Severity:** Info · **Location:** `windows_killswitch_smoke.rs` — `TcpStream::connect_timeout("[2606:4700:4700::1111]:443")`
- **Patch:** Prefer lab-local off-LAN IPv6 target; document dependency.

### HB-6 — vm-lab orchestrator builds PowerShell scripts via `format!`
- **Severity:** Info · **Location:** `crates/rustynet-cli/src/vm_lab/**`
- **Patch:** Centralize PS-script assembly behind a builder that quotes by construction.

### B.4.1 — DNS rebind/re-poison protection (partially landed)
- **Severity:** Medium · **Location:** DNS zone parser rejects loopback/link-local/test-net `expected_ip`; resolver-output filter still pending
- **Patch:** Complete the resolver-output filter when the DNS protocol handler lands.

---

## 7. Attack Surface Matrix (Verified)

| Boundary | Protocol | Untrusted Input | Parsing Safety | AuthN/Z | Rate Limit | Fuzz Target |
|---|---|---|---|---|---|---|
| WireGuard | UDP:51820 | Handshake + transport | Boringtun (audited) | Preshared key | Boringtun cookie | N/A (upstream) |
| Relay | UDP:51821 | Hello + session token | Bounded, **no fuzz** (RN-N6) | Signed token | Token-bucket (10k pps) | **MISSING** |
| Gossip | UDP:51821 | Signed bundle | 4KB cap, verify_strict | Ed25519 | **NONE** (RN-N4) | **MISSING** |
| STUN | UDP:19302→ | Binding response | 1024B, boundary-checked | None (public) | N/A | **MISSING** |
| UPnP | UDP:1900/TCP | SSDP + SOAP + XML | 256KB HTTP cap, control-char sanitized | None (LAN) | 4-device cap | **MISSING** |
| PCP | UDP:5351 | MAP response | Fixed 110B buffer | None (LAN) | 5 retry cap | **MISSING** |
| IPC (local) | Unix socket | Newline command | 4KB cap, null-byte rejected | SO_PEERCRED | **NONE** (RN-N3) | N/A |
| IPC (remote) | Unix socket | Signed envelope | 4KB cap, signature-verified | Ed25519 + nonce | Per-command nonce | N/A |
| Bundle-pull | TCP:51822 | HTTP GET + token | Bounded response | HMAC token | Single-use ledger | **MISSING** |
| Enrollment | TCP (mesh) | 64B token | Constant-time HMAC | Token + TTL | Single-use ledger | Present |
| DNS resolver | UDP:53 (lo) | DNS question | Bounded, panic-free | None (local) | N/A | **MISSING** |

---

## 8. Hardening Patches — Code Examples

### 8.1 Fix RN-03 (force_fail_closed fatal)

```rust
// BEFORE (daemon.rs — 10 sites):
let _ = self.controller.force_fail_closed("membership_stale");

// AFTER:
if let Err(e) = self.controller.force_fail_closed("membership_stale") {
    tracing::error!(
        %e,
        reason = "membership_stale",
        "force_fail_closed failed; dataplane safety cannot be guaranteed — aborting"
    );
    self.restrict_recoverable(format!(
        "force_fail_closed failed: {e}"
    ));
    // On first bootstrap with no prior killswitch table, abort so systemd
    // restarts us with the boot killswitch backstop. On steady-state with a
    // prior generation table, the existing policy drop still protects.
    if self.is_first_bootstrap() {
        std::process::abort();
    }
}
```

### 8.2 Fix RN-05 (non-node selector revocation)

```rust
// BEFORE (rustynet-policy/src/lib.rs:305):
fn selector_membership_allowed(selector: &str, membership: &MembershipState) -> bool {
    let node_id = match selector.strip_prefix("node:") {
        Some(id) => id,
        None => return true,  // BUG: non-node selectors skip revocation
    };
    membership.is_active_member(node_id)
}

// AFTER:
fn selector_membership_allowed(selector: &str, membership: &MembershipState) -> bool {
    let node_ids = resolve_selector_to_member_node_ids(selector, membership);
    // Unresolvable identity → deny (fail-closed)
    node_ids.is_some_and(|ids| ids.iter().all(|id| membership.is_active_member(id)))
}
```

### 8.3 Fix RN-N1 (relay_client expect panic)

```rust
// BEFORE (daemon.rs:5908):
let mut relay_client = self
    .relay_client
    .take()
    .expect("relay client should remain available during establish");

// AFTER:
let mut relay_client = self
    .relay_client
    .take()
    .ok_or_else(|| {
        DaemonError::State(
            "relay client already consumed; concurrent establish call detected".into()
        )
    })?;
```

---

## 9. Cross-Reference

- **SecurityReview_2026-05-24.md** — 38 findings, 8 fixed, 30 open (authoritative firm-grade review)
- **SecurityHardeningAudit_2026-04-28.md** — Phase A+B comparative audit (most items cleared)
- **SecurityHardeningBacklog_2026-06-01.md** — Net-new HB-1..7 items + re-verified P0s
- **SecurityMinimumBar.md** — Release-blocking controls
- **AGENTS.md §3-4, §10** — Engineering constraints + security patterns
