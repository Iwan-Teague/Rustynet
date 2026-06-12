# Rustynet Security Analysis — Verified & Patched

**Date:** 2026-06-12 · **Commit:** `4fbd5f1` · **Status:** Every claim verified against live code at `file:line`

---

## 0. Methodology

Each finding below was verified by reading the actual source code at the cited location. Findings that could not be confirmed were removed. Severity reflects both exploitability and blast radius. Every finding includes a concrete fix direction.

**Sources cross-referenced:**
- `SecurityReview_2026-05-24.md` — 38 findings (8 fixed, 30 open)
- `SecurityHardeningAudit_2026-04-28.md` — Phase A+B (most cleared)
- `SecurityHardeningBacklog_2026-06-01.md` — HB-1..7 + re-verified P0s

---

## 1. P0 — Fix Immediately (fail-open / leak / DoS)

### 1.1 RN-03 — 10 sites discard `force_fail_closed` Result

**Verified:** `grep 'let _ =.*force_fail_closed' crates/rustynetd/src/daemon.rs` → 10 hits.
```
daemon.rs:6651   let _ = self.controller.force_fail_closed("trust_bootstrap_failed");
daemon.rs:6725   let _ = self.controller.force_fail_closed("invalid_local_node_id");
daemon.rs:6801   let _ = self.controller.force_fail_closed("bootstrap_apply_failed");
daemon.rs:6808   let _ = self.controller.force_fail_closed("bootstrap_apply_failed");
daemon.rs:7878   let _ = self.controller.force_fail_closed("local_key_revoked");
daemon.rs:7955   let _ = self.controller.force_fail_closed("state_persist_failure");
daemon.rs:8069   let _ = self.controller.force_fail_closed("trust_reconcile_failed");
daemon.rs:8186   let _ = self.controller.force_fail_closed("invalid_local_node_id");
daemon.rs:8320   let _ = self.controller.force_fail_closed("reconcile_apply_failed");
daemon.rs:8330   let _ = self.controller.force_fail_closed("reconcile_apply_failed");
```
`force_fail_closed` → `block_all_egress()` → programs `policy drop` killswitch. If this fails (nft unavailable, helper down, transaction race), the error is swallowed. Worst case: first bootstrap, no prior killswitch table exists → daemon proceeds as if protected → host egresses cleartext.

**Fix direction:**
```rust
// Replace each `let _ =` with:
if let Err(e) = self.controller.force_fail_closed(reason) {
    tracing::error!(%e, reason, "force_fail_closed failed; cannot guarantee dataplane safety");
    self.restrict_recoverable(format!("force_fail_closed failed: {e}"));
    return; // or abort on first-bootstrap path
}
```
At minimum, never discard the Result without logging at error level. On the bootstrap path (no prior generation table), abort to let systemd's mandatory boot killswitch backstop.

---

### 1.2 RN-04 — Killswitch programmed AFTER tunnel interface comes up

**Verified:** `phase10.rs:4386` — `self.backend.start(context)` creates the tunnel interface.
`phase10.rs:4541` — `self.system.apply_firewall_killswitch()` programs the killswitch **8 operations later**.

Order in `apply_generation_stages`:
1. `backend.start()` — **tunnel interface UP** (line 4386)
2. `rollback_routes()` (line 4527)
3. `apply_peer_endpoint_bypass_routes()` (line 4528)
4. `backend.apply_routes()` (line 4531)
5. `system.apply_routes()` (line 4535)
6. `system.apply_firewall_killswitch()` — **killswitch FINALLY active** (line 4541)

There is a window between steps 1 and 6 where the tunnel interface exists with routes but no `policy drop`. If the daemon crashes or is killed during this window, the host has routes with no killswitch. The `ExecStartPre` boot killswitch (`linux_killswitch_boot.rs`) is **opt-in** (`--install-boot-killswitch`).

**Fix direction:**
1. Move `apply_firewall_killswitch()` to BEFORE `backend.start()`
2. Make `ExecStartPre` boot killswitch **mandatory** in the shipped `rustynetd.service` unit
3. Gate `backend.start()` on boot killswitch table presence (verifier already exists)

---

### 1.3 RN-05 — Policy revocation bypass for non-`node:` selectors

**Verified:** `rustynet-policy/src/lib.rs:396-405`
```rust
fn selector_membership_allowed(selector: &str, membership: &MembershipDirectory) -> bool {
    let Some(node_id) = selector_node_id(selector) else {
        return true;  // ← Any selector without "node:" prefix SKIPS the membership gate
    };
    membership.node_status(node_id) == MembershipStatus::Active
}

fn selector_node_id(selector: &str) -> Option<&str> {
    selector.strip_prefix("node:")
}
```
A revoked node matching a `group:family` or `user:admin` rule is permitted. Revocation is silently ineffective across the entire non-`node:` rule surface.

**Fix direction:**
```rust
fn selector_membership_allowed(selector: &str, membership: &MembershipDirectory) -> bool {
    // Resolve group/tag/user selectors to their member node set
    let node_ids = resolve_selector_to_node_ids(selector, membership);
    match node_ids {
        Some(ids) => ids.iter().all(|id| membership.node_status(id) == MembershipStatus::Active),
        None => false, // Unresolvable → deny (fail-closed)
    }
}
```
If group resolution is not yet implemented, the immediate mitigation is to return `false` for unresolvable non-`node:` selectors, breaking rules that use group selectors but closing the revocation bypass immediately.

---

### 1.4 RN-11 — Empty membership directory = allow-all

**Verified:** `phase10.rs:5362-5369`
```rust
fn check_peer_membership_active(node_id: &NodeId, membership: &MembershipDirectory) -> Result<(), Phase10Error> {
    if !membership.is_populated() {
        // Membership governance not yet active — skip the gate.
        return Ok(());
    }
    match membership.node_status(node_id.as_str()) { ... }
}
```
When the membership directory is empty (unpopulated), every peer is allowed. This is indistinguishable from "membership state failed to load / was wiped."

**Fix direction:**
1. Distinguish "explicit opt-out" (`--membership-governance=disabled`) from "unpopulated/unloadable"
2. Default to **deny** when membership is empty
3. Fail closed if snapshot path was configured but failed to load

---

### 1.5 RN-02 — Dead `dataplane.rs` module

**Verified:** `LinuxDataplane` in `crates/rustynetd/src/dataplane.rs` is referenced only in its own `#[cfg(test)]` block and one string in `security_audit_catalog.rs`. No production code constructs it. The live dataplane is `phase10.rs`.

**Fix:** Delete `dataplane.rs`. Point `security_audit_catalog.rs` at `phase10.rs`.

---

## 2. P1 — Fix Soon (integrity / defense-in-depth)

### 2.1 RN-N1 — Production `expect()` panic (daemon crash → tunnel drop)
**Location:** `daemon.rs:5908`
```rust
let mut relay_client = self.relay_client.take()
    .expect("relay client should remain available during establish");
```
If this path executes twice (concurrent traversal probe + relay health check), the second `take()` returns `None` → panic → daemon crash → tunnel drops.

**Fix:** `.ok_or_else(|| DaemonError::State("relay client already consumed".into()))?`

### 2.2 RN-08 — Key envelope lacks AAD binding
**Location:** `rustynet-crypto/src/lib.rs:942` — empty AAD in XChaCha20-Poly1305.
**Fix:** Bind `MAGIC || version || salt || nonce` as AAD.

### 2.3 RN-09 — systemd-credential passphrase group-readable
**Location:** `key_material.rs:674` — wider permission mask on `/run/credentials/` prefix.
**Fix:** Require parent dir `0o700` + file group = 0 before honoring wider mask.

### 2.4 RN-10 — Corrupt rotation ledger silently resets to genesis
**Location:** `daemon.rs:8082` — `load_rotation_ledger` returns `genesis()` on any error.
**Fix:** Distinguish absent (→genesis) from corrupt (→refuse to proceed).

### 2.5 RN-16 — GitHub Actions pinned to mutable tags
**Location:** `.github/workflows/cross-platform-ci.yml`, `release-windows.yml`.
**Fix:** Pin every `uses:` to full 40-char commit SHA.

---

## 3. P2 — Defense-in-Depth (new findings)

### 3.1 RN-N4 — Gossip has no per-peer rate limiting
**Location:** `gossip_runtime.rs` — `drain_gossip_inbound` processes every bundle in a tight loop. A rogue peer flooding forged bundles can consume CPU with Ed25519 verification.
**Fix:** Token-bucket per source (10 bundles/sec, burst 20). Drop above limit before signature verification.

### 3.2 RN-N5 — Enrollment TTL checked before constant-time HMAC
**Location:** `enrollment_token.rs` — verify path checks expiry before HMAC compare. Different response timing for "expired" vs "wrong secret."
**Fix:** Reorder: decode → HMAC compare (constant-time) → check consumed-ledger → check expiry.

### 3.3 RN-N6 — No fuzz targets for relay hello parser
**Location:** `crates/rustynet-relay/src/transport.rs`, `session.rs`. Relay processes untrusted UDP from any source.
**Fix:** Add `cargo-fuzz` targets for `parse_relay_hello`, `verify_session_token`, rate-limiter.

---

## 4. Status Changes from SecurityReview

| Finding | SecurityReview | Verified Status | Change |
|---|---|---|---|
| RN-01 | Fixed (RL-1) | Fixed | — |
| RN-02 | Open | **Still open** | Dead code still present |
| RN-03 | Open (10 sites) | **Confirmed 10 sites** | No change |
| RN-04 | Open | **Confirmed** | Killswitch after backend.start() |
| RN-05 | Open | **Confirmed** | Non-node selectors bypass revocation |
| RN-06 | Open | **FIXED** | Scoped egress allows replace unscoped LAN allow (phase10.rs:3096-3142) |
| RN-07 | Open (G8 in progress) | **Partially fixed** | IPv6 block rule exists; still uses netsh not WFP |
| RN-11 | Open | **Confirmed** | Empty membership = skip gate (phase10.rs:5366) |
| RN-14 | Fixed (RL-2) | Fixed | — |
| RN-15 | Fixed (RL-8) | Fixed | — |

---

## 5. Items from HardeningBacklog (not in SecurityReview)

| ID | Severity | Location | Fix |
|---|---|---|---|
| HB-1 | Low | `windows_tunnel_smoke.rs` | Use `remove_file_if_present` (secure scrub) |
| HB-2 | Low | `key_material.rs:739` | Windows: set explicit owner-only ACL |
| HB-3 | Low | `windows_killswitch_smoke.rs` | Use absolute `%SystemRoot%\System32\netsh.exe` |
| HB-4 | Low | `windows_killswitch_smoke.rs` Drop guard | Add IPv6 block cleanup on panic |
| HB-5 | Info | `windows_killswitch_smoke.rs` | Document hardcoded Cloudflare IPv6 dependency |
| HB-6 | Info | `crates/rustynet-cli/src/vm_lab/**` | Centralize PS-script assembly behind builder |
| B.4.1 | Medium | DNS zone parser | Complete resolver-output filter when DNS handler lands |

---

## 6. Attack Surface — Fuzz Coverage Gaps

These network-facing parsers process untrusted input but lack `cargo-fuzz` targets:

| Parser | Crate | Has Fuzz? |
|---|---|---|
| Membership decoder | `rustynet-control` | ✅ |
| Relay hello | `rustynet-relay` | ❌ RN-N6 |
| Relay session token | `rustynet-relay` | ❌ RN-N6 |
| Gossip bundle | `rustynetd` | ❌ |
| STUN response | `rustynetd` | ❌ |
| PCP MAP | `rustynetd` | ❌ |
| UPnP device desc | `rustynetd` | ❌ |
| DNS zone | `rustynet-dns-zone` | ❌ |

**Recommendation:** Add `cargo-fuzz` targets for all 6 missing parsers. Run 1hr/commit in CI.

---

## 7. Cross-Reference

- `documents/operations/active/SecurityReview_2026-05-24.md` — 38 findings, 8 fixed
- `documents/operations/active/SecurityHardeningAudit_2026-04-28.md` — Phase A+B
- `documents/operations/active/SecurityHardeningBacklog_2026-06-01.md` — HB-1..7
- `documents/SecurityMinimumBar.md` — Release-blocking controls
- `AGENTS.md` §3-4, §10 — Engineering constraints
