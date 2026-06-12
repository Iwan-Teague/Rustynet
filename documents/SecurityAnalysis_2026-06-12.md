# Rustynet Security Analysis — Verified & Patched

**Date:** 2026-06-12 · **Commit:** `4fbd5f1` originally, reconciled against current `129cf4d69fb2` + working-tree fixes · **Status:** Current findings below were re-checked against live code; stale/false items were removed or narrowed.

---

## 0. Methodology

Each finding below was verified by reading the actual source code at the cited location. Findings that could not be confirmed were removed. Severity reflects both exploitability and blast radius.

**Important:** Fix directions in this document are suggestions — sketches of one possible approach, not prescriptive mandates. The implementer should research the best solution for each finding using their knowledge of the codebase, the project's architecture, and the relevant RFCs. Do not blindly copy the suggested code.

**Sources cross-referenced:**
- `SecurityReview_2026-05-24.md` — 38 findings (8 fixed, 30 open)
- `SecurityHardeningAudit_2026-04-28.md` — Phase A+B (most cleared)
- `SecurityHardeningBacklog_2026-06-01.md` — HB-1..7 + re-verified P0s

---

## 1. P0 — Fix Immediately (fail-open / leak / DoS)

### 1.1 RN-03 — `force_fail_closed` Results are discarded across daemon paths

**Verified:** `rg 'force_fail_closed\(' crates/rustynetd/src/daemon.rs` shows 40 daemon call sites. The previous "10 sites" count only matched single-line `let _ = ...force_fail_closed(...)` forms and missed multiline discarded Results.

`force_fail_closed` → `block_all_egress()` → programs `policy drop` killswitch. If this fails (nft unavailable, helper down, transaction race), many daemon paths do not propagate the error. Worst case: first bootstrap, no prior killswitch table exists → daemon proceeds as if protected → host egresses cleartext.

**Suggested approach** (the implementer should research the best solution):
- At minimum, never discard the Result without error-level logging
- On the bootstrap path (no prior generation table), aborting lets systemd's mandatory boot killswitch backstop
- On the steady-state path (prior generation table exists), the existing policy drop still protects, so a retry-with-backoff may be appropriate
- The implementer should evaluate whether `abort()`, retry, or a different escalation fits the project's fail-closed contract

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

**Suggested approach** (the implementer should research the best solution):
- Reorder so the killswitch is programmed before the interface comes up (may need carve-outs for bootstrap traffic like STUN and control-plane fetch)
- Consider making the boot killswitch mandatory in the shipped unit, not opt-in
- The existing verifier that checks for boot killswitch table presence could gate `backend.start()`

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

**Suggested approach** (the implementer should research the best solution):
- The core issue: non-`node:` selectors skip the membership revocation check. The fix needs to map group/tag/user selectors to their member node set, then check each member's status
- If group resolution data isn't available yet, the fail-closed default is to deny unresolvable selectors. This breaks rules using group selectors but closes the revocation bypass immediately
- The implementer should decide whether to build the resolution layer first or take the simpler deny-by-default path as an interim step

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

**Suggested approach** (the implementer should research the best solution):
- Distinguish an explicit operator opt-out (`--membership-governance=disabled`) from genuinely unpopulated or unloadable state
- Default to denying when membership is empty
- Fail closed if a snapshot path was configured but failed to load

---

### 1.5 RN-02 — Dead `dataplane.rs` module

**Verified:** `LinuxDataplane` in `crates/rustynetd/src/dataplane.rs` is referenced only in its own `#[cfg(test)]` block and one string in `security_audit_catalog.rs`. No production code constructs it. The live dataplane is `phase10.rs`.

**Suggested approach:** Either delete `dataplane.rs` and point the security-audit catalog at `phase10.rs`, or wire the daemon through `dataplane.rs`. The implementer should evaluate which path keeps the project's security guarantees intact with the least risk of introducing divergence.

---

## 2. P1 — Fix Soon (integrity / defense-in-depth)

### 2.1 RN-N1 — Production `expect()` panic (daemon crash → tunnel drop)
**Location:** `daemon.rs:5908`
```rust
let mut relay_client = self.relay_client.take()
    .expect("relay client should remain available during establish");
```
If this path executes twice (concurrent traversal probe + relay health check), the second `take()` returns `None` → panic → daemon crash → tunnel drops.

**Suggested approach:** Replace with proper error propagation (`.ok_or_else(|| ...)?`). The implementer should verify that the error type and handling path are appropriate for this call site.

### 2.2 RN-08 — Key envelope lacks AAD binding
**Location:** `rustynet-crypto/src/lib.rs:942` — empty AAD in XChaCha20-Poly1305.
**Suggested approach:** Bind `MAGIC || version || salt || nonce` as AAD. The implementer should choose the exact framing format and add a version byte for future algorithm agility.

### 2.3 RN-09 — systemd-credential passphrase group-readable
**Location:** `key_material.rs:674` — wider permission mask on `/run/credentials/` prefix.
**Suggested approach:** Require stricter parent-directory ownership and group checks before honoring the wider mask. Verify the filesystem is actually a systemd-managed tmpfs mount.

### 2.4 RN-10 — Corrupt rotation ledger returns `genesis()` after logging
**Location:** `daemon.rs:8601` — `load_rotation_ledger` logs on load error but still returns `genesis()`, so callers cannot distinguish "ledger absent on first run" from "ledger corrupt/unparseable."
**Suggested approach:** Distinguish absent (genesis is correct) from corrupt/unparseable (refuse to proceed). The implementer should also add a clear operator runbook entry for recovery from a genuinely corrupt ledger.

### 2.5 RN-16 — GitHub Actions pinned to mutable tags
**Location:** `.github/workflows/cross-platform-ci.yml`, `release-windows.yml`.
**Suggested approach:** Pin every `uses:` to a full 40-char commit SHA. The implementer should verify each SHA against the upstream repository and add a CI check that prevents unpinned actions from being merged.

---

## 3. P2 — Defense-in-Depth (new findings)

### 3.1 RN-N4 — Gossip has no per-peer inbound rate limiting
**Location:** `gossip_runtime.rs` / `peer_gossip.rs` — inbound gossip has freshness, known-peer, signature, and monotonic-sequence checks, but no token-bucket or budget per authenticated source. A rogue authenticated peer flooding forged/stale bundles can consume CPU with repeated Ed25519 verification.
**Suggested approach:** Token-bucket per source node (e.g. 10 bundles/sec). Drop above-limit bundles before signature verification. The implementer should tune the rate based on expected cluster size and gossip propagation latency requirements.

### 3.2 RN-N6 — No fuzz targets for relay hello parser
**Location:** `crates/rustynet-relay/src/main.rs:669` (`parse_relay_hello` / `parse_relay_token`) and `crates/rustynet-relay/src/transport.rs` (hello validation state machine). Relay hello handling has strong unit tests and pre-signature rate limiting, but no `cargo-fuzz` target for hostile wire bytes.
**Suggested approach:** Add `cargo-fuzz` targets for `parse_relay_hello`, `parse_relay_token`, and the `RelayTransport` hello validation state machine. The implementer should also consider adding fuzz targets for the other parsers listed in §6.

---

## 4. Status Changes from SecurityReview

| Finding | SecurityReview | Verified Status | Change |
|---|---|---|---|
| RN-01 | Fixed (RL-1) | Fixed | — |
| RN-02 | Open | **Still open** | Dead code still present |
| RN-03 | Open | **Confirmed broader than prior single-line count** | Current daemon has 40 `force_fail_closed()` call sites; many discarded |
| RN-04 | Open | **Confirmed** | Killswitch after backend.start() |
| RN-05 | Open | **Confirmed** | Non-node selectors bypass revocation |
| RN-06 | Open | **FIXED** | Scoped egress allows replace unscoped LAN allow (phase10.rs:3096-3142) |
| RN-07 | Open (G8 in progress) | **Partially fixed** | IPv6 block rule exists; still uses netsh not WFP |
| RN-11 | Open | **Confirmed** | Empty membership = skip gate (phase10.rs:5366) |
| RN-14 | Fixed (RL-2) | Fixed | — |
| RN-15 | Fixed (RL-8) | Fixed | — |

---

## 5. Items from HardeningBacklog (not in SecurityReview)

| ID | Severity | Location | Direction to investigate |
|---|---|---|---|
| HB-1 | Low | `windows_tunnel_smoke.rs` | Use secure scrub (`remove_file_if_present`) instead of plain `remove_file` for ephemeral key cleanup |
| HB-2 | Low | `rustynet-crypto/src/lib.rs:1573` | Narrowed: daemon DPAPI passphrase paths now validate Windows ACLs, but the generic encrypted-file fallback permission check still no-ops on non-Unix |
| HB-3 | Low | `windows_killswitch_smoke.rs` | Use absolute `%SystemRoot%\System32\netsh.exe` instead of PATH-resolved `netsh` |
| HB-4 | Low | `windows_killswitch_smoke.rs` Drop guard | Add IPv6 block rule cleanup in the Drop guard for panic safety |
| HB-5 | Info | `windows_killswitch_smoke.rs` | Document the hardcoded Cloudflare IPv6 dependency; prefer a lab-local target when available |
| HB-6 | Info | `crates/rustynet-cli/src/vm_lab/**` | Centralize PowerShell script assembly behind a builder with quote-by-construction to reduce `format!` surface |
| B.4.1 | Medium | DNS zone parser | Complete the resolver-output filter when the DNS protocol handler lands (reject RFC1918 answers for tailnet-internal names) |

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

**Recommendation:** Add `cargo-fuzz` targets for the missing hostile-input parsers. Run 1hr/commit in CI.

---

## 7. Additional Findings from Deep Scan (2026-06-12)

### RN-N7 — CIDR validation is character-set-only, not structural
**Location:** `ipc.rs:272-282` — `validate_cidr` checks only hex-digit/dot/colon/slash characters and length (3-43). It does not parse the CIDR to verify it represents a valid network prefix (e.g. `999.999.999.999/33` passes).
**Severity:** Low — the OS networking stack rejects structurally invalid CIDRs downstream. The pre-filter reduces garbage input but is not a security gate.
**Suggested approach:** Parse with `IpNet` or `ipnet` crate to validate structure at input boundary. Reject before any privileged operation uses the value.

### RN-N8 — `SeenSequenceState` (gossip replay ledger) grows unbounded per source
**Location:** `peer_gossip.rs:213` — `HashMap<[u8; 32], u64>` with no eviction. Each new peer adds a permanent entry.
**Severity:** Low — the map is bounded by the number of peers in the mesh (typically <100). An attacker who can inject arbitrary source IDs into the gossip path could grow the map, but the source must pass Ed25519 signature verification under a known verifying key first, which gates this to authenticated peers only.
**Suggested approach:** Add an LRU eviction policy or a maximum entry count. Document the operational bound.

### Positive Controls Verified This Pass

These were checked during the deep scan and confirmed as correctly implemented:

| Area | Control | Status |
|---|---|---|
| Env-var binary paths | All `RUSTYNET_*_BINARY_PATH` overrides go through `validate_binary_path` (absolute, canonicalize, regular-file, executable, non-group-writable, root-owned) | ✅ |
| Relay hello handler | 12-step ordered security check (rate-limit → signature → TTL → freshness → replay → ct_eq bindings → scope → capacity) | ✅ |
| Enrollment tokens | HMAC is recomputed and compared with `ct_eq` before expiry, future-issued, or replay checks in both consume and inspect paths | ✅ |
| Key material | `symlink_metadata()` BEFORE every I/O op; `create_new(true)` for atomic writes; `fs::rename()` for commit; symlink rejection on all paths | ✅ |
| Service exposure | Tunnel-only bind enforced; default-deny via `evaluate_with_membership`; session severance on policy change; audit events with thumbprints only | ✅ |
| Gossip deserialization | `checked_add`/`checked_mul` on all offsets; `MAX_CANDIDATES_PER_BUNDLE=32`; `WireTruncated`/`WireMalformed` errors; version gate | ✅ |
| Windows named pipes | `PIPE_REJECT_REMOTE_CLIENTS` at kernel level; SDDL ACL with forbidden principals list; 16KB message cap | ✅ |
| macOS utun helper | Unsafe isolated in one file; bounded buffers; MSG_CTRUNC detection; truncated cmsg test coverage | ✅ |
| DNS zone parser | 256KB bundle cap; 16K line cap; 4KB line cap; 128B key cap; 1.5KB value cap; 1024 record cap; 8 alias cap | ✅ |
| UPnP HTTP client | 256KB body cap with +1 byte overflow detection; control-char sanitization on gateway-supplied strings; 4-device SSDP cap | ✅ |
| STUN parser | 1024B buffer; attribute boundary check; 4-byte alignment; transaction ID match | ✅ |
| Unsafe code | Zero `unsafe` in `rustynetd/src/` outside `macos_utun_helper_unsafe.rs`; `#![forbid(unsafe_code)]` on all other files | ✅ |

---

## 8. Cross-Reference

- `documents/operations/active/SecurityReview_2026-05-24.md` — 38 findings, 8 fixed
- `documents/operations/active/SecurityHardeningAudit_2026-04-28.md` — Phase A+B
- `documents/operations/active/SecurityHardeningBacklog_2026-06-01.md` — HB-1..7
- `documents/SecurityMinimumBar.md` — Release-blocking controls
- `AGENTS.md` §3-4, §10 — Engineering constraints
