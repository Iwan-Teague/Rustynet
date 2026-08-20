# Rustynet Security Analysis — Verified & Patched

**Date:** 2026-06-12 · **Commit:** `4fbd5f1` originally, reconciled against current `129cf4d69fb2` + working-tree fixes · **Status:** Current findings below were re-checked against live code; stale/false items were removed or narrowed. Working-tree P0 fixes now close RN-03, RN-04, RN-05, and RN-11; RN-02 remains open as cleanup/dead-code risk.

> **Staleness note — 2026-07-27** (added by an adversarial re-review of the security-claims
> cluster; original text above and below left intact). This document's status line and several
> findings describe a tree that has since moved. Verified in committed code on 2026-07-27:
> - **"Working-tree P0 fixes"** (RN-03/04/05/11) are long since committed and were
>   independently re-verified by the 2026-06-18 audit ledger (Batch 2 positive controls,
>   `SecurityAuditLedger_2026-06-18.md:1036-1041`). Read "Fixed in working tree" below as
>   "fixed, committed".
> - **RN-02 is resolved in code, not open.** `crates/rustynetd/src/dataplane.rs` no longer
>   exists — deleted 2026-06-26 in `a39a70aa` ("security: retire dead dataplane.rs, point
>   phase-4 assurance at the live path (RN-02)"); no `LinuxDataplane` type remains (only
>   `LinuxDataplaneMode` in `phase10.rs`). §1.5's "**Verified:** … is referenced only in its
>   own `#[cfg(test)]` block" and §4's "RN-02 | **Still open** | Dead code still present" are
>   both stale statements of current fact. **Residual (code, not corrected here):**
>   `crates/rustynet-cli/src/security_audit_catalog.rs:279` still lists the deleted
>   `crates/rustynetd/src/dataplane.rs` in the `server_ip_bypass` spec's `affected_files`,
>   even though the same file's `:415` comment records the removal — an ops-report catalog
>   citing a nonexistent enforcement point (the RSA-0049 assurance-over-claim class).
> - **RN-N7 (§7, CIDR validation character-set-only) is fixed.** `validate_cidr` now does a
>   structural parse — `crates/rustynetd/src/ipc.rs:272-292` (split on `/`, `IpAddr::parse`,
>   family-appropriate prefix bound); tracked as ledger RSA-0027, applied 2026-06-24.
> - **RN-08 (§2.2) remains real**: the ambiguous v0/v1 envelope detection is still present at
>   `crates/rustynet-crypto/src/lib.rs:1605-1607` (`bytes.len() >= 45 && bytes[0] != 0`). Note
>   the disposition conflict a reader must reconcile: this document says "do not close yet /
>   **Required follow-up**", while `SecurityRemediationPlan_2026-06-19.md` Wave P2 records the
>   same finding (RSA-0001) as **DEFERRED 2026-06-24** with an on-disk-migration rationale.
>   One of the two needs to become the record; that is an owner call.
> - The §6 fuzz-coverage table is still accurate: `fuzz/fuzz_targets/` contains exactly
>   `ipc_parse_command.rs`, `membership_decode_state.rs`, `membership_decode_signed_update.rs`
>   — the relay/gossip/STUN/PCP/uPnP/dns-zone gaps (RN-N6 class) are unchanged.

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

**Status:** Fixed in working tree.

**Fix:** daemon call sites now route through `DaemonRuntime::force_fail_closed_or_restrict`. If `force_fail_closed` fails, the daemon records a **permanent restriction** (the enforcement error is surfaced, never discarded) and **leaves the existing killswitch drop baseline in place** so egress stays blocked (fail CLOSED). It deliberately does NOT call `controller.shutdown()` on this path: shutdown rolls the firewall back (deletes the nft killswitch table / flushes the pf anchor), which would let traffic fall back to the open physical NIC — a fail-OPEN. (A shutdown "backstop" was present in an earlier draft of this fix and removed after review confirmed it re-introduced the very leak RN-03 closes.)

**Verification:** `daemon::tests::daemon_does_not_discard_force_fail_closed_results`; `cargo test -p rustynetd daemon --lib`.

---

### 1.2 RN-04 — Killswitch programmed AFTER tunnel interface comes up

**Status:** Fixed in working tree.

**Fix:** `Phase10Controller::apply_dataplane_generation` applies the firewall killswitch before `backend.start()` and before route mutation. If pre-start killswitch application fails, the controller calls `force_fail_closed("killswitch_pre_start_failed")` and returns the original system error only after fail-closed enforcement succeeds.

**Verification:** `phase10::tests::full_tunnel_route_dns_apply_order_keeps_exit_commit_last`, `phase10::tests::killswitch_apply_failure_fails_closed_before_exit_mode`; `cargo test -p rustynetd phase10::tests --lib`.

---

### 1.3 RN-05 — Policy revocation bypass for non-`node:` selectors

**Status:** Fixed in working tree.

**Fix:** `MembershipDirectory` now carries explicit selector-member mappings for `user:`, `group:`, and `tag:` selectors. Unresolved membership selectors fail closed; mapped selectors require every mapped node to be active. Literal route destinations such as CIDRs are not treated as membership selectors. Daemon membership conversion maps `user:local` to the signed local node only.

**Verification:** `rustynet-policy` tests `non_node_selectors_require_membership_resolution` and `literal_route_destinations_do_not_require_membership_resolution`; daemon auto-tunnel tests pass after wiring signed membership into the controller.

---

### 1.4 RN-11 — Empty membership directory = allow-all

**Status:** Fixed in working tree.

**Fix:** `check_peer_membership_active` no longer treats an empty membership directory as governance-disabled. A peer must be positively present and `Active`. Daemon now pushes the signed membership directory into `Phase10Controller` before bootstrap and reconcile applies.

**Verification:** `phase10::tests::test_empty_membership_directory_denies_peer_provisioning`; `cargo test -p rustynetd phase10::tests --lib`.

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
**Status:** Partially fixed in `cc5ca96`; do not close yet.

**Current issue to fix:** `rustynet-crypto/src/lib.rs:1601` auto-detects v1 blobs with `bytes.len() >= 45 && bytes[0] != 0`. Legacy v0 blobs start with the random salt, so about 255/256 existing v0 key files will have a nonzero first byte and will be misclassified as v1. That makes most legacy encrypted keys fail to decrypt after upgrade.

**Required follow-up:** Change the envelope framing/detection so v0 legacy blobs always decode correctly and v1 blobs remain AAD-bound. Add a regression test that manually builds an old v0 `[salt][nonce][len][ciphertext]` blob and proves `read_encrypted_key_file`/`decrypt_private_key_envelope` can still decrypt it. Also add negative tests that v1 rejects tampered version/AAD framing.

**Original issue:** `rustynet-crypto/src/lib.rs` used empty AAD in XChaCha20-Poly1305. The fix direction remains binding the envelope to a versioned Rustynet framing, but backward-compatible decoding must be correct.

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
| RN-03 | Open | **Fixed in working tree** | Daemon no longer discards fail-close Results; regression test added |
| RN-04 | Open | **Fixed in working tree** | Killswitch now applies before backend start and fail-closes on pre-start failure |
| RN-05 | Open | **Fixed in working tree** | Non-node membership selectors require explicit active member resolution |
| RN-06 | Open | **FIXED** | Scoped egress allows replace unscoped LAN allow (phase10.rs:3096-3142) |
| RN-07 | Open (G8 in progress) | **Partially fixed** | IPv6 block rule exists; still uses netsh not WFP |
| RN-11 | Open | **Fixed in working tree** | Empty membership now denies peer provisioning |
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
| Service exposure | Tunnel-only bind enforced; default-deny via `evaluate_with_membership`; session severance on policy change; audit events with thumbprints only | ✅ ⚠ **partly unenforced — see 2026-07-27 note below** |
| Gossip deserialization | `checked_add`/`checked_mul` on all offsets; `MAX_CANDIDATES_PER_BUNDLE=32`; `WireTruncated`/`WireMalformed` errors; version gate | ✅ |
| Windows named pipes | `PIPE_REJECT_REMOTE_CLIENTS` at kernel level; SDDL ACL with forbidden principals list; 16KB message cap | ✅ |
| macOS utun helper | Unsafe isolated in one file; bounded buffers; MSG_CTRUNC detection; truncated cmsg test coverage | ✅ |
| DNS zone parser | 256KB bundle cap; 16K line cap; 4KB line cap; 128B key cap; 1.5KB value cap; 1024 record cap; 8 alias cap | ✅ |
| UPnP HTTP client | 256KB body cap with +1 byte overflow detection; control-char sanitization on gateway-supplied strings; 4-device SSDP cap | ✅ |
| STUN parser | 1024B buffer; attribute boundary check; 4-byte alignment; transaction ID match | ✅ |
| Unsafe code | Zero `unsafe` in `rustynetd/src/` outside `macos_utun_helper_unsafe.rs`; `#![forbid(unsafe_code)]` on all other files | ✅ ⚠ **first half holds; the `forbid` mechanism claim does not — see 2026-07-27 note below** |

### Corrections to the Positive-Controls table — 2026-07-27

Added by an adversarial re-review of the security-claims document cluster. The rows above are
left as written (they are the dated record of what this pass asserted); the corrections below
state what was verified in code on 2026-07-27. No ✅ is removed and no finding status is
changed — those are owner decisions.

- **"Service exposure — Tunnel-only bind enforced … session severance on policy change ✅"
  overstates two of its four sub-claims.** What is real: the **default-deny** path is wired
  end-to-end — `crates/rustynetd/src/daemon.rs:4512-4560`
  (`materialize_service_access_state`, called from bootstrap/reconcile/membership-apply at
  `:4938`, `:7536`, `:8489`, `:9051`) derives grants via
  `crates/rustynetd/src/service_access_state.rs:38` (`evaluate_service_access`), fails closed
  to `force_deny_all` on a write error, and the sibling binaries deny when the files are
  absent (`crates/rustynet-nas/src/main.rs:279-292` `admitted_peer`). What is **not**
  enforced: the *authoritative* tunnel-only bind check and session severance are dead code —
  `validate_tunnel_only_bind` / `validate_loopback_only_bind` have **zero callers** anywhere
  in `crates/` (the only two mentions are doc comments at
  `crates/rustynetd/src/linux_runtime_nftables.rs:432` and
  `crates/rustynet-nas/src/main.rs:182`), and `ServiceExposureController` (which owns E3
  teardown-before-revoke / `capability_release_ready`) is never constructed by the daemon.
  The nas/llm binaries do only a **bind-shape** startup check
  (`crates/rustynet-nas/src/main.rs:167,184-195` — rejects unspecified/loopback/multicast),
  whose own comment says the authoritative check "lives in the daemon". This matches ledger
  finding **RSA-0024** (`SecurityAuditLedger_2026-06-18.md:1093-1102`), which is still
  `open`; this ✅ row therefore contradicts the ledger on the more widely-read artifact.
  Honest wording: *"per-peer default-deny is enforced (daemon-materialised grants +
  deny-on-missing in the service binaries); tunnel-only bind is a shape-only check in the
  service binary — the authoritative signed-state bind validation and E3 session severance
  are implemented and unit-tested but unwired (RSA-0024)."*
- **"Unsafe code … `#![forbid(unsafe_code)]` on all other files"** — the *property* holds
  (no `unsafe` block or `unsafe fn` exists in `crates/rustynetd/src/` outside
  `macos_utun_helper_unsafe.rs`), but the *mechanism* named does not: the crate root uses
  `#![deny(unsafe_code)]` (`crates/rustynetd/src/lib.rs:1`) with an explicit
  `#[allow(unsafe_code)]` on the exception module (`:56`); only 29 of the 86 files in
  `crates/rustynetd/src/` carry any `forbid(unsafe_code)`. The distinction is load-bearing for
  a reader relying on this row: `forbid` cannot be overridden downstream, `deny` can — line 56
  is itself the proof. Honest wording: *"crate-level `#![deny(unsafe_code)]` with one
  documented module-level `#[allow]` (`macos_utun_helper_unsafe.rs`); no other `unsafe` in the
  crate."*

---

## 8. Cross-Reference

- `documents/operations/active/SecurityReview_2026-05-24.md` — 38 findings, 8 fixed
- `documents/operations/active/SecurityHardeningAudit_2026-04-28.md` — Phase A+B
- `documents/operations/active/SecurityHardeningBacklog_2026-06-01.md` — HB-1..7
- `documents/SecurityMinimumBar.md` — Release-blocking controls
- `AGENTS.md` §3-4, §10 — Engineering constraints
