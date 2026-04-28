# Security Hardening Audit (2026-04-28)

Date: 2026-04-28
Status: in progress (W3-window pass complete; post-W4 deep audit pending)

## 0) Scope and Purpose

This document captures the security-focused audit work the user
authorised on top of the OS-Agnostic Orchestrator + Windows-Peer
delta plan (2026-04-27). The work is in two phases:

- **Phase A — pre-W4 quick-wins window** (this commit and earlier):
  fix anything found that is (a) cheap to land, (b) genuinely
  fail-closed in posture, and (c) doesn't risk regressing existing
  validators. Don't open large new abstractions in this phase.
- **Phase B — post-W4 deep audit** (TODO, scheduled after the W4
  capability-gating + Windows-mesh-join slice lands): compare
  Rustynet's posture to Tailscale, WireGuard, and other reviewed
  mesh-VPN projects' published security guidance and import the
  practices that translate.

This file is intentionally a *running ledger*: each finding gets a
dated entry with severity, file:line, and either an "applied" commit
SHA or a "deferred — tracked under" pointer.

## 1) Source-Of-Truth Cross-References

- `documents/Requirements.md`
- `documents/SecurityMinimumBar.md`
- `documents/operations/active/OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md`
- `documents/operations/active/SecurityHardeningBacklog_2026-03-09.md`
  (older long-running backlog — this audit is *not* a replacement,
  it complements that doc with the W3/W4-window pass)

## 2) Phase A — Pre-W4 Quick-Wins Window

### A.1 Tooling Gates

| Tool | Result | Date | Notes |
|---|---|---|---|
| `cargo audit` | **0 vulnerabilities** | 2026-04-28 | 1058 advisories scanned, 182 deps. |
| `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok | 2026-04-28 | All four categories pass. |
| `cargo clippy --workspace --all-features -- -D warnings` | clean (production code) | 2026-04-28 | Closes the long-standing W1.1 / W2.x residual-risk note. `--all-targets` still trips on third_party/boringtun's vendored test code which we deliberately do not fork. |
| `#![forbid(unsafe_code)]` enforcement | clean | 2026-04-28 | Every reviewed daemon module carries the lint, plus repo ships a `check_no_unsafe_code` enforcement bin and `ops_phase1.rs` unsafe-keyword scanner. |

### A.2 Findings + Resolutions

#### A.2.1 [HIGH] DoS panic on signed-bundle freshness when host clock < UNIX_EPOCH

**Where:** [crates/rustynetd/src/fetcher.rs:179](../../crates/rustynetd/src/fetcher.rs:179) (now line 184 post-fix), `SignedBundleFetcher::check_freshness`.

**Risk:** Every signed-bundle fetch (assignment, traversal, auto-tunnel,
DNS-zone) called `SystemTime::now().duration_since(UNIX_EPOCH).unwrap()`.
On a host with a clock rolled back before 1970-01-01 (BIOS clock
corruption, adversarial NTP injection, malicious VM clock skew), the
unwrap panicked. A daemon panic in this code path tears down the
enforced WireGuard tunnel + the fail-closed DNS / firewall posture,
even though the freshness check itself is meant to be a fail-closed
gate. The right fail-closed posture is to *refuse the bundle* and
keep the rest of the daemon's enforcement live.

**Resolution:** Replaced the unwrap with a `map_err` that propagates
a stale-bundle error reason citing the clock-pre-EPOCH state, so the
existing freshness-rejection path handles it without daemon
termination.

**Evidence:** Commit `de4c7ba` ("Fix DoS panic on signed-bundle
freshness when host clock < UNIX_EPOCH"); tests `cargo test -p
rustynetd --lib fetcher` 11/11 pass post-fix.

---

#### A.2.2 [INFRA] Workspace clippy gate previously failed on baseline

**Where:** ~80 call sites in
- `crates/rustynet-cli/src/bin/live_linux_role_switch_matrix_test.rs`
- `crates/rustynet-cli/src/ops_e2e.rs`
- `crates/rustynet-cli/src/ops_security_audit_workflows.rs`
- `crates/rustynet-cli/src/vm_lab/bootstrap/windows.rs`
- `crates/rustynet-cli/src/vm_lab/mod.rs`

**Risk:** Not a vulnerability per se, but the workspace clippy gate
mandated by CLAUDE.md §7 was failing on baseline `clippy::uninlined_format_args`
drift. Each W slice (W1.1 / W1.2b / W2.x / W3.x) has been carrying
this as a residual-risk note. A failing gate erodes the security-bar
contract over time — defenders need every gate they declare to
actually hold.

**Resolution:** Mechanical 1-line `format!("{} ...", var)` →
`format!("{var} ...")` conversions across the affected files,
applied via `cargo clippy --fix --tests -p rustynet-cli` so there is
zero behavior change. Plus visibility fix on `pub enum
VmGuestPlatform` so RustOrchestrator's public API isn't "more
public than the type". third_party/boringtun was NOT modified —
it's a vendored upstream BSD-3 crate and forking it for clippy
would break upstream sync.

**Evidence:** Commit `2e71184` ("Clean up workspace
clippy::uninlined_format_args drift in rustynet-cli"); workspace
`cargo clippy --workspace --all-features -- -D warnings` now clean.

---

### A.3 Findings explicitly cleared (no fix needed)

#### A.3.1 Path traversal / symlink follow

**Result:** No path-traversal concerns found in scope. The repo has
mature path safety discipline — `validate_windows_runtime_file_path`,
`validate_windows_secret_blob_path`, `validate_secret_file_security`
all enforce: reject `..`, reject absolute escapes from reviewed
roots, whitelist reviewed roots, enforce expected extensions. All
`symlink_metadata()` calls happen *before* the corresponding I/O
operation (no TOCTOU windows). The `privileged_helper.rs` socket
path is explicitly rejected if it resolves to a symlink. The
`windows_runtime_boundary.rs` write paths check `symlink_metadata()`
before the write. **Cleared 2026-04-28.**

#### A.3.2 Secret material in logs / error messages

**Result:** No secret-leakage concerns found in scope.
- `SecretKey` (`rustynet-crypto/lib.rs:53`) has a custom `Debug`
  impl that redacts as `"SecretKey(REDACTED)"`.
- `Ed25519SigningProvider` (`rustynet-crypto/lib.rs:702`) custom
  `Debug` redacts the signing key, exposes only the public
  `verifying_key` (safe).
- `NodeKeyPair` derives `Debug` but its `SecretKey` field
  redacts via the impl above.
- `Zeroizing<String>` passphrases (`rustynetd/key_material.rs:60`,
  `:76`, `:130`) are never interpolated into error messages; error
  strings reference operation failure (I/O, decryption status), not
  contents.
- WireGuard private-key decrypt failures (`daemon.rs:7687`)
  propagate from custody manager without exposing key bytes.
- All `eprintln!` / `log::*!` call sites grep clean for
  secret-bearing identifiers. **Cleared 2026-04-28.**

#### A.3.3 Constant-time comparison of secrets

**Result:** Reviewed paths use `subtle::ConstantTimeEq`:
- `rustynet-relay/src/transport.rs` uses `ct_eq` on `node_id`,
  `peer_node_id`, `relay_id` per documented contract (lines 205,
  216, 224). Module header comment (lines 13-30) explicitly
  documents the policy.
- The one non-`ct_eq` byte-by-byte compare in
  `rustynet-crypto/src/lib.rs:135-137` (`is_all_zeros`) checks a
  freshly OS-RNG-generated key against the all-zeros vector during
  keygen weak-material rejection. Attacker cannot influence OsRng
  output; the timing leak is purely theoretical (would require
  the attacker to bias OsRng output, which they can't). Keeping
  the short-circuit `.iter().all(...)` avoids a tiny dependency
  surface for negligible benefit. **Cleared 2026-04-28** with
  rationale recorded.

#### A.3.4 `unsafe` blocks audit

**Result:** Every reviewed daemon source carries
`#![forbid(unsafe_code)]` at the top. The only legitimate `unsafe`
blocks are in `crates/rustynet-windows-native/src/lib.rs` for Win32
FFI calls (`GetFileSecurityW`, `GetLastError`, etc.) — unavoidable
because Win32 APIs require unsafe for FFI. Each block is small,
focused on a single Win32 call, with bounds-checked arguments. The
repo also ships `crates/rustynet-cli/src/bin/check_no_unsafe_code.rs`
+ `ops_phase1.rs` scanner that fails CI if `unsafe` keyword usage
is reintroduced into reviewed Rust sources (line 1255: "unsafe
keyword usage is forbidden in repository Rust sources"). **Cleared
2026-04-28.**

#### A.3.5 Unwrap / expect on attacker-reachable paths

**Result:** Audited via parallel agent. `fetcher.rs:179` was the
one genuine concern (now fixed — A.2.1 above). All other
reviewed `.unwrap()` / `.expect()` call sites either operate on
infallible-by-construction values (literal parses, `Vec::with_capacity`,
etc.) or are preceded by Result-propagating `?` validation. Areas
verified clean: privileged helper IPC bounds checking, DNS zone
parsing exhaustive validation, membership state Result-based
deserialization, Windows IPC serde_json size limits, STUN protocol
manual bounds checks, config parsing Result-based, backend-wireguard
test-only fixtures. **Cleared 2026-04-28.**

## 3) Phase B — Post-W4 Deep Audit (TODO)

After W4 lands the per-stage capability gating + Windows mesh-join,
extend this document with:

- **Tailscale comparison**: Tailscale's published security model
  (DERP relay handshake replay protection, magic-DNS poisoning
  resistance, MagicDNS rebind protection, MITM scenarios for
  bootstrap, key-rotation cadence) — translate the relevant
  practices to Rustynet's relay + DNS zone code.
- **WireGuard comparison**: WireGuard whitepaper + audited
  implementations' practices around handshake replay windows,
  key rotation, formal proof obligations for handshake state
  machines.
- **OPENVPN / OpenWRT-WireGuard / Nebula** secondary references
  for things like rate-limit windows, bootstrap-safety, traversal
  trust policy.
- **Windows-specific** hardening recommendations from
  Microsoft's published service hardening guidance (least-privilege
  service SIDs, mandatory-integrity DACLs, AppContainer where
  applicable). Rustynet already runs the service under
  `unrestricted` SID type with the install-helper's W2.2-grade
  lock-down; the deep audit should look at whether tighter
  options (`-restricted`, `-virtual`) are usable.

Each finding gets the same shape as Phase A: file:line, severity,
risk description, remediation, evidence (commit SHA or "deferred —
tracked under …"). Findings that are *not* applied this session
are tracked here as future work, not as TODOs in source.

## 4) Agent Update Rules

Same rules as the OS-agnostic delta plan:
1. Update this document immediately after each materially
   completed slice; do not maintain a private checklist.
2. Mark completion conservatively. `[x]` only after code +
   verification.
3. Record evidence under the touched section. Minimum fields:
   commit SHA, verification command, file:line of change.
4. Do not delete historical context that still matters; correct
   stale claims in place.
5. Findings that remain unfixed must point to the tracker
   (typically the OS-agnostic delta plan's W-series) so they
   are not orphaned.
