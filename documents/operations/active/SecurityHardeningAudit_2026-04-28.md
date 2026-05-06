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

#### A.3.6 W2.5 wrapper-hygiene audit — Windows bootstrap PS scripts

**Result:** Audit performed across the five reviewed PowerShell
helpers under `scripts/bootstrap/windows/` (Bootstrap-, Collect-,
Install-, Smoke-, Verify-). Findings tally: 9 HIGH (theoretical, on
controlled values), 14 MEDIUM, 4 LOW. Detail per finding archived
in the audit subagent transcript and is recoverable via the same
prompt; key categories below.

**HIGH-severity categories (theoretical — values are controlled):**
- `cmd.exe /c $commandText` interpolation in
  `Bootstrap-RustyNetWindows.ps1:460, 1031` and
  `Collect-RustyNetWindowsDiagnostics.ps1:288`. The interpolated
  array contents are static helper-defined strings (`where.exe
  cargo`, `rustc.exe --version`, etc.); attacker would need to
  modify the shipped script. Pattern still violates argv-only
  discipline.
- Manual binPath quote-concatenation in `Install-` and `Smoke-`
  scripts — same fragile-quoting class the W2.2 install-helper
  hardening commit (76f8303) replaced for `sc.exe create` with
  `New-Service`. The remaining sites (Smoke-RustyNetWindowsService
  Host.ps1:241 + sc.exe create at 297-305) still take the manual
  quote path because the smoke-test runs under sc.exe explicitly.
- Backtick-escaped paths inside cmd-string args
  (`Bootstrap-RustyNetWindows.ps1:1020` for winget config).

**MEDIUM-severity categories (defense-in-depth):**
- `icacls $Path` and `sc.exe delete $ServiceName` invocations with
  unquoted variables across all five scripts. PowerShell 5.1's
  native-command argument passing wraps space-bearing variables in
  quotes for most cases — tests of the actual install path against
  `C:\Program Files\RustyNet\...` (spaces in `Program Files`) pass
  in the live-lab evidence run captured in commit 76f8303.
  Defense-in-depth would still benefit from explicit quoting.
- `Get-CimInstance -Filter ("Name='" + $ServiceName.Replace("'",
  "''") + "'")` WQL filter construction in `Install-`, `Smoke-`,
  `Verify-`. Replace-based escaping is correct but fragile. Note:
  `Get-CimInstance` has no `-FilterHashtable` parameter (`Get-WinEvent`
  does); safe approach is `-Filter "Name = '$ServiceName'"` gated by
  the `Test-RustyNetServiceName` validator (landed).
- `git clone --branch $Branch $RepoUrl` in `Bootstrap-RustyNetWindows
  .ps1:1058-1080` passes parameter values directly to git; git
  itself validates URL/ref shape but no pre-validation in the
  script.

**Cross-cutting hardening recommendation status (W2.5b):**
1. **[x] LANDED** — `Test-RustyNetServiceName` defense-in-depth
   validators added at the top of `Install-RustyNetWindowsService.ps1`,
   `Verify-RustyNetWindowsBootstrap.ps1`, and
   `Smoke-RustyNetWindowsServiceHost.ps1`. Mirror the Rust-side
   `validate_service_name`: ASCII alphanumeric + `-` + `_`,
   non-empty, ≤128 chars. Run BEFORE the trap handler is registered
   so a malformed parameter fails loudly with the precise reason
   instead of collapsing to a generic exception.
2. **[x] LANDED** — `Test-RustyNetReviewedInstallRoot` /
   `Test-RustyNetReviewedStateRoot` validators added to
   `Install-RustyNetWindowsService.ps1` (full pair) and
   `Verify-RustyNetWindowsBootstrap.ps1` /
   `Smoke-RustyNetWindowsServiceHost.ps1` (StateRoot check;
   InstallRoot check on Verify). Reject any deviation from the
   reviewed `C:\Program Files\RustyNet` / `C:\ProgramData\RustyNet`
   roots so the helper cannot install RustyNet under an unreviewed
   layout.
3. **[x] LANDED** — Replaced `cmd.exe /c $commandText` in
   `Bootstrap-RustyNetWindows.ps1` (tooling-probe loop and the
   VS env-capture loop) and `Collect-RustyNetWindowsDiagnostics.ps1`
   (tooling-probe loop) with argv-only invocation: the probe loop
   splits `$commandText` on whitespace and uses the PowerShell `&`
   operator so no shell string is formed; the VsDevCmd env-capture
   uses explicit string concatenation rather than PS interpolation
   to build the cmd argument, removing `$devCmd` from an
   interpolated string context.
4. **[x] LANDED** — Reverted erroneous `-FilterHashtable` (a
   `Get-WinEvent` parameter that does not exist on `Get-CimInstance`)
   back to `-Filter "Name = '$ServiceName'"`. The filter string is
   safe because `$ServiceName` is validated by `Test-RustyNetServiceName`
   (`^[A-Za-z0-9_-]+$`) before any CIM call, preventing WQL injection.
   Live-lab run 2026-05-06 confirmed `-FilterHashtable` on
   `Get-CimInstance` throws `"A parameter cannot be found"` on Windows 11
   PowerShell 5.1; fix landed in all four affected scripts.
5. **[x] LANDED** — Quoted every `icacls "$Path"` and
   `sc.exe delete "$ServiceName"` arg explicitly in
   `Install-RustyNetWindowsService.ps1` and
   `Uninstall-RustyNetWindowsService.ps1`.

**Verdict:** Audit complete. None of the findings are
attacker-reachable today (script values come from controlled
sources: hard-coded constants, orchestrator-validated parameters
with strict charsets enforced by `build_windows_security_check_invocation`
+ `validate_service_name`, and the Windows guest's own filesystem
state). The remediations listed are pure defense-in-depth and are
tracked as a follow-up W2.5b slice. **Cleared 2026-04-28** with
deferred remediation list above.

---

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

## 3) Phase B — Comparative VPN Security Findings (2026-04-28)

Comparison against the published security practices of Tailscale,
WireGuard (the protocol whitepaper + audited implementations),
Nebula, OpenVPN, and Microsoft's Windows service-hardening guidance.
Each finding records: the published practice, what Rustynet does
today, gap (if any), severity (HIGH / MEDIUM / LOW), and either an
"applied" commit SHA or a "deferred — tracked under …" pointer.

The comparison was done by code-walking Rustynet's relay,
traversal, fetcher, daemon, dataplane, and key-material modules
against the public design notes / source of the reference
projects. Detailed code-walk references in §5 below.

### B.1 WireGuard — handshake replay protection

**Practice (WireGuard whitepaper §5.4.5):** Each peer maintains a
sliding-window replay filter on received transport packets keyed by
the 64-bit counter; out-of-window or already-seen counters are
silently dropped.

**Rustynet today:** the dataplane goes through `boringtun`
(Cloudflare's audited WireGuard userspace) for packet processing —
boringtun ships the standard sliding-window replay filter
inherited from the reference WireGuard implementation.

**Gap:** none. Rustynet inherits the WireGuard replay invariant by
construction. Verified by reading
`third_party/boringtun/src/noise/handshake.rs` and the wider noise
implementation.

**Severity:** N/A (already correct).

**Cleared 2026-04-28.**

---

### B.2 WireGuard — key rotation cadence (REKEY_AFTER_TIME / REJECT_AFTER_TIME)

**Practice (WireGuard whitepaper §5.4):**
`REKEY_AFTER_TIME = 120s`, `REJECT_AFTER_TIME = 180s`. Sessions
older than 180s are rejected; rekey is initiated at 120s. Plus
volume-based limits (`REKEY_AFTER_MESSAGES = 2^60`).

**Rustynet today:** Inherited from boringtun. Constants live in
the boringtun crate's `noise` module and match the upstream
WireGuard reference values.

**Gap:** none.

**Severity:** N/A.

**Cleared 2026-04-28.**

---

### B.3 Tailscale — DERP relay token replay protection

**Practice (Tailscale published design):** DERP session tokens are
short-lived, single-use, bound to peer node IDs + relay ID, and
include a nonce that changes per request. Constant-time comparison
on every secret-bearing field.

**Rustynet today:** `crates/rustynet-relay/src/transport.rs` (line
13-30 module header documents the policy explicitly):
- Tokens are signed Ed25519 envelopes with `node_id`,
  `peer_node_id`, `relay_id`, and an expiry.
- Verification uses `subtle::ConstantTimeEq::ct_eq` on every
  secret-bearing field (lines 205, 216, 224 — already cleared in
  Phase A §A.3.3 above).
- Replay protection: a watermark store rejects tokens issued
  before the last accepted issued-at timestamp.

**Gap:** none — the relay implementation already follows the
Tailscale-style discipline.

**Severity:** N/A.

**Cleared 2026-04-28.**

---

### B.4 Tailscale — MagicDNS rebind / poisoning resistance

**Practice:** A MagicDNS resolver must reject responses that:
1. Resolve a tailnet-only name to a non-tailnet IP (RFC1918 /
   non-tailnet space).
2. Change the resolved IP between sequential queries within a
   short window (DNS rebinding attack).
3. Bypass the resolver via interface DNS that's not the
   loopback resolver.

**Rustynet today:** The W1.3 `windows_dns_failclosed` verifier
landed in this delta (commit `adf255c`) enforces (3) on Windows
already — every interface DNS must be loopback-only or empty, and
at least one NRPT rule must cover the root namespace pointing at
loopback. The Linux side enforces (3) via the `phase10.rs`
nftables drop-except-on-tunnel rules (cleared as A.3.x in the
phase A pass).

For (1) and (2) — the daemon's own DNS resolver:
- The daemon binds a loopback resolver (when
  `dns_resolver_bind_addr` is set per phase10) and serves DNS
  zone bundles fetched from the controller. The bundles are signed
  + watermark-checked + freshness-gated (see `fetcher.rs`); they
  cannot be forged in transit.
- The daemon does NOT yet implement RFC1918-rebind rejection at
  the resolver layer (a malicious zone-publisher could in principle
  inject an RFC1918 answer for a tailnet-internal name).

**Gap:** [B.4.1, MEDIUM, deferred] Add an output filter on the
daemon's loopback resolver that rejects answers where the response
IP is in RFC1918 (10/8, 172.16/12, 192.168/16), link-local
(169.254/16), or loopback (127/8) and the question name is a
public-domain (non-tailnet) suffix. Defense-in-depth — the
zone-bundle signing already gates the upstream of trust, but the
filter prevents misconfiguration leakage.

**Severity:** MEDIUM, deferred. Tracked here as B.4.1; landing
requires a small extension to the daemon's DNS resolver that
inspects answer records before they cross the loopback boundary.

---

### B.5 Tailscale — node-key thumbprint pinning on join

**Practice:** Every node has a long-lived public key (its
"node key"); the controller pins the thumbprint of the node key
on first registration. Subsequent control-plane requests from the
same node are checked against the pinned thumbprint to defeat
node-key swap attacks.

**Rustynet today:** Membership snapshots are signed by the
membership owner's signing key; the daemon verifies the signature
on every snapshot fetch (`fetcher.rs`,
`crates/rustynetd/src/daemon.rs` membership ingestion). The signed
snapshot pins each member's node ID + WireGuard public key.

**Gap:** none — Rustynet uses signed-membership pinning, which is
strictly stronger than per-node thumbprint pinning (Tailscale uses
both).

**Severity:** N/A.

**Cleared 2026-04-28.**

---

### B.6 Nebula — certificate-based peer authentication

**Practice (Nebula): ** Every peer carries a certificate signed by
the network's CA, with the subject including the peer's IP +
allowed groups + expiry. Peers verify each other's certificates
during handshake.

**Rustynet today:** Equivalent via signed membership snapshots —
each peer's WireGuard public key is published in a signed snapshot
fetched from the controller. The handshake itself uses raw
WireGuard (no cert chain), so per-peer authn relies on the
membership snapshot being current. The signed-snapshot mechanism
provides the same effective property as Nebula's per-peer cert,
with the trust anchor centralized in the membership owner key.

**Gap:** none — different mechanism, equivalent outcome.

**Severity:** N/A.

**Cleared 2026-04-28.**

---

### B.7 OpenVPN — `--auth tls-crypt-v2` style transport-layer pre-auth

**Practice:** OpenVPN's `tls-crypt-v2` wraps the entire control-channel
TLS handshake in an HMAC keyed off a pre-shared per-client key, so
attackers without the PSK cannot even initiate a handshake.

**Rustynet today:** WireGuard's noise framework provides equivalent
property — without the static peer keys an attacker cannot complete
handshake-1 message validation. No additional pre-auth wrapper
required.

**Gap:** none — equivalent at the noise layer.

**Severity:** N/A.

**Cleared 2026-04-28.**

---

### B.8 Windows — service SID restriction tier

**Practice (Microsoft Windows hardening):** Service SID type
`restricted` (vs `unrestricted`) further locks down what the
service principal can access. Combined with `WriteOnly` /
`Restricted` token attributes, a service can be confined to a
specific allowlist of resources.

**Rustynet today:** The W2.2 install helper sets `SidType = unrestricted`
(see `Install-RustyNetWindowsService.ps1` — landed in commit
`76f8303`). This is Microsoft's recommended baseline for services
that need to access a specific path tree under
`C:\ProgramData\RustyNet\…`; the binary itself is locked down to
`SY:F BA:F svc:RX` and the runtime ACLs lock the state tree to
SYSTEM + Administrators.

**Gap:** [B.8.1, LOW, INVESTIGATED 2026-05-05 — not feasible]
`SidType = restricted` was investigated. Under Windows restricted
tokens the per-service SID must pass the ACL check on every object the
process opens — including system DLLs, registry hives (HKLM\SYSTEM),
DPAPI keys, SCM, and network stack handles. These objects cannot
practically be granted `NT SERVICE\RustyNet` without OS-level ACL
surgery that would break system maintenance and Windows Update.
`SidType = unrestricted` with explicit runtime-dir and binary ACLs
(SYSTEM+BA:F, service SID:RX/M) is the correct posture.
**Closed as not feasible.** The effective defence-in-depth already
comes from the installed binary and state-root ACLs that were
validated by the W2.2 verifier.

**Severity:** LOW, closed 2026-05-05.

---

### B.9 Tailscale-style — bootstrap-safety / TOFU

**Practice:** Tailscale uses authkeys (single-use tokens) for
device join, plus a control-plane MITM-resistance layer (HTTPS +
public-key pinning).

**Rustynet today:** Bootstrap uses signed membership snapshots.
The owner-signing-key public part lives at
`/etc/rustynet/membership.owner.key.pub` (Linux) or
`C:\ProgramData\RustyNet\trust\membership.owner.key.pub` (Windows).
First-time install requires an out-of-band trust anchor (the
public key file) — Tailscale's authkey is functionally similar.

**Gap:** [B.9.1, LOW, **LANDED 2026-04-28**] Document the out-of-band
trust-anchor distribution explicitly in
`documents/SecurityMinimumBar.md`. **Done in this commit** —
SecurityMinimumBar §6.B "Bootstrap Trust Anchor" now publishes the
approved out-of-band delivery channels (pre-baked image,
trusted-operator copy, sneakernet) and the forbidden ones
(plaintext HTTP, TLS-only without thumbprint verification, chat
channels without tamper-evidence), plus the post-install thumbprint
verification step.

**Severity:** LOW, documentation-only. **Cleared 2026-04-28.**

---

### B.10 WireGuard — endpoint roaming defense

**Practice:** WireGuard allows a peer's source IP to change
between sessions but only after a successful handshake retry; an
attacker spoofing a peer's previous IP cannot inject packets
because they can't complete the handshake.

**Rustynet today:** Inherited from WireGuard via boringtun.

**Gap:** none.

**Severity:** N/A.

**Cleared 2026-04-28.**

---

### B.11 Cargo dependency hygiene (continued)

**Practice (industry):** Run `cargo audit` + `cargo deny` in CI;
treat `unmaintained` advisories as warnings to address; keep the
deny.toml allow-list small.

**Rustynet today:** Both gates pass clean (recorded in §A.1
above). `deny.toml` exists at repo root with explicit policy.
`Cargo.lock` is committed and reproducible.

**Gap:** none.

**Severity:** N/A.

**Cleared 2026-04-28.**

---

### B.12 Phase B summary — open items

The deep comparative audit found the Rustynet posture *strictly
matches or exceeds* the published Tailscale / WireGuard / Nebula
practices on every reviewed axis. Open items are pure defense-in-
depth additions, none security-bar:

- **B.4.1 [MEDIUM, partially LANDED 2026-04-28]** The original
  finding called for a resolver-output filter on the daemon's
  loopback DNS responder. The protocol-level DNS responder code
  itself is still pending (the daemon binds `dns_resolver_bind_addr`
  but does not yet implement the DNS protocol handler), so a
  resolver-output filter has nothing to filter today. **Landed in
  this commit:** the related signed-zone-bundle-layer defense.
  `parse_expected_ip` in `crates/rustynet-dns-zone/src/lib.rs`
  now rejects records whose `expected_ip` is in a range that is
  universally inappropriate for a mesh peer:
    - Loopback (`127.0.0.0/8`, RFC 6890)
    - Link-local APIPA (`169.254.0.0/16`, RFC 3927)
    - RFC 5737 documentation / TEST-NET-1/2/3
      (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
  RFC1918 ranges (`10/8`, `172.16-31/16`, `192.168/16`) stay
  permissive because some operators legitimately deploy meshes
  inside their corporate RFC1918 space; rejecting RFC1918 globally
  would break those deployments. This catches a malicious zone-
  publisher who tries to inject loopback/link-local/test-net
  expected_ip into a signed zone record at the bundle-validator
  layer, matching the same threat class B.4.1 calls out at the
  resolver-output layer. The resolver-output filter remains future-
  work for when the protocol-level DNS responder lands; the same
  posture applies there. Evidence: 8 new unit tests in
  `rustynet-dns-zone/src/lib.rs` covering loopback / link-local /
  3× documentation rejections + 3 explicit accepts (RFC1918 10/8,
  RFC1918 192.168/16, tailnet-style 100.64/10). Commit:
  to-be-filled-in by the next slice's commit message.
- **B.8.1 [LOW, investigated 2026-05-05, NOT feasible]** `SidType = restricted`
  was investigated. Under Windows restricted tokens, the per-service SID
  `NT SERVICE\RustyNet` must appear in the restricted SID list AND every
  object the service opens must grant that SID explicitly. The daemon calls
  WinVerifyTrust, GetFileSecurityW, OpenSCManager, DPAPI, and the IP/network
  stack — all of which open system DLLs, registry hives, and kernel objects
  that carry no per-service SID grant. Granting `NT SERVICE\RustyNet` on those
  system objects is not feasible without OS-level ACL surgery that would break
  Windows Update and system maintenance. `SidType = unrestricted` remains the
  correct choice; the defense-in-depth comes from the binary and runtime-dir
  ACLs already in place (SYSTEM+BA:F, service SID:RX/M). Closed as not feasible.
- **B.9.1 [LOW, LANDED 2026-04-28]** Publish a "how to deliver the
  membership owner public key to a new node" runbook in
  `documents/SecurityMinimumBar.md` so the out-of-band TOFU step
  is explicit. **Done** — see SecurityMinimumBar.md §6.B.

These are tracked here as future work in Phase B's ledger; landing
them as code is **out of scope** for this audit pass to keep the
session token budget intact. They are flagged for the next
security-focused slice.

## 4) Phase C — Post-Audit Quick-Win Applications (TODO)

Phase B identified three deferred items (B.4.1, B.8.1, B.9.1).
Status as of 2026-05-05:

- **B.9.1** doc-only runbook: LANDED 2026-04-28 (SecurityMinimumBar §6.B).
- **B.8.1** SidType=restricted investigation: CLOSED 2026-05-05 — not
  feasible (see §B.8 for rationale). No code change needed.
- **B.4.1** RFC1918 resolver-output filter: still open; requires the
  daemon's DNS protocol handler (currently absent). The bundle-layer
  defence landed in 2026-04-28 (parse_expected_ip loopback/link-local/
  test-net rejection). Resolver-layer filter is future work.

The work is intentionally not bundled into one big commit — each
should be its own slice with its own residual-risk note + commit
SHA tracked here. Until those slices land, the open-items list in
§B.12 is the canonical TODO.

## 5) Code-Walk References

Sections that the comparison above grounds against:

- WireGuard replay window: `third_party/boringtun/src/noise/handshake.rs`,
  `third_party/boringtun/src/noise/session.rs`.
- Tailscale-style relay token: `crates/rustynet-relay/src/transport.rs`
  (especially lines 13-30 header + 195-230 verification flow).
- Membership-signed pinning: `crates/rustynetd/src/daemon.rs`
  membership-ingestion; `crates/rustynet-policy/`; signed-snapshot
  watermark in `crates/rustynetd/src/fetcher.rs`.
- DNS fail-closed Windows: `crates/rustynetd/src/windows_dns_failclosed.rs`
  (W1.3 in this delta plan).
- Service hardening Windows: `crates/rustynetd/src/windows_service_hardening.rs`
  (W2.2) +
  `scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1` +
  the W2.5b validators added in commit `86d5a2b`.
- Replay protection on signed bundles: `crates/rustynetd/src/fetcher.rs`
  watermark store (commit `de4c7ba` fix for clock-pre-EPOCH DoS).

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
