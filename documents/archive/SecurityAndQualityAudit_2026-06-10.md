# Rustynet Security & Quality Audit (2026-06-10)

Status: COMPLETE — coverage ledger (§10) at 100% with three justified low-risk exceptions. All four read-only gates green (check, clippy `-D warnings`, audit, deny).

Auditor: principal-level security review (AI-assisted, multi-pass: per-crate deep reads + cross-cutting threat models + first-hand verification of load-bearing findings).
Baseline: working tree at `main` commit `699892a` **plus uncommitted changes** (modified: rustynet-cli main/vm_lab/bootstrap, rustynet-mcp build.rs + bins; untracked-in-index: `crates/rustynet-cli/src/vm_lab/overnight/*` staged). Uncommitted code reviewed at elevated scrutiny.
Read-only audit: no code, config, inventory, or VM/network state was modified. Only this report (and an index entry) are written.

Relationship to prior reviews: `SecurityReview_2026-05-24.md` (RN-01..RN-38) is the prior authoritative assessment; `SecurityHardeningBacklog_2026-06-01.md` (HB-1..HB-7) tracks post-review items. This audit is a fresh full-repo pass: it re-verifies the status of prior findings (§8), does not re-narrate still-open RN-xx except where status changed, and numbers net-new findings AUDIT-001+.

2026-06-12 working-tree update: RN-03/RN-04/RN-05/RN-11 have code fixes and focused tests. `force_fail_closed` Results are no longer discarded in the daemon; Phase10 applies the killswitch before backend start and fail-closes on pre-start failure; non-node policy selectors require explicit active membership resolution; empty membership denies peer provisioning. RN-02 remains open. Older "still open" text below is the original audit snapshot unless specifically superseded by this update or `documents/SecurityAnalysis_2026-06-12.md`.

2026-06-12 P1 review update: RN-08 is only partially fixed. The AAD-bound v1 envelope was added, but the v0/v1 decoder currently treats any blob with `len >= 45 && first_byte != 0` as v1. Legacy v0 blobs start with random salt, so most existing v0 encrypted keys will be misclassified as v1 and fail to decrypt after upgrade. Do not mark RN-08 closed until legacy v0 decode compatibility is fixed and covered by an explicit old-format regression test.

---

## 1. Executive summary

**Posture verdict: the security-critical core is strongly engineered and predominantly fail-closed, but the project is NOT ship-ready and one new tool must not be run as-is.** Fourteen independent deep reviews (every workspace crate, the vendored WireGuard, all scripts/CI, the agent tooling) plus first-hand verification of the load-bearing items converge on the same picture the prior `SecurityReview_2026-05-24.md` found: vetted crypto only (no custom crypto, fail-closed CSPRNG, zeroize, constant-time compares), verify-before-apply with anti-replay across every signed-state loader, a model argv-only privileged-helper boundary, bounded/panic-free network parsers, and clean architecture boundaries. There is **no Critical finding** — no remote-unauthenticated RCE, key disclosure, or traffic-interception path was found, and `cargo audit`/`cargo deny` are clean.

**Severity counts (this audit, net-new + re-rated):** Critical 0 · High 11 · Medium 19 · Low 16 · Info 7. (Prior RN-xx still-open Low/Info reconciled separately in §8.)

**Top risks (the 11 Highs cluster in five places):**
1. **The fail-closed killswitch can fail open (RN-03/RN-04/RN-10).** All ~39 `force_fail_closed` sites in the daemon discard the Result, the tunnel/routes come up before the killswitch, and a corrupt rotation ledger silently resets to genesis. On a transient nft/helper fault during first bootstrap a node can egress cleartext while reporting "restricted." This is the project's central guarantee and the highest residual risk.
2. **New agent/automation tooling outruns its safety envelope.** The uncommitted overnight driver (AUDIT-017/018/019) never checks out its isolation branch (commits land on `main`) and runs `git reset --hard && git clean -fd` in the operator's real tree (destroys all uncommitted work) — **do not run its live path**. The `lab_state` MCP `report_dir` escape (AUDIT-006) is fixed in uncommitted 2026-06-12 work; the overnight driver remains unsafe.
3. **A trust-core correctness bug disables revocation (AUDIT-040):** the membership reducer stamps wall-clock time into the hashed state, so `RevokeNode`/`RotateNodeKey`/`SetNodeCapabilities`/`RestoreNode` updates fail the state-root check and cannot be applied — and replay of any logged such op breaks daemon bootstrap. Fail-closed in direction, but a compromised node cannot be revoked via the signed path.
4. **Windows key custody fails open (AUDIT-027/RN-33):** the encrypted-at-rest fallback's permission/ACL check is a no-op `Ok(())` on Windows (the real SDDL validator exists in-tree, just unwired).
5. **Remote relay DoS (AUDIT-031)** and a **macOS bootstrap privilege-escalation residue (AUDIT-045/RN-32):** an unbounded pre-auth map keyed by attacker `node_id` can OOM the relay; the macOS bootstrap leaves a `NOPASSWD: ALL` sudoers file on disk if the Homebrew install fails.

**Good news / improvement since the last review:** the headline open High from the 2026-06-01 backlog — **RN-06, the Windows killswitch allowing all non-DNS LAN egress — is now fixed** (rescoped to WFP egress allow-lists), and RN-07 (IPv6) is largely fixed. RN-01/17/19/22(in-scope)/23/24 fixes all hold.

**Ship / no-ship recommendation: NO-SHIP until the P0 set (§9) is closed.** Concretely, before release: fix the killswitch fail-open cluster (RN-03/RN-04) and the revocation bug (AUDIT-040); wire/fail-close the Windows key-custody ACL (AUDIT-027); cap the relay pre-auth map (AUDIT-031); trap-clean the macOS sudoers file (AUDIT-045). **Independently of release: do not invoke `ops vm-lab-overnight` without `--dry-run`** — its live path is destructive today (AUDIT-017/018/019). MCP `lab_state` `report_dir` confinement (AUDIT-006) is fixed in uncommitted 2026-06-12 work. None of these is a remote-compromise Critical, but several defeat controls the product markets as guarantees (fail-closed leak prevention, revocation, unattended-autonomy safety), which is a release blocker for a security-first VPN. The Medium/Low set is dominated by Windows-side hardening gaps, false-assurance diagnostics/gates, and supply-chain pinning — all individually small fixes.

**Verification honesty:** this is a static review. Windows/macOS firewall + key-custody behavior was read but not validated on a live host; the relay/overnight Highs were confirmed by code path (the overnight ones first-hand) but not by live PoC. See §11.

## 2. Methodology

Phases: (0) orient on authoritative docs (AGENTS/CLAUDE.md, Requirements.md, SecurityMinimumBar.md, prior reviews); (1) read-only gates — cargo check/clippy workspace all-targets all-features, cargo audit, cargo deny, static security gate scripts; (2) per-crate deep read of all 19 workspace crates in dependency order against the full checklist (fail-open paths, default-deny, verify-before-apply, secrets hygiene, panic/DoS surface, hostile-input parsing, unsafe, concurrency, TOCTOU); (3) cross-cutting trust-boundary threat models (enrollment, bundle ingestion, gossip, relay, exit NAT, DNS, privileged exec, key custody, MCP servers, orchestrator) plus scripts/CI/gate-script review; (4) reconciliation with RN-01..RN-38 + false-positive pass on every candidate finding; (5) completeness sweep against the coverage ledger.

Gate results (Phase 1):
- `cargo audit --deny warnings`: PASS (1123 advisories loaded, 181 deps scanned, no findings).
- `cargo deny check bans licenses sources advisories`: PASS (all four checks ok).
- `cargo check --workspace --all-targets --all-features`: **PASS** (exit 0, 16m24s) — workspace compiles clean on all targets/features.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: **PASS** (exit 0, 24m58s) — zero lint warnings workspace-wide (run with `-D warnings`).
- Static security gate scripts: see §6/§8 (the gate *bins* were source-audited rather than executed against the running cargo lock; AUDIT-012/013 document gate-coverage gaps).

Not done and why:
- No live VM-lab runs, no deployment, no state mutation (read-only mandate).
- No dynamic exploitation / fuzz campaign (static review; fuzz targets inspected statically).
- Windows/macOS firewall behavior reviewed statically only (no live host validation) — same limitation as prior review; flagged in §11.

## 3. Master findings table

Net-new findings (AUDIT-NNN) plus the load-bearing prior findings re-verified this pass. Still-open RN-xx not given an AUDIT id are reconciled in §8. Status "Open (uncommitted)" = the defect is in code staged but not yet committed (the overnight driver), so its blast radius is realized only when that code lands/runs.

| ID | Title | Severity | Crate/Area | Location | Confidence | Status |
|---|---|---|---|---|---|---|
| RN-03 | `force_fail_closed` Result swallowed at all ~39 sites (fail-open killswitch) | High | rustynetd | daemon.rs (39 sites) | confirmed | Open |
| RN-04 | Tunnel/routes up before killswitch; boot killswitch opt-in/Linux-only | High | rustynetd | phase10.rs:4386/4541 | confirmed | Open |
| RN-10 | Corrupt rotation ledger silently resets to genesis (anti-rollback loss) | High (was Med) | rustynetd | daemon.rs:8432 | confirmed | Open |
| AUDIT-006 | MCP `lab_state` unconfined `report_dir` → arbitrary host read + recursive delete | High | rustynet-mcp | lab_state.rs:109 | confirmed | Fixed (2026-06-12, uncommitted) |
| AUDIT-017 | Overnight: isolation branch never checked out → commits land on `main` | High | rustynet-cli/overnight | mod.rs:200-232 | confirmed | Open (uncommitted) |
| AUDIT-018 | Overnight: `git reset --hard`+`clean -fd` in operator tree destroys uncommitted work | High | rustynet-cli/overnight | executor.rs:401 | confirmed | Open (uncommitted) |
| AUDIT-019 | Overnight: security-diff "revert" resets to the offending commit (no-op) | High | rustynet-cli/overnight | executor.rs:401 | confirmed | Open (uncommitted) |
| AUDIT-027 | Windows encrypted-key custody ACL check is a no-op `Ok(())` (RN-33 escalated) | High | rustynet-crypto | lib.rs:1549 | confirmed | Open |
| AUDIT-031 | Relay `HelloLimiter` unbounded map keyed by pre-auth attacker `node_id` (DoS) | High | rustynet-relay | transport.rs:954 | confirmed | Open |
| AUDIT-040 | Non-deterministic membership reducer breaks revocation/key-rotation/replay | High | rustynet-control | membership.rs:1156-1200 | confirmed | Open |
| AUDIT-045 | macOS bootstrap leaves `NOPASSWD: ALL` sudoers on failure (RN-32 escalated) | High | scripts | Bootstrap-RustyNetMacos.sh:245 | confirmed | Open |
| RN-08 | Encrypted-key envelope: no AAD binding / magic+version | Medium | rustynet-crypto | lib.rs:1300/1466 | confirmed | Open |
| RN-12 | Linux exit-serving DNS leak: egress `accept` precedes `:53 drop` | Medium | rustynetd | phase10.rs:2110/2150 | confirmed | Open |
| AUDIT-005 | RN-22 incomplete: 13 non-strict ed25519 `.verify()` sites remain | Medium | dns-zone/rustynetd/cli | (13 sites) | confirmed | Open |
| AUDIT-020 | Overnight agent: no tool allowlist/permission-mode/env scrub (ambient authority) | Medium | rustynet-cli/overnight | mod.rs:217 | confirmed | Open (uncommitted) |
| AUDIT-021 | Overnight: agent/wall-clock timeout not enforced against a hung agent | Medium | rustynet-cli/overnight | executor.rs:316 | confirmed | Open (uncommitted) |
| AUDIT-022 | Overnight: case-sensitive denylist bypass + live path is default | Medium | rustynet-cli/overnight | safety.rs:47; main.rs:3370 | confirmed | Open (uncommitted) |
| AUDIT-025 | boringtun userspace engine never drives `update_timers` (no rekey/keepalive) | Medium | rustynet-backend-wireguard | userspace_shared/engine.rs | confirmed | Open (pre-prod) |
| AUDIT-028 | DPAPI used with no secondary entropy (same-machine decrypt) | Medium | rustynet-windows-native | lib.rs:335-396 | confirmed | Open |
| AUDIT-029 | Decrypted DPAPI plaintext `LocalFree`d without zeroization | Medium | rustynet-windows-native | lib.rs:1286 | confirmed | Open |
| AUDIT-032 | Relay control-port log/IO amplification (non-HELLO bypasses pre-auth limiter) | Medium | rustynet-relay | main.rs:422 | confirmed | Open |
| AUDIT-033 | Relay forwarding serializes on a global write-lock + busy-polls every port | Medium | rustynet-relay | main.rs:532-606 | probable | Open |
| AUDIT-034 | Relay logs peer IPs/`node_id`s unredacted (privacy policy) | Medium | rustynet-relay | transport.rs:407; main.rs | confirmed | Open |
| AUDIT-036 | sysinfo fabricates TLS/cert-expiry/cipher/service signals (false assurance) | Medium | rustynet-sysinfo | lib.rs:4819/5203/3252/3172 | confirmed | Open |
| AUDIT-037 | `live_chaos_signed_state_adversarial_test` reports pass without a daemon | Medium | rustynet-cli/bin | …adversarial_test.rs:198 | confirmed | Open |
| AUDIT-038 | sysinfo Windows PowerShell `-Command` interpolated host/path (injection sink) | Medium | rustynet-sysinfo | lib.rs:5200/4903/6265 | confirmed | Open |
| AUDIT-041 | Break-glass secret compared with non-constant-time `!=` | Medium | rustynet-control | scale.rs:268 | confirmed | Open |
| AUDIT-046 | CI/release Actions pinned to mutable tags not SHAs (RN-16) | Medium | .github/workflows | both workflows | confirmed | Open |
| AUDIT-047 | Shipped binaries built with non-pinned toolchain (RN-30) | Medium | scripts/CI | release-windows.yml:55 | confirmed | Open |
| AUDIT-048 | Bootstrap builds omit `--locked` (RN-15 partial) | Medium | scripts | rn_bootstrap.sh:445 | confirmed | Open |
| AUDIT-049 | Hostile-input network parsers have no fuzz target | Medium | fuzz | relay/port_mapper/stun | confirmed | Open |
| AUDIT-001 | Overnight security denylist omits rustynetd/backend-wireguard/relay | Low→High-if-auto-merge | rustynet-cli/overnight | safety.rs:12 | confirmed | Open (uncommitted) |
| AUDIT-002 | Prior "unsafe only in windows-native/vendored" claim stale (rustynetd FFI) | Info | docs/rustynetd | macos_utun_helper_unsafe.rs | confirmed | Open |
| AUDIT-003 | SCM_RIGHTS receiver doesn't bound/close surplus fds (DiD) | Info | rustynetd | macos_utun_helper_unsafe.rs:197 | confirmed | Open |
| AUDIT-004 | rustynetd uses `deny` not `forbid` unsafe (overridable; documented) | Info | rustynetd | Cargo.toml:47 | confirmed | Open |
| AUDIT-007 | MCP `get_inventory` emits VM `ssh_password` | Low | rustynet-mcp | lab_state.rs:2621 | confirmed | Fixed (2026-06-12, uncommitted) |
| AUDIT-008 | New `build.rs` build-time exec + non-reproducible; "no build.rs" claim stale | Low | rustynet-mcp | build.rs:31 | confirmed | Open |
| AUDIT-009 | MCP `run_with_timeout` orphans grandchildren on timeout | Low | rustynet-mcp | lib.rs:475 | confirmed | Fixed (2026-06-12, uncommitted) |
| AUDIT-010 | MCP: no concurrency cap on background live-lab jobs | Low | rustynet-mcp | lab_state.rs:2946 | confirmed | Fixed (2026-06-12, uncommitted) |
| AUDIT-011 | `enrollment mint --output` writes bearer token without 0600 | Low | rustynet-cli | main.rs:6526/14083 | confirmed | Open |
| AUDIT-012 | `secrets_hygiene_gates` content-scan narrowly scoped (false assurance) | Low | rustynet-cli | ops_phase1.rs:2006 | confirmed | Open |
| AUDIT-013 | `check_backend_boundary_leakage` omits dns-zone + weak pattern | Low | rustynet-cli | check_backend_boundary_leakage.rs:9 | confirmed | Open |
| AUDIT-014 | Linux secret-service `key_id` not validated before argv (arg injection) | Low | rustynet-crypto | lib.rs:904 | confirmed | Open |
| AUDIT-015 | `verify_signed_dns_zone_bundle` enforces neither expiry nor watermark | Low | rustynet-dns-zone | lib.rs:273 | needs-runtime-verification | Open |
| AUDIT-016 | DNS-zone watermark ordering ignores payload_digest; parse/verify split | Info | rustynet-dns-zone | lib.rs:521/290 | confirmed | Open |
| AUDIT-023 | `SyncDevice::from_raw_fd` is a safe fn taking fd ownership (unsound) | Low | rustynet-tun | lib.rs:226 | confirmed | Open |
| AUDIT-024 | Windows WG config render leaves plaintext key in non-zeroized String | Low | rustynet-backend-wireguard | windows_command.rs:272 | confirmed | Open |
| AUDIT-026 | boringtun `.unwrap()` on AEAD init; pre-release crypto version reqs | Low/Info | third_party/boringtun | handshake.rs/session.rs | confirmed | Open |
| AUDIT-030 | Windows FFI: interior-NUL truncation, LocalAlloc leak, under-aligned deref | Low/Info | rustynet-windows-native | lib.rs:1300/1241/863 | confirmed | Open |
| AUDIT-035 | Relay: nonce-retention boundary, uncapped node_id, keepalive sniff, health timeout | Low/Info | rustynet-relay | transport.rs:52; main.rs | confirmed | Open |
| AUDIT-042 | Control: break-glass in Debug; membership fields unvalidated vs separators | Low | rustynet-control | scale.rs:221; membership.rs | confirmed | Open |
| AUDIT-043 | Windows forwarding/NAT PowerShell `-Command` trailing-arg injection | Low | rustynetd | phase10.rs:5661 | confirmed | Open |
| AUDIT-044 | daemon rollback/exit-restore best-effort discards (state divergence) | Low | rustynetd | daemon.rs:7685/6688 | confirmed | Open |
| AUDIT-050 | Supply-chain LOW cluster: SSH TOFU, bypassable win gate, unsigned SBOM, no-lints crate | Low/Info | scripts/CI | (multiple) | confirmed | Open |
| AUDIT-051 | uPnP IGD SSRF via attacker SSDP `LOCATION`/`controlURL` (opt-in, LAN-local) | Low | rustynetd | port_mapper.rs:1938 | confirmed | Open |
| AUDIT-052 | Dead `fetcher.rs` with latent panics + stale "mTLS" claim | Low | rustynetd | fetcher.rs | confirmed | Open |
| AUDIT-053 | Relay REJECT reason logged without control-char sanitization | Info | rustynetd | relay_client.rs:1021 | confirmed | Open |

Tally (net-new + re-rated): **High 11, Medium 19, Low 16, Info 7.** No Critical. The still-open prior RN-xx Low/Info (RN-18/25/26/27/28/29/34/35/36/37/38) are tracked in §8.

## 4. Detailed findings

### Area: Cross-cutting (auditor first-hand verification)

#### AUDIT-002 — Prior review's "unsafe only in windows-native + vendored" claim is stale; rustynetd carries a first-party unsafe FFI module never covered by prior audits
- **Severity:** Info (assurance/coverage-accuracy; the module itself is sound — see §7).
- **CWE:** CWE-1059 (insufficient assurance evidence) / doc-impl drift.
- **Location:** `crates/rustynetd/src/macos_utun_helper_unsafe.rs` (589 lines, `#[cfg(target_os="macos")]`, gated by `#[allow(unsafe_code)]` at `crates/rustynetd/src/lib.rs:44`; crate uses `#![deny(unsafe_code)]` + `[lints.rust] unsafe_code = "deny"` in `crates/rustynetd/Cargo.toml:47-54`, a deliberately documented downgrade from the workspace `forbid`).
- **Description (verified first-hand):** `SecurityReview_2026-05-24.md` §7 and §14 assert unsafe is "genuinely contained (only FFI/vendored)" and "13/14 crate roots carry `#![forbid(unsafe_code)]` (only the FFI crate `rustynet-windows-native` lacks it)". In current code there are **two** first-party crates with unsafe: `rustynet-windows-native` (Win32 FFI) and `rustynetd` (the macOS SCM_RIGHTS fd-passing module for the utun privileged helper). The prior review's scope explicitly excluded the latter — so a privilege-boundary FFI surface (fd passing between the daemon and the privileged helper) went un-audited. This audit reviewed it in full (see §7 — it is sound).
- **Impact:** assurance gap only — the file is well-isolated and correct. But the documented claim that unsafe lives only in windows-native/vendored is false, which could cause a future reviewer to skip a real unsafe surface.
- **Confidence:** confirmed.
- **Recommendation:** update the unsafe-containment statement to enumerate both first-party unsafe surfaces (`rustynet-windows-native`, `rustynetd::macos_utun_helper_unsafe`); keep the `deny`+scoped-`allow` design (it is the right pattern). Consider a defense-in-depth tweak in `recvmsg_one_fd` (see AUDIT-003).

#### AUDIT-003 — SCM_RIGHTS receiver does not bound/close surplus fds (defense-in-depth)
- **Severity:** Info (not exploitable under the current trusted-sender protocol).
- **CWE:** CWE-404 (improper resource shutdown) / CWE-770.
- **Location:** `crates/rustynetd/src/macos_utun_helper_unsafe.rs:197-211` (`recvmsg_one_fd`).
- **Description:** the ancillary-data walk reads only the first fd of the first `SCM_RIGHTS` cmsg (`read_unaligned(data_ptr)` then `break`). It does not consult `cmsg_len` to detect a cmsg carrying multiple fds, nor close any surplus fds the kernel already installed into the process. If a sender ever passed >1 fd in one cmsg, the extras would leak (an fd-exhaustion DoS) and be silently dropped. Not reachable today: the only sender is the trusted privileged helper, which sends exactly one fd; the socket peer is credential-checked elsewhere.
- **Impact:** none today; latent fd-leak/exhaustion if the protocol or a compromised same-uid helper ever sends multiple fds.
- **Confidence:** confirmed (read the code path).
- **Recommendation:** validate `(*cmsg).cmsg_len == CMSG_LEN(size_of::<RawFd>())` and, if more fds are present, close all received fds and fail closed. Cheap hardening on a privilege boundary.

#### AUDIT-004 — `rustynetd` not opted into workspace `unsafe_code = "forbid"` lint (intentional, but weakens RN-14's blanket guarantee)
- **Severity:** Info.
- **Location:** `crates/rustynetd/Cargo.toml:47` (`[lints.rust] unsafe_code = "deny"` instead of `[lints] workspace = true`).
- **Description:** RN-14 (fixed) made the workspace `unsafe_code = "forbid"` real by opting crates into `[lints] workspace = true`. `rustynetd` necessarily opts out (it has the macOS unsafe module) and uses crate-level `#![deny(unsafe_code)]`. `deny` is overridable by a stray `#[allow(unsafe_code)]`, whereas `forbid` is not — so a future unsafe block added anywhere in the 102k-line daemon would compile if annotated `#[allow]`, unlike the forbid-protected crates. This is a conscious, commented trade-off, not a defect, but it means the daemon (the largest security-sensitive crate) has the weaker of the two postures.
- **Confidence:** confirmed.
- **Recommendation:** acceptable as-is given the documented constraint; optionally move the macOS unsafe FFI into its own tiny crate (like `rustynet-windows-native`) so `rustynetd` proper can return to `forbid`. Low priority.

### Area: Cryptographic signature verification (cross-crate)

#### AUDIT-005 — RN-22 ("ed25519 verify_strict everywhere") is materially incomplete: 13 non-strict `.verify()` sites remain, including signed-trust-state network paths
- **Severity:** Medium — systemic violation of the project's explicit ban on non-strict ed25519 across signed-trust-state verification, and the master tracker marks RN-22 **Fixed**, which is inaccurate. Per-site malleability impact is Low today (no replay/dedup keys on signature bytes — see analysis), so not High; but it is a mandated-control gap on the trust-verification surface and a false-"Fixed" status.
- **CWE:** CWE-347 (improper signature verification) / signature malleability (RFC 8032 strict / ZIP-215).
- **Location (verified first-hand):** 13 `VerifyingKey::verify(...)` (non-strict) vs only 10 `verify_strict(...)` workspace-wide. Non-strict sites: `crates/rustynet-dns-zone/src/lib.rs:285` (signed DNS-zone bundle); `crates/rustynetd/src/traversal.rs:606` (traversal endpoint-hint coordination record — network-facing); `crates/rustynetd/src/peer_gossip.rs:401` (gossip candidate bundle — network-facing); `crates/rustynetd/src/fetcher.rs:227` (signed-bundle fetch); `crates/rustynetd/src/daemon.rs:6747, 11128, 12020, 13045, 13312` (incl. trust-bootstrap evidence at 11128); `crates/rustynet-cli/src/ops_phase9.rs:2813, 3000, 3389, 3687` (release/evidence verification).
- **Description:** RN-22's remediation (RL-3) replaced `verify()`→`verify_strict()` at exactly 10 sites in `rustynet-crypto` (1) and `rustynet-control` lib.rs (7) + membership.rs (2), and the tracker (§18) marks RN-22 Fixed. But the daemon's own verification paths, the DNS-zone bundle verifier, the signed-bundle fetcher, gossip, traversal, and the CLI evidence verifier were never converted. I confirmed each of the five rustynetd sites is `ed25519_dalek::VerifyingKey::verify(payload, &signature)` (not HMAC) by reading their context. So the documented "verify_strict() at all 10 sites + malleability negative test" closes the property only inside two crates, not "everywhere."
- **Impact / exploit scenario:** ed25519 non-strict accepts non-canonical `S` and small-order/torsion points, so an attacker who observes one valid signature can produce a distinct byte-encoding that still verifies. This is malleability, not forgery (no key → no new payloads). I checked the two network-facing sites for replay amplification: gossip anti-replay keys on a strictly-monotonic per-source sequence (peer_gossip.rs:108/128, not signature bytes) and traversal keys on a coordination nonce (traversal.rs:89/191), so malleability does not currently bypass either replay gate. Residual risk is therefore the mandate violation itself plus any future code that treats a signature as a unique identifier or replay key.
- **Confidence:** confirmed (13 sites enumerated and five spot-confirmed as ed25519 first-hand).
- **Recommendation:** convert all 13 to `verify_strict()`; add a CI gate (extend `security_regression_gates`) that greps for non-strict `ed25519`/`VerifyingKey::verify(` and fails — the absence of such a gate is why RN-22 silently regressed across crates. Add a malleability negative test per crate. Update the RN-22 status from Fixed to partially-fixed.

### Area: rustynet-mcp (agent-facing servers)

#### AUDIT-006 — `lab_state` MCP server: unconfined `report_dir` gives a (confused/injected) agent arbitrary host-file read and recursive delete
- **Severity:** High — arbitrary read of host secrets (SSH private keys, cloud creds) into the model context + arbitrary recursive directory delete, reachable by any agent driving the lab-state MCP server; compounds directly with AUDIT-001 (the overnight driver spawns agents that use this very server and read untrusted VM/repo content = prompt-injection surface).
- **CWE:** CWE-22 (path traversal) / CWE-73 (external control of path) / CWE-200 (exposure).
- **Location (verified first-hand):** `crates/rustynet-mcp/src/bin/lab_state.rs:109` `abs_path()` — accepts absolute paths verbatim and joins relative paths to `repo_root` without `..` normalization or a `starts_with(repo_root)` check. Reached via `resolve_report_dir`/`resolve_report_dir_keyed` from sinks: `grep_report` (:1066, walks + returns matching lines), `read_report_artifact` (:3517 — its own `..`/`starts_with` check uses the attacker-chosen dir as base, so it's vacuous for repo-escape), `list_report_artifacts` (:3495), `get_stage_log` (:1136), `ensure_report_dir`→`create_dir_all` (:103/:105), and `prune_jobs`→`std::fs::remove_dir_all` (:3597) on a `report_dir` recorded verbatim at job start (:2957).
- **Description:** `abs_path` performs no confinement. `grep_report{report_dir:"/Users/iwan/.ssh", pattern:"PRIVATE KEY"}` returns matching lines from the developer's SSH keys; `list_report_artifacts{report_dir:"/Users/iwan"}` enumerates the home dir; `read_report_artifact{report_dir:"/etc", path:"passwd"}` returns `/etc/passwd` (its `starts_with(base)` check passes because `base` is the attacker's `/etc`). `start_live_lab_run{report_dir:"/Users/iwan/important"}` + later `prune_jobs{delete_report_dirs:true}` recursively deletes that tree. The sibling `repo_context.rs:1067` resolver does this correctly (reject `..`+absolute, canonicalize, `starts_with(repo_root)`) — so this is a genuine boundary break, not an accepted design.
- **Impact / exploit scenario:** a prompt-injected or merely confused agent exfiltrates `~/.ssh/rustynet_lab_ed25519` (and any other host secret) into its context, or destroys arbitrary host directories. The overnight autonomous driver (AUDIT-001) makes this reachable unattended.
- **Confidence:** confirmed (read `abs_path` first-hand; delete path is two-step but fully reachable).
- **Recommendation:** confine `abs_path`/`resolve_report_dir` to `repo_root` (ideally `repo_root/state`): reject absolute paths and any `..`, canonicalize the *result*, require `starts_with(repo_root)` — apply at resolution so read/create/delete sinks all inherit it. Reuse the `repo_context.rs:1067` pattern.
- **2026-06-12 fix evidence:** `lab_state` now resolves report paths through a repo-confined canonical-prefix resolver before read/create/delete sinks, rejects absolute or relative escapes, refuses invalid stored job `report_dir`s, and covers the boundary with `report_dir_inputs_are_confined_to_repo`.

#### AUDIT-007 — `get_inventory` MCP tool emits VM `ssh_password` into the response
- **Severity:** Low — throwaway committed lab creds; key-auth is used everywhere, so the agent never needs the password.
- **CWE:** CWE-312 (cleartext exposure).
- **Location:** `crates/rustynet-mcp/src/bin/lab_state.rs:2621-2636` (`get_inventory` returns inventory JSON verbatim); secret at `documents/operations/active/vm_lab_inventory.json` (`"ssh_password":"tempo"` ×8). `get_lab_topology` (:397) deliberately omits creds, so the exposure is inconsistent.
- **Recommendation:** redact `ssh_password` (and any future secret field) in `get_inventory`; longer-term move the password out of the committed inventory. Also reachable via AUDIT-006's arbitrary read.
- **2026-06-12 fix evidence:** `get_inventory` now redacts credential-like fields recursively and refuses to echo malformed inventory JSON; `get_lab_topology_digest_and_resolution` asserts the `tempo` password is absent and `<redacted>` appears.

#### AUDIT-008 — `build.rs` build-time exec + non-reproducible output; prior review's "no build.rs anywhere" claim is now false (doc drift)
- **Severity:** Low (assurance/doc-drift + reproducibility).
- **Location:** `crates/rustynet-mcp/build.rs:31-54` (`git rev-parse`/`git status` + `date -u`, PATH-resolved, baked into `serverInfo.version`); stale claim at `documents/operations/active/SecurityReview_2026-05-24.md:224` ("no build.rs anywhere (zero build-time code-exec surface)").
- **Description:** the only first-party `build.rs`. No injection (args are static literals; outputs flow only into `cargo:rustc-env` string values read via `option_env!`, never into generated source; failures degrade to `"unknown"`). Real effects: stale "verified: no build.rs" security claim; non-reproducible build (embeds wall-clock time + VCS dirty state); no `rerun-if-changed`.
- **Recommendation:** update SecurityReview_2026-05-24.md:224 to record the new build.rs + its exec surface; optionally honor `SOURCE_DATE_EPOCH` for reproducibility.

#### AUDIT-009 — `run_with_timeout` kills only the immediate child on timeout, orphaning grandchildren
- **Severity:** Low (resource hygiene, dev host).
- **CWE:** CWE-404.
- **Location:** `crates/rustynet-mcp/src/lib.rs:475-478` (`child.kill()` only; not a process-group leader, unlike the background-job path which correctly uses `process_group(0)` at lib.rs:569).
- **Description:** synchronous ops (cargo check/test, gate scripts) leave `rustc`/script grandchildren on timeout, holding `target/` locks and CPU. Recommendation: spawn as group leader and TERM/KILL the group, mirroring the background-job path.
- **2026-06-12 fix evidence:** `run_with_timeout` now starts Unix children as process-group leaders and kills the group on timeout; `run_with_timeout_kills_child_process_group` proves a shell-spawned grandchild cannot hold MCP pipes open.

#### AUDIT-010 — No concurrency cap on background live-lab jobs
- **Severity:** Low (host resource exhaustion, dev host).
- **CWE:** CWE-770.
- **Location:** `crates/rustynet-mcp/src/bin/lab_state.rs:2946` `start_live_lab_run`.
- **Description:** each call spawns a heavy detached `cargo orchestrate-live-lab` tree; nothing limits in-flight count. A looping agent can exhaust the host. Recommendation: cap concurrent non-finished jobs and surface the count.
- **2026-06-12 fix evidence:** `start_live_lab_run` now rejects a second running job (`MAX_CONCURRENT_LIVE_LAB_JOBS=1`) using durable job records plus PID identity checks; `start_live_lab_run_rejects_second_running_job` covers the guard.

### Area: rustynet-cli (operator CLI + gate bins)

#### AUDIT-011 — `enrollment mint --output` writes the bearer enrollment token with default umask (no explicit 0600)
- **Severity:** Low — bounded by token TTL + single-use consumed-token ledger, but a bearer credential written world-readable on a multi-user host.
- **CWE:** CWE-276 / CWE-732.
- **Location:** `crates/rustynet-cli/src/main.rs:6526` (mint), `:6660` (admit), shared writer `write_text_file` at `:14083-14088` (`fs::write`, no mode); `main()` sets no restrictive umask (`:1335`).
- **Description:** the enrollment token is a bearer credential (mint→admit/consume adds a node to the mesh). It is written via `fs::write` inheriting umask (typically 0644). The encrypted-key writers in the same file enforce 0600 + owner check — the token writer is the outlier. On a multi-user host a local user can read the token from the world-readable file and replay it before expiry.
- **Recommendation:** write with `OpenOptions...create_new(true).mode(0o600)` (the pattern already in `ops_install_systemd.rs:create_secure_temp_file`); same for the admit envelope as defense-in-depth.

#### AUDIT-012 — `secrets_hygiene_gates` content-scan is narrowly scoped → false assurance (committed key material outside artifact dirs, and Debug-leak of new key types, pass green)
- **Severity:** Low (false assurance; the gate's name overpromises vs its coverage). Extends RN-38.
- **CWE:** CWE-693.
- **Location:** `crates/rustynet-cli/src/ops_phase1.rs:execute_ops_check_secrets_hygiene` (1944-2197): artifact content-scan restricted to roots `["artifacts","tmp","tmpcfg"]` (:2007) × suffixes `[".json",".log",".ndjson",".txt",".env"]` (:2006); repo-wide scan only `.rs/.sh/.service/.timer` for literal flags `--passphrase/--password/--secret-value/--token-value`; redaction relies on a fixed per-type test list in `secrets_hygiene_gates.rs:13-66`.
- **Description:** a PEM private key committed as `docs/sample.pem`/`config/signing.key`/`*.toml`/`*.yaml` passes (content scan never runs there; basename allowlist doesn't match). `println!("{:?}", signing_key)` or a new key-bearing struct deriving `Debug` is not detected (only the fixed test list covers specific named types). Recommendation: run the PEM/secret-assignment content scan across all tracked text files (exclude `.git`/`target`); add a structural lint requiring any secret-bearing type to have a manual redacting `Debug`.

#### AUDIT-013 — `check_backend_boundary_leakage` omits `rustynet-dns-zone` and uses a separator-dependent token pattern
- **Severity:** Low (coverage gap; no active leak — I independently confirmed domain crates have zero backend deps).
- **CWE:** CWE-693.
- **Location:** `crates/rustynet-cli/src/bin/check_backend_boundary_leakage.rs:9-16` (`LEAKAGE_PATTERN="(wireguard|wg[-_]|wgctrl)"`, `SCAN_TARGETS`=control/policy/crypto/backend-api/relay).
- **Description:** CLAUDE.md §10.3 names dns-zone a domain crate, but it isn't scanned; the `wg[-_]` arm misses no-separator `WgDevice`/`WgPeer`, and `boringtun` isn't in the pattern. Recommendation: add `rustynet-dns-zone` (and other transport-agnostic crates) to `SCAN_TARGETS`; broaden the pattern; share one source-of-truth list with the `.sh` wrapper.

#### AUDIT-014 — Linux OS-secure-store path does not validate `key_id` before passing it as `secret-tool` argv (argument injection)
- **Severity:** Low — argv-only (no shell injection); `key_id` is an internal constant in current callers.
- **CWE:** CWE-88 / CWE-20.
- **Location:** `crates/rustynet-crypto/src/lib.rs:904-927` (`store_in_linux_secret_service`) / `:929-948` (`load_from_linux_secret_service`); dispatched from `:403`/`:427` with no prior validation. macOS (:471/:483) and Windows (:1003) validate `key_id` via `is_valid_key_identifier`; Linux does not.
- **Description:** a `key_id` beginning with `-`/`--` could be parsed as a `secret-tool` option. Reachability low (constant key_ids today). Recommendation: validate `key_id` with `is_valid_key_identifier` in both Linux helpers (or centrally before backend dispatch), matching the other two platforms.

#### AUDIT-015 — `verify_signed_dns_zone_bundle` enforces neither expiry-vs-now nor replay watermark (caller-dependent fail-open risk)
- **Severity:** Low (realized only in a caller that treats it as complete; needs caller verification).
- **CWE:** CWE-613 / CWE-294.
- **Location:** `crates/rustynet-dns-zone/src/lib.rs:273-288`.
- **Description:** the verify entry checks only `generated_at < expires` internal consistency + the signature — never `expires_at_unix` vs now, never the `DnsZoneWatermark`. Freshness/anti-replay are silently deferred to callers with no doc contract; the name implies full verification. Recommendation: accept a `now`/previous-watermark and enforce expiry + monotonic `(generated_at, nonce)` here, or add an explicit doc contract + a verifying caller test. (Needs-runtime-verification of the daemon caller — see §11.)

#### AUDIT-016 — Two Info-level DNS-zone hygiene items
- **Severity:** Info.
- `dns_zone_watermark_ordering` (`crates/rustynet-dns-zone/src/lib.rs:521-529`, test pins at :1140) returns `Equal` when `(generated_at, nonce)` match even if `payload_digest` differs — a `>`-based caller would reject a second legitimately-signed bundle reusing a timestamp/nonce. Break ties on `payload_digest`.
- Parse and verify are separate (`:290` parse vs `:273` verify); a `SignedDnsZoneBundle` can hold an unverified signature (the "Signed" name implies trust before `verify`). Document the parse→verify ordering or expose `parse_and_verify`.

### Area: vm_lab overnight driver (UNCOMMITTED new code)

#### AUDIT-001 — Overnight security-crate denylist omits rustynetd (killswitch, privileged helper, key custody), backend-wireguard, and relay; their diffs auto-commit as "Safe"
- **Severity:** Medium — defense-in-depth gap in an unattended-autonomy system; bounded today by branch isolation + no-push + morning review, but becomes High the moment `--auto-merge-safe-cells` is wired against this list.
- **CWE:** CWE-184 (incomplete blocklist) / CWE-1188.
- **Location:** `crates/rustynet-cli/src/vm_lab/overnight/safety.rs:12-29` (`DENYLISTED_CRATES`, `DENYLISTED_PATH_FRAGMENTS`), consumed by `classify_touched_paths` (:63) and the executor commit path.
- **Description (verified first-hand):** `DENYLISTED_CRATES` lists only `rustynet-policy`, `-control`, `-crypto`, `-local-security`, `-dns-zone`. The path-fragment net (`key_custody`, `keychain`, `signing`, `signature`, `secret`, `killswitch`) matches path *strings*, not content. Consequently an overnight agent diff touching `crates/rustynetd/src/phase10.rs` (the live killswitch/dataplane), `crates/rustynetd/src/privileged_helper.rs` (the privileged exec boundary), `crates/rustynetd/src/key_material.rs` (key custody — "key_material" ≠ fragment "key_custody"), `crates/rustynet-backend-wireguard/**`, or `crates/rustynet-relay/**` classifies as `DiffSafety::Safe` and is auto-committed on a green oracle without the adversarial second review. The unit test at safety.rs:201 even pins `crates/rustynet-relay/src/health.rs` as not-denylisted. The proposal (`OvernightAutonomousBugHuntProposal_2026-06-08.md` §10.2) promises review for "trust-state / signed-bundle paths, key-custody, or crypto code" — key_material.rs is key custody and phase10.rs is the fail-closed enforcement point, so the implementation does not meet its own spec (code-vs-proposal drift).
- **Impact / exploit scenario:** an overnight work-unit agent (confused, or steered by hostile content it read from a VM/log — prompt-injection surface) weakens `block_all_egress`/helper validation in phase10.rs to make a red cell go green; the diff auto-commits as Safe. Today a human still reviews before merge to main; the control intended to make that review *focused* (escalation) is silent precisely for the most dangerous files.
- **Confidence:** confirmed (read the constants, the matcher, and the pinning test).
- **Recommendation:** add `rustynetd`, `rustynet-backend-wireguard`, `rustynet-backend-userspace`, `rustynet-relay`, `rustynet-windows-native` to `DENYLISTED_CRATES` (or invert: allowlist the few crates that are *not* security-sensitive, e.g. docs/test-bins — fail-closed posture per CLAUDE.md §10.1); add fragments `privileged`, `key_material`, `phase10`, `dataplane`, `traversal`. Keep the empty-path fail-closed branch (already correct).

#### AUDIT-017 — Overnight live path never checks out the isolation branch: unattended agent commits land on the operator's current branch (today `main`)
- **Severity:** High — defeats the proposal's central marketed guarantee ("can never silently break `main`"). Latent: the live path (`LiveExecutor`) is implemented but documented as never yet run (§18 of the proposal); blast radius is realized on first non-`--dry-run` invocation. Code is staged for commit.
- **CWE:** CWE-691 (insufficient control-flow management).
- **Location (verified first-hand):** `crates/rustynet-cli/src/vm_lab/overnight/mod.rs:200-232` computes `overnight_branch_name(...)` and calls `assert_safe_target_branch(&branch)` but never checks it out; grep confirms the module's only git subcommands are `rev-parse/diff/status/reset/clean` — no `checkout`/`switch`/`worktree`/`branch`. `executor.rs:run_agent` (:302) spawns the agent in the current process tree.
- **Description:** the branch string is used only for the name-refusal check and prompt interpolation ("you are on branch X; never commit to main"). With the operator on `main` (per `git status`), the spawned agent starts on `main`; its commit lands on `main`, and `drive_unit`'s green+committed path keeps it. Branch isolation depends entirely on the model obeying prose.
- **Impact:** unattended autonomous commits to `main`; the §10.1 isolation control is unimplemented.
- **Confidence:** confirmed.
- **Recommendation:** create+checkout the isolated branch (or a per-unit `git worktree`) before the loop and assert HEAD is on it before every commit-detection; fail closed if checkout fails.

#### AUDIT-018 — Overnight revert runs `git reset --hard && git clean -fd` in the operator's real working tree (no worktree, no current_dir): destroys all uncommitted work on the first no-commit unit
- **Severity:** High — silent, unrecoverable loss of all uncommitted/staged/untracked work, executed unattended. Latent until first non-`--dry-run` run; code staged for commit.
- **CWE:** CWE-691 / destructive op on unintended scope.
- **Location (verified first-hand):** `crates/rustynet-cli/src/vm_lab/overnight/executor.rs:401-419` (`revert_to_clean`) — `Command::new("git").args(...).status()` with **no `.current_dir()`**, so it runs in the process cwd (repo root); argv from `safety.rs:revert_to_clean_argv` = `["git","reset","--hard",<base>]` then `["git","clean","-fd"]`. Invoked by `drive_unit` (executor.rs:147) on every unit where the agent did not commit.
- **Description:** on the first no-commit unit (the common case for a hard cell, or any `claude -p` exit without a commit), `git reset --hard HEAD` discards every tracked modification in the operator's tree and `git clean -fd` deletes untracked files. Against the current tree that means the staged overnight `*.rs`, the modified `main.rs`/`mod.rs`/`windows.rs`, and untracked docs (including this audit) are wiped. `git clean` correctly omits `-x` (gitignored files like `target/` preserved) — the one mitigation.
- **Impact:** catastrophic local data loss, unattended; compounds with AUDIT-017 (runs against `main`).
- **Confidence:** confirmed (read `revert_to_clean` first-hand; no `current_dir`, no worktree anywhere in the module).
- **Recommendation:** run each unit in a dedicated `git worktree` and scope all git ops with `.current_dir(worktree)`; refuse to start if the primary tree is dirty; never `reset --hard`/`clean -fd` a tree that may hold operator work.

#### AUDIT-019 — Overnight security-diff "revert" resets to the offending commit itself, leaving the flagged commit in history
- **Severity:** High — defeats the §10.2 adversarial-review control: a policy/control/crypto/key-custody change the system explicitly flags is *not* actually undone. Latent until first live run.
- **CWE:** CWE-665 (improper initialization of revert base).
- **Location (verified first-hand):** `crates/rustynet-cli/src/vm_lab/overnight/executor.rs:401-403` — `let base = Self::current_head()?;` then `git reset --hard <base>` where `base` IS the agent's just-made commit; the security gate at `executor.rs:113-117` calls this then parks the cell.
- **Description:** `git reset --hard <bad-commit>` is a no-op against itself; only untracked residue is cleaned. The flagged commit remains on the branch (and, per AUDIT-017, on `main`) and would be merged if the operator accepts the branch. The mock test only counts `revert` calls; it never asserts the commit was removed, so the gap is untested.
- **Confidence:** confirmed.
- **Recommendation:** capture the pre-agent base rev per unit and `git reset --hard <unit_base>` (or `HEAD~N`); assert `HEAD == unit_base` after a security revert.

#### AUDIT-020 — Overnight agent spawned with no tool allowlist, no permission mode, and full inherited environment (no `--mcp-config`, no `.env_clear()`)
- **Severity:** Medium — no positive confinement over the unattended agent's tool/network/secret surface; the agent inherits the operator's broad Claude Code permissions and full env (API keys, cloud creds). Combined with the prompt-injection surface (reads journal/repo/VM content) there is no technical barrier to `git push`, secret exfil, or `sudo`.
- **CWE:** CWE-732 / CWE-77 (LLM command injection to ambient authority).
- **Location:** `crates/rustynet-cli/src/vm_lab/overnight/mod.rs:217-218` (`mcp_config_path: String::new()`, `allowed_tools: Vec::new()`); `agent.rs:25-36` (argv = `["claude","-p",<prompt>]`, no `--permission-mode`/`--allowedTools`); `executor.rs:316` spawn with no `.env_clear()`.
- **Description:** good — `--dangerously-skip-permissions` is NOT passed. But with an empty MCP config the agent does not even receive the three MCP servers the design centers on (drift vs §8), and with no env scrub the operator's environment secrets are visible to the spawned process. The only barriers to a hijacked agent are prompt prose, the oracle (catches only false-green), and the (incomplete) path denylist (AUDIT-001) — none stops an injected push/exec/exfil.
- **Confidence:** confirmed (wiring); runtime permission posture depends on the operator's `~/.claude/settings.json`.
- **Recommendation:** wire `--mcp-config` + a minimal `--allowedTools`, set an explicit non-interactive permission mode, and `.env_clear()` + allowlist the spawned env. Never rely on prompt prose as a security boundary.

#### AUDIT-021 — Overnight per-unit agent timeout and wall-clock budget are not enforced against a hung agent
- **Severity:** Medium — `--agent-timeout-secs` (default 3600) and `--max-duration-secs` (default 36000) are parsed/printed but inert in the failure mode they exist for.
- **CWE:** CWE-400.
- **Location:** `crates/rustynet-cli/src/vm_lab/overnight/executor.rs:316-326` (`run_agent` uses blocking `.status()` with no timeout/kill); the duration check runs only between units (`executor.rs:205`).
- **Description:** a single wedged `claude -p` (or a hung orchestrate verify, also blocking at executor.rs:389) stalls the entire run with no upper bound, past morning, with lab VMs left mid-mutation. Recommendation: spawn with a watchdog (reuse the `rustynet-xtask gates` timeout/kill-process-group pattern) and treat timeout as NoProgress.

#### AUDIT-022 — Overnight crate denylist is case-sensitive (macOS case-insensitive FS bypass) and the live path is the default (no confirmation gate)
- **Severity:** Medium (case bypass) + Low (default-to-live).
- **CWE:** CWE-178 (improper case handling) / CWE-184.
- **Location:** `crates/rustynet-cli/src/vm_lab/overnight/safety.rs:47-58` — crate-name branch matches case-sensitively (`normalized.contains(format!("crates/{crate_name}/"))`) while the fragment branch lowercases; `crates/rustynet-cli/src/main.rs:3370` (`--dry-run` opt-in, live path is the default).
- **Description:** on the default case-insensitive macOS dev FS, a path like `crates/Rustynet-Policy/src/eval.rs` resolves to the real `rustynet-policy` crate but fails the case-sensitive crate check → a policy/control/crypto change auto-commits without the §10.2 review. Separately, a bare `ops vm-lab-overnight ...` goes straight to the destructive live path (AUDIT-017/018/019) with no `--yes`/confirmation. Recommendation: lowercase before the crate-name comparison (match the fragment branch); invert the default so the live path requires an explicit opt-in flag. (See also AUDIT-001 for the missing-crates dimension of this denylist.)

### Area: backend adapters (rustynet-backend-*, rustynet-tun)

#### AUDIT-023 — `SyncDevice::from_raw_fd` is a safe `fn` that takes fd ownership and closes it on Drop (unsound ownership transfer through a safe signature)
- **Severity:** Low — no live bug (sole caller transfers ownership correctly); latent double-close/cross-fd-close for any future safe caller.
- **CWE:** CWE-758 / CWE-672.
- **Location:** `third_party/rustynet-tun/src/lib.rs:226` (`pub fn from_raw_fd(fd: RawFd) -> io::Result<Self>`, macOS), Drop at `:237-246` (`libc::close`). Sole caller: `userspace_shared_macos/tun.rs:965` (transfers via `OwnedFd::into_raw_fd()`, correct).
- **Recommendation:** mark `unsafe fn` with a `# Safety` contract, or accept `OwnedFd` so the type system enforces the transfer.

#### AUDIT-024 — Windows WireGuard config render leaves a plaintext private key in a non-zeroized heap `String`
- **Severity:** Low — local memory-disclosure (core dump/scrape) only; not network-reachable. Inconsistent with the userspace engine, which uses `Zeroizing`.
- **CWE:** CWE-316 / CWE-226.
- **Location:** `crates/rustynet-backend-wireguard/src/windows_command.rs:272-301` (`render_config` does `rendered.push_str(private_key.as_str())` into a plain `String`, returned/DPAPI-protected/dropped un-zeroized); used by `sync_persistent_config` (:132-138).
- **Recommendation:** build the rendered config in `Zeroizing<String>` and pass `Zeroizing` bytes into `protect_config_bytes`.

### Area: vendored boringtun (third_party/boringtun)

Provenance verified: Cloudflare boringtun **0.7.0** (upstream git `cdf3b245...`), vendored in a single squash commit `929b1d8`. Diff vs the pristine crate = 9 files; the only crypto change is a faithful ring→RustCrypto AEAD swap (identical IETF ChaCha20-Poly1305 primitive) + `subtle` constant-time compares; Noise/cookie/rate-limiter/replay-window logic is byte-identical to upstream. The entire **compiled** surface contains ZERO `unsafe` (the `device/ffi/jni` unsafe files are dead — not declared in `lib.rs`, their enabling features+deps removed). No applicable RUSTSEC advisory for 0.7.0; `curve25519-dalek` resolves to 4.1.3 (RUSTSEC-2024-0344 fixed).

#### AUDIT-025 — Userspace boringtun engine never drives `Tunn::update_timers` / `RateLimiter::reset_count`: no proactive rekey, no persistent keepalive, rate-limiter latches under-load permanently
- **Severity:** Medium — forward-secrecy-refresh and connection-liveness degradation **if** the `userspace_shared` (boringtun) engine carries live traffic. Default backend is command-mode `wg`/wireguard-go and the engine methods carry `#[cfg_attr(not(test), allow(dead_code))]`, so this reads as a pre-production wiring gap rather than a live exposure — confirm before shipping the userspace dataplane.
- **CWE:** CWE-324 / CWE-665.
- **Location:** `crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs` drives `Tunn` only via `encapsulate`/`decapsulate` (lines 270, 307); `Tunn::new(...,None,None,idx,None)` (141-148). Workspace grep for `update_timers`/`reset_count`/`timer_tick` = zero call sites.
- **Description:** boringtun's `timers.rs::update_timers` (which also calls `rate_limiter.reset_count()`) is never invoked. Consequences: no rekey at `REKEY_AFTER_TIME`; no keepalive (NAT lapse); the per-peer `RateLimiter.count` never resets so `is_under_load()` latches `true` permanently after 10 lifetime handshakes (fail-safe over-enforcement of cookies, not a flood bypass — RN-13's mac1/cookie path IS present and invoked on every `decapsulate`).
- **Confidence:** High that the calls are absent; Medium on severity (engine appears pre-production).
- **Recommendation:** drive `update_timers` on a ~1s tick (and pump the resulting outputs) before the engine carries real traffic; regression-test that rekey occurs after `REKEY_AFTER_TIME`.

#### AUDIT-026 — `.unwrap()` on AEAD/cipher init in boringtun crypto paths; pre-release crypto version requirements in the fork manifest
- **Severity:** Low / Info.
- **Location:** non-attacker-reachable `.unwrap()` on infallible key/cipher init at `third_party/boringtun/src/noise/handshake.rs:106,116,147`, `session.rs:215,252` (decrypt paths correctly use `.map_err(...)?`); `third_party/boringtun/Cargo.toml` requires `chacha20poly1305 = "0.10.0-pre.1"`, `aead = "0.5.0-pre.2"` (lockfile resolves to stable 0.10.1/0.5.2).
- **Recommendation:** propagate the crypto-init `unwrap()`s to satisfy CLAUDE.md §10.2 (functionally inert today); tighten the `-pre` version requirements to stable. Cleanup: delete the dead `device/ffi/jni` unsafe files from the vendored copy so a future feature edit cannot silently re-arm them.

### Area: rustynet-windows-native (Win32 FFI) + Windows key custody

#### AUDIT-027 — Windows encrypted-file key-custody ACL check is a no-op `Ok(())` (RN-33 confirmed; elevated): the encrypted-at-rest fallback performs no permission/ACL/symlink enforcement on Windows
- **Severity:** High — fail-open on a trust-sensitive workflow (CLAUDE.md §3/§4: "encrypted-at-rest fallback with strict permissions and startup permission checks"). A real, sound SDDL validator exists in-tree and is simply not called here. (Prior review rated RN-33 Low; the dedicated Windows FFI review rates it High because it is an actual fail-open on the custody path, not just a missing feature. See §8 reconciliation.)
- **CWE:** CWE-732 / CWE-280.
- **Location:** `crates/rustynet-crypto/src/lib.rs:1549-1554` (`validate_key_custody_permissions`, `#[cfg(not(unix))] => { let _ = (...); Ok(()) }`); reached by `read_encrypted_key_file` (:1460) and `write_encrypted_key_file` (:1396). The sound validator `rustynet_windows_native::inspect_file_sddl` is imported (crypto lib.rs:18) and used on the DPAPI path (`validate_windows_dpapi_root/file`, :1010/:1027) but NOT on the encrypted-file fallback.
- **Description:** the Unix arm enforces exact `0o700`/`0o600`; the Windows arm validates nothing and returns `Ok(())`. An encrypted signing-key file in a loosely-ACL'd / inherited-ACE directory passes custody validation and is loaded. The DPAPI store path does enforce SDDL, so the gap is the fallback path only.
- **Confidence:** confirmed (the validator exists and is unwired here).
- **Recommendation:** call `inspect_file_sddl` on both directory and file and apply the DPAPI path's SYSTEM/Administrators-only + symlink rejection; until wired, return `Err(PermissionValidationUnavailable)` (fail closed), never `Ok(())`.

#### AUDIT-028 — DPAPI used with no secondary entropy: LocalMachine-scoped blobs (WG key, signing passphrase) decryptable by any same-machine principal
- **Severity:** Medium — defense-in-depth gap; confidentiality of the most sensitive blobs collapses to the file ACL alone (which, per AUDIT-027, is unvalidated on the fallback path).
- **CWE:** CWE-311 / CWE-522.
- **Location:** `crates/rustynet-windows-native/src/lib.rs:335-396` (`dpapi_protect`/`dpapi_unprotect` hardcode `pOptionalEntropy = null()`; `description` is a label, not entropy); callers `key_material.rs:250`, `windows_command.rs:630` use `WindowsDpapiScope::LocalMachine`.
- **Recommendation:** add an `entropy: &[u8]` parameter and thread a per-install/per-blob secret (itself held in the OS secure store) through `pOptionalEntropy` on protect and unprotect.

#### AUDIT-029 — Decrypted DPAPI plaintext buffer is `LocalFree`d without zeroization
- **Severity:** Medium — window of plaintext key residue in freed heap (heap-spray / crash-dump / cold-boot).
- **CWE:** CWE-244 / CWE-226.
- **Location:** `crates/rustynet-windows-native/src/lib.rs:1286-1298` (`blob_to_vec`): copies `blob.pbData` (decrypted key material) into a `Vec`, then `LocalFree(blob.pbData)` without zeroing the source. Callers `Zeroizing`-wrap the returned copy but cannot reach the freed source buffer.
- **Recommendation:** zero `blob.pbData[..cbData]` (volatile/`zeroize`) before `LocalFree` on the unprotect path.

#### AUDIT-030 — Windows FFI hygiene: interior-NUL truncation in `to_wide`, LocalAlloc leak on UTF-16 decode error, under-aligned struct deref
- **Severity:** Low / Info (none currently reachable; the full Win32 unsafe inventory was reviewed and every block is otherwise sound — no double-free/UAF/BOOL-confusion).
- **Location:** `crates/rustynet-windows-native/src/lib.rs:1300-1307` (`to_wide`/`to_wide_os` accept interior NUL → silent truncation; an ACL-inspect target could diverge from the path actually opened — CWE-158/367); `:1241-1244` (`owned_pwstr_to_string` early-`?` skips `LocalFree` → leak on decode error — CWE-401); `:863-916,1051-1054` (`Vec<u8>`-backed `&*TOKEN_USER`/`TOKEN_GROUPS`/`IP_ADAPTER_ADDRESSES_LH` deref relies on allocator over-alignment — CWE-704, technically UB, benign on Win64).
- **Recommendation:** reject interior NUL with `Err`; `LocalFree` before the fallible decode; back pointer-bearing structs with over-aligned allocations or use `read_unaligned`.

### Area: rustynet-relay (zero-ingress ciphertext relay)

#### AUDIT-031 — Unbounded per-node `HelloLimiter.counts` map keyed by unauthenticated attacker-chosen `node_id` (pre-signature): remote memory-exhaustion DoS
- **Severity:** High — remote unauthenticated OOM of the relay (DoS of a security-critical availability path; violates SecurityMinimumBar High-7 relay abuse controls).
- **CWE:** CWE-770 / CWE-400.
- **Location (verified by the relay reviewer):** `crates/rustynet-relay/src/transport.rs:954-983` (`HelloLimiter::check` does `counts.entry(node_id.to_owned()).or_insert(...)` — grows, never evicts/caps), reached at `transport.rs:315` (`validate_hello` Check 1) **before** the ed25519 signature check (Check 2); `node_id` length is bounded only by the ~64 KiB datagram (`parse_relay_hello`, main.rs:685). `cleanup_idle_sessions` prunes the nonce store + packet `RateLimiter` but NOT `hello_limiter`.
- **Description:** an attacker sends `RelayHello` (type `0x01`) with a unique, padded `node_id` per packet; the map entry is inserted before signature verification, so no valid token is needed. The only gate is the per-IP `PreAuthHelloLimiter` (50/sec/IP). Single non-spoofed IP: ~50×64 KiB/sec ≈ 11.5 GB/hour permanently-retained; with source-IP spoofing across up to 4096 per-IP buckets, far worse. Even tiny ids grow the map unbounded.
- **Confidence:** High (no prune/cap exists; key set pre-signature; node_id uncapped).
- **Recommendation:** cap the `counts` map size and reject new ids when full (mirror `PreAuthHelloLimiter`); prune stale windows on the cleanup tick; cap `node_id`/`peer_node_id` length in `parse_relay_hello`. Regression-test that flooding unique ids keeps the map bounded.

#### AUDIT-032 — Relay control-port log/IO amplification: non-HELLO datagrams bypass the pre-auth limiter and emit one unbounded `eprintln!` each
- **Severity:** Medium — CPU/stderr-IO DoS + log-spam/disk-fill, fully bypassing the only pre-auth throttle; reflection at ≤1:1 on the reject path.
- **CWE:** CWE-779 / CWE-400.
- **Location:** `crates/rustynet-relay/src/main.rs:422-441` (`handle_control_packet` — the `PreAuthHelloLimiter` is consulted only inside the `RELAY_HELLO_MSG_TYPE` arm); unknown message types fall to `Err(...)` logged per-packet at `main.rs:388` with the source address; reject paths also log (`:458`,`:524`).
- **Recommendation:** apply the per-IP pre-auth limiter to all inbound control datagrams before any logging/response; rate-limit/sample the reject/error logs; drop (no reply) on unknown message types.

#### AUDIT-033 — Relay dataplane forwarding serializes on one global transport write-lock and busy-polls every allocated port
- **Severity:** Medium — CPU/contention/head-of-line-blocking DoS under flood and reconnect churn (the High-7 target conditions); rate-limited packets still take the global lock.
- **CWE:** CWE-400 / CWE-662.
- **Location:** `crates/rustynet-relay/src/main.rs:532-606` (`spawn_forward_task`): every forwarded datagram takes `self.transport.write().await` (:577) before the per-node token-bucket check inside `forward_packet` (`transport.rs:522-528`); each allocated port task busy-polls with `try_recv_from` + `sleep(100µs)` (:604) instead of awaiting `recv_from`, with up to 4096 such tasks.
- **Recommendation:** await `recv_from` on per-port sockets (each task owns its socket); move the cheap rate-limit check ahead of / out from under the global lock, or shard transport state.

#### AUDIT-034 — Relay logs peer source IPs and `node_id`s unredacted (vs PrivacyRetentionPolicy gossip-level redaction)
- **Severity:** Medium — privacy-retention violation + correlation surface; compounds AUDIT-032's log flood. (Secrets hygiene itself is clean — no key/nonce/signature bytes logged.)
- **CWE:** CWE-532.
- **Location:** `crates/rustynet-relay/src/transport.rs:407-411` (raw `node_id`); `main.rs:388,435,458,509-514,524` (full `from_addr`).
- **Recommendation:** redact/truncate peer IPs and `node_id`s (hashed thumbprint / short prefix, matching the existing `relay_id[..4]` style) and gate behind a rate-limited path.

#### AUDIT-035 — Relay lower-severity items: nonce-retention boundary, uncapped node_id length, keepalive ciphertext sniffing, lock-across-bind, health endpoint no timeout
- **Severity:** Low / Info.
- **Location:** `transport.rs:52,60` (`NONCE_RETENTION = MAX_TTL*2` holds the anti-replay invariant with equality → ~1s boundary replay window if a cleanup tick aligns with exact expiry — CWE-294, Low); `main.rs:685-707` + `transport.rs:285-301` (`node_id`/`peer_node_id` uncapped length, count-bounded only — CWE-770, Low, control-plane-signed so DiD); `main.rs:569-573` (keepalive detection reads first byte/len of opaque ciphertext — backend-specific assumption leaking into the agnostic relay, Info); `main.rs:289-324` (`allocate_port` holds locks across async `bind`, Info); `main.rs:924-972` (loopback-only health endpoint has no read/idle timeout → local slowloris, Info).
- **Recommendation:** give nonce retention strict slack over max validity (assert `<`, not `<=`); cap identity lengths at parse; document the min-ciphertext-size assumption or use a non-colliding keepalive marker; release locks across `bind`; add a health read timeout + concurrency cap.

### Area: rustynet-sysinfo + rustynet-cli diagnostics / test bins

#### AUDIT-036 — sysinfo fabricates TLS / certificate-expiry / cipher-strength / service-health security signals (CLI-reachable false assurance)
- **Severity:** Medium — security-relevant diagnostics report a confident "valid / not-expired / 256-bit TLS 1.3 / service healthy" regardless of reality.
- **CWE:** CWE-693 / CWE-655.
- **Location:** `crates/rustynet-sysinfo/src/lib.rs`: `tls_certificate_expiry_all_internal` Linux `:4819-4828` computes `is_expired` then **shadows it with `let is_expired = false;`** (dead), macOS `:4877` / Windows `:4909-4915` hardcode `is_expired:false, days_until_expiry:0` — the cert-expiry checker can never report expiry on any platform; `tls_cipher_suite_strength_internal` Windows `:5203-5211` returns hardcoded `TLS_AES_256_GCM_SHA384/TLSv1.3/256` on any successful connect; `tls_check_internal` `:3252-3258` always `tls_available:true, certificate_valid:true`; `service_check_internal` `:3172-3178` always `daemon_running:true`. Wired into CLI diagnostics at `main.rs:16686,16758`.
- **Confidence:** High (dead shadow + hardcoded returns under explicit "STUB IMPLEMENTATIONS" banners).
- **Recommendation:** implement real parsing (days-until-expiry from `notAfter`; negotiated cipher) or return an explicit `unknown/unsupported` state instead of a confident "valid"; delete the dead `is_expired` line at :4819.

#### AUDIT-037 — `live_chaos_signed_state_adversarial_test` reports `status=pass` / `expected_result=reject_fail_closed` without ever submitting a bundle to a daemon (false live-assurance)
- **Severity:** Medium — the emitted report (consumed into the live-lab run matrix) can be mistaken for evidence the daemon actually rejected replay/forgery; it only checks fixture-existence.
- **CWE:** CWE-693 / test-validity.
- **Location:** `crates/rustynet-cli/src/bin/live_chaos_signed_state_adversarial_test.rs:198-222` (`render_stage`: `status = if scenario_values.is_empty(){"fail"}else{"pass"}`; `measured_recovery_secs` hardcoded 0; `production_state_mutation:false` asserted not measured), driven by `run()` (:128-163) which only does generate→validate→render. The `security_invariants.offline_only:true` field is honest (why this is Medium not High).
- **Recommendation:** rename to reflect "offline fixture preparation" or strip the `expected_result`/`status=pass` framing; keep the live verdict solely in the daemon-facing bins (`real_wireguard_signed_state_tamper_e2e`).

#### AUDIT-038 — sysinfo Windows PowerShell `-Command` strings built with interpolated host/path (injection-shaped sink; operator-arg today)
- **Severity:** Medium — genuine injection sink violating CLAUDE.md §4 ("no shell construction with untrusted values") and the project's own recorded lesson that `powershell -Command "<script>"` is not safe param-binding; immediate exploitability low (operator-supplied args today), becomes exploitable if any caller feeds config-/network-derived values.
- **CWE:** CWE-78.
- **Location:** `crates/rustynet-sysinfo/src/lib.rs:5200` (`...Create('https://{}:{}')...`, host from `main.rs:16753`), `:4903` (`...X509Certificate2('{}')...`), `:6265,6273` (`Get-ChildItem -Path '{}'`). Linux/macOS counterparts use argv (`openssl`/`du`/`find`) and are NOT vulnerable.
- **Recommendation:** pass values as bound parameters (`-File` + `-ArgumentList`, or `param()`/env) or validate against a strict allow-list before interpolation; mirror the Linux/macOS argv discipline.

#### AUDIT-039 — `live_linux_secrets_not_in_logs_test` under-detects (no native-base64 WG key scan; false-pass on empty journal); plus §6.D role/blind_exit spec gaps and a sysinfo underflow
- **Severity:** Low (cluster).
- **Location & detail:** `crates/rustynet-cli/src/bin/live_linux_secrets_not_in_logs_test.rs` scans only 64/32-char hex + DER base64 prefixes — a WG key in native base64 (`[A-Za-z0-9+/]{43}=`) slips through, and the journal fetch uses `unwrap_or_default()` with no `line_count>0` assert → empty/failed journal yields PASS (CWE-693). `rustynet role set` lacks the §6.D-9 `platform-blocked` typed error (no platform param in `plan_concrete_actions`; no `RoleCliError::PlatformBlocked`) so a gated role on Windows can partially apply `AdvertiseDefaultRoute` before an installer fails (`main.rs:17196-17213`, `role_cli.rs:275-472`). §6.D-2 typed-confirmation for blind_exit entry/exit is not present on the reviewed CLI/wizard surfaces (env-var provisioning via `normalize_role` bypasses any confirmation); the practical posture (hard-blocked leave, flag-gated non-auto-executing enter) is arguably equivalent but the literal control + test are absent. `key_expiry_internal` (`rustynet-sysinfo/src/lib.rs:1770,1793,1818`) `now - since_epoch` underflows on a future-dated key mtime (debug panic / release wrap-to-fail-safe; CWE-191) — use `saturating_sub`.
- **Recommendation:** add native-base64 WG-key scanning + assert journal non-empty; gate `RoleCommand::Set` on `HostProfile` with a `PlatformBlocked` error before side-effects; add a typed-confirmation prompt (or reconcile §6.D-2 wording) with a test; `saturating_sub` the key-age math.

### Area: rustynet-control (trust core) + rustynetd daemon/dataplane (confirmations of prior Highs)

#### AUDIT-040 — Non-deterministic membership reducer makes revocation / key-rotation / capability-change updates unappliable and breaks snapshot+log replay (NEW)
- **Severity:** High — disables a security-critical control (node revocation and node key rotation cannot be durably applied) and breaks deterministic state reconstruction after restart. Fail-CLOSED in direction (over-rejection / trust-core self-DoS, not a trust bypass), but it means a compromised node cannot be revoked via the signed-update path and the daemon cannot rebuild membership once such an op is logged. Violates CLAUDE.md §8 "deterministic, testable state transitions."
- **CWE:** CWE-697 (incorrect comparison) / non-deterministic trust-state transition.
- **Location:** `crates/rustynet-control/src/membership.rs` — `reduce_membership_state` stamps `node.updated_at_unix = unix_now()` at :1156 (`SetNodeCapabilities`), :1175 (`RevokeNode`), :1187 (`RestoreNode`), :1200 (`RotateNodeKey`); `unix_now()` (:1836) reads `SystemTime::now()` directly, ignoring the `now_unix` argument threaded into `apply_signed_update` (:728-731). `canonical_payload` (:262-284) hashes `node.{i}.updated_at_unix` into the state root.
- **Description:** `apply_signed_update` recomputes the post-state and compares `next.state_root_hex()` to the signed `record.new_state_root`. Because the reducer stamps the *current* wall-clock second (not a value carried in the signed operation, nor the `now_unix` arg), the recomputed root for these four operations almost never equals the root the signer computed earlier → `NewStateRootMismatch` → rejected. `AddNode`/`SetQuorum`/`RotateApprover`/`RemoveNode` are unaffected (no per-node timestamp), which is why the passing tests and the enrollment bridge only ever exercise `AddNode`. Reached in production: `daemon.rs:3870/7494/10812` and `cli/main.rs:6414` call `replay_membership_snapshot_and_log(..., unix_now())` at bootstrap — once a `RevokeNode`/`RotateNodeKey`/`RestoreNode`/`SetNodeCapabilities` entry is in the audit log, replay re-derives at a new second → mismatch → bootstrap/replay fails.
- **Confidence:** confirmed (non-determinism + reachable via the production replay path; the test suite's gap — only `AddNode` round-trips — corroborates).
- **Recommendation:** make the reducer deterministic — derive `updated_at_unix` from data carried in the signed record (e.g. `record.created_at_unix`) or copy a value carried in the operation. Add sign→apply→replay round-trip tests for all four ops.

#### AUDIT-041 — Break-glass trust-hardening secret compared with non-constant-time `!=`
- **Severity:** Medium — timing oracle on the secret that disables the entire trust-hardening control; lone deviation from the crate's otherwise-consistent `subtle`/`ct_eq` discipline.
- **CWE:** CWE-208 / CWE-385.
- **Location:** `crates/rustynet-control/src/scale.rs:268` (`disable_trust_hardening`): `if submitted_break_glass_secret != config.break_glass_secret { return Err(...) }` — `String` `!=` short-circuits on first differing byte.
- **Recommendation:** compare via `subtle::ConstantTimeEq` over the byte slices (match `admin.rs`'s CSRF check). Also (AUDIT-042) `TrustHardeningConfig` (scale.rs:221-225) derives `Debug` exposing the plaintext `break_glass_secret` — give it a redacting `Debug` like the crate's other secret types.

#### AUDIT-042 — Lower-severity control-crate items: break-glass secret in derived Debug; membership string fields not validated against canonical-payload separators
- **Severity:** Low.
- **Location:** `crates/rustynet-control/src/scale.rs:221-225` (`#[derive(Debug)]` on `TrustHardeningConfig` with plaintext `break_glass_secret`); `crates/rustynet-control/src/membership.rs` `MembershipState::validate` (:188-241) / `canonical_payload` (:438-514) embed `node_id`/`owner`/`network_id`/`update_id`/`target`/`reason_code`/`policy_context`/`roles` as `key={value}\n` with only `trim().is_empty()` checks — no rejection of embedded `\n`/`=` (contrast `lib.rs`'s `is_single_line_payload_value`). Fail-closed in practice (duplicate-key rejection + state-root recompare turn an injected line into a decode error / `NewStateRootMismatch`, and it requires an authorized signer), so a robustness/canonicalization-ambiguity gap, not a demonstrated forgery.
- **Recommendation:** redacting `Debug` for `TrustHardeningConfig`; apply a single-line/charset validator to all membership string fields at construction/validate so malformed identifiers are rejected at the boundary.

#### AUDIT-043 — Windows forwarding/NAT helpers use `powershell -Command "<script>" <alias>` trailing-arg concatenation with a metacharacter-permissive interface-alias validator (latent SYSTEM-context injection)
- **Severity:** Low — operator/admin-trust (the alias is `--wg-interface`/auto-detected; renaming a Windows adapter needs admin and the daemon runs as SYSTEM), so a footgun/defense-in-depth gap, not privilege escalation in the common deployment. Flagged because it is a real latent injection in the *production reconcile path* inconsistent with the team's own NRPT `reg.exe` hardening and HB-6.
- **CWE:** CWE-78.
- **Location:** `crates/rustynetd/src/phase10.rs:5661` (`windows_powershell_command_args` appends the alias after `-Command "<script>"`); sinks `WINDOWS_PS_{GET,SET}_FORWARDING` (:3412/3424), `WINDOWS_PS_{NEW,REMOVE,ASSERT}_NAT` (:3455-3470), `WINDOWS_PS_PREFLIGHT_EXIT_SERVING` (:3567); validator `validate_windows_interface_alias` (:5613) rejects only non-ASCII/control/`=` and permits `; & | \` $ ( ) " '` and space.
- **Description:** PowerShell appends every token after `-Command "<script>"` and re-parses it — the exact failure the team fixed for NRPT by moving to `reg.exe` argv. An alias like `Ethernet 2; Stop-Service rustynetd` passes the validator and runs the trailing statement as SYSTEM. The mesh-CIDR arg is safe (typed `ManagementCidr`); rule-name args are constants.
- **Recommendation:** reject PowerShell metacharacters in `validate_windows_interface_alias`, or pass aliases via a param-binding mechanism that doesn't re-parse trailing args (the NRPT `reg.exe` pattern).

#### AUDIT-044 — daemon rollback/restore best-effort discards (state divergence)
- **Severity:** Low.
- **CWE:** CWE-252 / CWE-754.
- **Location:** `crates/rustynetd/src/daemon.rs:7685` (`restore_key_backups`: `let _ = self.apply_interface_private_key_runtime(path)` — live-interface re-apply of the prior WG key on rotation rollback is discarded while the file restore uses `?`; mitigated by the state machine's dedicated `rollback_wg_apply` at :8561 but silently divergent in the interim); `daemon.rs:6688` (legacy non-auto-tunnel exit-restore path: `let _ = set_exit_node(...)` leaves `selected_exit_node` set so status reports an exit the dataplane never programmed; next reconcile re-evaluates).
- **Recommendation:** propagate the rollback re-apply error; on exit-restore failure clear `selected_exit_node` so status and dataplane agree.

#### RECONCILED-HIGH RN-03 / RN-04 / RN-10 — prior High/Medium findings re-verified STILL OPEN (and RN-03 worse) by two independent reads
- **RN-03 (High, fail-open killswitch) — STILL OPEN, recount worse.** Both the dataplane reviewer and the daemon reviewer independently counted **38-39** `let _ = self.controller.force_fail_closed(...)` sites in `daemon.rs` (e.g. :4343, :6510, :6521, :6593, :7721, :7798, :7912, :8151, :8161), **100% swallowed** — the prior review's "10 of 44" undercounted single-line forms; there is now no handled site. `restrict_recoverable/permanent` (daemon.rs:8285-8298) only set an in-memory flag with no network effect, so `block_all_egress` is the only thing that closes egress. The sibling test `phase10.rs:9581 force_fail_closed_returns_err_and_skips_state_transition_when_block_all_egress_fails` proves the discarded `Result` is exactly the "could not cut traffic" signal. On a persistent nft/helper failure the node keeps forwarding with stale/revoked trust while status claims "restricted." Mitigated (not Critical) by the 1s reconcile loop self-healing transient failures and `revoke_local_key_material` tearing the interface down separately. **Recommendation:** never `let _ =` the fail-closed primitive; on `Err` escalate (tear interface down as backstop and/or exit so a mandatory boot killswitch backstops).
- **RN-04 (High, bootstrap leak window) — STILL OPEN.** `phase10.rs:apply_dataplane_generation` calls `backend.start()` (:4386, interface up) and route apply (:4531/:4535) **before** `apply_firewall_killswitch` (:4541); the pre-protective boot killswitch (`linux_killswitch_boot.rs`) is invoked only from the explicit `--install-boot-killswitch` CLI subcommand (main.rs:1018), never from the daemon run path, and is Linux-only. On a fresh `Init` host there is a window with a live tunnel+routes and no `policy drop`. **Recommendation:** program a mandatory, cross-platform `policy drop` before `backend.start()`/route apply; gate backend start on the boot killswitch table's presence (the verifier exists).
- **RN-10 (prior Medium → re-rated High, corrupt rotation ledger fail-open) — STILL OPEN.** `daemon.rs:8432 load_rotation_ledger` returns `LocalKeyRotationLedger::genesis()` on any `load` `Err` (:8440-8453), discarding `current_epoch`/`archive`/replay-`watermark` — the rotation anti-rollback state for the long-lived WG identity key. The signature returns a plain value (not `Result`), so the caller cannot surface the error, directly contradicting the function's own doc comment (:8428-8431 "must not be silently reset … caller surfaces the error"); a second inline comment (:8443-8447) falsely claims rotation will "refuse" (genesis is `RotationState::Idle` ⇒ `ensure_idle` Ok ⇒ rotation proceeds from epoch 0). A torn write / crash-mid-rotation / tamper rewinds the rotation epoch. Re-rated High (from the prior review's Medium) because it discards anti-rollback/replay state on the identity key and the "contained downstream" claim depends on epoch-tagged verification that this very reset weakens. **Recommendation:** return `Result`, distinguish absent (→genesis) from corrupt (→`LedgerCorrupt`, refuse startup / hard fail-close); fix or delete the two misleading comments.

### Area: scripts / CI / supply chain

#### AUDIT-045 — macOS bootstrap leaves a `NOPASSWD: ALL` sudoers file on disk if the Homebrew install fails (no trap cleanup) — RN-32 escalated to High
- **Severity:** High — a passwordless-root sudoers entry for the desktop user can persist across reboots, giving any local code running as that user prompt-free root. (Prior review rated RN-32 Low; the dedicated review escalates because the `rm` is not trap-protected and `set -e` aborts before it on a common failure.)
- **CWE:** CWE-271 / CWE-732.
- **Location:** `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh:245-250` — `ensure_homebrew()` writes `${REAL_USER} ALL=(ALL) NOPASSWD: ALL` to `/etc/sudoers.d/rustynet-bootstrap-tmp` (:246), runs `curl … | /bin/bash` (:248-249), then plain `rm -f` (:250). Under `set -euo pipefail`, a Homebrew install failure/interrupt (the VM is frequently offline) aborts at :249 and :250 never runs; the `trap … EXIT` handlers elsewhere (:574/596/920/941) are scoped to other functions.
- **Impact:** persistent passwordless root for `REAL_USER`; even on success the grant is live for the multi-minute install window.
- **Confidence:** confirmed (RN-32 still present; escalated).
- **Recommendation:** install `trap 'rm -f "${sudoers_tmp}"' EXIT` immediately after creating the file; scope the grant to the specific commands Homebrew needs rather than `ALL=(ALL) NOPASSWD: ALL`.

#### AUDIT-046 — Release/CI GitHub Actions pinned to mutable tags, not commit SHAs (RN-16 confirmed open)
- **Severity:** Medium — the release job (`permissions: contents: write`) uses `softprops/action-gh-release@v2` to upload the Authenticode-signed `rustynetd.exe` + SBOM; a tag repoint/action compromise runs attacker code in the release pipeline and can tamper with the signed artifact.
- **CWE:** CWE-1357 / CWE-829.
- **Location:** `.github/workflows/release-windows.yml:49,158,205`; `.github/workflows/cross-platform-ci.yml:16,37,56,83` (`actions/checkout@v4`, `softprops/action-gh-release@v2`).
- **Recommendation:** pin every `uses:` to a full commit SHA (with a `# vX.Y` comment), Dependabot-managed.

#### AUDIT-047 — Shipped binaries built with a toolchain different from the pinned canonical one (RN-30 confirmed open)
- **Severity:** Medium — the artifact users run is not built with the audited/pinned compiler; misses std/compiler fixes; non-reproducible.
- **CWE:** CWE-1104 / reproducibility.
- **Location:** `rust-toolchain.toml:2` pins `1.88.0`; `release-windows.yml:55-56` and `cross-platform-ci.yml:93-95` build with `1.85.0`; `Bootstrap-RustyNetMacos.sh:351,743,748,758,763` uses floating `stable`. Linux bootstrap correctly reads the pinned channel.
- **Recommendation:** build the Windows release with `1.88.0` (or bump `rust-toolchain.toml` deliberately and align all jobs); make the macOS bootstrap read+install the channel from `rust-toolchain.toml` like Linux does.

#### AUDIT-048 — On-host bootstrap builds omit `--locked`, so installed binaries can diverge from the audited `Cargo.lock` (RN-15 only partially fixed)
- **Severity:** Medium — CI uses `--locked` everywhere, but the bootstrap `cargo build` that produces the binary actually installed on hosts does not, so it can pull semver-compatible deps never vetted by `cargo audit`/`cargo deny` (which ran against the committed lock).
- **CWE:** CWE-829.
- **Location:** `scripts/bootstrap/linux/rn_bootstrap.sh:445,453,456,457`; `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh:743,748,758,763`.
- **Recommendation:** add `--locked` to all bootstrap `cargo build` commands (online and `--offline`).

#### AUDIT-049 — Hostile-input network parsers have no fuzz target (assurance gap)
- **Severity:** Medium — the parsers that consume raw bytes from arbitrary network senders are unfuzzed; the per-parser reviews this audit found them bounded today, but there is no continuous coverage and these are exactly the classes where a regression silently reintroduces a panic/overflow.
- **CWE:** CWE-1120 (insufficient verification) / coverage-completeness.
- **Location:** existing fuzz targets (`fuzz/fuzz_targets/`) cover only `ipc_parse_command`, `membership_decode_state`, `membership_decode_signed_update`. No target for: relay frames `parse_relay_hello`/`parse_relay_token` (`rustynet-relay/src/main.rs:674,730`, fed from `recv_from` — arbitrary UDP); port-mapper UPnP/SSDP/SOAP/NAT-PMP/PCP parsers (`rustynetd/src/port_mapper.rs:345,376,785,912,1300,1331,1519,1736,1887` — LAN IGD XML/UDP); STUN/traversal `parse_stun_xor_mapped_address`/`parse_coordination_payload` (`rustynetd/src/traversal.rs:460,610`); signed DNS-zone wire `parse_signed_dns_zone_bundle_wire` (`rustynet-dns-zone/src/lib.rs:290`, signature-gated → lower).
- **Recommendation:** add fuzz targets for the relay frame, port-mapper, and STUN/traversal parsers (the relay + port-mapper ones are the highest priority — unauthenticated remote/LAN bytes).

#### AUDIT-050 — Supply-chain / gate lower-severity cluster
- **Severity:** Low / Info.
- **Detail & location:**
  - SSH TOFU deviation: `scripts/e2e/live_linux_path_handoff_under_load_test.sh:70` uses `StrictHostKeyChecking=accept-new` instead of sourcing the hardened `live_lab_common.sh` (`=yes` + pinned non-symlink known_hosts) — contradicts `scripts/e2e/README.md:55`. CWE-322. (Low, lab-only.)
  - Bypassable gate: `scripts/ci/windows_cross_compile_gate.sh:31-34,41-44` prints `SKIP` + `exit 0` when rustup/targets are absent (contrast `windows_compile_check.sh:43-66` which `exit 2`). CWE-693. Mitigated by the authoritative `windows` CI job doing a real build. (Low/Med — fail closed when used as a required gate.)
  - Unsigned SBOM: `release-windows.yml:190-209` ships `cargo metadata` JSON + a co-located `sbom.sha256` (integrity, not authenticity; not CycloneDX/SPDX); a `sign-release-artifact`/provenance path exists in `ops_ci_release_perf.rs` but is not invoked by the SBOM job. CWE-345. (Low — the binary itself is Authenticode-signed.) Note SecurityMinimumBar §3-10 requires "SBOM generated and retained" (met) but the signing intent is unrealized.
  - `rustynet-windows-native/Cargo.toml` has no `[lints]` block at all (the most unsafe-heavy crate inherits no workspace lints) — RN-14 residual; matches AUDIT-004's dimension. Add `[lints.rust] unsafe_code = "deny"` (or documented `"allow"`). CWE-1126. (Low.)
- **RN-31 (deny.toml yanked/unmaintained):** assessed **acceptable** — `[advisories] version=2` with no explicit keys relies on cargo-deny v2 defaults, but `cargo audit --deny warnings` in every CI job escalates yanked→error, so yanked IS caught; no suppressed advisories. Recommend setting `yanked = "deny"` explicitly for clarity. `[bans] multiple-versions = "warn"`, `wildcards = "allow"` (no wildcard deps present today).

### Area: rustynetd remaining modules (port_mapper / traversal / gossip / fetcher / key_material / relay_client / ipc)

This subsystem's load-bearing trust-boundary code (gossip parse+accept+watermark, traversal coordination verify-before-record, the production `daemon::StateFetcher` ordering, key custody atomic writes, IPC envelope, NAT-PMP/PCP/STUN parsers, relay-client token handling with source-address ack filtering) was read line-by-line and is **well-hardened and fail-closed** — see §7. Net-new findings here are Low/Info only.

#### AUDIT-051 — uPnP IGD SSRF: daemon fetches attacker-controlled SSDP `LOCATION` / `controlURL` with no host restriction
- **Severity:** Low — uPnP is opt-in (`upnp_enabled=false` by default, only under `--port-mapping-mode auto`) and the attacker must already be on the LAN (same trust position as the gateway); blind SSRF (fixed SOAP body).
- **CWE:** CWE-918.
- **Location:** `crates/rustynetd/src/port_mapper.rs:1938-1973` (`discover_one` → `http_get(&device.location_url)`), `:1736-1788` (`parse_http_url` rejects control chars + requires `http://` but does not restrict the host); `location_url`/`controlURL` come verbatim from an SSDP responder (`parse_ssdp_location:1300`).
- **Impact:** a malicious LAN device answering the M-SEARCH can point the daemon's GET + SOAP-POST at any reachable `host:port` (e.g. `169.254.169.254`, internal admin endpoints).
- **Recommendation:** require the `LOCATION`/`controlURL` host to equal the detected default-gateway IP, or restrict to RFC1918/RFC4193/link-local; reject public/metadata addresses.

#### AUDIT-052 — Dead, divergent signed-state fetcher (`fetcher.rs`) with latent panics and a stale "mTLS" claim
- **Severity:** Low — not reachable in production (the daemon uses its own `daemon::StateFetcher`); latent if ever wired.
- **CWE:** CWE-1041 / CWE-248.
- **Location:** `crates/rustynetd/src/fetcher.rs` (whole module, zero non-test importers). `RefreshScheduler::next_refresh_at` panics on `jitter_max_secs==0` (`rand::random::<u64>() % …`, :449) and on `SystemTime` under/overflow (`:447`,`:450`); `fetch_bundle` comment claims "mTLS" (:100-101) but transport is plaintext HTTP (:143); `WatermarkStore::persist_to_disk` (:398-420) is non-atomic and chmods after writing (Info; the production `gossip_runtime::write_gossip_watermark` does it atomically).
- **Recommendation:** delete the module, or make it the single fetcher and fix the panics (guard the modulo, `checked_add`/`checked_sub` on time math) + atomic watermark write. (Note this is a second "audited-looking but dead" module alongside RN-02's `dataplane.rs` — see theme §5.2/§5.3.)

#### AUDIT-053 — Relay REJECT reason logged without control-char sanitization (log injection)
- **Severity:** Info.
- **CWE:** CWE-117.
- **Location:** `crates/rustynetd/src/relay_client.rs:1021-1027` (`parse_relay_hello_ack` REJECT branch) — `String::from_utf8_lossy(&data[1..])` becomes the logged error without the `sanitize_log_excerpt` stripping applied to other untrusted wire fields; a rogue relay (semi-trusted, in the signed relay-fleet bundle) could embed CR/LF/escape sequences (bounded to the 1500-byte recv buffer).
- **Recommendation:** strip/escape control chars on the reject reason before constructing the error.

## 5. Cross-cutting themes

Recurring systemic patterns that produced multiple findings — fixing the pattern is higher-leverage than fixing each instance:

1. **Swallowed `Result` on a security-control side effect (`let _ = …`).** The single most load-bearing theme. RN-03 (38-39 swallowed `force_fail_closed` in daemon.rs), AUDIT-044 (rollback re-apply / exit-restore), and the relay's best-effort logging all share the shape: the operation that *enforces* the security state returns a `Result` that is discarded, so an enforcement failure is invisible and the system continues as if it succeeded. In a fail-closed system this is the canonical fail-open. Systemic fix: a lint/grep gate forbidding `let _ =` on the fail-closed/killswitch/trust-persist primitives, plus an "on enforcement error, escalate hard" convention.

2. **Doc/comment claims that contradict the code (assurance drift).** RN-10 (doc says "must not be silently reset," code resets to genesis, *plus* a second comment falsely claiming fail-closed), AUDIT-008 (prior review "no build.rs anywhere" — now false), AUDIT-002 ("unsafe only in windows-native/vendored" — misses rustynetd's macOS module), AUDIT-036/037 (test/diagnostic names and `pass_criterion` strings claiming verification that the code does not perform). A reviewer who trusts the prose validates a control that does not run. Systemic fix: treat a security doc-comment as a testable claim; delete or correct comments that the code contradicts.

3. **Verification scoped to where it was first needed, not everywhere it is needed.** RN-22 `verify_strict` (fixed in crypto+control, missed in dns-zone/rustynetd/cli — AUDIT-005); `is_valid_key_identifier` validation (macOS/Windows but not Linux — AUDIT-014); the backend-leakage gate (omits dns-zone — AUDIT-013); the secrets-hygiene content scan (3 dirs/5 extensions — AUDIT-012). A control lands at its first site and the equivalent sites silently diverge. Systemic fix: drive each control from a single enforcement helper + a gate that asserts no un-converted sites remain.

4. **Fail-open-on-empty / permissive default.** RN-05 (non-`node:` selectors → allow), RN-11 (empty membership → allow-all; empty `allowed_contexts` → matches all), AUDIT-001/AUDIT-031 patterns. Default-deny requires empty/missing/malformed to *deny*; several gates treat empty as "not configured = allow."

5. **Unbounded resource keyed by attacker-controlled, pre-authentication input.** AUDIT-031 (relay HelloLimiter map keyed by pre-signature node_id), AUDIT-032 (per-packet logging pre-auth), and the uncapped node_id length. Maps/logs that grow on unauthenticated input are DoS amplifiers. Systemic fix: cap-and-evict every attacker-keyed structure, and rate-limit *before* the signature check, not after.

6. **Windows-specific security weaker than Linux/macOS.** AUDIT-027 (key-custody ACL no-op), AUDIT-028/029 (DPAPI entropy/zeroize), AUDIT-024 (config key not zeroized), AUDIT-038/043 (PowerShell `-Command` injection sinks). The Windows port repeatedly lands the functional behavior but not the hardening that the Unix path has. (Note the headline RN-06/RN-07 Windows *killswitch* leak is now largely fixed — see §8 — so this theme is improving on the dataplane but persists in key custody and command construction.)

7. **Autonomy tooling outrunning its safety envelope.** The uncommitted overnight driver (AUDIT-001, 017-022): branch isolation, clean-tree-without-collateral, security-diff non-commit, time bounding, and agent confinement are each either unimplemented or defeated by a bug, while the marketing doc presents them as guarantees. New autonomous capability should not merge until its safety envelope is wired and tested.

## 6. Trust-boundary threat-model results

Per the §12.2 boundaries in the prior review, re-evaluated against current code:

- **TB1 Network → daemon (peers/relay/STUN/UPnP/DNS bytes):** parsers are bounded and panic-free (verified across membership, gossip, dns-zone, relay frames, STUN, port_mapper, backend uapi). Residual: signature verification is non-strict at several trust-state sites (AUDIT-005); relay pre-auth map is unbounded (AUDIT-031); port_mapper/relay/STUN parsers are unfuzzed (AUDIT-049). Gossip anti-replay (monotonic per-source sequence) and traversal nonce checks are sound; verify-before-apply ordering is correct in every daemon loader.
- **TB2 IPC control socket → daemon:** SO_PEERCRED per-command authz is enforced on every Unix command (read + mutating), fail-closed on `peer_uid` unavailable; role-based command gating (Admin-only mutations) verified; 4 KiB/16 KiB frame caps. Windows control pipe relies on a hardened SDDL (no per-command peer gate — documented asymmetry). Solid.
- **TB3 daemon → privileged helper:** model boundary — closed-enum program allowlist, per-program argv schema, argv-only exec, binary integrity (absolute+canonical+root-owned+non-writable), post-connect peer-cred (RN-17 fixed), direct-path `validate_request` (RN-19 fixed), absolute binary paths (RN-20 fixed in prod). Residual: helper accepts any uid==0 (RN-18, Low); private-key/pf-rules paths not pinned (RN-34/35, Info).
- **TB4 on-disk artifacts → daemon:** signed snapshots/ledgers are signature+watermark+digest gated with bounded reads and atomic writes (verified). Residual: corrupt rotation ledger resets to genesis instead of failing closed (RN-10, High); Windows encrypted-key custody ACL unchecked (AUDIT-027, High).
- **TB5 process memory ↔ at-rest key storage:** strong on Unix (zeroize on Drop + derived keys, strict perms, atomic+fsync writes). Residual: DPAPI plaintext not zeroized before LocalFree (AUDIT-029); Windows config render leaves plaintext key in a non-zeroized String (AUDIT-024); DPAPI no secondary entropy (AUDIT-028); envelope AAD/version binding absent (RN-08).
- **TB6 build/CI → released artifact:** CI uses `--locked` + fails loud on missing signing secrets + Authenticode self-verify. Residual: mutable action tags (RN-16/AUDIT-046), toolchain drift (RN-30/AUDIT-047), bootstrap omits `--locked` (AUDIT-048), unsigned SBOM, macOS bootstrap sudoers (AUDIT-045, High).
- **TB7 (new) agent/automation → host & repo (MCP servers, overnight driver):** the audit's net-new boundary. The MCP `lab_state` arbitrary host-file read/delete primitive (AUDIT-006, High) is fixed in uncommitted 2026-06-12 work; the overnight driver can still destroy the operator tree and commit to main unattended (AUDIT-017/018/019, High) and grants the spawned agent ambient authority (AUDIT-020). This boundary is the least mature and gates "can this tooling run unattended" = currently no.
- **Killswitch / dataplane leak prevention (AS4):** the central guarantee. RN-03 (swallowed fail-closed) + RN-04 (interface-before-killswitch) remain the highest-residual-risk pair: on a transient nft/helper fault during first bootstrap a node can egress cleartext while reporting "restricted." Windows killswitch RN-06 (IPv4 LAN leak) is now **fixed** (scoped WFP egress allows) and RN-07 (IPv6) is largely fixed (block rule added; assert-drift + address-flush gaps remain). Linux exit-serving DNS ordering (RN-12) still leaks for explicit-resolver apps on exit nodes only.

## 7. Verified-solid controls + refuted hypotheses (coverage evidence)

Controls confirmed present AND backed by enforcement + test (first-hand or via the per-crate reads):
- **Architecture boundary (CLAUDE.md §8):** domain crates (control/policy/dns-zone/crypto) have zero backend/wireguard/boringtun deps; the only `wireguard` token in domain src is an error-message string. Dependency graph is an acyclic DAG. `rustynet-backend-api` exposes only abstract types. (First-hand + 2 agents.)
- **No-placeholder mandate (§9):** zero real `TODO`/`FIXME`/`unimplemented!`/`todo!()` in production code (the grep hits are doc-comments and a scanner's own pattern list). "not yet implemented" strings are fail-closed `UnsupportedPlatform` errors. (First-hand.)
- **Crypto primitives:** vetted only (ed25519-dalek 2.x, XChaCha20-Poly1305, Argon2id @ OWASP params, subtle, HMAC); fail-closed CSPRNG (no ThreadRng fallback); fresh nonce+salt per envelope; zeroize on Drop + derived keys (RN-24 fixed); redacting Debug; constant-time secret/MAC compares (one exception, AUDIT-041). No custom crypto. (crypto + control agents, tests cited.)
- **boringtun integrity:** faithful 0.7.0 with a ring→RustCrypto AEAD swap that preserves the primitive; Noise/cookie/rate-limiter/replay-window byte-identical to upstream; zero unsafe in the compiled surface; anti-replay sliding window correct; decrypt paths fail closed. (boringtun agent, diff-vs-upstream.)
- **Signed-state verify-before-apply + anti-replay:** every daemon loader verifies signature → freshness → replay/watermark → then returns; watermarks persisted atomically (temp+sync_all+rename+parent fsync); quorum/owner/epoch-chain enforced; canonical-payload outer/inner cross-check defeats bundle re-framing. (daemon + control agents, tests cited.)
- **Privileged helper:** see TB3 — model boundary, multiple controls verified with tests.
- **macOS SCM_RIGHTS fd-passing (rustynetd unsafe module):** MSG_CTRUNC fails closed, fd reconstructed only when ≥0 and untruncated, CMSG sizing correct, bounded error payload, strong negative tests. (First-hand full read — AUDIT-003 is the only minor DiD note.)
- **Win32 FFI (windows-native):** full unsafe inventory reviewed — no double-free/UAF/BOOL-HRESULT confusion; correct size-then-fill, RAII guards, named-pipe UAC-filtered token check, WinVerifyTrust fail-closed. (windows-native agent.)
- **Relay auth/anti-abuse:** signed-token verify_strict before mutation, constant-time id compares, durable anti-replay nonce store, TTL+skew clamp, relay-id/peer-id binding (no open-relay/SSRF, no cross-session injection), oversized-payload drop, generic reject (no info leak), CSPRNG session ids. (relay agent, adversarial tests cited.)
- **systemd hardening:** NoNewPrivileges, ProtectSystem=strict, empty CapabilityBoundingSet, MemoryDenyWriteExecute, LoadCredentialEncrypted, UMask=0077, mandatory ExecStartPre boot-killswitch in the shipped unit, fail-safe ExecStopPost. (CLI + scripts agents.)
- **SSH harness:** StrictHostKeyChecking=yes + pinned non-symlink known_hosts + argv-only remote commands + UTF-16LE PowerShell encoding with NUL detection (one ad-hoc test deviates — AUDIT-050). (CLI + scripts agents.)

**SecurityMinimumBar.md control trace (enforcement point + verifying test, or finding):**
- §3.1 Proven crypto only — **verified solid** (vetted primitives; boringtun faithful; no custom crypto; AlgorithmPolicy fail-closed). Enforcement: rustynet-crypto + boringtun; tests cited §7.
- §3.2 Control-plane transport security (TLS 1.3 + signed peer data verified-before-apply) — signed-data-before-apply **verified solid** (every daemon loader); **finding** AUDIT-005 (13 non-strict ed25519 sites). TLS-1.3-enforced not exercised statically (no live control-plane TLS path read).
- §3.3 Auth/enrollment hardening (rate-limit, lockout, anti-replay, atomic one-time consume) — single-use consume is **verified solid** (atomic conditional UPDATE, TOCTOU-safe, tested); relay/enrollment anti-replay solid; **finding** RN-26 (`ConsumedTokenLedger::purge_expired` stub, not re-verified).
- §3.4 Secret/key handling (OS store, encrypted-at-rest perms+startup checks, zeroize, fail-closed trust state) — Unix **verified solid**; **High findings** AUDIT-027 (Windows custody no-op), RN-08 (envelope AAD), AUDIT-028/029/024 (DPAPI/render), RN-09 (systemd-cred gate).
- §3.5 Host-OS boundary enforcement — host-profile gating present (operator `normalize_role`, daemon runtime roots); `role set` platform-blocked gap = AUDIT-039 (§6.D-9).
- §3.6 Policy/privilege (default-deny ACL, RBAC, MFA) — default-deny evaluator **verified solid** + role-based IPC gating; **findings** RN-05/RN-11/RN-28 (default-allow gaps). MFA not exercised (web/admin UI not in the audited Rust paths).
- §3.7 Web/admin + privileged helper argv-only — privileged-helper **verified solid** (model boundary); CSRF/cookie/clickjacking are admin-UI controls not in the audited crates (residual unknown).
- §3.8 Data-plane leak prevention (tunnel + DNS fail-close, traversal replay-bounded, failover no-bypass) — **High/Medium findings** RN-03/RN-04 (killswitch fail-open/ordering), RN-12 (exit DNS), RN-25 (in-memory replay); Windows RN-06 **now fixed**, RN-07 largely fixed.
- §3.9 Audit/forensics (tamper-evident append-only) — role-transition + membership audit entries present and emitted on success/fail/abort (verified, control + daemon agents); integrity-chain depth not independently stress-tested.
- §3.10 Supply-chain (signed artifacts, SBOM, staged tracks) — Authenticode signing + fail-loud-on-missing-secret **verified solid**; **findings** AUDIT-046 (mutable tags), AUDIT-047 (toolchain), AUDIT-048 (bootstrap --locked), AUDIT-050 (unsigned SBOM).
- §6.B Bootstrap trust anchor (out-of-band owner pubkey, root-only ACL) — daemon refuses signed-state load without the anchor; ACL verifier present (Linux runtime ACL / Windows SDDL). Verified at the enforcement level; out-of-band delivery is operational.
- §6.C Anchor capability controls — signed capability advertisement + loopback-default bundle-pull + single-use token ledger + downgrade replay-watermark **verified** (control + daemon agents); anchor secret custody shares the Windows custody gap (AUDIT-027).
- §6.D Role-transition controls — transition matrix fail-closed + blind_exit irreversibility **verified solid** (`role_presets.rs` + tests); **findings** AUDIT-039 (§6.D-9 platform-blocked typed error, §6.D-2 typed confirmation).

Notable refuted hypotheses (investigated, found NOT to be bugs): membership `count() as u8` truncation (fail-closed only); `decode_encrypted_blob` u32-length DoS (exact-length guard); macOS pf DNS ordering (correct — block precedes pass); Linux masquerade NATing non-tunnel traffic (forward chain restricts to tunnel-sourced); relay open-relay/SSRF (destination from session binding, never payload); daemon lock-across-await (runtime is single-threaded, threads marshal via mpsc); boringtun short-data underflow (parse arm guarantees ct_len≥16); CSP backend stub/in-memory reachable in production (cfg/Err-gated).

## 8. Reconciliation with RN-01..RN-38 / HB-1..HB-7

Re-verified status of every prior finding (sampled "fixed" ones re-checked first-hand or by the per-crate agents):

**Fixed — re-verified holding (no regression):** RN-01 (membership decode bounds present + tests), RN-17 (post-connect peer-cred), RN-19 (direct-path validate_request), RN-23 (macOS keychain key_id validated), RN-24 (zeroize on Drop + derived keys).
**Fixed within scope but regressed/incomplete elsewhere:** RN-22 (verify_strict holds in crypto+control, but **13 other ed25519 verify sites remain non-strict** — AUDIT-005); RN-20 (fixed in production exec; bare-name `Command::new` survives in test-gated `in_memory.rs`/`linux_command.rs` and HB-3 `windows_killswitch_smoke.rs`); RN-14 (14/17 crates opt in; `rustynet-windows-native` has no `[lints]` block — AUDIT-050); RN-15 (`--locked` in CI but **not** in bootstrap install builds — AUDIT-048).
**Newly fixed since the prior review (good news):** RN-06 (Windows unscoped `interfacetype=lan` allow is **gone** — replaced by scoped WFP egress allows; the headline open High in the 2026-06-01 backlog is resolved). RN-07 partially (IPv6 block rule added; assert-drift + address-flush gaps remain — AUDIT/§11).
**Still open, re-verified:** RN-02 (dead dataplane.rs), RN-03 (worse — all 38-39 sites swallowed), RN-04 (killswitch ordering + opt-in boot killswitch), RN-05 (non-`node:` selector revocation bypass), RN-08 (envelope AAD/version), RN-09 (systemd-credential mask widening still gated only by the `/run/credentials/` path prefix — re-verified at `key_material.rs:736-738`+`:612`/`:625`), RN-10 (corrupt ledger → genesis; re-rated High), RN-11 (empty membership/contexts allow-all), RN-12 (Linux exit DNS ordering), RN-13 (flood guard in dead code), RN-16 (mutable action tags), RN-18 (helper uid==0), RN-25 (re-verified: `CoordinationReplayWindow` is a bare in-memory `BTreeMap` reset on restart, bounded by the record TTL; the bundle side is stateless in control — `traversal.rs:837-856`), RN-26 (`ConsumedTokenLedger::purge_expired` stub — not re-verified this pass), RN-27 (block_all_egress trusts single drop rule), RN-28 (validate_policy_safety per-protocol bypass), RN-29 (improved — clients fail-closed; exit-node 443 residual), RN-30 (toolchain drift), RN-31 (acceptable — cargo audit catches yanked), RN-32 (escalated High — AUDIT-045), RN-33 (escalated High — AUDIT-027), RN-34/35 (path pinning, Info), RN-36 (re-verified: `main.rs:372-384` parse `u32` with no floor/zero rejection), RN-37 (re-verified present: passphrase `Zeroizing` cloned at `key_material.rs:555`), RN-38 (scanner scope — not deep-read this pass, but corroborated by AUDIT-012); HB-2 re-verified present (`write_runtime_private_key` `0o600` is `#[cfg(unix)]`-only at `key_material.rs:751-756`/`:1132`; `%TEMP%` smoke targets are the gap).
**Accepted (unchanged):** RN-21 / HB-7 (AlgorithmPolicy inverted guard — fail-closed, dead exception branch).
**HB-1..HB-6 (Windows smoke/harness):** not re-verified this pass (the smoke modules were out of the deep-read scope); statuses relayed from the backlog. HB-3 (bare-`netsh`) corroborated by RN-20's residual.

## 9. Prioritized remediation roadmap

**P0 — fix before any release / before running the overnight driver:**
1. Overnight driver (AUDIT-017/018/019): do not run the live path; before it ships, add worktree isolation + branch checkout + correct revert base + a confirmation gate. *Effort: M.* (Today: only `--dry-run` is safe.)
2. RN-03 + RN-04: stop swallowing `force_fail_closed`; program a mandatory cross-platform killswitch before backend start. *Effort: M (behavioral, regression-risk — confirm direction).*
3. AUDIT-031: cap + evict the relay HelloLimiter map; rate-limit before signature; cap node_id length. *Effort: S.*
4. AUDIT-040: make the membership reducer deterministic so revocation/key-rotation can actually be applied. *Effort: S-M + round-trip tests.*
5. AUDIT-045 (RN-32): trap-cleanup the macOS bootstrap sudoers file. *Effort: S.*

**P1 — high-value integrity/assurance:**
7. AUDIT-027 (RN-33): wire the Windows key-custody ACL validator or fail closed. *Effort: S (validator exists).*
8. AUDIT-005 (RN-22): convert the 13 non-strict ed25519 sites + add a grep gate. *Effort: S.*
9. RN-10: corrupt rotation ledger → fail closed; fix the contradictory comments. *Effort: S.*
10. RN-05 + RN-11: close the non-`node:` selector and empty-membership/contexts default-allow. *Effort: M (policy decision — confirm deployment story).*
11. AUDIT-028/029/024 + RN-08: Windows DPAPI entropy + zeroize-before-free + zeroize config render + envelope AAD/version. *Effort: M.*
12. RN-16/RN-30/AUDIT-048: SHA-pin actions, align toolchain to 1.88, `--locked` in bootstrap. *Effort: S.*

**P2 — defense-in-depth / hygiene / assurance:**
13. RN-12/RN-27/RN-29/AUDIT-043: exit-node DNS ordering, killswitch-tamper depth, PowerShell alias metachar rejection. *Effort: M.*
14. AUDIT-036/037/039: stop fabricating TLS/cert/service signals and rename the offline "adversarial" test (false-assurance class). *Effort: M.*
15. AUDIT-049: fuzz targets for relay frames + port_mapper + STUN. *Effort: M.*
16. AUDIT-012/013: broaden the secrets-hygiene + boundary-leakage gates. *Effort: S.*
17. The Low/Info remainder (AUDIT-002/003/004/007/008/009/010/011/014/015/016/023/025/026/030/035/041/042/044/050) and RN-18/25/26/34/35/36/37/38. *Effort: S each.*

## 10. Coverage ledger

Status: pending → in-progress → done (or exception with justification). Must reach 100%.

### Workspace crates (from cargo metadata; authoritative)
| Crate | LoC (.rs) | Status | Coverage notes |
|---|---|---|---|
| rustynet-crypto | 2,407 | **done** | full read incl. tests (crypto agent) |
| rustynet-local-security | 384 | **done** | full read (crypto agent) |
| rustynet-policy | 690 | **done** | full read + first-hand RN-05/11 verify |
| rustynet-dns-zone | 1,185 | **done** | full read (crypto agent) |
| rustynet-control | 16,907 | **done** | all src fully read incl. membership.rs/tests (control agent) |
| rustynet-backend-api | 1,304 | **done** | full read (backend agent) |
| rustynet-backend-stub | 744 | **done** | full read (backend agent) |
| rustynet-backend-userspace | 468 | **done** | full read (backend agent) |
| rustynet-backend-wireguard | 20,297 | **done** | prod paths fully read; test helpers skimmed (backend agent) |
| rustynet-windows-native | 1,950 | **done** | full read, every unsafe block inventoried (windows-native agent) |
| rustynetd | 102,366 | **done** | daemon.rs 1-14580 line-by-line; phase10.rs 1-6220 full; priv_helper full; traversal/port_mapper/key_material/gossip/fetcher/ipc/relay_client full; macos_utun_helper_unsafe first-hand. Exceptions: `secret_log_audit.rs` (RN-38 owner, not deep-read), windows_*_smoke.rs (HB-1..5 owner, relayed), platform report-collector modules spot-checked not exhaustively read (§11). |
| rustynet-relay | 7,252 | **done** | main.rs + transport.rs + session/rate_limit/lib fully read incl. tests (relay agent) |
| rustynet-cli | 184,536 | **done** (targeted-deep) | main.rs security regions + all gate bins fully read; ops_* skimmed-deep on exec/remote/secret; vm_lab/overnight/* (7 files) fully read; vm_lab/mod.rs diff + exec/quoting surface; 5 live-bins sampled. Bulk report/status formatting + ~21k test lines skimmed (justified — not security paths). |
| rustynet-operator | 2,216 | **done** | full crate read (sysinfo agent) |
| rustynet-sysinfo | 6,677 | **done** | full read (sysinfo agent) |
| rustynet-mcp | 8,739 | **done** | build.rs + lib.rs + gate_runner full; lab_state all tool/fs/spawn sites read, descriptive blocks skimmed; repo_context confinement verified (mcp agent) |
| rustynet-xtask | 746 | **done** | full read (sysinfo agent) |
| third_party/boringtun | 7,853 | **done** | compiled surface (noise/*) fully read + full diff-vs-upstream-0.7.0; dead device/ffi/jni inventoried not soundness-audited (not compiled) |
| third_party/rustynet-tun | 408 | **done** | full read, all unsafe justified (backend agent) |

### Non-crate surfaces
| Surface | Status | Coverage notes |
|---|---|---|
| Workspace Cargo.toml / deny.toml / rust-toolchain.toml / .cargo | **done** | all read; `.cargo/config*` confirmed absent; 17 manifests + fuzz checked for lints/wildcards/git/patch |
| crates/rustynet-mcp/build.rs | **done** | full read + diff (AUDIT-008) |
| .github/workflows/* | **done** | both workflows read in full (scripts agent) |
| scripts/ci/* (43 gate scripts) | **done** | all 43 dispositioned; real-logic gates read fully; ~28 thin wrappers bulk-read |
| scripts/bootstrap/* (linux, macos, windows) | **done** | linux full; macOS security sections (~440/1225 L); Windows .ps1 enumerated + signer via workflow |
| scripts/e2e/* (~60) | **done** (sampled) | live_lab_common.sh (3497 L) + orchestrator diff full; 10+ scripts sampled; rest confirmed thin Rust-dispatch wrappers |
| scripts/mcp/install.sh, dev/, systemd/, operations/, perf/, release/, fuzz/ | **done** | install.sh + setup.sh + systemd units full; rest are Rust-dispatch wrappers (read) |
| scripts/vm_lab/probe_and_recover_local_utm.sh, scripts/launchd/, scripts/windows/ | exception | not individually opened (low security hot-path; recovery/launchd helpers). Justified low-risk; flagged §11. |
| start.sh + repo-root scripts | **done** | start.sh full (Rust-dispatch) |
| Docs accuracy (Requirements/SecurityMinimumBar/CODE_MAP/indexes vs code) | **done** | read in full; doc-drift findings AUDIT-002/008, RN-10 comment contradiction; SecurityMinimumBar controls traced in §6/§7 |
| fuzz/ targets | **done** | target list read; coverage gaps = AUDIT-049 |
| Cross-cutting greps (boundary leak, unsafe, lints, TODO, secrets-in-logs) | **done** | first-hand (this transcript) |

**Ledger status: 100% of workspace crates, build.rs, gates, and CI reviewed.** Three justified exceptions, all low-risk and explicitly flagged: (a) `rustynetd/src/secret_log_audit.rs` and the `windows_*_smoke.rs` modules (assigned to RN-38/HB-1..5 owners; statuses relayed from the prior backlog, not re-deep-read); (b) `rustynetd` platform report-collector modules (`linux_*`/`macos_*`/`windows_*` for dns_failclosed/runtime_acls/service_hardening/mesh_status/etc.) — spot-checked via grep for path-injection/with_capacity/panic (clean), not exhaustively read, because they are host-only diagnostic collectors limited to static review anyway; (c) `scripts/vm_lab/probe_and_recover_local_utm.sh`, `scripts/launchd/`, `scripts/windows/` recovery helpers.

## 11. Residual unknowns / items needing runtime or live-lab verification

Items this static, read-only pass could not fully settle:

- (Resolved) `cargo clippy --workspace --all-targets --all-features -- -D warnings` **completed PASS** (exit 0, 24m58s, zero warnings) — all four read-only gates are now green.
- **Windows/macOS firewall + key-custody behavior is static-only.** AUDIT-027 (Windows key-custody ACL no-op), AUDIT-028/029 (DPAPI), the RN-06/RN-07 Windows killswitch *fixes*, RN-12 (Linux exit DNS ordering), and the macOS pf ordering were reasoned from code, not validated on a live host. The killswitch fail-open cluster (RN-03/RN-04) needs a live nft/helper fault-injection test on a fresh `Init` host to confirm the leak window empirically.
- **The overnight driver's live path was never executed** (by design — running it *is* running it). AUDIT-017/018/019 were confirmed by first-hand code read (no `git checkout`; `revert_to_clean` has no `current_dir`; `run_agent` blocking `.status()`), but the destructive behavior was not (and must not be) reproduced. The spawned-agent permission posture (AUDIT-020) depends on the operator's `~/.claude/settings.json` at run time.
- **Relay DoS magnitudes (AUDIT-031/032/033)** are reasoned from the code (unbounded map, per-packet logging, global lock); the GB/sec growth and contention figures are analytical, not measured under load.
- **AUDIT-015 (DNS-zone verify defers expiry/replay to the caller)** is `needs-runtime-verification`: whether it is a real fail-open depends on the daemon caller enforcing the watermark + clock; the daemon loaders generally do verify-then-watermark, but the specific DNS-zone caller chain was not traced end-to-end this pass.
- **AUDIT-025 (boringtun engine never drives `update_timers`)** severity hinges on whether the `userspace_shared` boringtun engine carries production traffic today (default is command-mode `wg`/wireguard-go). Confirm the deployment posture before rating it beyond pre-production.
- **Not re-deep-read this pass (relayed from prior backlog, flagged in §10):** `rustynetd/src/secret_log_audit.rs` (RN-38), the `windows_*_smoke.rs` modules (HB-1..HB-5), and the `rustynetd` platform report-collector modules. The vm_lab recovery/launchd/windows helper scripts were not individually opened.
- **Multi-version dependency duplication** (`[bans] multiple-versions = "warn"`) allows boringtun-driven duplicate `base64`/`nix` versions — track transitively for advisories (Low, noted in the prior review).

---
*End of audit. Coverage ledger (§10) is at 100% of crates/build.rs/gates/CI with three justified low-risk exceptions. Findings are AUDIT-001..053 plus reconciled RN-01..RN-38 / HB-1..HB-7. No repository changes were made other than this report and its index entry.*
