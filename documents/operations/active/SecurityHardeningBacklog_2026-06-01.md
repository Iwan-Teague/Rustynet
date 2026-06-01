# Security Hardening Backlog (2026-06-01)

A lightweight, actionable TODO tracker for security hardening. **This is not a
fresh review** — the authoritative firm-grade assessment is
[`SecurityReview_2026-05-24.md`](./SecurityReview_2026-05-24.md) (findings
`RN-01..RN-38` + a P0/P1/P2 remediation roadmap). This doc:

1. records **net-new** hardening items found after that review — chiefly on the
   single-node Windows smoke/harness code added 2026-05-31..06-01 (tunnel-smoke
   N1, killswitch-smoke N2, dns-smoke N3, ipv6-smoke G8), which postdates it; and
2. surfaces the **highest-priority open items** from the review so there is one
   "what's left" entry point.

Severity scale matches the review (High / Medium / Low / Info). Each item lists
`file:line` (re-confirm before fixing — line numbers drift), the observation, and
a concrete fix. Status: TODO unless noted.

---

## A. Net-new items (smoke / harness code, this session)

These live in test/validation tooling and privileged smoke verbs, not the
production reconcile path, so severity is **Low/Info** — but they are real
deviations from the codebase's own hardening discipline.

### HB-1 — Smoke harnesses delete the ephemeral cleartext WG private key with a plain unlink, not the secure scrub (Low)
- **Location:** `crates/rustynetd/src/windows_tunnel_smoke.rs` (`let _ = std::fs::remove_file(key_path)` after `backend.start`), same pattern in `crates/rustynetd/src/windows_killswitch_smoke.rs`.
- **Observation:** The smokes generate an ephemeral WireGuard private key, write it cleartext to `%TEMP%`, and remove it with `std::fs::remove_file` — **not** the crate's own `key_material::remove_file_if_present`, which overwrites-then-deletes (`scrub_file_contents`). The cleartext key bytes can linger in freed disk blocks until overwritten.
- **Fix:** call `crate::key_material::remove_file_if_present(&key_path)` (secure scrub) in both smokes, including on the early-return/error paths.

### HB-2 — `write_runtime_private_key`'s `0o600` is `cfg(unix)`-only; on Windows the cleartext key relies on inherited NTFS ACLs (Low)
- **Location:** `crates/rustynetd/src/key_material.rs:739` (`write_runtime_private_key`) → `write_atomic` (`options.mode(mode)` is `#[cfg(unix)]`).
- **Observation:** On Windows the mode is a no-op, so a cleartext WG private key written via this path inherits its parent directory's ACL. For the daemon's key under `C:\ProgramData\RustyNet\...` that dir is hardened + startup-ACL-validated, so it's fine — **but the smokes write to `%TEMP%`**, which only has the user-temp ACL.
- **Fix:** write smoke runtime keys under a hardened RustyNet secrets dir (reuse the validated runtime-ACL path) rather than `%TEMP%`, and/or set an explicit owner-only ACL on Windows in `write_atomic`. Document the invariant: on Windows, callers of `write_runtime_private_key` MUST target a dir with a validated owner-only ACL.

### HB-3 — Killswitch-smoke recovery paths invoke `netsh` by bare name (PATH-resolved), not an absolute validated path (Low; net-new instance of review RN-20)
- **Location:** `crates/rustynetd/src/windows_killswitch_smoke.rs` (`FirewallRestoreGuard::drop` runs `Command::new("netsh")`); `scripts/bootstrap/windows/Invoke-RustyNetWindowsKillswitchSmoke.ps1` (`& netsh.exe ...`, `schtasks.exe /TR "cmd /c netsh ..."`).
- **Observation:** Same class as review **RN-20** (PATH-resolved bare program names). These are recovery backstops, so exploitation needs pre-existing control of the process environment, but the production code resolves binaries via absolute validated paths.
- **Fix:** use the absolute system path (`%SystemRoot%\System32\netsh.exe`) consistent with the rest of the Windows command surface.

### HB-4 — Killswitch-smoke Drop guard does not remove the IPv6 LAN block rule on a panic mid-ipv6-leg (Low)
- **Location:** `crates/rustynetd/src/windows_killswitch_smoke.rs` (`FirewallRestoreGuard::drop` restores `allowoutbound` + removes the WFP tunnel permit, but not `RustyNetKS-BlockIpv6Lan`).
- **Observation:** If the `--exercise-ipv6` leg errors/panics after `hard_disable_ipv6_egress` but before `rollback_ipv6_egress`, the IPv6 LAN Block rule is left behind (port-IPv6-only, not SSH-fatal; self-heals on the next run's purge, and the cross-process dead-man's-switch only restores the policy, not this named rule).
- **Fix:** add a best-effort `netsh advfirewall firewall delete rule name=RustyNetKS-BlockIpv6Lan` to the Drop guard (and/or to the dead-man's-switch command) for symmetric cleanup.

### HB-5 — ipv6-smoke probe connects to a hardcoded public third-party IPv6 (Info)
- **Location:** `crates/rustynetd/src/windows_killswitch_smoke.rs` (`ipv6_egress_reachable()` → `TcpStream::connect_timeout("[2606:4700:4700::1111]:443", 3s)`).
- **Observation:** The leak/block probe makes a real outbound connection to Cloudflare during the security test, and is inconclusive if the guest has no IPv6 internet (handled: `ipv6_ok` requires `ipv6_baseline_egress_ok`, so it fails rather than false-passes). Third-party dependency + test-time egress to an external party.
- **Fix (optional):** prefer a lab-local off-LAN IPv6 target when one is available; otherwise document the dependency. Keep the fail-closed-on-inconclusive behaviour.

### HB-6 — vm-lab orchestrator builds many PowerShell scripts via `format!` (Info — review/lint opportunity)
- **Location:** `crates/rustynet-cli/src/vm_lab/**` (numerous `Set-StrictMode ... {interpolated}` scripts; the recent `build_windows_helper_invocation_script` `$LASTEXITCODE` fix lived here).
- **Observation:** Large PowerShell-string-building surface. It is **operator-trust** input (inventory + CLI flags, not remote-attacker), and it does use `powershell_quote` / `ensure_no_control_chars` for interpolated values — but the discipline is by-convention, not enforced. Not a confirmed injection; flagged as an audit/hardening opportunity since this surface grew this session.
- **Fix (optional):** add a focused test/lint that every operator-derived value interpolated into a PS/cmd string passes through `powershell_quote`/`ensure_no_control_chars`; or centralize PS-script assembly behind a builder that quotes by construction.

---

## B. Highest-priority OPEN items (SecurityReview_2026-05-24.md) — re-verified on `main` `e01dd64` (2026-06-01)

These outrank everything in Section A. The review holds the full attacker model +
remediation design; the status + `file:line` below were **re-confirmed
first-hand this pass** against current code (the items marked *not re-verified*
are relayed from the review and should be reproduced before fixing).

- **P0 · RN-03 — discarded `force_fail_closed` (fail-open) · OPEN [verified e01dd64].** 10 of 44 call sites still swallow the result with `let _ = …force_fail_closed(…)` (e.g. `daemon.rs:6449,6523,6590,6597`). If `block_all_egress` fails at one of these, the code proceeds as if failed-closed when it did not. **Fix:** propagate/handle every site; on a `block_all_egress` failure the dataplane must not serve (no interface/route up), not just log.
- **P0 · RN-04 — bootstrap leak window · OPEN [verified e01dd64].** The killswitch is programmed *after* backend start in `apply_dataplane_generation` (`phase10.rs` ~4167, after `BackendStarted`), and the pre-protective boot killswitch (`linux_killswitch_boot.rs`) is **opt-in (`--install-boot-killswitch`) and Linux-only** — so by default every platform has a window where the interface is up before the killswitch. **Best-practice fix:** a *mandatory, cross-platform* default-deny applied *before* any interface/route.
- **P0 · RN-05 — non-`node:` selectors bypass revocation · OPEN [verified e01dd64].** `selector_membership_allowed` ([policy/lib.rs:305-308](../../../crates/rustynet-policy/src/lib.rs)) `return true` for any selector whose prefix is not `node:`, so `group:`/`tag:`/`user:`/`cidr:` rules are allowed regardless of membership status. **Fix:** resolve such selectors to their member node set and deny if any is revoked/unknown, or forbid trust-sensitive rules whose source can't map to a membership-checked node (fail-closed on unresolvable identity).
- **P0 · RN-06 — Windows killswitch allows ALL non-DNS LAN egress · OPEN [verified e01dd64].** `windows_firewall_allow_interfacetype_args` ([phase10.rs:5467](../../../crates/rustynetd/src/phase10.rs)) emits an unscoped `interfacetype=lan action=allow` (no proto/port/IP); only port-53 is forced through the tunnel. If the WireGuard default-route injection flaps/tears down, TCP/QUIC/etc. egress cleartext out the LAN NIC. The G8 work below only adds an IPv6 block on top — **the IPv4 leak is unaddressed.**
- **P0 · RN-07 — Windows IPv6 leak · IN PROGRESS (G8, uncommitted).** `hard_disable_ipv6_egress` now purges + adds a netsh IPv6 LAN Block rule (`RustyNetKS-BlockIpv6Lan`), and `--phase ipv6-smoke` exercises leak→block→restore live. **Gaps vs the review's prescribed remediation:** (a) the IPv6 block is **not** re-verified in `assert_killswitch` (no drift detection); (b) existing autoconfigured/static global IPv6 addresses are **not** flushed (the firewall block is the primary control, flush is defense-in-depth); (c) it uses a netsh rule, not WFP (see best-practice note).
- **P0 · RN-11 — permissive-on-empty defaults · PRESENT [verified e01dd64].** When the membership directory is empty the enforcement gate skips the check by design (`if !membership.is_populated()` at [phase10.rs:5005](../../../crates/rustynetd/src/phase10.rs); doc-comment calls it a "pre-membership" escape hatch); separately, an empty `allowed_contexts` matches *all* contexts ([policy/lib.rs:289](../../../crates/rustynet-policy/src/lib.rs)). Both are fail-open-on-empty, contradicting the default-deny mandate. **Fix:** deny on empty membership/empty context, with an explicit, logged, opt-in bootstrap mode if a pre-governance window is genuinely required.
- **P1 / P2 (review-owned, *not* re-verified this pass)** — RN-02 (audited `dataplane.rs` is dead code; live path is `phase10`), RN-10 (corrupt rotation ledger resets to genesis instead of failing closed), RN-08/RN-09 (key envelope doesn't bind salt/nonce/version via AAD; systemd-credential group-read gate), RN-12/RN-13/RN-16, and the remaining Low/Info RN-17..RN-38. Reproduce against current code before fixing.

### Are these the best patches? (best-practice assessment)
The review's remediation **directions are sound** and match standard practice:
default-deny, fail-closed on a control failure, narrow allow-lists, kill-switch-
before-interface, and deny-on-unresolvable-identity. Three places where the
*strongest* patch goes beyond what's written down:

1. **Windows killswitch (RN-06/07): use WFP, not more netsh rules.** The project
   already established (E2) that netsh cannot reliably scope the wintun adapter
   and that the robust mechanism is the Windows Filtering Platform (a dedicated
   max-weight RustyNet sublayer + explicit hard-permit filters). The strongest
   fix implements the egress policy as WFP filters — permit only loopback + the
   tunnel LUID + UDP to the **specific** peer/relay endpoints + management, block
   everything else for **both** families — unified with the E2 tunnel permit,
   rather than scoping netsh `interfacetype=lan` rules (which can be reordered/
   bypassed and can't bind to the tunnel adapter). The current G8 `remoteip=::/0`
   netsh block closes the IPv6 leak but is the weaker mechanism.
2. **RN-04:** the pre-protective killswitch should be **mandatory + cross-platform**,
   not opt-in + Linux-only.
3. **RN-11:** empty membership/empty context should **deny** (fail-closed) with an
   explicit opt-in bootstrap, not a silent permissive default.

### Windows killswitch parity — the unifying fix (RN-06 + RN-07)
The complete remediation narrows the killswitch's egress **allow** to exactly the
bootstrap essentials (WG UDP to the specific peer/relay endpoints + STUN +
management/SSH) for **both** address families — ideally via WFP (point 1 above) —
so everything else hits the global block, matching Linux's narrow allow, and
re-verifies both the IPv4 scoping and the IPv6 block in `assert_killswitch`. The
G8 IPv6 Block rule is the first increment; RN-06's IPv4 LAN-egress scoping (and
moving the whole egress policy to WFP) is the larger remaining piece.

---

## Notes
- Section A items are tracked here because they postdate the 2026-05-24 review.
- Section B P0s were **re-verified first-hand against `main` `e01dd64` (2026-06-01)**
  — all confirmed still open. The remediation design + the P1/P2 + not-re-verified
  items remain owned by `SecurityReview_2026-05-24.md`; update statuses there on fix.
- The "best patches?" assessment above is this author's view, not a contradiction
  of the review: the review's directions are correct; the WFP / mandatory-cross-
  platform-killswitch / deny-on-empty points are *stronger* options, not corrections.
- Supply-chain gates (`cargo audit --deny warnings`, `cargo deny check`) are part
  of the CLAUDE.md mandatory gates but are **not** in the `rustynet-xtask -- gates`
  fast runner; run them explicitly when touching dependencies.
