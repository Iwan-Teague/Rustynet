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

## B. Highest-priority OPEN items (from SecurityReview_2026-05-24.md — pointers, not duplicates)

These outrank everything in section A. Full detail, attacker model, and
remediation design are in the review; status re-confirm before fixing.

- **P0 · RN-03 + RN-04** — `force_fail_closed(...)` results are discarded at ~10 sites, and the tunnel/routes come up *before* the killswitch is programmed: a failed killswitch on first bootstrap leaves the host **open**. (Review §3, §11.)
- **P0 · RN-06** — **Windows killswitch allows ALL non-DNS outbound on the physical LAN** (`interfacetype=lan action=allow`); only port-53 is forced through the tunnel. Real IPv4 traffic leak if the WireGuard default-route injection flaps. **Not yet fixed.** The G8 work below closes only the IPv6 dimension. (Review RN-06.)
- **P0 · RN-07** — **Windows IPv6 leak.** *In progress (2026-06-01):* `hard_disable_ipv6_egress` now adds a netsh IPv6 LAN Block rule (`RustyNetKS-BlockIpv6Lan`) and `ipv6-smoke` exercises leak→block→restore live. **Residual:** (a) the IPv6 block is not yet re-verified in `assert_killswitch` (the review's prescribed remediation), and (b) autoconfigured/static global IPv6 addresses are not flushed (the firewall block is the primary control, flush is defense-in-depth).
- **P0 · RN-05 + RN-11** — policy engine **default-allows** selectors not prefixed `node:` (revocation bypass), and **allow-all when the membership directory is empty**. (Review RN-05/RN-11.)
- **P1 · RN-02** — the audited `dataplane.rs` is dead code; the live path is `phase10`. Resolve the split so the audited control is the one that runs.
- **P1 · RN-10** — corrupt rotation ledger silently resets to genesis instead of failing closed.
- **P1 · RN-08 / RN-09** — encrypted-key envelope doesn't bind salt/nonce/version via AAD; systemd-credential passphrase files may be group-readable (gated only by a path prefix).
- **P2** — RN-12 (Linux exit-node DNS ordering leak), RN-13 (`HandshakeFloodGuard` unbounded + not run in prod), RN-16 (SHA-pin GitHub Actions), and the remaining Low/Info (RN-17..RN-38).

### Windows killswitch parity — the unifying fix (RN-06 + RN-07)
The complete remediation narrows the killswitch's egress-LAN **allow** to exactly
the bootstrap essentials (WG UDP to peer/relay endpoints + STUN + management/SSH)
for **both** address families, so everything else hits the global block —
matching Linux's narrow allow — and re-verifies both the IPv4 scoping and the
IPv6 block in `assert_killswitch`. The G8 IPv6 Block rule is the first increment;
RN-06's IPv4 LAN-egress scoping is the larger remaining piece.

---

## Notes
- Section A items are tracked here because they postdate the 2026-05-24 review.
- Section B items remain owned by `SecurityReview_2026-05-24.md`; this is a
  convenience index, not a re-assessment — update statuses there on fix.
- Supply-chain gates (`cargo audit --deny warnings`, `cargo deny check`) are part
  of the CLAUDE.md mandatory gates but are **not** in the `rustynet-xtask -- gates`
  fast runner; run them explicitly when touching dependencies.
