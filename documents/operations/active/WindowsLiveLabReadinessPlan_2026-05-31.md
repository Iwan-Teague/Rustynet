# Windows Live-Lab Readiness Plan (2026-05-31)

Focused readiness ledger: what the Windows version of Rustynet can already
do, what is still missing, and the ordered path to running a live-lab
session **on a Windows node** (single-node smoke → two-node mesh → roles →
full matrix).

This doc owns the *Windows-before-live-lab* status picture. It does **not**
duplicate the detailed design ledgers — it points at them:

- IPC / service access recovery: [WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md](./WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md)
- Tunnel connectivity gap vs Linux (W1-W4): [HomelabConnectivityParityDeltaPlan_2026-05-21.md](./HomelabConnectivityParityDeltaPlan_2026-05-21.md)
- Exit / relay roles on Windows: [WindowsExitAndRelayDeltaPlan_2026-05-10.md](./WindowsExitAndRelayDeltaPlan_2026-05-10.md)
- OS-agnostic orchestrator + Windows peer: [OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md](./OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md)
- Cross-platform role / topology delta (Track B landed): [AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md](./AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md)
- Lab guest facts + recover runbook: [UTMVirtualMachineInventory_2026-03-31.md](./UTMVirtualMachineInventory_2026-03-31.md)

Status legend: ✅ done + validated · 🟡 implemented, not validated on Windows ·
🔴 missing / unproven · ⚙️ engineering enabler.

---

## 1. Headline

The Windows daemon now **builds, installs as a service, starts, and serves
its hardened local IPC** end-to-end over the orchestrator. `restart-runtime`
is **GREEN** (`RESTART_EXIT=0`, `completed bootstrap phase=restart-runtime`)
driven over pinned SSH through `sync-source → build-release →
install-release → restart-runtime`.

**Update 2026-06-01 — the tunnel comes up AND the killswitch holds.** `N1.3`
passed: the first-ever WireGuard tunnel bring-up on `windows-utm-1` succeeded via
`--phase tunnel-smoke` (`overall_ok=true`, clean teardown). `N2` then passed via
`--phase killswitch-smoke`: the killswitch applies, `assert_killswitch` confirms
it active (netsh default-block-outbound + WFP tunnel permit), and it rolls back
cleanly (WFP permit absent→present→absent; firewall restored; SSH never lost) —
backed by a dead-man's-switch so an unattended run can't brick SSH, and a
unit-proven fail-closed-on-apply-error path. `N3` then passed via `--phase
dns-smoke`: with the killswitch active, the netsh port-53 LAN-block applies,
asserts, and rolls back (no plaintext-DNS leak in protected mode). The remaining
unproven surface — multi-node mesh + traffic (N4), NetNat/role forwarding (N5),
and the full matrix (N6) — is what N4→N6 close. IPv6-leak (G8) is still open
before protected-mode can be called *secure*.

---

## 2. What is done (✅ / 🟡)

### Daemon lifecycle + local IPC — ✅ validated on `windows-utm-1`
- Service install + start; `--windows-service` path reaches the reconcile
  loop. Evidence: `restart-runtime` exit 0.
- **Self-recovery from a wedged WMI provider.** Every Windows helper
  subprocess (`run_netsh` / `run_powershell` in `phase10.rs`) runs under a
  20s spawn→poll→kill+reap watchdog (`run_helper_command_with_timeout`), so a
  hung CIM cmdlet can no longer block startup or leak child processes (the
  leak was the original cause of the WMI wedge). No reboot required.
- **Native default-egress detection** via in-process `GetAdaptersAddresses`
  (`select_windows_default_egress_interface`) — replaced the hang-prone
  `powershell Get-NetRoute` (CIM) on the synchronous startup path.
- **Daemon logging on the service path** (previously a silent no-op): tees to
  `<state-root>/logs/rustynetd.log` with startup-milestone logs.
- **Named-pipe IPC hardened**: graceful pipe teardown + read-before-impersonate
  closed the `CallNamedPipeW` error-109 / error-1368 races; control pipe
  `\\.\pipe\RustyNet\rustynetd` and privileged pipe
  `\\.\pipe\RustyNet\rustynetd-privileged` both served.
- **Pipe-ACL inspection** uses `SE_FILE_OBJECT` + group-SID round-trip; the
  `NT SERVICE\RustyNet` SID is passed as a reviewed principal (not drift).
  `windows-named-pipe-acls-check --service-sid <SID>` → `overall_ok=true`.
- **Verify helper** wraps daemon self-checks in `ErrorActionPreference=Continue`
  so a non-zero check no longer emits a false `service_status=missing`.
- **DPAPI key custody** round-trip (`store → read`) is exercised by
  `windows-runtime-boundary-check` (part of the green `restart-runtime`), and
  dated service-hardening / runtime-ACL collector evidence exists
  (`windows_utm_1_service_hardening_*.json`, `windows_utm_1_runtime_acls_*.json`).

### Backend readiness — ✅
- `windows_backend_readiness` confirms `wireguard.exe` / `wg.exe` / `netsh` /
  `sc` / `powershell` presence; no longer requires a standalone
  `wireguard.dll` (some WireGuard-for-Windows installs no longer ship it).

### Data-plane + roles code — 🟡 implemented, never run on Windows
- `WindowsWireguardBackend` (`rustynet-backend-wireguard/src/windows_command.rs`):
  `start` → `wireguard.exe /installtunnelservice`, DPAPI-encrypted config,
  `wg.exe` peer sync, `netsh` route/address, `stats` via `wg show`,
  `uninstall_tunnel_service` teardown. **Not exercised live.**
- Killswitch (`phase10.rs`): default-block-outbound applied via **netsh**
  (reliable); per-tunnel allow rule via `New-NetFirewallRule -InterfaceAlias`
  (CIM — see Gap G2). **Never exercised in anger on Windows.**
- NetNat forwarding / exit preflight / port-mapping gateway detection for
  exit + anchor roles exist in code; topology-selection + validator gaps that
  blocked Windows as active exit/relay/anchor are reported landed in Track B
  of [AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md](./AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md),
  but no role has been run live on Windows.

---

## 3. Gaps blocking a Windows live-lab run (🔴 / ⚙️)

- **G1 — Tunnel bring-up — ✅ proven (2026-06-01).** A `rustynet0` WireGuard
  interface was created, reported by `wg show`, and torn down cleanly on the
  guest via the `tunnel-smoke` phase (`overall_ok=true`). The foundational
  data-plane question is closed; passing *traffic* across a mesh is N4.
- **G2 — Killswitch + fail-closed — ✅ proven (2026-06-01).** The per-tunnel
  allow rule is now a native WFP filter (E2), so the last `New-NetFirewallRule`
  (CIM) cmdlet is gone from the apply path. The `killswitch-smoke` phase
  exercised it live on `windows-utm-1`: apply → `assert_killswitch` active
  (netsh default-block-outbound policy + WFP tunnel permit present) → rollback →
  assert inactive, with the WFP permit observed absent→present→absent and the
  firewall restored to `AllowInbound,AllowOutbound` (no residual block; SSH
  never lost — the egress-allow rule kept it up). Fail-closed-on-apply-error is
  unit-proven (`killswitch_apply_failure_fails_closed_before_exit_mode`: a failed
  `apply_firewall_killswitch` drives `block_all_egress`/FailClosed and never
  commits the tunnel). **E2 go/defer decision: E2 is shipped + live-validated** —
  no remaining CIM-cmdlet timing concern to defer.
- **G3 — DNS fail-closed — ✅ proven (2026-06-01).** The netsh port-53 LAN-block
  was exercised live in protected mode (`--phase dns-smoke`): while the killswitch
  was active, `apply_dns_protection` → `assert_dns_protection` (both
  `RustyNetDNS-BlockLanUdp`/`-BlockLanTcp` rules present, Outbound/Block/Enabled) →
  rollback → assert inactive, then the killswitch rolled back. Post-run there are
  **no residual `RustyNetKS-*`/`RustyNetDNS-*` rules** and the firewall is back to
  `AllowOutbound`. The Block rule overrides the killswitch's egress-allow for
  port 53, so plaintext DNS to a LAN/ISP resolver is dropped while the tunnel is
  up. The opt-in loopback-resolver/NRPT enforcement remains a deferred, stronger
  control (a separate design decision); the firewall block is the baseline parity
  control with Linux/macOS.
- **G4 — No multi-node mesh with a Windows node (🔴).** The live-lab
  orchestrator/matrix is Linux-first (macOS recently added). `live_mixed_topology`
  currently **skips when no Windows host is in the mix**. Windows is not yet a
  first-class node in an end-to-end run.
- **G5 — Single-node smoke harness — ✅ landed.** `ops vm-lab-bootstrap-phase
  --phase tunnel-smoke` (N1) and `--phase killswitch-smoke` (N2) provide minimal
  bring-up-and-assert paths for fast iteration without a full dataplane
  generation. The killswitch smoke arms a guest-side dead-man's-switch
  (schtasks firewall-restore) so a wedged apply cannot strand SSH.
- **G6 — Roles never run on Windows (🔴).** blind_exit / anchor / exit_server
  on a Windows host are untested; an earlier `windows-exit-topology` attempt
  recorded `overall_status: failed`.
- **G7 — No Windows compile/lint/test gate (⚙️).** `cfg(windows)` code cannot
  be `clippy`/`test`-gated on the macOS host (Windows-target std unavailable);
  the guest `build-release` is the only Windows compile gate today.
- **G8 — IPv6 leak / fail-closed unvalidated on Windows (🔴, security).** The
  dataplane abstraction has `hard_disable_ipv6_egress` / `rollback_ipv6_egress`,
  but `ipv6_parity_supported` defaults `false` and Windows IPv6-leak behaviour
  in protected mode has never been verified. Flagged as an open **P0** in
  [SecurityReview_2026-05-24.md](./SecurityReview_2026-05-24.md) ("Windows
  killswitch/IPv6 leaks") and as **W4** in
  [HomelabConnectivityParityDeltaPlan_2026-05-21.md](./HomelabConnectivityParityDeltaPlan_2026-05-21.md).
  Must confirm no IPv4 **or IPv6** leak under a live tunnel.
- **G9 — Rollback-on-failure + guest-lockout recovery (🔴, operational).**
  Windows `rollback_firewall` (netsh) exists, but rollback-on-failure and
  fail-closed persistence across a daemon crash/restart are unvalidated. A
  failed killswitch apply or rollback can leave default-block-outbound active
  and **lock SSH out of the guest mid-run**. **This lockout was observed and
  recovered on 2026-05-31**: the `RustyNet` service was left RUNNING with the
  Windows Firewall at `AllowInbound,BlockOutbound` on all profiles, so inbound
  SSH was accepted but the (outbound) SSH/ICMP replies were dropped → host saw
  TCP/22 + ping timeouts.
  - **Recovery is NOT manual-only.** Contrary to the earlier assumption,
    `windows-utm-1` is a **QEMU/VirtIO guest with a working guest agent** (NOT
    Apple Virtualization), so `utmctl exec` / `utmctl file pull|push` work and
    allow full host-side diagnosis + recovery **without SSH**. Proven recovery
    recipe (run via `utmctl exec "Windows" --cmd cmd.exe /c "..."`):
    `sc stop RustyNet` → `sc config RustyNet start= demand` (stop auto-relock on
    reboot) → `netsh advfirewall set allprofiles firewallpolicy
    allowinbound,allowoutbound`. After this, host ping + TCP/22 recovered and
    the service read `STOPPED`.
  - `scripts/vm_lab/probe_and_recover_local_utm.sh` still **skips** Windows
    guests (its header repeats the stale Apple-Virt/no-exec claim); extending it
    to drive this `utmctl exec` recipe for `windows-utm-1` is the open
    automation follow-up. Until then, recovery is a one-liner from the host, not
    a UTM-console session.
  - Still validate rollback/restart fail-closed before any unattended run — the
    recipe recovers a *locked* guest, but the daemon should not lock it in the
    first place.

---

## 4. Next steps (ordered)

Each step lists a concrete **done-criterion**. Do them in order — each de-risks
the next.

**Minimum bar for a *first* Windows live-lab run:** N1 + N4 + (N2/G9). That is —
a tunnel can come up (N1), a Windows node joins a mesh and passes traffic
bidirectionally (N4), and the killswitch is fail-closed + the guest is
recoverable so an unattended run can't brick SSH (N2 + G9). N3 (DNS) and G8
(IPv6 leak) are required before calling protected-mode *secure*; N5 (roles) and
N6 (full matrix) are beyond the first run.

| Step | Effort | In minimum bar? |
| ---- | ------ | --------------- |
| N1 single-node tunnel smoke ✅ | M | **yes** |
| N2 killswitch + fail-closed ✅ | M | **yes** (safety) |
| N3 DNS fail-closed ✅ | S–M | before "secure" |
| N4 two-node mesh w/ Windows | L | **yes** |
| N5 roles (blind_exit → anchor) | L | no |
| N6 full matrix incl. Windows | M | no |
| G8 IPv6 leak validation | S–M | before "secure" |
| G9 rollback/recover hardening | S–M | **yes** (safety) |

### N1 — Single-node WG-NT tunnel bring-up smoke ✅ (N1.3 passed 2026-06-01)
Bring up one tunnel on the guest through `WindowsWireguardBackend`: generate a
keypair, write the DPAPI-encrypted config, `/installtunnelservice`, assign the
address via netsh, verify the interface via `GetAdaptersAddresses` + `wg show`,
then tear down. Likely needs a small smoke verb (reuses the existing backend).
- **Done when:** `rustynet0` appears up with the expected address and `wg show`
  reports the interface on `windows-utm-1`, then tears down cleanly. No leaks.

Progress (2026-05-31):
- **Smoke verb** `rustynetd windows-tunnel-smoke` landed on `main` (commit
  59d5497, `crates/rustynetd/src/windows_tunnel_smoke.rs`). **N1.1 done
  (2026-05-31): its `cfg(windows)` body now compiles on Windows** — `build-release`
  on `windows-utm-1` succeeded (exit 0) and the built
  `C:\Rustynet\target\release\rustynetd.exe` (5,156,352 bytes, 2026-05-31 20:39)
  lists the `windows-tunnel-smoke` subcommand in `--help`. First-ever Windows
  compile of the smoke body; closes the G7 compile question for it.
- **Orchestrator harness landed (host-gated):** a `tunnel-smoke` bootstrap
  phase + `scripts/bootstrap/windows/Invoke-RustyNetWindowsTunnelSmoke.ps1`
  (admin-gated, timeout+kill bounded, fail-closed JSON envelope surfacing
  `overall_ok`) + a `parse_windows_tunnel_smoke_output` parser + unit tests,
  modeled on the `smoke-service-host` harness. The phase requires proven
  host-side access, is **excluded from `All`** (privileged, checkpoint-gated),
  and fails closed as "Windows-only" on Linux/macOS. `cargo fmt`/`clippy
  -D warnings`/unit tests are green on the macOS host.
- **Run path (once the guest is reachable):** `sync-source` → `build-release`
  (this is also the N1.1 guest-compile gate for the `cfg(windows)` smoke body)
  → `ops vm-lab-bootstrap-phase --phase tunnel-smoke --vm windows-utm-1`. The
  smoke runs the freshly built `target\release\rustynetd.exe` directly; it does
  **not** require `install-release`/`restart-runtime`.
- **Guest recovered (2026-05-31), N1.1/N1.3 unblocked.** `windows-utm-1` had
  been unreachable from the host (ping/TCP-22 timeouts at `192.168.0.45`) — root
  cause was the **G9 killswitch lockout**, not a network/IP problem: the
  `RustyNet` service was RUNNING with the firewall at `AllowInbound,BlockOutbound`
  (see G9 for the recovery recipe). Recovered from the host via `utmctl exec`
  (the guest is QEMU/VirtIO with a working guest agent, not Apple-Virt — earlier
  assumption corrected). The guest is now reachable (host ping + TCP/22 stable),
  the service is STOPPED + set to demand-start, and its IPv4 is still
  `192.168.0.45` (inventory unchanged). N1.1 (guest compile) and the live N1.3
  bring-up can proceed via the orchestrator.
- **N1.3 PASSED (2026-06-01) — first-ever live tunnel bring-up.** After a fresh
  `sync-source` → `build-release` (the first guest compile to include the E2 WFP
  killswitch code; exit 0), `ops vm-lab-bootstrap-phase --phase tunnel-smoke`
  reported `status=pass` / `overall_ok=true`, daemon exit 0, clean teardown.
  Post-run `netsh interface show interface` shows no residual `rustynet*`
  adapter (no leak/leftover). **One orchestrator bug was fixed to get here**
  (not a daemon/data-plane defect): the shared Windows helper-invocation wrapper
  (`build_windows_helper_invocation_script`, `vm_lab/mod.rs`) read
  `[string]$LASTEXITCODE` raw under `Set-StrictMode -Version Latest`. The smoke
  `.ps1` returns via `Start-Process` and falls off its end without ever invoking
  an external `.exe`, so `$LASTEXITCODE` was never set → strict-mode threw "cannot
  be retrieved because it has not been set", discarding the helper's own
  `overall_ok` JSON *after* the tunnel had already come up and torn down. Fix:
  seed `$LASTEXITCODE = 0` before the helper runs (mirrors the result-file
  sibling); regression test
  `windows_helper_invocation_script_preseeds_lastexitcode_under_strictmode`.

### N2 — Killswitch + protected-mode exercise on the single node ✅ (2026-06-01, covers G2)
With a tunnel up, apply the killswitch and verify default-deny + the tunnel /
egress allowances behave. Confirm **fail-closed**: if killswitch apply fails,
the daemon must not serve a protected tunnel.
- **Done when:** killswitch verified active under a live tunnel, fail-closed
  proven, and a go/defer decision recorded for E2.

Progress (2026-06-01) — **N2 PASSED**:
- A dedicated single-node smoke verb `rustynetd windows-killswitch-smoke`
  (`crates/rustynetd/src/windows_killswitch_smoke.rs`) + bootstrap phase
  `killswitch-smoke` + admin-gated harness
  `scripts/bootstrap/windows/Invoke-RustyNetWindowsKillswitchSmoke.ps1` were
  built (mirrors the N1 tunnel-smoke). It brings up a self-only tunnel, then
  drives the real `WindowsCommandSystem`: `apply_firewall_killswitch` →
  `assert_killswitch` (active) → `rollback_firewall` → assert (inactive),
  gating the verdict on the WFP tunnel-permit observed **absent → present →
  absent** plus the netsh default-block-outbound policy asserted active.
- **Live result on `windows-utm-1`:** `status=pass` / `overall_ok=true`. Post-run
  the firewall is back to `AllowInbound,AllowOutbound` on all profiles (no
  residual block), no `rustynet*` adapter remains, and TCP/22 stayed up
  throughout — the killswitch's egress-allow rule keeps the LAN SSH session
  alive by design, now verified.
- **Lockout safety net (covers G9):** the harness arms a guest-side
  dead-man's-switch (a one-shot SYSTEM `schtasks` task that restores
  allow-outbound at T+180s) **before** any killswitch is applied, plus a
  finally-block inline restore and an in-process Rust `Drop` guard. After the
  clean run the dead-man's-switch task was confirmed deleted (it never had to
  fire). So an unattended killswitch run can no longer brick SSH.
- **Fail-closed-on-apply-error** is unit-proven (OS-agnostic reconcile):
  `killswitch_apply_failure_fails_closed_before_exit_mode` injects an
  `apply_firewall_killswitch` failure and asserts the generation drops to
  `FailClosed` via `block_all_egress`, with exit mode never committing.
- **`--exercise-full-block`** (opt-in) additionally runs `block_all_egress` and
  asserts the WFP permit is removed (the 295d780 fail-OPEN fix) — deliberately
  off by default because it cuts the LAN SSH session until rollback; reserved
  for an explicit operator run behind the dead-man's-switch.

### N3 — DNS fail-closed validation ✅ (2026-06-01, covers G3)
Exercise the netsh DNS lockdown under a live tunnel; confirm no plaintext DNS
leak in protected mode.
- **Done when:** DNS fail-closed verified live on Windows.

Progress (2026-06-01) — **N3 PASSED**:
- Rather than a third standalone smoke, the N2 `killswitch-smoke` was extended
  with an opt-in DNS leg (`--exercise-dns`) and a `dns-smoke` bootstrap phase
  drives it. While the killswitch is active, the sequence runs
  `apply_dns_protection` → `assert_dns_protection` (active) → `rollback_dns_protection`
  → assert (inactive); `overall_ok` now also gates on the DNS signals. This is the
  most faithful "DNS fail-closed *in protected mode*" proof: the netsh port-53
  Block rule must hold while the killswitch's egress-allow is in force.
- **Live result on `windows-utm-1`:** `--phase dns-smoke` → `status=pass` /
  `overall_ok=true`. Post-run: firewall `AllowInbound,AllowOutbound`, zero
  residual `RustyNetKS-*`/`RustyNetDNS-*` rules, no `rustynet*` adapter, the
  dead-man's-switch task auto-deleted, and TCP/22 never lost (the DNS block is
  port-53 only; SSH is port 22).
- **Follow-up (minor, non-blocking):** the smoke gates on `apply`/`assert`/`rollback`
  returning Ok + the assert-active OS query; it does not separately OS-assert
  post-rollback rule *absence* (that was confirmed manually here). A future
  hardening could add a post-rollback absence assertion to the verdict.

### N4 — Two-node mesh: Windows guest + one peer 🔴 (covers G4)
Drive enrollment + signed-state + dataplane reconcile so the Windows guest and
one Linux/macOS peer form a tunnel and pass traffic both ways. Promote Windows
to a first-class node in the orchestrator path.
- **Done when:** bidirectional ping/throughput across the mesh with a Windows
  node, with a row appended to `live_lab_run_matrix.csv`.

### N5 — Roles on Windows (blind_exit, then anchor) 🔴 (covers G6)
With two-node mesh working, run Windows as blind_exit (NetNat forwarding + exit
preflight), then as anchor. Build on Track B of the cross-platform role delta.
- **Done when:** a client routes its exit through a Windows blind_exit node;
  anchor role validated separately.

### N6 — Full live-lab matrix including Windows 🔴
Fold Windows into the standard matrix run so `live_mixed_topology` and the
role-switch matrix include a Windows node.
- **Done when:** a matrix run with Windows passes and is recorded as evidence.

---

## 5. Engineering enablers (⚙️, parallelizable)

- **E1 — Windows compile gate (G7) — ✅ landed (cross-`check`).**
  `scripts/ci/windows_compile_check.sh` cross-`cargo check`s `cfg(windows)` code
  against `x86_64-pc-windows-msvc` (the guest ABI) via the pinned rustup 1.88.0
  toolchain, giving local compile feedback without a guest build. Setup gotcha
  (documented in the script): plain `cargo`/`rustc` on this host are **Homebrew
  Rust** with no Windows target std, so the gate invokes the rustup toolchain's
  cargo + `RUSTC` explicitly. **Limitation:** pure-Rust Windows crates
  (`rustynet-windows-native`) cross-`check` cleanly, but crates pulling **C deps**
  (`rustynetd` → `libsqlite3-sys`) cannot cross-compile on macOS (no Windows C
  headers for `cc`); those still rely on the guest build for the full compile.
  So the gate covers the FFI crates directly and the rest via the host build
  (against the non-windows stubs) + the guest build.
- **E2 — Native WFP killswitch (G2) — ✅ landed + guest-validated + live (2026-06-01).**
  `apply_wfp_tunnel_permit` / `remove_wfp_tunnel_permit` in `rustynet-windows-native`
  replace the last `New-NetFirewallRule` (CIM) allow rule with a native WFP filter
  keyed on the tunnel interface LUID — no CIM, cannot hang. A persistent max-weight
  RustyNet sublayer wins arbitration over the netsh default-block-outbound policy;
  hard-permit filters at ALE_AUTH_CONNECT_V4/V6 permit outbound on the tunnel LUID.
  `phase10.rs` `apply_firewall_killswitch` calls it (rollback removes it). Validated:
  `windows-native` cross-compiles for msvc (E1); the full `rustynetd` Windows compile
  succeeded on the guest `build-release`; and **N2's `killswitch-smoke` exercised it
  live** — `wfp_tunnel_permit_present()` observed absent → present (under the
  killswitch) → absent (after rollback), with `assert_killswitch` confirming the
  permit while the netsh default-block-outbound policy was active. The CIM cmdlet is
  gone from the apply path.
- **E3 — Gate stage-timing CSV.** Record per-stage wall-clock from the xtask
  gates runner to `documents/operations/gate_timings.csv` (separate, queued).

---

## 6. Constraints to preserve (from CLAUDE.md / SecurityMinimumBar)

- **No CIM/PowerShell cmdlets on the daemon's synchronous startup or
  dataplane-apply path** — use native Win32 APIs; if a subprocess is
  unavoidable, bound + kill it.
- **Fail closed** when trust/security state or a security control (killswitch,
  DNS lockdown) is missing or cannot be applied.
- **One hardened path** per security-sensitive workflow; no fallback/downgrade.
- argv-only exec for privileged helpers; never log secrets/keys; DPAPI key
  custody preserved.

---

## 7. Pointers

- Lab guest: `windows-utm-1` (UTM "Windows"), `192.168.0.45:22`, ssh user
  `windows`, key `/Users/iwan/.ssh/rustynet_lab_ed25519` (host key pinned).
  Backend auto-selects `windows-wireguard-nt`.
- Recover a stuck guest before retrying:
  `scripts/vm_lab/probe_and_recover_local_utm.sh`.
- Append a `live_lab_run_matrix.csv` row after every run used as evidence.
