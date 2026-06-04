# Windows Exit Node — Active Full-Tunnel Exit Runbook (2026-06-04)

How to run (and prove) a **successful live lab with Windows actively serving as a
full-tunnel exit** — NAT'ing a client's internet traffic out the Windows host.

All Rustynet code is in place and validated. The only prerequisite is a Windows
guest with a working **WinNAT/HNS networking stack**; the current `windows-utm-1`
lab VM lacks it (minimal image, no Host Network Service, no `WinNATWmiProv.dll`).

## Background — why the standard "exit" run is not enough

The standard lab `windows:exit` topology validates the exit **role** + posture +
mesh in **split-tunnel** only. It never activates exit-serving, so the exit never
applies IP forwarding or NAT (live evidence r50–r52: `forwarding=Disabled`, no NAT
the whole run). A node serves as a full-tunnel exit only after it receives
`route advertise 0.0.0.0/0` (the operator "become an exit" action;
`handle_exit_service_route_advertise` → `apply_windows_exit_nat_forwarding`).

The `active_exit` orchestration stage (commits `f1992a0`, `c09de60`) closes this:
it runs after `exit_handoff`, sends the route-advertise over the daemon's control
named pipe (a `NamedPipeClientStream` — the guest's `rustynet.exe` is only the
trust CLI and has no route-advertise command), then asserts the exit forwards +
NATs and that the **client's traffic egresses via the exit's NAT**
(`Get-NetNatSession` shows a mesh-sourced `100.64.0.0/10` translation).

## Prerequisite 1 — a WinNAT/HNS-capable Windows guest

Use a standard Windows 10/11 Pro or Windows Server image (these ship WinNAT/HNS;
it is what WSL2 / Docker / Hyper-V use). Verify a candidate guest:

```powershell
# Both must succeed. If either errors "Invalid class" / "Not found", the guest
# lacks the WinNAT WMI provider and CANNOT serve as an exit.
Get-NetNat | Out-Null; "Get-NetNat ok"
Get-CimClass -Namespace root/standardcimv2 -ClassName MSFT_NetNat | Out-Null; "MSFT_NetNat present"
Get-Service hns                                   # Host Network Service should exist
```

The daemon also enforces this: `WINDOWS_PS_REQUIRE_EXIT_CMDLETS` /
`WINDOWS_PS_PREFLIGHT_EXIT_SERVING` now check `Get-CimClass MSFT_NetNat`, so a
WinNAT-less guest fails closed at `active_exit` with a clear remediation message
(commit `94598c9`) rather than a misleading all-green split-tunnel run.

## Prerequisite 2 — the exit guest needs internet egress

An exit forwards client traffic to the internet, so it needs a default route. The
lab Windows VM is static / gateway-less; give it one (a real exit has one):

```powershell
$idx = (Get-NetAdapter -Name Ethernet).ifIndex
route -p add 0.0.0.0 mask 0.0.0.0 192.168.0.1 metric 25 if $idx
Test-Connection 8.8.8.8 -Count 1 -Quiet   # must be True
```

## Run it

Same command as any windows:exit run (working-tree builds the new stage on the
host orchestrator):

```bash
cargo run -p rustynet-cli -- ops vm-lab-orchestrate-live-lab \
  --inventory /tmp/lab_inv_live.json --report-dir /private/tmp/rn_live_win_exit \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 --known-hosts-file ~/.ssh/known_hosts \
  --node windows-utm-1:exit --node debian-headless-1:client \
  --source-mode working-tree --collect-artifacts-on-failure
```

Pre-clean both nodes first (firewall reset on Windows, stop units + delete nft
tables on debian) — see the live-lab re-verify recipe in
`memory/lab_debian_node_state.md` / the standard pre-clean used in the run matrix.

**Expected on a WinNAT-capable guest:** all 18 stages green, including
`active_exit` (forwarding + NAT applied, and a `Get-NetNatSession` shows debian's
`100.64.x` mesh address NAT-translated outbound → client egress via Windows proven).

## After a green run — promote the support posture (optional, deliberate)

Windows Exit is `is_supported_for_platform = false` (fail-closed) BY DESIGN in
`crates/rustynet-cli/src/vm_lab/orchestrator/role.rs`, pending this exact live
evidence. Once `active_exit` passes on a real guest, the support flag may be
flipped to promote Windows-as-exit to **supported** (a one-line change in
`is_supported_for_platform` + its test). This is a deliberate security-posture
change — do it only with the green-run evidence archived, not before.

## State of play (2026-06-04)

- Trigger (named-pipe route-advertise): built + live-proven (reaches daemon).
- IP forwarding apply: proven.
- `active_exit` stage (activate → forwarding/NAT → client-egress NAT session):
  built, unit-tested, fail-path live-validated (r54). Success path needs a
  WinNAT/HNS guest.
- Blocker: the WinNAT/HNS-capable guest (the only remaining item; environment, not
  code).

Related: `project_windows_runtime_state.md` (memory), `dns_failclosed_plan.md`,
`reference_windows_utm_recovery.md`, `RustynetDataplaneExecutionPlan_2026-05-18.md`
(§D7 Windows-as-exit live evidence).
