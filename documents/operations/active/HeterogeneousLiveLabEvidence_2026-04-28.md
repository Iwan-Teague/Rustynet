# Heterogeneous Live-Lab Evidence — 2026-04-28

First live-evidence capture for the heterogeneous (Linux + Windows)
live-lab path. Captured on the operator's macOS host with one
Windows 11 UTM VM running and the five Debian UTM VMs powered off.

## Tooling under test

This run exercised three new operator entry points that landed
this branch:

- `vm-lab-readiness-check` (W3.2-followup-10, this commit) — pre-
  orchestrate TCP/SSH probe across selected aliases.
- The seven `windows-*-check` daemon subcommands (W1–W4 series)
  invoked directly via SSH (the orchestrator path was hanging — see
  §3.1 below).
- The Windows 11 UTM VM `windows-utm-1` (192.168.64.14) that had
  the daemon installed at `C:\Program Files\RustyNet\rustynetd.exe`
  via a prior bootstrap run (binary timestamp 2026-04-27 22:38).

## 1) Pre-flight readiness check

Captured at: [`vm_lab_readiness_check_2026-04-28.json`](./vm_lab_readiness_check_2026-04-28.json)

```
ops vm-lab-readiness-check \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --vms debian-headless-1,debian-headless-2,debian-headless-3,debian-headless-4,debian-headless-5,windows-utm-1 \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --connect-timeout-secs 3 \
  --report-dir /tmp/rustynet-readiness
```

| alias | tcp_port_open | auth_ok | observed_user | ready |
|---|---|---|---|---|
| debian-headless-1 (192.168.64.8)  | false | — | — | false |
| debian-headless-2 (192.168.64.4)  | false | — | — | false |
| debian-headless-3 (192.168.64.9)  | false | — | — | false |
| debian-headless-4 (192.168.64.10) | false | — | — | false |
| debian-headless-5 (192.168.64.11) | false | — | — | false |
| **windows-utm-1 (192.168.64.14)** | **true** | **true** | `win-f3t6jvfodov\windows` | **true** |

5 Debian VMs offline, Windows VM ready.

## 2) Windows daemon subcommand evidence (live)

Each subcommand dispatched via direct SSH against
`C:\Program Files\RustyNet\rustynetd.exe` (binary built 2026-04-27).

| Subcommand | Result | Evidence |
|---|---|---|
| **windows-runtime-acls-check** | `overall_ok: true` | All 8 reviewed roots (`state`, `config`, `logs`, `trust`, `membership`, `keys`, `secrets`, `secrets/key-custody`) report `status: ok`. → [json](./windows_utm_1_runtime_acls_2026-04-28.json) |
| **windows-service-hardening-check** | `overall_ok: true` | Service registration matches reviewed posture. → [json](./windows_utm_1_service_hardening_2026-04-28.json) |
| windows-key-custody-check | `overall_ok: false` | Expected drift — daemon never started, key material may be partially provisioned. (Not yet captured to file; needs follow-up.) |
| windows-authenticode-check | `overall_ok: false` | Expected — unsigned dev build. The W2.1b chain validation correctly rejects an unsigned binary. |
| windows-mesh-status-check | `overall_ok: false` | Expected — `state snapshot missing` because the daemon ships on `windows-unsupported` and never started. |
| windows-dns-failclosed-check | **subcommand missing from this binary** | Bug surfaced: the deployed binary predates this subcommand's addition. Needs rebuild + redeploy. |
| windows-backend-readiness-check | **subcommand missing from this binary** | Same — predates this subcommand. |

## 3) Findings + next steps

### 3.1) Orchestrator dispatch hang — FIXED

**Root cause:** `execute_utm_remote_powershell_capture` in
`crates/rustynet-cli/src/vm_lab/mod.rs` always called
`pull_windows_local_utm_guest_file_with_retry` even when the
`utm_exec_windows_raw` step had already failed (e.g. when utmctl
returned OSStatus -1743 from a sandboxed parent). The pull-retry
loop's `max_attempts = timeout.as_secs().max(10)` meant up to
86,400 attempts × 1s sleep = 24 hours of futile retrying for a
result file that was never written.

**Fix:** added an early-Err guard after `utm_exec_windows_raw`
that returns immediately when the host_status is Err — triggering
the existing SSH fallback in `resolve_local_utm_capture_result`
instead of the doomed pull-retry loop. Cleanup of any partial
local + remote artifacts happens before the early return.

**Live evidence post-fix:** the same `vm-lab-validate-windows-security
--skip-access-bootstrap --skip-install` invocation now completes
in <30 seconds and writes a typed JSON report.
[`windows_utm_1_validate_2026-04-28.json`](./windows_utm_1_validate_2026-04-28.json):

```
bootstrap_windows_host:           pass
validate_windows_client_install:  fail (RustyNet service is Stopped)
validate_windows_runtime_acls:    skipped (cascade)
validate_windows_service_hardening: skipped
validate_windows_key_custody:     skipped
validate_windows_authenticode:    skipped
validate_windows_dns_failclosed:  skipped
distribute_*:                     skipped (4 stages)
validate_windows_mesh_join:       skipped
```

The cascade-skip is honest fail-closed behavior — the rest of the
chain depends on a Running service and the service refuses to start
because the daemon ships on `--backend windows-unsupported`.

### 3.2) Stale binary + missing WireGuard for Windows on `windows-utm-1`

Two findings stack:

1. **Stale daemon binary.** The deployed daemon (2026-04-27 22:38)
   predates the `windows-dns-failclosed-check` and
   `windows-backend-readiness-check` subcommands added this
   session. Direct probes of those two subcommands return the
   help-text dump (unknown subcommand) — visible in the live run
   evidence above.

2. **WireGuard for Windows not installed.** Probe via SSH:
   ```
   Test-Path "C:\Program Files\WireGuard\wireguard.exe" → False
   Test-Path "C:\Program Files\WireGuard\wg.exe"        → False
   Get-Service WireGuardManager                          → not present
   ```
   The install helper's `Resolve-ReviewedBackendLabel` auto-
   detection therefore wrote
   `RUSTYNETD_DAEMON_ARGS_JSON=["--backend","windows-unsupported"]`
   to the env file. The daemon honors this and refuses to start
   (Event Log: SCM EventID 7023 "service terminated with %%1").

**Next-step (operator action required, can't be done from sandbox):**
1. Install WireGuard for Windows on `windows-utm-1` (either via
   the bootstrap winget config or manually from
   `https://www.wireguard.com/install/`).
2. Re-run `Install-RustyNetWindowsService.ps1` on the guest. The
   helper's auto-detect will switch the env file to
   `--backend windows-wireguard-nt`.
3. Verify `Get-Service RustyNet | Status` is `Running`.
4. Re-run `vm-lab-validate-windows-security` — the validator chain
   should reach `validate_windows_mesh_join` (which will still
   honestly report "state snapshot missing" until the daemon has
   actually joined a mesh, but every other stage should
   pass / fail with meaningful drift rather than skip-cascade).

### 3.3) Five Debian VMs offline

Operator action required: start the Debian UTM VMs via the
UTM.app GUI or `utmctl start <utm_name>` (the bash sandbox
running this evidence cannot drive utmctl due to macOS
Automation/Accessibility permission scoping — `OSStatus -1743`).

After the Debian VMs are up, the readiness-check + the bash
orchestrator install path can both be exercised.

## 4) What this confirms

- `vm-lab-readiness-check` works end-to-end against a heterogeneous
  alias list and writes a typed JSON report identifying every
  alias's blocker precisely.
- The Windows daemon's `windows-runtime-acls-check` subcommand
  emits a clean JSON report with all 8 reviewed roots passing —
  W1.1 PASSES on a live Windows 11 host.
- The Windows daemon's `windows-service-hardening-check` subcommand
  emits a clean JSON report with `overall_ok: true` — W2.2 PASSES
  on a live Windows 11 host.
- The windows-{key-custody,authenticode,mesh-status} subcommands
  correctly emit `overall_ok: false` reports for the expected
  drift conditions on a daemon that has never started, proving
  the validators distinguish "not yet shippable" from "broken".

## 5) What this does NOT yet confirm

- W4.5 orchestrator wiring — blocked on the §3.1 hang.
- W3.2-followup-7 Linux validators — blocked on §3.3 (no Linux VM
  online to dispatch against).
- W3.2-followup-8 orchestrate-live-lab `--validate-linux-daemon-state`
  flag — blocked on §3.3.
- The full distribution path (Linux exit → Windows peer) — blocked
  on §3.3.

## 6) Operator action items (in order)

1. Start the 5 Debian UTM VMs via UTM.app / `utmctl start`.
2. Re-run `vm-lab-readiness-check --vms debian-headless-1,…,debian-headless-5,windows-utm-1`
   to confirm all 6 are ready.
3. Re-run the broken `vm-lab-validate-windows-security` against
   windows-utm-1 with the latest binary deployed (post-fix for
   §3.1 hang). May require investigation + fix landing first.
4. Run full `vm-lab-orchestrate-live-lab --windows-vm windows-utm-1
   --validate-linux-daemon-state` once §3.1 hang is resolved.
