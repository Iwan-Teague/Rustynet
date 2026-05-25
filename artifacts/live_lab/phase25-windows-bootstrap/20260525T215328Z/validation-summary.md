# Phase 25 Windows orchestrator bootstrap validation - Summary

**Target:** `windows@192.168.65.8` (`WIN-F3T6JVFODOV`, Windows 10.0.26200.0)
**UTC timestamp:** `20260525T215328Z`
**Outcome:** **BLOCKED** - guest paging-file exhaustion prevents any SSH-side
command execution. Live re-bootstrap and live observation of Phase 23/26/27
acceptance criteria cannot be completed without operator intervention.

## What was validated (positive)

1. **Network reachability + SSH transport handshake.** A bare
   `ssh windows@192.168.65.8 'hostname'` returned `WIN-F3T6JVFODOV`
   during the very first probe of the session (before subsequent
   PowerShell invocations exhausted the guest's paging file).

2. **Prior RustyNet install IS present.** A single
   `Test-Path 'C:\Program Files\RustyNet'` returned `True`. A
   `Get-Service RustyNet` returned `Status=Running, StartType=Automatic`.
   This confirms the Phase 23/26/27 install layout has been provisioned
   on this VM previously and the daemon was Running at the start of the
   evidence window.

## What could NOT be validated (blocked)

Items 3-7 of the Phase 25 prompt all require running a non-trivial
PowerShell or rustynetd.exe command over SSH. Every retry triggered one
of (in order, as guest memory degraded):

- `Thread failed to start.`
- `Exception of type 'System.OutOfMemoryException' was thrown.`
- `Could not load file or assembly 'System.Management.Automation, ...': The paging file is too small for this operation to complete. (Exception from HRESULT: 0x800705AF)`
- `Process is terminated due to StackOverflowException. Attempting to perform the InitializeDefaultDrives operation on the 'FileSystem' provider failed.`
- `kex_exchange_identification: read: Connection reset by peer` (sshd itself dropping connections).

Even `scp` round-trip fails (`scp: Connection closed`) because Windows
OpenSSH invokes the default shell (PowerShell) at session establishment
time. Per the prompt, this is operator/user territory - I did not exceed
the 30-minute VM-troubleshooting budget.

Blocked steps:
- **Step 3** - re-run orchestrator `stage_bootstrap_hosts` with a Windows
  arm in scope. Even pre-flight `verify_ssh_reachability` would fail.
- **Step 4** - directory enumeration of `C:\ProgramData\RustyNet\`,
  service-status verification, DPAPI blob SHA256 distinctness check.
- **Step 5** - `rustynetd.exe windows-named-pipe-acls-check`.

## Defects surfaced

### Phase 25 surfaced - Phase 23 follow-up needed (LATENT)

**File:** `scripts/e2e/live_linux_lab_orchestrator.sh`
**Lines:** 2879-2891 (the `bootstrap_host_worker_windows` invocation
of `live_lab_ssh "$target" "$invoke_cmd"`)

**Issue:** the orchestrator's Windows arm invokes PowerShell over SSH
directly:

```bash
invoke_cmd="powershell.exe -NoProfile -ExecutionPolicy Bypass -File '${remote_wrapper}' -NodeId '${node_id}' ..."
live_lab_ssh "$target" "$invoke_cmd"
```

Per the Phase 23 reviewer (commit `4a7af92` review), PowerShell-over-SSH
fails with `Thread failed to start.` on memory-pressured Windows hosts.
The documented compatibility workaround is to wrap in `cmd.exe`:

```
cmd.exe /c "powershell.exe -EncodedCommand <base64-utf16le>"
```

The Phase 23 commit shipped the wrapper script correctly but did NOT
apply that workaround in the orchestrator-side invocation. So on any
Windows host under non-trivial memory pressure the orchestrator's
`bootstrap_host_worker_windows` will fail before it even reaches the
wrapper script.

**Fix sketch (Phase 23 follow-up):**
1. Add a helper in `scripts/e2e/live_lab_common.sh` -
   `live_lab_ssh_windows()` - that takes a PowerShell command string,
   converts it to UTF-16LE base64 in bash via
   `printf '%s' "$cmd" | iconv -t UTF-16LE | base64 | tr -d '\n'`,
   and SSHes:
   `cmd.exe /c "powershell.exe -NoProfile -OutputFormat Text -EncodedCommand $B64"`
2. Replace the PowerShell invocation in `bootstrap_host_worker_windows`
   (lines 2879-2891) with a single call to that helper, threading the
   wrapper invocation as a single PowerShell command:
   `& 'C:\\Windows\\Temp\\rn_bootstrap_windows.ps1' -NodeId '<id>' ...`
3. Likewise refactor `collect_pubkey_worker`, `membership_add_worker`,
   etc., for any other Windows-targeted ssh call.
4. Add a unit-equivalent: invoke `live_lab_ssh_windows` against the
   live `windows-client-1` VM with a tiny `Get-Date` payload as a
   smoke gate at the start of `stage_bootstrap_hosts` when any node is
   `platform=windows`.

(Could not be patched in this commit because it requires touching the
shared `live_lab_common.sh` and re-running all Linux paths to prove no
regression - that's beyond the scope of an evidence-only Phase 25
commit. Filed as a Phase 23 follow-up.)

### No new Phase 26/27 defects surfaced

The Phase 26 named-pipe ACL hardening + the Phase 27 DPAPI key
separation are both correct in tree (unit tests exist). Live
verification is blocked solely by the guest state.

## Operator action required (BEFORE re-running Phase 25)

1. Open the `windows-client-1` (UTM `windows-utm-1`) guest console.
2. If the OS desktop is responsive: open Task Manager, identify any
   process holding significant RAM (likely `rustynetd.exe` from the
   prior bootstrap), and either kill it or reduce its working set.
   Then open `sysdm.cpl` -> Advanced -> Performance -> Settings ->
   Advanced -> Virtual memory -> Change..., uncheck "Automatically
   manage", select drive `C:`, set Custom size to Initial=4096 MB,
   Maximum=8192 MB (or to the guest's available disk). Reboot.
3. If the OS desktop is not responsive: force-restart the UTM VM,
   then perform step (2) on first boot.
4. Re-run Phase 25 starting from `Step 1 - pre-flight Windows VM` of
   the original prompt. The evidence directory
   `artifacts/live_lab/phase25-windows-bootstrap/20260525T215328Z/`
   captures the failure baseline and should remain in tree so the
   re-run's evidence supersedes it under a fresh UTC timestamp.

## What's owed (after operator action)

- Re-run of the orchestrator's `stage_bootstrap_hosts` against a
  profile containing windows-client-1 (recommended:
  `profiles/live_lab/phase31_mixed_os_five_node.env` with
  `--rerun-stage bootstrap_hosts --setup-only`).
- Live capture of Step 4 (service status + canonical layout +
  DPAPI blob distinctness).
- Live capture of Step 5 (`windows-named-pipe-acls-check` JSON).
- If the Phase 23 follow-up `live_lab_ssh_windows` helper is shipped
  before that re-run, the re-run also serves as its smoke gate.
