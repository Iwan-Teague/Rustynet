# Windows UTM Transport Architecture

Date: 2026-04-30
Status: active reference
Owner: Rustynet engineering
Branch baseline: `main` @ work in progress on `awesome-rosalind-5540e1`

## Purpose

Document the orchestration transport for Windows local-UTM guests after
the 2026-04-30 rework. Lab orchestration currently uses macOS-hosted UTM
to drive a Windows 11 guest (`Windows.utm`, alias `windows-utm-1`).

Two transport channels are available to the orchestrator:

1. **SSH** (`ssh`/`scp` from host to guest TCP/22) — primary for steady
   state, but breaks during mid-orchestration network changes (e.g.
   WireGuard interface coming up, route reordering).
2. **utmctl exec / utmctl file push / utmctl file pull** — host-to-guest
   over the QEMU/SPICE guest agent, network-independent.

The Windows guest needs both because mesh-join changes routing on the
guest side and SSH connections drop. utmctl survives because it never
goes through the network stack of the guest.

## Identity asymmetry

The orchestrator's security model and the guest agent's identity disagree
on Windows in a way that does not happen on Linux:

| Channel | Identity inside guest |
|---|---|
| SSH (`scp`, `ssh ... powershell.exe ...`) | the SSH login user (`windows`) |
| utmctl exec / file push / file pull | `NT AUTHORITY\SYSTEM` (the QEMU/SPICE guest agent service) |

Linux UTM guests do not have this problem because the agent and the SSH
user can be reconciled (root vs. user; `runuser` bridges them).

## Why utmctl previously failed

The Windows runtime bootstrap hardens the entire `C:\ProgramData\RustyNet`
tree with `takeown ... /r` followed by `icacls ... /grant:r <user>:(OI)(CI)(F) /T`.
The `/grant:r` flag REPLACES all explicit ACEs, so after bootstrap runs:

```
C:\ProgramData\Rustynet\vm-lab
  WIN-...\windows:(OI)(CI)(F)
  WIN-...\windows:(I)(OI)(CI)(F)
  NT SERVICE\RustyNet:(I)(OI)(CI)(M)
```

SYSTEM is absent. That is the entire root cause of `utmctl file push`
failing with `OSStatus -2700` ("Access is denied" wrapped by an Apple
Events surface). The macOS Privacy & Security Automation permission is
NOT involved.

The SSH user `windows` retains access (explicit grant), so SSH/SCP keep
working. utmctl runs as SYSTEM and is denied.

## Architecture: separate orchestration root for UTM-Windows

The fix preserves state-tree hardening as-is and instead routes
orchestration scratch to a directory that grants both identities access.

### `utm_staging_dir`

A new inventory field carried through to `RemoteTarget`. For Windows
local-UTM targets, it defaults to:

```
C:\Users\<ssh_user>\rustynet-utm-stage
```

That path inherits from the user's profile dir, which by Windows
defaults grants `SYSTEM:F`, `BUILTIN\Administrators:F`, and the user
itself `:F`. Both transports therefore have read+write access. The
state-tree hardening (`takeown C:\ProgramData\Rustynet /r`) does not
reach into `C:\Users\...`, so future hardening cannot regress this path.

For non-Windows targets and for future non-UTM Windows targets the field
is `None`; existing `remote_temp_dir` (vm-lab) semantics apply.

### `windows_orchestration_root(target)`

Single source of truth. For Windows local-UTM targets, returns
`utm_staging_dir`; otherwise returns `remote_temp_dir`. Used by
`windows_helper_script_remote_path` and
`build_windows_build_release_report_paths`, so every helper script,
result file, and bootstrap report root for a Windows-UTM target lives
under one directory both transports can reach.

### Transport routing for Windows-UTM targets

- `run_remote_shell_command_for_target_with_phase` (Windows branch):
  primary path is `execute_utm_remote_powershell_capture` (utmctl exec
  + result file). On utmctl error, falls back to SSH.
- `capture_remote_shell_command_for_target_with_phase` (Windows branch):
  same pattern; output captured via result-file in staging dir.
- `scp_to_remote_for_target_with_phase` (Windows branch): SSH SCP
  directly into the staging dir. Before each SCP, an idempotent
  `utmctl exec` mkdir ensures the staging dir exists (SCP does not
  create intermediate directories). This is network-independent.
- Helper-script invocation in `run_helper_via_local_utm_result_file`:
  SCP helper to staging dir, utmctl exec wrapper that invokes it,
  utmctl file pull of the result file. All three steps share one
  directory; SYSTEM has read access for the invocation, write access
  for the result file, and the host can pull the result file back.

### `execute_utm_remote_powershell_capture`

Runs an inline PowerShell script on the guest via `utmctl exec` with
`-EncodedCommand`. Captures the script's output and exit code via two
files written to `utm_staging_dir`, then `utmctl file pull`s them back.
Best-effort cleanup on the way out. The script itself is never
materialized as a file on the guest — it travels in argv via base64
encoding — so identity does not matter for the inner script's source.

## Why this is robust to future state-tree hardening

`utm_staging_dir` lives outside `C:\ProgramData\Rustynet`. Any future
tightening of the state tree (additional `takeown /r`, `icacls /T`,
inheritance breaks, group policy) has no effect on the orchestration
channel. Both halves of the staging directory's ACL come from
inheritance off the user profile, which Windows itself owns.

The split also prevents accidental re-coupling: when someone modifies
the bootstrap hardening, they do not have to remember "and also re-grant
SYSTEM on vm-lab" because vm-lab is no longer on the orchestration path
for utmctl.

## Field reference

- Inventory JSON key: `utm_staging_dir` (string, optional)
- `RemoteTarget.utm_staging_dir: Option<String>`
- `default_utm_staging_dir_for_profile(profile, ssh_user)` — only emits
  `Some` for Windows
- `remote_target_windows_utm_staging_dir(target)` — error if a Windows
  UTM target has no staging dir resolved (either explicit or default)
- `ensure_utm_windows_dir(utm_name, dir, timeout)` — idempotent mkdir
  via utmctl exec PowerShell
- `windows_orchestration_root(target)` — unified scratch root
- `windows_helper_script_remote_path(target, file_name)` — joins via
  the unified root

## Related code

- `crates/rustynet-cli/src/vm_lab/mod.rs`:
  - `default_utm_staging_dir_for_profile`
  - `remote_target_windows_utm_staging_dir`
  - `windows_orchestration_root`
  - `ensure_utm_windows_dir`
  - `utm_push_to_windows_staging`
  - `build_utm_windows_result_file_wrapper_script`
  - `execute_utm_remote_powershell_capture`
  - `run_remote_shell_command_for_target_with_phase` (Windows branch)
  - `capture_remote_shell_command_for_target_with_phase` (Windows branch)
  - `scp_to_remote_for_target_with_phase` (Windows branch)
- `crates/rustynet-cli/src/vm_lab/bootstrap/windows.rs`:
  - `local_utm_result_file_supported_for_phase`
  - `build_windows_build_release_report_paths`
  - `build_windows_diagnostics_invocation`

## Future work

- Inline-exec channel for mesh-join stages: even with the staging dir,
  staging files cross the `windows`-user → SYSTEM boundary on every
  call. For stages that run during/after the WireGuard interface
  flips (`distribute_windows_membership`, `distribute_windows_assignment`,
  `distribute_windows_traversal`, `distribute_windows_dns_zone`,
  `validate_windows_mesh_join`), payload can be base64-embedded in the
  utmctl exec argv directly with the result token written to staging
  and read back. This removes the need for any prior SCP, so even if
  SSH is mid-flap the stage completes via utmctl alone. Tracked as the
  next iteration on top of this architecture.
- Eventual lab-LAN Windows targets (no UTM controller) keep using SSH
  with `remote_temp_dir`; no staging-dir changes apply. The
  conditional in `windows_orchestration_root` already handles this.
