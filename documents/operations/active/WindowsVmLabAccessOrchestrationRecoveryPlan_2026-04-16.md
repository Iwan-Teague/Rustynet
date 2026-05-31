# Windows VM-Lab Access And Orchestration Recovery Plan

## Objective

Close the current Windows VM-lab orchestration gap so Windows UTM guests can be
bootstrapped, reached, and validated authoritatively through the Rustynet
Windows PowerShell path without routing Windows into Linux-only shell stages and
without false-green results.

## Current Status

- Windows VM execution is **proven** through local UTM guest exec.
- Windows source sync is **proven** through the current ZIP/PowerShell sync
  path.
- Windows compile capability is **proven** on the live UTM guest by building
  real Rust targets there.
- Windows SSH/access orchestration is **not yet authoritative**.
- Windows bootstrap/install/verify evidence is **not yet authoritative** because
  host-side pinned SSH reachability remains blocked even though guest-side SSH
  readiness now proves healthy.

### 2026-05-30 Closure Pass

Code-side phases 1 through 5 are implemented on branch
`codex/windows-orchestrator-access-recovery`.

Implemented changes:

- Windows access establishment no longer falls back to SSH while SSH is being
  established. UTM exec, capture, helper staging, and access bootstrap now
  return the dominant Windows UTM/probe error on access-establishment failure.
- Windows discovery no longer marks a Windows VM `execution_ready=true` merely
  because it is powered and has a live IP. Windows now requires powered,
  networked, TCP-ready, auth-ready, and authoritative target state before
  reporting execution readiness.
- Windows `install-release`, `restart-runtime`, and `verify-runtime` now gate on
  proven host-side Windows access before running runtime phases, even when the
  local UTM result-file path is available.
- Windows SSH readiness discovery now runs through the inventory `utm_staging_dir`
  instead of the hardened `C:\ProgramData\Rustynet\vm-lab` tree, uses a direct
  JSON PowerShell probe, and applies a 30-second minimum timeout for the slow
  Windows UTM guest-agent path.
- Windows readiness keeps a host transport reason when the in-guest SSH probe is
  healthy but host-side TCP/22 is still closed or timed out.
- Unit coverage was added for Windows access-establishment fallback blocking
  and Windows readiness requiring SSH for execution readiness, direct SSH
  readiness probing, staging-path selection, timeout flooring, and host
  transport reason retention.

Validation run on 2026-05-30:

- `cargo fmt --all -- --check` passed.
- `cargo test -p rustynet-cli --all-features windows -- --nocapture` passed.
- `cargo test -p rustynet-cli --all-features windows_ssh_readiness -- --nocapture`
  passed.
- `cargo test -p rustynet-cli --all-features windows_utm_readiness -- --nocapture`
  passed.
- `cargo run --quiet -p rustynet-cli -- ops vm-lab-discover-local-utm-summary --inventory documents/operations/active/vm_lab_inventory.json`
  returned `windows-utm-1` with `ssh_port_status=closed`,
  `readiness.execution_ready=false`, reason code `ssh-firewall-not-open`, and
  `windows_ssh_probe.kind=ok` with `openssh_installed=true`,
  `service_running=true`, `firewall_rule_enabled=true`,
  `host_key_present=true`, and `listener_ready=true`.
- `cargo run --quiet -p rustynet-cli -- ops vm-lab-bootstrap-phase --phase install-release --inventory documents/operations/active/vm_lab_inventory.json --vm windows-utm-1 --dest-dir 'C:\Rustynet' --ssh-identity-file /Users/iwan/.ssh/rustynet_lab_ed25519 --known-hosts-file /Users/iwan/.ssh/known_hosts --timeout-secs 20`
  failed closed before install with
  `Windows phase install-release requires proven access ... ssh-firewall-not-open`
  and produced a Windows diagnostics root:
  `C:\Users\windows\rustynet-utm-stage\diagnostics\bootstrap-windows-utm-1-install-release-116663443087473836032003`.

Remaining live-environment blocker:

- Phase 6 clean-snapshot proof is still blocked by current VM access state:
  host-side SSH to `windows-utm-1` at `192.168.65.8:22` times out while the
  in-guest readiness probe reports OpenSSH installed, `sshd` running, the
  OpenSSH firewall rule enabled, the host key present, and a port 22 listener
  active. The remaining blocker is host-side reachability to the Windows guest,
  not missing guest-side SSH setup. The orchestrator now reports this as
  non-ready instead of false-green.

### 2026-05-30 Named-Pipe Lifecycle + Impersonation Hardening Pass

Host-side SSH reachability to `windows-utm-1` recovered (now `192.168.0.45:22`,
host key pinned). Full `sync-source` -> `build-release` -> `install-release` ->
`restart-runtime` was exercised live over pinned SSH. This surfaced a stack of
Windows local-IPC defects that the earlier `CallNamedPipeW failed with Windows
error 109` symptom was masking. Each was fixed at the root, not papered over.

Defects found and fixed (live-driven):

1. **Named-pipe teardown race (109 / error 2).** The one-shot privileged-IPC
   server (`serve_named_pipe_one_message_authorized` in
   `crates/rustynet-windows-native/src/lib.rs`) called `DisconnectNamedPipe`
   immediately after writing the response, which forcibly discards unread bytes
   and races the client's in-flight read -> `ERROR_BROKEN_PIPE` (109); on slow
   spawns the client reached the pipe before `CreateNamedPipeW` -> error 2. Fix:
   drop the forced disconnect on the success path and rely on the existing
   `FlushFileBuffers` (blocks until the client drains) plus the graceful
   `CloseHandle` from handle drop. The boundary-check self-test
   (`crates/rustynetd/src/windows_runtime_boundary.rs`) was rewritten with a
   shared `run_self_check_exchange` retry that surfaces server-side handler
   errors instead of masking them behind a transient client-side pipe error,
   retries the full transient set (errors 2/109/231/233 and the not-ready
   wrapper) with backoff over 5 attempts, and raised the self-check timeout from
   5s to 10s for the slow ARM guest.

2. **Verify-helper trap emitted false `service_status=missing`.**
   `Invoke-WindowsRuntimeBoundaryCheck` / `Invoke-WindowsNamedPipeAclCheck` in
   `scripts/bootstrap/windows/Verify-RustyNetWindowsBootstrap.ps1` ran the daemon
   self-checks under the script-level `ErrorActionPreference='Stop'`, so a
   self-check that wrote to stderr and exited non-zero raised a terminating
   `NativeCommandError`, tripped the top-level trap, and emitted the fail-closed
   placeholder report (`service_status='missing'`, `notes=verify-helper-trap`)
   regardless of the real service state. Fix: a shared
   `Invoke-RustyNetDaemonCommand` runs each self-check under
   `ErrorActionPreference='Continue'` and returns `{exit_code, output}`, so a
   *failed* self-check now yields a clean `fail` report carrying the real daemon
   error and the true service state. With this fix the service correctly reports
   `service_status=Running backend_label=windows-wireguard-nt`.

3. **`ImpersonateNamedPipeClient` failed with error 1368
   (ERROR_CANNOT_IMPERSONATE).** Un-masked once the 109 race was gone, the
   boundary check's real failure was the server impersonating the client before
   reading its first message; Windows withholds the client's security context on
   the server end until the server has read from the pipe. Fix: in
   `serve_named_pipe_one_message_authorized`, read the (size-bounded) request
   *before* impersonating/authorizing; the request is still not passed to the
   handler until authorization passes, and the pipe's security descriptor already
   gates who may connect.

Live evidence (HEAD plus the uncommitted fixes above, carried via
`sync-source --local-source-dir`, rebuilt and reinstalled on the guest):

- `sync-source`, `build-release`, `install-release` all PASS over pinned SSH;
  the rebuilt daemon installs and the `RustyNet` service reaches `Running` with
  `backend_label=windows-wireguard-nt`.
- `rustynetd windows-runtime-boundary-check --state-root C:\ProgramData\RustyNet`
  run directly against the installed daemon now exits 0 with a clean report:
  `state_root_acl_validated`, `secret_root_acl_validated`, `secret_round_trip_ok`,
  and `ipc_probe_ok` all true and a real `inspected_acl_sddl`. No
  `Windows error 109`, no `Windows error 2`, no `ImpersonateNamedPipeClient ...
  1368`. The named-pipe lifecycle race and the impersonation-order defect are
  both closed and validated live.
- The verify helper no longer traps: it reports the true
  `service_status=Running backend_label=windows-wireguard-nt` and a precise
  remaining gate instead of the `service_status=missing` placeholder.
- Orchestrator-level confirmation: `ops vm-lab-bootstrap-phase --phase
  restart-runtime` now fails with `reason=windows-named-pipe-acl-check-failed`
  and `notes=named-pipe-acl-check-failed` only — the boundary-check note is gone,
  i.e. `runtime_boundary_validated` is now true and the sole remaining gate is the
  named-pipe-acls check (the daemon-IPC-pipe gap below). Before this pass the same
  command failed earlier at `failure_step=runtime-boundary-check` with
  `notes=runtime-boundary-check-failed, named-pipe-acl-check-failed`.

### 2026-05-31 Daemon Startup Stall Root-Caused And Fixed

The Windows daemon was stalling during `run_daemon` startup and never creating
its control/privileged IPC pipes (so `windows-named-pipe-acls-check` inspected
absent pipes and could not pass). Two changes resolved the diagnosis blocker and
the stall itself:

1. **Daemon file logging (was entirely absent on the service path).** The
   `--windows-service` host path initialised no logger at all, so every `log::`
   call in the running daemon was a silent no-op — the reason no runtime log ever
   existed. Added `init_daemon_logging` (in `crates/rustynetd/src/main.rs`) which
   tees records to `<state-root>/logs/rustynetd.log` (truncated per start) and
   stderr, honours `RUST_LOG`, and is wired into both the `--windows-service`
   path and the `daemon` subcommand. Added `log::info!` startup milestones across
   `run_daemon`. The log immediately pinpointed the stall: the daemon reached
   only `run_daemon entered` and then hung — i.e. the very first startup step,
   `resolve_configured_egress_interface`.

2. **Egress detection no longer shells out to a hang-prone WMI/CIM query.**
   `detect_default_egress_interface` (Windows) ran `powershell.exe Get-NetRoute`
   (a CIM query) via `Command::output()` with **no timeout** at the first step of
   startup. On this guest WMI became wedged — confirmed independently: a separate
   `Get-CimInstance Win32_Process` query also hung, and dozens of stuck
   `powershell.exe` processes had accumulated (one leaked per service start). The
   blocking `.output()` hung `run_daemon` forever, before it validated config or
   spawned the control pipe. (The earlier ~222ms `Get-NetRoute` timing was taken
   before WMI wedged.) Fix: `detect_default_egress_interface` now enumerates
   adapters in-process via the `GetAdaptersAddresses` Win32 API
   (`rustynet_windows_native::get_adapters_addresses`) and selects the
   lowest-metric, operational, non-tunnel interface that advertises a default
   gateway through a new pure, unit-tested `select_windows_default_egress_interface`
   helper. No subprocess, no CIM, cannot hang. The reusable alias validator
   (`parse_windows_default_egress_interface_output`) is retained and applied to
   the native result.

**Live result after the egress fix:** `rustynetd.log` now shows the daemon
racing through `run_daemon entered` -> `configuration and runtime ACLs
validated` -> `runtime key material prepared` -> `preflight checks passed` ->
`daemon runtime constructed` in ~5ms (egress no longer hangs), then stalling
at the *next* step — `runtime.bootstrap()` — which never logs
`runtime bootstrap complete`. So the egress hang is fixed and a **second,
distinct startup hang** is now exposed.

**Second hang (identified, not yet fixed):** `bootstrap()` reaches
`controller.apply_dataplane_generation` (the initial dataplane apply, which runs
*before* the control-pipe spawn), whose firewall killswitch
(`WindowsCommandSystem::apply_firewall_killswitch`) adds the tunnel-interface
allow rule via PowerShell `New-NetFirewallRule` — another WMI/CIM cmdlet, same
class as the egress `Get-NetRoute`. On this guest WMI is now badly wedged: a
plain `Get-CimInstance Win32_OperatingSystem` probe hung even after the leaked
egress `powershell.exe` orphans were killed. The wedge was caused by the old
egress bug (one stuck CIM client leaked per service start, accumulated over the
session).

**Systemic fix — the daemon now bounds and recovers from hung helpers (no
reboot needed).** The root flaw was that *every* Windows helper subprocess
(`run_netsh`, `run_powershell` in `phase10.rs`) used `Command::output()`, which
waits forever. A single hung CIM cmdlet therefore blocked the daemon *and*
leaked the child, and the leakage is what wedged WMI in the first place.
`run_netsh` / `run_powershell` now go through `run_helper_command_with_timeout`,
which spawns the child, polls `try_wait` against a 20 s deadline, and on timeout
**kills and reaps** the child and returns a clean error. Consequences:

- The daemon can no longer hang indefinitely on a helper, and can no longer leak
  a stuck `powershell.exe` — so it cannot re-wedge WMI. The egress path is also
  off CIM entirely (native `GetAdaptersAddresses`).
- On the *currently* wedged guest the killswitch's `New-NetFirewallRule` now
  times out after 20 s, is killed, the killswitch/`apply_dataplane_generation`
  fails closed, `bootstrap()` returns, and `run_daemon` proceeds to bind DNS and
  **spawn the control pipe** — i.e. the daemon self-recovers and serves its IPC
  pipes without an operator reboot. The killed CIM clients also release their WMI
  sessions, relieving the wedge over time.
- `restart-runtime` (no live-path requirement) becomes the achievable green
  target once the pipes are served. Unit tests cover the timeout helper
  (`helper_command_timeout_kills_a_hung_command`,
  `helper_command_timeout_returns_fast_command_output`).

Optional later hardening (not required for self-recovery): replace the wintun
tunnel rule's `New-NetFirewallRule` with a native/COM firewall rule so the
killswitch uses no CIM at all (the rest already uses non-CIM `netsh`; only the
tunnel rule uses PowerShell because `netsh` cannot bind by interface alias for
`MediaType=IP` adapters).

### 2026-05-31 `restart-runtime` Is Green

The daemon now starts cleanly, serves **both** reviewed named pipes, and
`ops vm-lab-bootstrap-phase --phase restart-runtime` **passes**
(`completed bootstrap phase=restart-runtime`, exit 0). Getting there required
three more fixes on top of self-recovery:

1. **Persistent privileged-helper pipe server.** `run_daemon` (Windows) now
   spawns a second background thread alongside the control-pipe thread that
   serves `\\.\pipe\RustyNet\rustynetd-privileged` via
   `serve_windows_privileged_request_once` (created with the hardened
   SYSTEM/Administrators/service-SID security descriptor; handler answers the
   protocol probe and reviewed-runtime-path ACL inspection). Both
   `\\.\pipe\RustyNet\rustynetd` and `…\rustynetd-privileged` are now present.
2. **`inspect_named_pipe_sddl` read fix.** Switched `GetNamedSecurityInfoW` from
   `SE_KERNEL_OBJECT` (handle object type → `ERROR_BAD_PATHNAME` 161 for a path)
   to `SE_FILE_OBJECT`, and added `GROUP_SECURITY_INFORMATION` to both the read
   and the SDDL serialization (now parameterized) so the round-tripped SDDL
   carries the `G:SY` group the evaluator requires.
3. **Service-SID expectation.** The daemon builds each reviewed pipe DACL with an
   allow-ACE for the service identity (`NT SERVICE\RustyNet`). The verify helper
   now resolves that SID and passes `--service-sid` to
   `windows-named-pipe-acls-check`, so the service ACE is validated as a reviewed
   principal instead of flagged as drift.

Direct evidence: `windows-named-pipe-acls-check --service-sid <RustyNet-SID>`
returns `overall_ok: true` with both pipes `status: ok` and SDDL
`O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-80-…)`.

- **`verify-runtime` still requires a live data-plane path** (`-RequireLivePath`),
  which a standalone Windows guest with no mesh assignment cannot satisfy;
  `restart-runtime` (no live-path requirement) is the achievable green target and
  is now green.

Net: the named-pipe 109/error-2 race, the verify-helper trap, the
impersonation-order defect, the egress-detection CIM hang, the
unbounded-subprocess hang/leak (which wedged WMI), the missing privileged-helper
pipe, the pipe-ACL inspection object-type/group defect, and the service-SID
expectation are all fixed and validated live. The Windows daemon self-recovers,
serves both hardened IPC pipes, and `restart-runtime` passes end-to-end with no
operator reboot. The only remaining gate for `verify-runtime` is a live mesh
data-plane path (out of standalone-guest scope).

## Current Repo Truth To Preserve

- `documents/Requirements.md` and `documents/SecurityMinimumBar.md` remain the
  governing source of truth.
- Windows is currently `runtime-host-capable only`, not release-gated and not
  dataplane-capable.
- Linux-only live-lab wrappers remain fail-closed for any target that is not
  `platform=linux` / `remote_shell=posix` / `guest_exec_mode=linux_bash` /
  `service_manager=systemd`.
- Windows helper/system integration stays argv-only and PowerShell-first.
- Windows must not silently reuse Linux runtime roots or Linux shell stages.

## Problem Statement

The Windows VM itself is not the primary blocker. The stronger evidence is:

- local source sync to the Windows guest works
- guest-side PowerShell execution works
- real Rust code compiled successfully inside the Windows guest

The orchestration gap is instead in the Windows access/reachability path:

- the access bootstrap helper mutates guest state but does not verify end-state
- local UTM Windows capture still depends too heavily on stdout marker parsing
- Windows local UTM execution falls back to SSH too early, including while SSH
  is still being established
- discovery/readiness collapses distinct Windows failure modes into coarse
  reason codes
- higher Windows bootstrap phases consume those weak lower-level signals

## Scope

This plan covers:

- Windows access bootstrap hardening
- Windows UTM transport and capture hardening for access/bootstrap operations
- Windows readiness classification improvements
- Windows bootstrap/provider integration for authoritative blocked or passing
  results
- clean-snapshot validation and evidence requirements

This plan does not cover:

- Windows dataplane/backend implementation beyond the current reviewed
  `windows-unsupported` truth
- release-gate promotion
- Linux live-lab wrapper broadening
- SSH trust weakening or host-key TOFU in the active wrapper path

## Primary Files

- `scripts/vm_lab/windows/Enable-WindowsVmLabAccess.ps1`
- `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1`
- `scripts/bootstrap/windows/Collect-RustyNetWindowsDiagnostics.ps1`
- `crates/rustynet-cli/src/vm_lab/mod.rs`
- `crates/rustynet-cli/src/vm_lab/bootstrap/windows.rs`

## Failure Map

### F1. Access bootstrap returns success too early

Current behavior:

- installs or starts OpenSSH
- writes `administrators_authorized_keys`
- may create the firewall rule
- returns host-key text

Missing proof:

- `sshd -t` configuration validation
- deterministic ACL repair/verification
- listener validation
- firewall enabled-state validation
- host-side SSH reachability proof
- structured pass/fail result

### F2. UTM Windows capture is too fragile for authority

Current behavior:

- PowerShell capture wraps stdout with markers
- CLI parser expects those markers to survive `utmctl exec` output handling

Observed failure shape:

- `UTM Windows capture output was missing rc marker`

### F3. SSH fallback sequencing is wrong during access establishment

Current behavior:

- Windows local UTM command failures fall back to SSH

Problem:

- SSH is the thing being established, so fallback obscures the real failure and
  produces compound error noise instead of a clear root cause

### F4. Windows readiness is under-specified

Current behavior:

- discovery emits coarse readiness such as `ssh-auth-not-ready`

Missing distinction:

- host route broken
- guest agent unavailable
- guest IP not authoritative
- firewall closed
- `sshd` not running
- listener missing
- host key missing
- auth rejected
- auth timeout

### F5. Higher Windows phases depend on weak lower-level truth

Current behavior:

- install/restart/verify depend on helper capture and current transport truth

Problem:

- if access bootstrap truth is weak, higher-level Windows phase results cannot
  be treated as authoritative

## Phase Plan

### Phase 1. Harden Windows Access Bootstrap

**Goal:** make the guest-side access helper verification-based instead of
mutation-only.

Files:

- `scripts/vm_lab/windows/Enable-WindowsVmLabAccess.ps1`
- `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1`

Implementation tasks:

- ensure OpenSSH capability installation remains explicit
- ensure `sshd` startup type is correct
- recreate or re-enable the firewall rule when disabled or malformed, not only
  when missing
- rewrite `administrators_authorized_keys` deterministically
- repair SSH file ACLs deterministically using localized administrator/system
  principals
- validate `sshd_config` with `sshd -t`
- restart `sshd` after config/key mutation
- verify the `sshd` service is `Running`
- verify a listener exists on port `22`
- emit structured JSON result instead of only returning the host key

Required JSON fields:

- `openssh_installed`
- `service_running`
- `firewall_rule_enabled`
- `authorized_keys_applied`
- `host_key_present`
- `listener_ready`
- `default_shell_configured`
- `status`
- `reason`

Tests and checks:

- PowerShell syntax validation
- unit tests or parser tests on the CLI side for the result schema if the JSON
  contract is parsed there
- negative guest validation for a disabled firewall rule, bad key state, and
  invalid config

Phase exit criteria:

- guest helper fails closed on invalid SSH config
- guest helper does not report success unless `sshd`, firewall, and listener
  state all validate
- helper output is machine-readable and deterministic

### Phase 2. Split Windows UTM Transport Into Status And Capture Paths

**Goal:** stop using fragile stdout-marker capture as the authority for Windows
access/bootstrap bring-up.

Files:

- `crates/rustynet-cli/src/vm_lab/mod.rs`

Implementation tasks:

- separate Windows local UTM execution into:
  - status/probe path
  - capture-output path
- use exit status or guest-written result files for access/bootstrap probes
- reserve capture-output parsing for workflows that genuinely need payload
  output after transport is already stable
- keep Linux and macOS behavior unchanged

Required behavior:

- access bootstrap must not depend on stdout markers to prove pass/fail
- access/bootstrap diagnostics must still fail closed if proof cannot be
  retrieved

Tests and checks:

- unit tests for Windows status-only command execution and parse paths
- negative tests for missing result files or malformed result payloads
- regression tests proving Linux UTM and SSH paths were not weakened

Phase exit criteria:

- Windows access bootstrap no longer depends on
  `__RUSTYNET_CAPTURE_RC__=...` markers for authority
- result retrieval failures return direct root-cause errors

### Phase 3. Remove Premature SSH Fallback During Windows Access Establishment

**Goal:** make Windows access/bootstrap failures report the real broken layer.

Files:

- `crates/rustynet-cli/src/vm_lab/mod.rs`

Implementation tasks:

- remove SSH fallback for Windows local UTM access-establishment steps
- keep SSH fallback only for operations that are explicitly post-bootstrap and
  already require a healthy SSH transport
- tag Windows transport failures with the exact UTM/probe/readiness cause

Tests and checks:

- negative tests proving Windows access bootstrap does not attempt SSH fallback
  when the UTM step fails
- regression tests proving non-Windows fallback behavior is preserved where
  currently intended

Phase exit criteria:

- Windows access bootstrap failure output reports one dominant root cause
- compound `UTM failed; SSH fallback failed` noise is removed from the access
  establishment path

### Phase 4. Add A Real Windows Readiness Ladder

**Goal:** make discovery and preflight tell operators exactly what is broken.

Files:

- `crates/rustynet-cli/src/vm_lab/mod.rs`

Implementation tasks:

- extend Windows readiness and reason-code generation so distinct failure modes
  are preserved
- keep Linux readiness behavior unchanged
- surface the finer-grained reason codes in JSON and user-visible failure
  output

Recommended reason codes:

- `process-not-ready`
- `guest-agent-not-ready`
- `live-ip-not-authoritative`
- `ssh-service-not-running`
- `ssh-firewall-not-open`
- `ssh-listener-not-ready`
- `ssh-host-key-not-ready`
- `ssh-auth-rejected`
- `ssh-auth-timeout`
- `no-authoritative-ssh-target`

Tests and checks:

- unit tests for Windows readiness classification
- regression tests proving existing Linux readiness expectations still pass
- report-contract checks for new reason codes in discovery artifacts

Phase exit criteria:

- discovery reports identify the broken access layer precisely enough to drive
  deterministic remediation
- `ssh-auth-not-ready` is no longer the only Windows access failure summary

### Phase 5. Rewire Higher Windows Bootstrap Phases To Proven Access Truth

**Goal:** make `install-release`, `restart-runtime`, and `verify-runtime`
depend on real Windows access/readiness proof.

Files:

- `crates/rustynet-cli/src/vm_lab/bootstrap/windows.rs`
- `crates/rustynet-cli/src/vm_lab/mod.rs`
- `scripts/bootstrap/windows/Collect-RustyNetWindowsDiagnostics.ps1`

Implementation tasks:

- gate higher Windows bootstrap phases on the strengthened readiness/access
  contract
- keep diagnostics collection available on failure
- preserve the current reviewed backend/dataplane truth
- ensure blocked backend cases still return explicit fail-closed reasons

Tests and checks:

- unit tests for phase gating and blocked-reason reporting
- diagnostics regression tests proving failures still produce a Windows
  diagnostics path when transport truth is available

Phase exit criteria:

- install/restart/verify consume proven access state instead of weak inferred
  state
- unsupported backend/dataplane truth remains explicit and blocked

### Phase 6. Clean-Snapshot Validation And Proof Refresh

**Goal:** prove the new orchestration path on a clean Windows guest instead of a
contaminated troubleshooting state.

Operational requirements:

- work from a known-clean Windows UTM snapshot
- do not accept stale guest state as fresh proof
- keep host-key trust pinned
- do not weaken Linux-only live-lab guardrails

Validation sequence:

1. `ops vm-lab-discover-local-utm`
2. Windows access bootstrap helper run through the UTM path
3. host-side pinned SSH readiness proof
4. `ops vm-lab-bootstrap-phase --phase install-release`
5. `ops vm-lab-bootstrap-phase --phase restart-runtime`
6. `ops vm-lab-bootstrap-phase --phase verify-runtime`
7. diagnostics collection on at least one forced negative case

Required artifacts:

- dated discovery JSON for the clean snapshot
- dated access-bootstrap result artifact
- host-side SSH proof log or machine-readable result
- install/restart/verify reports
- diagnostics output root for at least one negative case

Phase exit criteria:

- Windows access is proven from the host, not only from guest-local checks
- install/restart/verify results are authoritative for the current supported
  backend scope
- blocked backend/dataplane cases remain blocked, explicit, and non-green

### Phase 6 Immediate Closure Checklist

- [x] patch `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1` so
  `-ResultPath` writes fail-closed JSON on both success and top-level failure
- [x] rebuild `rustynet-cli` after helper-path changes
- [ ] rerun `ops vm-lab-start` and confirm Windows access bootstrap no longer
  collapses to `produced no output`
- [x] rerun `ops vm-lab-discover-local-utm` and capture the updated Windows
  readiness artifact
- [x] if access bootstrap still fails, preserve the dominant root cause verbatim and
  do not advance to runtime install/restart/verify
- [ ] only resume host-side pinned SSH proof after the access helper result file is
  present and machine-readable

## Milestones

### M1. Verified Windows Access Bootstrap

Reached when:

- Phase 1 is complete
- the helper emits structured JSON
- success requires real guest-side SSH/firewall/listener proof

### M2. Authoritative Windows Bootstrap Transport

Reached when:

- Phases 2 and 3 are complete
- access/bootstrap no longer relies on fragile stdout markers for authority
- Windows access bootstrap no longer falls back to SSH while trying to
  establish SSH

### M3. Actionable Windows Readiness Reporting

Reached when:

- Phase 4 is complete
- discovery and preflight distinguish the real broken layer

### M4. Authoritative Windows Runtime Wiring

Reached when:

- Phase 5 is complete
- install/restart/verify depend on proven access truth and still fail closed on
  unsupported backend/dataplane cases

### M5. Clean Guest Proof

Reached when:

- Phase 6 is complete
- a clean Windows UTM snapshot produces dated, repeatable install/restart/verify
  evidence for the current supported scope

## Validation Gates

Code-side validation for implementation slices:

- `cargo fmt --all -- --check`
- `cargo check -p rustynet-cli`
- `cargo test -p rustynet-cli`
- `cargo clippy -p rustynet-cli --all-targets --all-features -- -D warnings`
- `cargo check --workspace --all-targets --all-features`
- `cargo test --workspace --all-targets --all-features`

Real-environment validation for the orchestration gap:

- `rustynet-cli ops vm-lab-discover-local-utm ...`
- Windows access bootstrap through the Windows PowerShell helper path
- host-side pinned SSH probe
- `rustynet-cli ops vm-lab-bootstrap-phase --phase install-release ...`
- `rustynet-cli ops vm-lab-bootstrap-phase --phase restart-runtime ...`
- `rustynet-cli ops vm-lab-bootstrap-phase --phase verify-runtime ...`

## Definition Of Done

This plan is complete only when all are true:

- Windows access bootstrap is verification-based and machine-readable
- Windows access establishment no longer depends on fragile marker-only capture
- Windows readiness reports the broken layer precisely
- higher Windows bootstrap phases depend on proven access truth
- diagnostics still work on failure where transport is available
- clean-snapshot Windows evidence exists for the currently supported scope
- Windows remains outside Linux-only live-lab shell stages
- unsupported backend/dataplane cases still fail closed and do not produce
  false-green results

## Notes

- The Windows VM itself is not the dominant blocker; the orchestration and
  recovery path around it is.
- Do not treat compilation proof or guest-local service/listener checks as a
  substitute for host-side access proof.
- Do not promote Windows support posture based on this plan alone. Docs and
  release gates move only after measured clean-snapshot evidence exists.
