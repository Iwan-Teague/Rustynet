# Windows Lab VM Stability And Bootstrap Session Model

Date: 2026-04-30
Status: active plan
Owner: Rustynet engineering
Branch baseline: `main` @ `340488b`
Related: [WindowsUtmTransportArchitecture_2026-04-30.md](./WindowsUtmTransportArchitecture_2026-04-30.md)

## 0) Mission

The Windows UTM control channel works (commit 5f431b7 + 340488b).
`vm-lab-bootstrap-phase --phase sync-source` against `windows-utm-1`
runs end-to-end. The next phase, `build-release`, blocks on two
independent issues that surfaced together during the first live run:

1. **VM stability** — UTM crashed the guest under sustained CPU load
   (`cargo build --release`) while GPU acceleration was enabled. After
   the crash the guest dropped into Windows recovery / repair mode.
2. **Bootstrap session model** — `Bootstrap-RustyNetWindows.ps1`'s
   `build-release` phase requires a Windows-recognized **active**
   interactive session in order to register a Scheduled Task with
   `LogonType=Interactive`. UTM displays the desktop, but Windows'
   `quser` reports no session in `Active` state, so the bootstrap
   correctly fails fast rather than spinning for the 4-hour task
   timeout.

This plan locks both axes down without weakening any orchestrator
security control. Both fixes are one-time per VM image and remove
recurring friction every run after.

## 1) Scope

In scope:

- Reimage the Windows lab guest cleanly (current image is in repair
  mode after the crash).
- Pick a stable UTM configuration profile for the rebuilt guest.
- Pick a session model for `build-release` that does not depend on a
  human being signed into the desktop.
- Adjust `Bootstrap-RustyNetWindows.ps1` accordingly (resolver paths,
  fallbacks) and the inventory if any new fields are required.
- Document the chosen lab image so future lab nodes can reproduce it.

Out of scope:

- Multi-Windows lab. We are stabilizing one Windows guest first.
- Daemon-side Windows changes. Service install / runtime path is
  unchanged.
- Lab-LAN (non-UTM) Windows targets. They keep using the existing SSH
  path; this plan only touches the UTM controller branch.

## 2) Read order

1. [WindowsUtmTransportArchitecture_2026-04-30.md](./WindowsUtmTransportArchitecture_2026-04-30.md)
   — control-channel architecture this plan builds on.
2. [WindowsWorkingNodePlan_2026-04-17.md](./WindowsWorkingNodePlan_2026-04-17.md)
   — current Windows-as-peer requirements.
3. `documents/SecurityMinimumBar.md` — fail-closed bar this plan must
   not weaken.
4. `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1` — the
   script that this plan reshapes.

## 3) Current state snapshot (2026-04-30)

### 3.1 What worked
- utmctl primitives (`exec`, `file push`, `file pull`) against the
  rebuilt staging dir at `C:\Users\windows\rustynet-utm-stage`.
- `vm-lab-bootstrap-phase --phase sync-source` end-to-end:
  `cargo vendor --offline` ~5s, `git ls-files`-zip ~3s, SCP 36.8 MB
  at ~59 MB/s, utmctl mkdir ~300ms.
- SSH host key auth via `~/.ssh/rustynet_lab_ed25519`.

### 3.2 What broke
- `vm-lab-bootstrap-phase --phase build-release`:
  - `Bootstrap-RustyNetWindows.ps1` hit the
    `Get-ActiveInteractiveUserSessionName` guard: `quser` reported no
    session in `Active` state.
  - On retries the guest crashed under load and dropped into Windows
    recovery / repair mode.
  - UTM dialog: "Suspend not supported when GPU acceleration enabled.
    Closing window kills VM."

### 3.3 Why the bootstrap requires Interactive
[Bootstrap-RustyNetWindows.ps1:1370-1378](../../scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1#L1370):

```powershell
$systemScopedContext = (Test-SystemExecutionContext) -or
                       (Test-SystemProfileExecutionContext)
if (-not $InteractiveBuildBootstrapChild -and
    $null -ne $buildReportLayout -and
    $systemScopedContext -and
    (-not ($cargoPresent -and $rustcPresent -and $buildToolsPresent))) {
    Invoke-BuildReleaseViaInteractiveUserTask -Layout $buildReportLayout
    return
}
```

When the bootstrap runs as `SYSTEM` (which is what `utmctl exec` and
`OpenSSH` SCM-launched sessions do) AND any of cargo / rustc / VS
Build Tools is missing, it bounces to a Scheduled Task running as
the interactive user. This exists because:

- `rustup` installs to `%USERPROFILE%\.cargo` and `%USERPROFILE%\.rustup`
  by default. SYSTEM cannot see those.
- VS Build Tools usually install to `C:\Program Files (x86)\Microsoft Visual Studio\...`,
  but `vcvarsall.bat` is sometimes missing from SYSTEM's PATH and the
  Visual Studio detection paths assume a user profile.

The bootstrap is structured to **prefer** SYSTEM execution
([Bootstrap-RustyNetWindows.ps1:1379-1396](../../scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1#L1379)):
once tools are resolvable from machine-scoped paths, it short-circuits
the Scheduled Task entirely. The Interactive Task is a fallback for
the "tools live only in user profile" case, not a hard requirement.

That gives us the leverage: install tools machine-scoped, the
Interactive requirement evaporates.

## 4) Non-negotiable constraints

- No weakening of state-tree hardening, runtime ACLs, or
  `windows_orchestration_root` decoupling.
- No bootstrap fallback that downgrades to `LogonType=Interactive`
  when the SYSTEM path fails. SYSTEM must succeed deterministically
  on the lab image, or the run errors loudly.
- Build artifacts produced by SYSTEM (under `C:\ProgramData\Rustynet\`
  or wherever the build report layout points) keep the same ACL
  profile as today.
- All persistent install state (rustup home, cargo home, VS BT) lives
  outside `C:\Users\<user>\` so re-imaging or auto-login changes do
  not break tooling resolution.

## 5) Decision: option B — install Rust + VS Build Tools machine-scoped

Three options were considered (see decision log §10).

### 5.1 What we install on the image

| Tool | Install path | Scope | Owner |
|---|---|---|---|
| rustup | `C:\RustupHome` (`RUSTUP_HOME`), `C:\CargoHome` (`CARGO_HOME`) | machine | SYSTEM-readable, lab-user-readable |
| cargo / rustc | resolved through `CARGO_HOME\bin` | machine | inherited |
| Visual Studio 2022 Build Tools | `C:\BuildTools` (custom `--installPath`) | machine | inherited |
| Windows SDK + MSVC v143 | bundled with Build Tools | machine | inherited |

System-wide environment variables set on the image:

```
RUSTUP_HOME = C:\RustupHome
CARGO_HOME  = C:\CargoHome
PATH       += C:\CargoHome\bin
```

(Set via `setx /M`; survives reboot; visible to SYSTEM.)

### 5.2 Why these paths are SYSTEM-safe

- `C:\RustupHome` and `C:\CargoHome` live outside `C:\Users\` so
  per-user roaming profiles cannot shadow them.
- They live outside `C:\ProgramData\Rustynet\` so they are not subject
  to the runtime state-tree hardening (`takeown ... /r` +
  `icacls ... /grant:r windows:F /T`) that breaks utmctl access to
  vm-lab.
- Default ACL inheritance from `C:\` grants `BUILTIN\Administrators:F`
  + `NT AUTHORITY\SYSTEM:F` + `BUILTIN\Users:RX`. SYSTEM and the lab
  user (member of Administrators) both have access. No bespoke
  hardening required.
- `C:\BuildTools` follows the same pattern and matches the canonical
  Visual Studio Build Tools "single-install" deployment path.

### 5.3 What changes in the bootstrap script

`Bootstrap-RustyNetWindows.ps1`:

- `Resolve-CargoExePath`, `Resolve-RustcExePath`,
  `Resolve-RustupExePath`, `Resolve-VsDevCmdPath` add the
  machine-scoped canonical paths to the lookup list (first):
  - `C:\CargoHome\bin\cargo.exe`
  - `C:\CargoHome\bin\rustc.exe`
  - `C:\CargoHome\bin\rustup.exe`
  - `C:\BuildTools\Common7\Tools\VsDevCmd.bat`
- `Ensure-CargoOnPath` reads `CARGO_HOME` from machine env and
  prepends `$env:CARGO_HOME\bin` to PATH if the env var is set;
  preserves existing user-profile fallback.
- `Ensure-WingetConfigurationDependencies` and `Ensure-BuildTools`
  invoke their installers with explicit machine-scope flags
  (`rustup-init.exe --no-modify-path -y --default-toolchain stable`
  with RUSTUP_HOME/CARGO_HOME pre-set; VS Build Tools with
  `--installPath C:\BuildTools`).
- `Get-ActiveInteractiveUserSessionName` is no longer in the hot path
  for `build-release`. Keep it for diagnostics only.
- `Invoke-BuildReleaseViaInteractiveUserTask` is kept but becomes
  legacy fallback, gated behind a new `-AllowInteractiveTaskFallback`
  switch that is OFF by default. Lab runs do not pass it. SSH-direct
  runs against a manually-prepped Windows host can still pass it for
  ad-hoc compatibility.

### 5.4 What changes in the Rust orchestrator

Likely none. The orchestrator only knows that build-release is a
helper script invocation; the helper script's internal session model
is not the orchestrator's concern. We do **not** add a
`build_release_runs_as_system` field to the inventory. The image's
toolchain layout is what determines this, not the orchestrator config.

If we discover the orchestrator needs to communicate
`AllowInteractiveTaskFallback` for non-UTM Windows targets later, we
add a small flag. Not in this plan.

## 6) Decision: stable UTM profile

For the rebuilt guest:

| Setting | Value | Reason |
|---|---|---|
| Architecture | aarch64 (Apple Silicon native) | host is M-series macOS; HVF acceleration available |
| RAM | 8 GB minimum | `cargo build --release` peaks at ~5–7 GB for this workspace |
| CPU cores | 4 | balance between build throughput and host pressure |
| Disk | 80 GB qcow2 | accommodates full Rust toolchain + VS BT + workspace + target/ |
| Display | console enabled, **GPU acceleration off** (final decision) | guest is a headless build/runtime node; nothing on the bootstrap or service-runtime path renders to the guest desktop. UTM GPU accel exists to accelerate interactive guest graphics — no caller. The "Suspend not supported when GPU acceleration enabled" warning is direct evidence of an unwanted failure surface. |
| Suspend | enabled | matches "no GPU accel" line |
| Network | shared (192.168.64.0/24) | matches inventory `last_known_network` |
| Auto-login | on, for the lab user, even though we no longer need an Active session | safety net in case future changes regress to needing one |

Auto-login is configured because it is one `reg` import. Cost is low,
covers the diagnostic case where someone manually triggers the legacy
Interactive fallback, and means the desktop is "real" inside Windows
on every boot.

## 7) Phased plan

Each phase is independently committable and can be reverted without
affecting the rest. Each phase has a verification step.

### Phase L0 — write this plan and commit
Status: in this commit.
Verification: doc indexed in `documents/operations/active/README.md`.

### Phase L1 — reimage the lab Windows guest
Out-of-band ops. Not a code change.
- Fresh Windows 11 install in UTM with the §6 settings.
- Create `windows` lab user as Administrator.
- Configure auto-login for `windows`.
- Open RDP and OpenSSH Server roles.
- Inject the `~/.ssh/rustynet_lab_ed25519.pub` automation key into
  `C:\ProgramData\ssh\administrators_authorized_keys` (matching how
  the access-bootstrap helper currently does it).
- Smoke test: `ssh windows@192.168.64.14 powershell.exe -Command 'Get-Date'`
  works without a password prompt; `utmctl exec Windows --cmd cmd.exe /c whoami`
  returns `nt authority\system`.

Verification: rerun `vm-lab-bootstrap-phase --phase sync-source`. Same
green outcome as last time, against the rebuilt image.

### Phase L2 — install Rust + VS Build Tools machine-scoped on the image
One-time PowerShell sequence run elevated on the guest, captured as a
provisioning script committed to
`scripts/bootstrap/windows/Provision-RustyNetWindowsLabImage.ps1`.

```powershell
# RustupHome / CargoHome
[System.Environment]::SetEnvironmentVariable('RUSTUP_HOME', 'C:\RustupHome', 'Machine')
[System.Environment]::SetEnvironmentVariable('CARGO_HOME',  'C:\CargoHome',  'Machine')
$machinePath = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($machinePath -notmatch [regex]::Escape('C:\CargoHome\bin')) {
    [System.Environment]::SetEnvironmentVariable(
        'Path', "$machinePath;C:\CargoHome\bin", 'Machine')
}

# rustup-init
$env:RUSTUP_HOME = 'C:\RustupHome'
$env:CARGO_HOME  = 'C:\CargoHome'
Invoke-WebRequest 'https://win.rustup.rs/x86_64' -OutFile rustup-init.exe
.\rustup-init.exe -y --no-modify-path --default-toolchain stable --profile minimal

# VS Build Tools
Invoke-WebRequest 'https://aka.ms/vs/17/release/vs_BuildTools.exe' -OutFile vs_BuildTools.exe
.\vs_BuildTools.exe --installPath C:\BuildTools `
  --add Microsoft.VisualStudio.Workload.VCTools `
  --add Microsoft.VisualStudio.Component.Windows11SDK.22621 `
  --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
  --quiet --wait --norestart
```

Verification: from a fresh PowerShell as `SYSTEM` (via `psexec -s` or
a Scheduled Task running as `NT AUTHORITY\SYSTEM`):
`cargo --version`, `rustc --version`, `where cl.exe` all succeed.

### Phase L3 — bootstrap script: machine-scoped resolvers
Code change in `scripts/bootstrap/windows/Bootstrap-RustyNetWindows.ps1`.

- Update `Resolve-CargoExePath`, `Resolve-RustcExePath`,
  `Resolve-RustupExePath`, `Resolve-VsDevCmdPath` to check
  machine-scope paths first.
- Update `Ensure-CargoOnPath` to honor `CARGO_HOME` from machine env.
- Update `Ensure-BuildTools` and `Ensure-WingetConfigurationDependencies`
  to install to `C:\BuildTools` / `C:\CargoHome` / `C:\RustupHome`
  when running as SYSTEM. Existing user-profile install paths remain
  for non-SYSTEM execution.
- Bootstrap report (`build-release.manifest.json`) gains
  `toolchain_scope: "machine" | "user"` so we can confirm at the
  orchestrator end which path was taken.

Verification: unit-test new helpers in
`crates/rustynet-cli/src/vm_lab/bootstrap/windows.rs` (the helpers
that consume the manifest expect new fields). End-to-end via
`build-release` against the freshly-imaged guest.

### Phase L4 — gate the legacy interactive fallback
Code change in `Bootstrap-RustyNetWindows.ps1`.

- Add `-AllowInteractiveTaskFallback` switch (default off).
- `Invoke-BuildReleaseViaInteractiveUserTask` only runs when the
  switch is set AND the SYSTEM path failed.
- Without the switch, a SYSTEM-context build-release that cannot
  resolve the toolchain throws a precise error naming which paths
  were checked and which were missing.

Verification: test that `--phase build-release` against a guest
without machine-scope rust fails fast with a clean error instead of
silently bouncing to the Interactive Task. Then install rustup
machine-scoped, re-run, and watch it complete without a Scheduled
Task.

### Phase L5 — end-to-end
Run `vm-lab-bootstrap-phase` for `build-release`, `install-release`,
`restart-runtime`, `verify-runtime` against the rebuilt + provisioned
guest. Confirm the new UTM transport (commit 5f431b7) drives the
runtime phases via `execute_utm_remote_powershell_capture` (the
result-file path), with no SSH fallback.

Verification: timing table per phase, manifest of which transport
each phase used, `Get-Service RustyNet` reports `Running` on the guest.

### Phase L6 — sweep + cleanup
- Strip remaining `[RNTRACE]` traces if any survived.
- Update [WindowsUtmTransportArchitecture_2026-04-30.md](./WindowsUtmTransportArchitecture_2026-04-30.md)
  with a "validation" section pointing at the run logs.
- Move this plan to historical when L5 is green, or keep active and
  add a "post-mortem" section.

## 8) Risks and mitigations

| Risk | Mitigation |
|---|---|
| VS Build Tools install at `C:\BuildTools` not detected by `Resolve-VsDevCmdPath` | Add explicit fallback path before user-profile lookups; existing detection logic stays as last resort |
| `cargo build` under SYSTEM hits a path that hard-codes `%USERPROFILE%` | Set `CARGO_HOME`/`RUSTUP_HOME` machine-scoped; verify build doesn't write to `C:\Windows\system32\config\systemprofile\` (the SYSTEM profile dir) |
| QEMU/UTM still crashes the guest under load even with GPU accel disabled | Increase RAM to 12 GB; reduce parallel codegen units in `cargo` for the lab build (already controlled by repo `Cargo.toml` profile) |
| Auto-login conflicts with security guidance | Auto-login is to a non-domain local lab account on a developer-only host. Documented as lab-only. Production / live-lab boxes do not auto-login. |
| Inventory or orchestrator behavior diverges between this lab guest and future Windows targets | Keep the orchestrator-side knobs constant. The toolchain-scope decision is a guest-image property, not an orchestrator config. |

## 9) Definition of done

- `vm-lab-bootstrap-phase --phase build-release` succeeds against the
  rebuilt guest in under 30 minutes wall clock.
- `--phase install-release`, `--phase restart-runtime`,
  `--phase verify-runtime` each succeed in single attempts.
- `Get-Service RustyNet` on the guest reports `Running` after
  `verify-runtime`.
- Bootstrap report `toolchain_scope` is `"machine"` for all four
  runtime phases.
- No human signed into the desktop during any of the runs.
- `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets --all-features -- -D warnings`, `cargo test
  --workspace --all-targets --all-features` all pass on the
  bootstrap-script changes.

## 10) Decision log: why option B over A or C

**Option A — Auto-login the lab user.**
- Pros: trivial, one `reg` import, works with current bootstrap.
- Cons: requires the desktop to be "displayed" inside Windows (UTM
  console open or kept hot). Closing the UTM window or detaching the
  display can revert `quser` to "no Active session." Fragile in
  headless / CI / multi-VM contexts. Does not remove the underlying
  fragility — if the next bootstrap step also assumes a user profile
  for some reason, we hit the same class of issue.

**Option B — Install Rust + VS BT machine-scoped (chosen).**
- Pros: removes the entire "active session" question. UTM can be
  headless. Bootstrap takes the SYSTEM short-circuit path that
  already exists in the script. One-time per image.
- Cons: requires reshaping the resolver functions in the bootstrap
  script. Slightly larger image (machine-scope tools occupy ~3 GB).
  Auto-update of rustup needs to run as SYSTEM (handled by writing
  RUSTUP_HOME to a machine-writable path).

**Option C — Pre-baked Windows lab template.**
- Pros: fastest cold-start, deterministic.
- Cons: requires building and storing the template, version-managing
  it, and re-baking on toolchain bumps. Worth doing eventually but is
  a strict superset of B (a baked template still has to install Rust
  + BT machine-scoped). Defer until B is proven.

Option B does not preclude option C; once B works the resulting guest
IS a candidate template.
