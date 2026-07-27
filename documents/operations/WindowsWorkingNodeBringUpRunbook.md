# Windows Working-Node Bring-Up Runbook

Last updated: 2026-04-28

## 1) Mission

This runbook walks an operator from "fresh Windows 11 host" to
"daemon running on the `windows-wireguard-nt` backend, ready to
join a RustyNet mesh." It composes the verifier + install +
distribution surface that landed under the OS-Agnostic Orchestrator
+ Windows-Peer delta plan and the WindowsWorkingNodePlan.

Prerequisite: this runbook assumes the operator has the membership
owner public key delivered out-of-band per
[`SecurityMinimumBar.md` §6.B](../SecurityMinimumBar.md). Without
the trust anchor, no signed-state bundle can be ingested.

## 2) High-Level Flow

```
[1] Run the RustyNet bootstrap (winget installs WireGuard + Git + PS7 + rustup)
[2] Sync the Rustynet source tree to the Windows guest
[3] Build rustynetd.exe inside the guest
[4] Run windows-backend-readiness-check (confirms WG ended up installed)
[5] Run Install-RustyNetWindowsService.ps1 (auto-detects WG)
[6] Run windows-runtime-acls-check + the W2.x security validators
[7] Distribute signed bundles (membership + assignment + traversal + DNS zone)
[8] Verify the daemon ingested state via windows-mesh-status-check
```

## 3) Step-By-Step

### 3.1 Run the bootstrap (auto-installs WireGuard for Windows)

The `Bootstrap-RustyNetWindows.ps1` helper runs `winget configure`
against `RustyNetBootstrap.winget.yml`, which declares every
prerequisite the working-node bring-up depends on:

- `Git.Git` — source sync
- `Microsoft.PowerShell` (PS 7) — modern non-interactive scripting
- `Rustlang.Rustup` — toolchain management for the build phase
- **`WireGuard.WireGuard`** — installs the official WireGuard for
  Windows package, providing
  `C:\Program Files\WireGuard\wireguard.exe`,
  `C:\Program Files\WireGuard\wg.exe`, and the `WireGuardManager`
  tunnel-management service

Invoking it (orchestrator-driven path, from a Linux/macOS
workstation):

```bash
./target/release/rustynet-cli ops vm-lab-bootstrap-phase \
    --phase prepare-transport \
    --vm windows-utm-1 \
    --inventory documents/operations/active/vm_lab_inventory.json \
    --ssh-identity-file ~/.ssh/rustynet_lab_ed25519
```

After winget reports success, `Assert-RustyNetWingetDependenciesInstalled`
double-checks every package landed at its canonical path. If
WireGuard, Rustup, or Git is missing post-winget the bootstrap
fails LOUD with a precise list — preventing a downstream install
helper from silently falling back to `windows-unsupported` because
WireGuard wasn't actually installed.

To verify the WireGuard install signature out-of-band:

```powershell
Get-AuthenticodeSignature 'C:\Program Files\WireGuard\wireguard.exe'
```

Status MUST be `Valid`. (The winget package source is itself
signature-verified, but operators on regulated networks may want
the explicit confirmation.)

**WireGuard for Windows is required. There is no install path
without it, and this section previously said otherwise.**

The opt-out documented here — passing `-ForceUnsupportedBackend`
to stay on the fail-closed `windows-unsupported` backend on a
staging host — has not worked since 2026-04-30, when the install
helper gained its `rekey-wireguard-under-runtime-identity` step.
That step runs `rustynetd key init`, which shells out to
`wg genkey`, so a host without WireGuard fails the install
before reaching the service-install work that follows. It failed silently for
2 months 27 days; as of 2026-07-27 the helper refuses at
`require-wireguard-wg-binary` with an explicit message instead.

`-ForceUnsupportedBackend` still pins the label on a host that
*does* have WireGuard, which is the staging use it was written
for. Restoring a genuinely WireGuard-less install would mean
making the rekey step conditional — a product decision, not a
documentation fix.

### 3.2 Sync source + build

The orchestrator's `vm-lab-bootstrap-phase --phase build-release`
flow does this for VM-lab guests; an operator bringing up a Windows
host outside the lab can use the equivalent SSH-based path. The
build produces `target\release\rustynetd.exe` inside the
`C:\Rustynet\` source root.

### 3.3 Confirm backend prerequisites are present

Before flipping the install helper to `windows-wireguard-nt` mode,
run the daemon's own readiness check:

```powershell
& 'C:\Rustynet\target\release\rustynetd.exe' windows-backend-readiness-check
```

Expected output: `overall_ok: true` with all three reviewed paths
(`wireguard.exe`, `wg.exe`, `netsh.exe`) reporting
`present: true, probed: true`. If any entry is missing, the install
helper will fall back to `windows-unsupported` even on the next
run, so resolve missing prerequisites first.

### 3.4 Install the RustyNet service

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive `
    -ExecutionPolicy Bypass `
    -File 'C:\Rustynet\scripts\bootstrap\windows\Install-RustyNetWindowsService.ps1' `
    -OutputPath 'C:\Rustynet\.tmp\install-report.json'
```

The helper:
- Validates `-ServiceName`, `-InstallRoot`, `-StateRoot` parameters
  (defense-in-depth W2.5b validators rejecting metacharacters /
  unreviewed paths)
- Probes for WireGuard for Windows
  (`Test-WireGuardDriverPresence`) and writes `--backend
  windows-wireguard-nt` to the env file when detected, else
  `--backend windows-unsupported` for fail-closed
- Installs the daemon binary at `C:\Program Files\RustyNet\rustynetd.exe`,
  locks down the binary's ACL (W2.2: SYSTEM + Administrators full,
  service identity RX-only), creates the runtime ACL'd state tree,
  configures the service via `New-Service` with reviewed startup +
  failure-action policy, and starts the daemon

The console output advertises the chosen backend label so the
operator can confirm at a glance which path was taken.

To pin the install to fail-closed mode regardless of WG presence
(staging hosts, dry-run validation):

```powershell
... -ForceUnsupportedBackend
```

### 3.5 Run the W2.x security validators

After install, run every reviewed daemon-side validator to confirm
the host posture matches the security minimum bar:

```powershell
$exe = 'C:\Program Files\RustyNet\rustynetd.exe'
& $exe windows-runtime-acls-check
& $exe windows-service-hardening-check
& $exe windows-key-custody-check
& $exe windows-authenticode-check
& $exe windows-dns-failclosed-check
& $exe windows-backend-readiness-check
```

Each must report `overall_ok: true`. The orchestrator-side
`vm-lab-validate-windows-security` subcommand drives the same set
remotely over SSH; running them locally is the operator's
in-the-loop verification.

If `windows-authenticode-check` fails with `TRUST_E_NOSIGNATURE`,
the daemon binary is unsigned. Production deployments require a
signed binary built by the release pipeline
(`.github/workflows/release-windows.yml`); the W2.1b chain
validator gates daemon startup against the cert.

### 3.6 Distribute signed-state bundles

From the orchestrator host (Linux/macOS, where the rustynet-cli
tooling builds), push each signed bundle to the Windows guest. The
4 helpers in `crates/rustynet-cli/src/vm_lab/mod.rs` are:

```rust
run_distribute_windows_membership_stage(...)
run_distribute_windows_assignment_stage(...)
run_distribute_windows_traversal_stage(...)
run_distribute_windows_dns_zone_stage(...)
```

Each takes the local-filesystem path of the corresponding signed
bundle and pushes via SCP + atomic `Move-Item -Force` + watermark
clear. Order matters:

1. **membership** first — the daemon's peer table can't reconcile
   without a current membership snapshot.
2. **assignment** — exit / role assignment per peer.
3. **traversal** — STUN / relay traversal coordination.
4. **dns-zone** — magic-DNS records.

The orchestrator subcommand surface that exposes these helpers
(`ops vm-lab-distribute-windows-state` or similar) is a follow-up;
today the helpers are callable directly from any orchestrator
code path that wires up the Linux-side bundle-pull + Windows-side
bundle-push.

### 3.7 Confirm daemon ingestion

```powershell
& 'C:\Program Files\RustyNet\rustynetd.exe' windows-mesh-status-check
```

Expected output: `overall_ok: true` with `load_status: ok` and a
non-empty `peer_ids` list reflecting the distributed membership.

If `load_status: missing`, the daemon hasn't yet refreshed since
the bundle was pushed; the watermark-clear in the distribution
helpers forces re-ingestion on the next refresh tick. The default
refresh cadence is documented in `crates/rustynetd/src/fetcher.rs`
(`RefreshScheduler`).

## 4) Troubleshooting

### 4.1 Daemon refuses to start with `windows-runtime-backend-explicitly-unsupported`

Cause: install helper wrote `--backend windows-unsupported` to the
env file — either WireGuard for Windows was not fully installed
when the helper ran, or `-ForceUnsupportedBackend` was passed.

Both causes are still live. The `require-wireguard-wg-binary` gate
added 2026-07-27 in `8c5a24cd` does NOT make the first unreachable, because the
gate and the backend probe ask different questions about different
binaries: the gate resolves **`wg.exe`** (via
`RUSTYNET_WG_BINARY_PATH` or the canonical path), while
`Test-WireGuardDriverPresence` looks for **`wireguard.exe`** or the
`WireGuardManager` service. A host where `wg.exe` resolves but
`wireguard.exe` does not — a partial install, an AV quarantine of
the GUI binary, or `RUSTYNET_WG_BINARY_PATH` pointed outside the
canonical tree by an operator or an automation — passes the gate and
still gets the `windows-unsupported` label.

Note also that the gate throws before the env file is written, so on
an upgraded host a pre-existing `rustynetd.env` survives unchanged.

Two further routes reach the same label, and neither is a fresh
install:

- **A later helper run downgrades a working host.**
  `Write-ReviewedEnvFile` is an unconditional write with no
  read-modify-write, and `Resolve-ReviewedBackendLabel` is recomputed
  on every invocation — including the `-EnforceAutoTunnel` re-run that
  `EnforceBaselineRuntime` performs. A host that installed correctly as
  `windows-wireguard-nt` is silently rewritten to `windows-unsupported`
  by any later run in which `wireguard.exe` has stopped resolving while
  `wg.exe` still does. The operator symptom is "it worked yesterday and
  I changed nothing".
- **The probe runs as SYSTEM, and PATH differs.**
  `Test-WireGuardDriverPresence` falls back to `Get-Command
  wireguard.exe`, and the helper runs as SYSTEM via `utmctl exec`. A
  WireGuard installed to a non-default directory that is on the
  interactive administrator's PATH is invisible to SYSTEM. This makes
  §3.1's verification step non-predictive of §3.4's outcome: the admin
  sees all three paths present and the helper still labels the host
  unsupported.

Fix:
1. Install WireGuard for Windows (§3.1), and confirm BOTH
   `wireguard.exe` and `wg.exe` are present at the canonical path —
   checking as the account the helper runs under (SYSTEM), not as the
   interactive administrator.
2. Check `RUSTYNET_WG_BINARY_PATH`. If it is set, it is what makes the
   gate and the backend probe disagree; clear it or point it at the
   canonical `wg.exe`.
3. Re-run the install helper without `-ForceUnsupportedBackend`.
3. Confirm via `Get-Content C:\ProgramData\RustyNet\config\rustynetd.env`
   that the `RUSTYNETD_DAEMON_ARGS_JSON` line contains
   `windows-wireguard-nt`.
4. `Restart-Service RustyNet`.

### 4.1b Install fails at `sign-installed-binaries-for-authenticode` on an x86-64 host

**Fixed 2026-07-26 in `003d5edc` (release-affecting; touches the shipped install path).**

Both install helpers (daemon and relay) picked their `signtool.exe` from a hardcoded,
arm64-first candidate list. The Windows SDK installs
`bin\<version>\{arm,arm64,x64,x86}\` side by side regardless of host
architecture, so on an x86-64 host the arm64 pattern still matched and
won — and x64 Windows cannot execute an arm64 image (only ARM64 Windows
emulates x64, not the reverse). Signing then failed and the helper
`Write-Error`'d, failing `bootstrap_hosts`. In run
`winnat-20260725T190000Z` on `windows-x86-1` (`Architecture=AMD64`)
the captured stdout shows the helper selecting
`...\10.0.26100.0\arm64\signtool.exe`, and the run's
`first_failed_stage` is `bootstrap_hosts`. The step attribution is
inferred from stdout ordering rather than captured: that run's
`.progress` file was never collected, because `cleanup` also failed,
and no exec-failure or `signtool sign failed` line appears in the
artifacts.

The helper now resolves the architectures the host can actually execute
(`ARM64` → arm64, x64, x86; `AMD64` → x64, x86; `x86` → x86) and fails
closed on anything else rather than guessing.

The ARM64 architecture *sequence* is unchanged (arm64, x64, x86), but the
selection is not otherwise identical and is not meant to be: version
ordering moved from lexicographic to numeric (the old form sorted
`10.0.9041.0` above `10.0.26100.0`), root precedence within an
architecture was replaced by version ordering across merged roots, an
`x86` candidate under `Program Files` became reachable, and a
`^10\.\d+\.\d+\.\d+$` filter was added so a `zz-backup` directory can no
longer outrank a real SDK. On an ARM64 host with two SDK versions
installed, old and new can therefore select different files — deliberately,
since the old ordering was itself a defect.

The resolver is shared verbatim between
`Install-RustyNetWindowsService.ps1` and
`Install-RustyNetWindowsRelayService.ps1` and pinned by
`windows_installers_share_one_signtool_resolver` (marker-delimited region,
CRLF-normalised) — the daemon and the
relay must be signed by the same tool, and a comment asking for that is
not a control.

If you are on a host that previously failed here, no manual step is
needed beyond re-running the helper from a synced source tree.

### 4.2 `windows-authenticode-check` fails with `TRUST_E_NOSIGNATURE`

Cause: daemon binary is an unsigned local build.

Fix: download a signed release artefact from the GitHub Release
(produced by `.github/workflows/release-windows.yml` after a tag
push). Verify per
[`ReleaseSigningRunbook.md`](./ReleaseSigningRunbook.md) §5
(`Get-AuthenticodeSignature` Status = `Valid`, SHA-256 matches the
release notes) before installing.

### 4.3 `windows-mesh-status-check` reports `load_status: missing`

Cause 1: distribution helpers haven't run yet, or were interrupted
mid-flight. Re-run the distribution sequence (§3.6).

Cause 2: the membership.snapshot's signature failed verification
against the membership-owner public key. Confirm
`C:\ProgramData\RustyNet\trust\membership.owner.key.pub` matches
the operator's published thumbprint per SecurityMinimumBar §6.B.

Cause 3: the watermark file wasn't cleared (concurrent operator
runs, or manual operator intervention). Delete:
- `C:\ProgramData\RustyNet\membership\membership.watermark`
- `C:\ProgramData\RustyNet\trust\rustynetd.assignment.watermark`
- `C:\ProgramData\RustyNet\trust\rustynetd.traversal.watermark`
- `C:\ProgramData\RustyNet\trust\rustynetd.dns-zone.watermark`

then `Restart-Service RustyNet`. The daemon will re-ingest on next
refresh.

### 4.4 Service install succeeds but tunnels never come up

Confirm:
- `Get-Service WireGuardManager` reports `Running`
- `& 'C:\Program Files\WireGuard\wg.exe' show all` lists the
  expected interfaces
- The daemon's log (under
  `C:\ProgramData\RustyNet\logs\rustynetd.log` once that path is
  wired up) reports successful `WindowsWireguardBackend::start`

If the daemon log shows `install_tunnel_service` failing, the WG
installer's user account / service-control permissions may have
been altered; reinstall WireGuard for Windows.

## 5) Cross-References

- W1.1 runtime-paths verifier: `crates/rustynetd/src/windows_paths.rs`
- W1.3 DNS fail-closed verifier: `crates/rustynetd/src/windows_dns_failclosed.rs`
- W2.1a/b Authenticode verifier: `crates/rustynetd/src/windows_authenticode.rs`
- W2.2 service hardening verifier:
  `crates/rustynetd/src/windows_service_hardening.rs`
- W2.4 key-custody verifier: `crates/rustynetd/src/windows_key_custody.rs`
- W4.2 mesh-status verifier:
  `crates/rustynetd/src/windows_mesh_status.rs`
- Backend-readiness verifier (this slice):
  `crates/rustynetd/src/windows_backend_readiness.rs`
- Install helper:
  `scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1`
- Uninstall helper:
  `scripts/bootstrap/windows/Uninstall-RustyNetWindowsService.ps1`
  (least-destructive default: stops + removes the SCM service +
  removes the daemon binary, but preserves the `C:\ProgramData\RustyNet\`
  state root so a reinstall re-adopts the prior identity. Pass
  `-PurgeStateRoot` to wipe trust state, `-PurgeInstallRoot` to wipe
  `C:\Program Files\RustyNet\` if it ends up empty.)
- Bundle distribution helpers (membership / assignment / traversal /
  dns-zone): `crates/rustynet-cli/src/vm_lab/mod.rs`
  (`run_distribute_windows_*_stage` fns)
- Release signing: `.github/workflows/release-windows.yml`,
  `scripts/release/Sign-RustyNetWindowsBinary.ps1`,
  [`ReleaseSigningRunbook.md`](./ReleaseSigningRunbook.md)
- Trust-anchor delivery: [`SecurityMinimumBar.md` §6.B](../SecurityMinimumBar.md)
- WireGuard backend implementation:
  `crates/rustynet-backend-wireguard/src/windows_command.rs`
  (1042 lines wrapping `wireguard.exe` / `wg.exe` / `netsh.exe`)
- Linux symmetric tooling: [`LinuxDaemonValidatorRunbook.md`](./LinuxDaemonValidatorRunbook.md)
  describes the parallel `linux-*-check` daemon-side validators +
  the `vm-lab-validate-linux-security` orchestrator subcommand.
  Both Windows and Linux validator surfaces emit the same JSON
  schema so downstream tooling parses both with one parser.

## 6) What's Still Pending

The runbook above describes the path that's *already shippable
today*. Open follow-ups before this can be advertised as
release-ready:

- **Live evidence** — end-to-end run on a real Windows 11 host
  with WireGuard for Windows installed, confirming traffic flows.
  Today every step is unit-tested + cross-target compiled but no
  live evidence has been captured.
- ~~**Orchestrator wiring** — the four `run_distribute_windows_*_stage`
  helpers are `pub fn`s callable from orchestrator code; they're
  not yet wired into `run_windows_orchestration_stages_with_options`
  or exposed as a `vm-lab-distribute-windows-state` CLI subcommand.
  W4.5 territory.~~ **Closed** — orchestrator wiring landed in
  W4.5 (commit `414099d`); standalone subcommand
  `vm-lab-distribute-windows-state` landed in W4.2-followup-3
  (commit `0c171d9`); pull-from-Linux-exit subcommand
  `vm-lab-pull-windows-state-from-linux-exit` landed in
  W4.2-followup-4 (commit `186a48b`).
- **Signed-release production rollout** — the release-signing
  workflow exists (§3.5 references it) but requires the operator
  to plug in a code-signing cert via GitHub Secrets. Until then
  every release ships unsigned and W2.1b chain validation rejects.
- **Linux-side validator parity** — the orchestrator's
  `LinuxDaemonProbe` rejects every op with a roadmap blocker
  today. For a heterogeneous live-lab to have parity coverage,
  Linux daemon needs `linux-runtime-acls-check`,
  `linux-service-hardening-check`, etc. mirroring the Windows
  pattern.
