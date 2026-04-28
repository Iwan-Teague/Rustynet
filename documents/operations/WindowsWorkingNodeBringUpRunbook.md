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
[1] Install WireGuard for Windows
[2] Sync the Rustynet source tree to the Windows guest
[3] Build rustynetd.exe inside the guest
[4] Run windows-backend-readiness-check (confirms WG installed)
[5] Run Install-RustyNetWindowsService.ps1 (auto-detects WG)
[6] Run windows-runtime-acls-check + the W2.x security validators
[7] Distribute signed bundles (membership + assignment + traversal + DNS zone)
[8] Verify the daemon ingested state via windows-mesh-status-check
```

## 3) Step-By-Step

### 3.1 Install WireGuard for Windows

Download the official installer from
[https://www.wireguard.com/install/](https://www.wireguard.com/install/)
— this provides:
- `C:\Program Files\WireGuard\wireguard.exe`
- `C:\Program Files\WireGuard\wg.exe`
- The `WireGuardManager` tunnel-management Windows service

The signed installer's signature must validate (modern Windows
validates Authenticode signatures automatically; SmartScreen flags
unsigned installers). Verify the cert chain via PowerShell after
install:

```powershell
Get-AuthenticodeSignature 'C:\Program Files\WireGuard\wireguard.exe'
```

Status MUST be `Valid`.

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
env file (either WireGuard for Windows wasn't installed when the
helper ran, or `-ForceUnsupportedBackend` was passed).

Fix:
1. Install WireGuard for Windows (§3.1).
2. Re-run the install helper without `-ForceUnsupportedBackend`.
3. Confirm via `Get-Content C:\ProgramData\RustyNet\config\rustynetd.env`
   that the `RUSTYNETD_DAEMON_ARGS_JSON` line contains
   `windows-wireguard-nt`.
4. `Restart-Service RustyNet`.

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

## 6) What's Still Pending

The runbook above describes the path that's *already shippable
today*. Open follow-ups before this can be advertised as
release-ready:

- **Live evidence** — end-to-end run on a real Windows 11 host
  with WireGuard for Windows installed, confirming traffic flows.
  Today every step is unit-tested + cross-target compiled but no
  live evidence has been captured.
- **Orchestrator wiring** — the four `run_distribute_windows_*_stage`
  helpers are `pub fn`s callable from orchestrator code; they're
  not yet wired into `run_windows_orchestration_stages_with_options`
  or exposed as a `vm-lab-distribute-windows-state` CLI subcommand.
  W4.5 territory.
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
