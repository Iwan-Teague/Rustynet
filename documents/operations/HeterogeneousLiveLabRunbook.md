# Heterogeneous Live-Lab Runbook

How to drive an end-to-end live-lab run that includes a Windows
peer alongside the existing 5-node Linux topology, using the
Rust-side `vm-lab-*` orchestrator subcommands.

This runbook is the operator-facing companion to:
- [`OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md`](./active/OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md)
- [`WindowsWorkingNodeBringUpRunbook.md`](./WindowsWorkingNodeBringUpRunbook.md)
- [`LinuxDaemonValidatorRunbook.md`](./LinuxDaemonValidatorRunbook.md)
- [`LiveLinuxLabOrchestrator.md`](./LiveLinuxLabOrchestrator.md)

## 0) Prerequisites

- macOS host with UTM installed at the canonical
  `/Applications/UTM.app/Contents/MacOS/utmctl` path.
- The 5 Debian Linux UTM VMs from your inventory + the Windows 11
  UTM VM (`windows-utm-1`).
- An SSH keypair distributed to every VM:
  - Linux peers: public key in `~debian/.ssh/authorized_keys`.
  - Windows peer: public key in
    `C:\ProgramData\ssh\administrators_authorized_keys` (the
    `bootstrap_windows_access_for_target` Rust path or the
    `Bootstrap-RustyNetWindows.ps1` script handle this).
- Inventory file at
  `documents/operations/active/vm_lab_inventory.json` with current
  IPs (re-discover via `vm-lab-discover-local-utm` after reboots).

## 1) Pre-flight: confirm every selected VM is reachable

Run this BEFORE any orchestrate-live-lab attempt. Surfaces every
alias's TCP/22 + SSH-auth status in one report so you don't burn
30 minutes mid-orchestrate to discover one VM was off.

```sh
cargo run -p rustynet-cli --release -- \
  ops vm-lab-readiness-check \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --vms debian-headless-1,debian-headless-2,debian-headless-3,debian-headless-4,debian-headless-5,windows-utm-1 \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --connect-timeout-secs 5 \
  --report-dir /tmp/rustynet-readiness
```

Expected on success: `summary.ready == 6, blocked == 0`.

Common per-alias blockers:
- **`tcp_port_open: false, blocker: TCP/22 not reachable`** — VM
  is offline. Start it via UTM.app GUI or
  `/Applications/UTM.app/Contents/MacOS/utmctl start <utm_name>`.
- **`auth_ok: false, blocker: SSH identity probe failed`** — TCP
  port is open but SSH authentication failed. Common causes:
    * Windows peer: `administrators_authorized_keys` not set up;
      run the access-bootstrap path
      (`bootstrap_windows_access_for_target`) or manually copy the
      public key to
      `C:\ProgramData\ssh\administrators_authorized_keys` with the
      ACL `Administrators:F` `SYSTEM:F` (no other principals).
    * Linux peer: missing entry in `~/.ssh/authorized_keys`.

The readiness check returns exit code 1 when any alias is blocked,
so it's CI-friendly: `vm-lab-readiness-check && vm-lab-orchestrate-live-lab …`.

## 2) Per-platform validators (sanity check before full orchestrate)

If readiness passes but you want to confirm each peer's daemon-side
state matches the reviewed posture before starting the longer
orchestrate run:

```sh
# Linux side — six daemon-side validators, ~15s per peer:
cargo run -p rustynet-cli --release -- \
  ops vm-lab-validate-linux-security \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --linux-vm debian-headless-1 \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --report-dir /tmp/rustynet-stage1-linux

# Windows side — eight orchestrator stages, ~2-5min:
cargo run -p rustynet-cli --release -- \
  ops vm-lab-validate-windows-security \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --windows-vm windows-utm-1 \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --report-dir /tmp/rustynet-stage2-windows \
  --skip-access-bootstrap --skip-install
```

The skip flags assume the Windows VM has been bootstrapped + the
daemon installed in a prior run. Drop them on a fresh VM.

Both subcommands write a typed JSON report mirroring each other's
schema so downstream tooling parses both with one parser.

## 3) Full heterogeneous orchestrate-live-lab

When readiness + per-platform validators pass, run the all-in-one
orchestrator:

```sh
cargo run -p rustynet-cli --release -- \
  ops vm-lab-orchestrate-live-lab \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --report-dir /tmp/rustynet-orchestrate-$(date +%s) \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --windows-vm windows-utm-1 \
  --validate-linux-daemon-state
```

What runs, in order:
1. `discover_local_utm` — confirms every alias is up (utmctl + SSH
   readiness probe).
2. `wait_until_ready` — waits up to `--wait-ready-timeout-secs` (300s
   default) for every selected VM to reach SSH-ready.
3. The 5-node Linux live-lab via the bash orchestrator
   (`scripts/e2e/live_linux_lab_orchestrator.sh`) — install +
   bootstrap + 5-node enforce + traffic test + soak.
4. **Windows post-validate (if `--windows-vm` is set)** — eight
   stages: bootstrap → client_install → runtime_acls →
   service_hardening → key_custody → authenticode →
   dns_failclosed → distribute_{membership,assignment,traversal,dns_zone}
   → mesh_join.
5. **Linux daemon validators (if `--validate-linux-daemon-state` is
   set)** — six stages × N Linux peers, prefixed `<alias>::` in
   the master report.
6. `finalize_vm_lab_orchestration_result` — gathers artifacts,
   generates the run digest, exit-codes 1 on any failure.

Cost when both flags are on against a 5+1 lab: ≈ 30-90 minutes
depending on whether the daemon needs a fresh build. The bash
orchestrator install path dominates the wall-clock; the validator
stages add ≈ 5-10 minutes total.

Output:
- `<report-dir>/orchestration/` — per-stage JSON artifacts.
- `<report-dir>/windows_security_validation.json` — Windows side
  (when `--windows-vm` is set).
- `<report-dir>/validate_linux_daemon_state/<alias>/linux_security_validation.json`
  — per-Linux-peer side (when `--validate-linux-daemon-state` is
  set).
- `<report-dir>/run_result.json` — master command result.

Exit code 0 = full pass. Exit code 1 = at least one stage failed
or skipped due to upstream blocker.

## 4) Distribution path (Linux exit → Windows peer)

When the live-lab run completes successfully, the Linux exit guest
holds freshly-issued signed bundles at
`/var/lib/rustynet/{membership.snapshot,rustynetd.assignment,rustynetd.traversal,rustynetd.dns-zone}`.
Pull them down + push to the Windows peer:

```sh
# Step 1: pull from Linux exit
cargo run -p rustynet-cli --release -- \
  ops vm-lab-pull-windows-state-from-linux-exit \
  --linux-exit-vm debian-headless-1 \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --dest-dir /tmp/rustynet-staging \
  --report-dir /tmp/rustynet-distribute

# Step 2: push to Windows peer
cargo run -p rustynet-cli --release -- \
  ops vm-lab-distribute-windows-state \
  --windows-vm windows-utm-1 \
  --ssh-identity-file ~/.ssh/rustynet_lab_ed25519 \
  --membership-bundle /tmp/rustynet-staging/membership.snapshot \
  --assignment-bundle /tmp/rustynet-staging/rustynetd.assignment \
  --traversal-bundle  /tmp/rustynet-staging/rustynetd.traversal \
  --dns-zone-bundle   /tmp/rustynet-staging/rustynetd.dns-zone \
  --report-dir /tmp/rustynet-distribute
```

Two-step flow keeps the staging dir contents auditable between
fetch + push. A combined "pull + distribute" subcommand is
deliberately not provided.

## 5) Common operator flow shortcuts

| Goal | Subcommand sequence |
|---|---|
| First-run sanity from cold start | `vm-lab-start --all` → `vm-lab-readiness-check` → `vm-lab-orchestrate-live-lab --windows-vm windows-utm-1 --validate-linux-daemon-state` |
| Trust-state-only refresh after a daemon code change | `vm-lab-orchestrate-live-lab` (no flags) → `vm-lab-pull-windows-state-from-linux-exit` → `vm-lab-distribute-windows-state` |
| Diagnose drift on one peer without a full re-run | `vm-lab-validate-linux-security --linux-vm <alias>` or `vm-lab-validate-windows-security --windows-vm <alias> --skip-access-bootstrap --skip-install` |
| Diagnose a failed orchestrate run | `vm-lab-diagnose-live-lab-failure --profile <profile> --report-dir <prior-run-report-dir>` |

## 6) What is NOT covered today

- **Live operator evidence on Windows backend = `windows-wireguard-nt`.**
  Even when the Windows VM has WireGuard for Windows installed and
  the daemon auto-selects `windows-wireguard-nt`, the backend code
  itself has not been live-tested end-to-end (W4.3 / W4.4 traffic
  + route + DNS lifecycle stages still pending).
- **Mesh-join evidence on Windows.** The W4.2 verifier reports
  `state snapshot missing` until the daemon ships on a working
  backend that writes `rustynetd.state`. That's honest "not yet
  joined" posture, not a verifier bug.
- **Authenticode chain validation.** Requires a code-signed
  release binary. Dev builds will fail W2.1b chain validation
  with "no signature on binary"; that is correct behavior for
  unsigned bits.
- **Production code-signing cert.** The release-windows.yml
  GitHub Actions workflow exists but requires the operator to
  plug in a code-signing cert via GitHub Secrets before the
  signed-release path emits validatable Authenticode chains.

## 7) Cross-References

- Bash orchestrator (Linux install path): [`LiveLinuxLabOrchestrator.md`](./LiveLinuxLabOrchestrator.md)
- Windows bring-up: [`WindowsWorkingNodeBringUpRunbook.md`](./WindowsWorkingNodeBringUpRunbook.md)
- Linux daemon validators: [`LinuxDaemonValidatorRunbook.md`](./LinuxDaemonValidatorRunbook.md)
- Release signing: [`ReleaseSigningRunbook.md`](./ReleaseSigningRunbook.md)
- Inventory format: `crates/rustynet-cli/src/vm_lab/mod.rs` (search
  for `VmInventoryEntry`).
