# Linux Daemon Validator Runbook

How to use the `linux-*-check` daemon-side validator subcommands +
their orchestrator wrappers to confirm a Linux peer's runtime state
matches the reviewed posture.

This runbook is the operator-facing companion to W3.2-followup-1
through W3.2-followup-9 in
[`OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md`](./active/OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md).

## 1) When to run these

Run after the bash orchestrator (`scripts/e2e/live_linux_lab_orchestrator.sh`)
has finished installing + starting the daemon on a Linux peer. The
validators are read-only and never mutate runtime state; they exist
to surface drift between the live host and the reviewed posture.

Typical use cases:
- Live-lab evidence runs where you want JSON proof every peer's
  daemon-side state is clean.
- Post-install sanity check before declaring a node fit for traffic.
- Post-incident audit after a deploy to confirm no drift slipped in.

## 2) Six daemon-side subcommands

Each is a subcommand of `/usr/local/bin/rustynetd`. All accept
`--no-fail-on-drift` to keep the process exit code 0 when drift is
present; the JSON `overall_ok=false` field still signals drift to
downstream tooling.

| Subcommand | What it checks |
|---|---|
| `linux-runtime-acls-check` | `/var/lib/rustynet` (0700 `rustynetd:rustynetd`) and `/etc/rustynet` (0750 `root:rustynetd`) match reviewed mode + owner posture |
| `linux-key-custody-check` | `/var/lib/rustynet/keys/` directory + `wireguard.key.enc` present at 0600 + `wireguard.pub` present at 0640; legacy plaintext `wireguard.key` is forbidden at rest |
| `linux-service-hardening-check` | `systemctl show rustynetd.service` matches the 19 reviewed hardening directives (User/Group/NoNewPrivileges/PrivateTmp/PrivateDevices/ProtectSystem=strict/ProtectHome/etc.) |
| `linux-authenticode-check` | Always emits `applicable: false, overall_ok: true`. Linux does not enforce binary signatures at runtime; package signing happens via dpkg/rpm at install time. |
| `linux-dns-failclosed-check` | Every nameserver in `/etc/resolv.conf` is loopback (127.0.0.0/8 IPv4, ::1/128 IPv6); external + RFC1918 + unparseable nameservers all surface as drift |
| `linux-mesh-status-check` | `/var/lib/rustynet/rustynetd.state` is loadable; expected peer IDs are present (when `--expected-peer-id <id>` provided); snapshot age within `--max-age-seconds` |

Run a single subcommand directly via SSH:

```sh
ssh rustynet@debian-utm-1 \
  /usr/local/bin/rustynetd linux-runtime-acls-check --no-fail-on-drift
```

## 3) Orchestrator-side wrappers

For multi-stage runs against one or many peers, use the orchestrator
subcommands. Both write a typed JSON report so downstream tooling
parses the multi-stage output with one schema.

### 3.1) Single peer: `vm-lab-validate-linux-security`

Runs the six validators against one Linux peer with skip-cascade
gating (every stage gates on `runtime_acls_passed`; mesh-status
gates additionally on key-custody / hardening / dns-failclosed).

```sh
cargo run -p rustynet-cli --features vm-lab -- ops vm-lab-validate-linux-security \
  --inventory /path/to/inventory.json \
  --linux-vm debian-utm-1 \
  --ssh-identity-file ~/.ssh/id_ed25519 \
  --report-dir /tmp/rustynet-reports/$(date +%s)
```

Optional mesh-status overrides (Linux parity for the Windows side's
W4.2 mesh-join overrides):

```sh
  --mesh-status-state-path /var/lib/rustynet/rustynetd.state \
  --mesh-status-expected-peer-ids node-001,node-002 \
  --mesh-status-max-age-seconds 300
```

Output:
- `<report-dir>/linux_security_validation.json` — typed JSON
  report with `schema_version`, `linux_vm`, `dry_run`, and a
  `stages: [{stage, status, summary, artifacts}]` array.
- `<report-dir>/logs/<stage_name>.log` — per-stage raw report
  bodies for forensic post-mortem.

### 3.2) Multiple peers: `vm-lab-orchestrate-live-lab --validate-linux-daemon-state`

The existing `vm-lab-orchestrate-live-lab` subcommand grew an
opt-in flag that runs the six validators against every selected
Linux alias as a post-install validation phase:

```sh
cargo run -p rustynet-cli --features vm-lab -- ops vm-lab-orchestrate-live-lab \
  --inventory /path/to/inventory.json \
  --report-dir /tmp/rustynet-reports/$(date +%s) \
  --ssh-identity-file ~/.ssh/id_ed25519 \
  --validate-linux-daemon-state
```

Off by default to preserve existing latency. When enabled, costs
6 stages × N peers (≈ 30 SSH round-trips per 5-peer run). Each
peer's output lands under
`<report-dir>/validate_linux_daemon_state/<alias>/` and stage names
are prefixed `<alias>::` in the master report so multi-peer runs
disambiguate cleanly.

## 4) Reading the report

`overall_ok=true` for the run means every stage's `status="pass"`.
`overall_ok=false` means at least one stage is `fail` or `skipped`
due to upstream-stage failure (skip-cascade). The first failed
stage's `summary` is the load-bearing reason; subsequent skipped
stages cite their upstream blocker so an operator sees the full
chain in one report.

Common drift patterns:
- **`runtime_acls drifted`** — someone changed mode/owner on the
  state or config root. Fix: `chmod 0700 /var/lib/rustynet && chown rustynetd:rustynetd /var/lib/rustynet`.
- **`forbidden but present at rest: ... wireguard.key`** — a
  plaintext WireGuard private key is on disk. Phase E migrated to
  encrypted-at-rest custody; the plaintext file must be deleted
  after migration.
- **`ProtectSystem drifted: expected "strict", observed "false"`** —
  the systemd unit was edited or overridden. Re-deploy the
  reviewed `scripts/systemd/rustynetd.service` and run
  `systemctl daemon-reload`.
- **`nameserver 192.168.1.1 is non-loopback`** — the host has a
  LAN router DNS in `/etc/resolv.conf`. The mesh DNS fail-closed
  posture requires loopback-only resolvers; reconfigure
  systemd-resolved or the static resolv.conf to point at
  `127.0.0.53` / `127.0.0.1`.
- **`state snapshot missing: ENOENT`** — the daemon has not yet
  written a session snapshot. Either the daemon never reconciled
  (check `journalctl -u rustynetd`) or the unit's state path
  changed and the verifier is reading the stale path.

## 5) Cross-References

- Windows parity: [`WindowsWorkingNodeBringUpRunbook.md`](./WindowsWorkingNodeBringUpRunbook.md)
- Bash orchestrator (install path): [`LiveLinuxLabOrchestrator.md`](./LiveLinuxLabOrchestrator.md)
- Underlying systemd unit: `scripts/systemd/rustynetd.service`
- Verifier source modules: `crates/rustynetd/src/linux_*.rs`
- Stage runner + chainer: `crates/rustynet-cli/src/vm_lab/mod.rs`
  (search for `run_validate_linux_*_stage` and
  `run_linux_orchestration_stages_with_options`).
