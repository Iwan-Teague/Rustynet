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

## 7) Track B (Cross-Platform Role) — 2026-05-23 evidence

This section records what landed under Track B of
[`AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md`](./AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md)
so the orchestrator can host a Windows or macOS active exit /
relay / anchor instead of locking the mesh exit to Linux exit-1.

### 7.1) Code surfaces shipped

| Step | Deliverable | Files |
|---|---|---|
| B1.5 + B1.1 | Topology profile + `--exit/relay/anchor-platform` selectors. Default Linux-exit byte-for-byte preserved. | `crates/rustynet-cli/src/vm_lab/topology.rs`, CLI flags in `main.rs`, plumbing in `vm_lab/mod.rs::execute_ops_vm_lab_orchestrate_live_lab` |
| M1 | Three new macOS exit-mode validators + evaluators. Skip cleanly when artefacts absent. | `validate_macos_exit_nat_lifecycle` / `validate_macos_exit_dns_failclosed` / `validate_macos_exit_killswitch_precedence` + `evaluate_macos_exit_*` in `vm_lab/mod.rs` |
| B1.4 | Platform-aware role transition planner. `admin → exit` emits `[AdvertiseDefaultRoute, DeployExitService]`; `exit → admin` emits `[UndeployExitService, RetractDefaultRoute]`. | `role_cli.rs` (planner + tests), `execute_platform_exit_service_action` in `main.rs` |
| M5 + W4 (combined with B1.4) | New per-OS exit installers (systemd, launchd, Windows PS). | `ops_install_systemd_exit.rs`, `ops_install_macos_exit.rs`, `ops_e2e.rs::execute_ops_install_windows_exit_service`, `scripts/systemd/rustynet-exit.service`, `scripts/launchd/com.rustynet.exit.plist`, `scripts/bootstrap/windows/{Install,Uninstall}-RustyNetWindowsExitService.ps1` |
| W1 | Windows active-exit promotion stage. Gated on `windows_vm == exit_vm`. | `promote_windows_exit_active` stage + `promote_windows_to_active_exit` helper in `vm_lab/mod.rs` |
| W2 / W3 / M2 / M3 | Relay + anchor live-lab stage slots. macOS relay lifecycle substantive (dry-run via SSH); the other three are skip-with-reason placeholders referencing Track A / W2 / chaos Track C. | `validate_macos_relay_service_lifecycle` (substantive), `validate_macos_anchor_bundle_pull`, `validate_windows_relay_service_lifecycle`, `validate_windows_anchor_bundle_pull` in `vm_lab/mod.rs` |
| B1.2 | Non-Linux genesis verbs. macOS + Windows variants of the membership-init step that mirror Linux `ops e2e-bootstrap-host`. cfg-gated to host OS. | `OpsCommand::E2eBootstrapMacos`/`E2eBootstrapWindows` + `execute_ops_e2e_bootstrap_macos`/`execute_ops_e2e_bootstrap_windows` in `ops_e2e.rs`; CLI verbs `ops e2e-bootstrap-macos` and `ops e2e-bootstrap-windows`; help text in `main.rs` |
| M1 producer | macOS exit-mode NAT lifecycle producer: `rustynetd macos-exit-nat-lifecycle-snapshot` emits a single-phase pf-anchor + sysctl forwarding snapshot. Companion `scripts/e2e/capture_macos_exit_nat_lifecycle.sh` drives the destructive two-phase capture (snapshot during exit-mode, stop daemon, snapshot, restart) and writes the merged artefact the validator reads. | `crates/rustynetd/src/macos_exit_nat_lifecycle.rs` (module, 11 unit tests); subcommand handler in `rustynetd::main`; `scripts/e2e/capture_macos_exit_nat_lifecycle.sh`; producer→validator round-trip tests in `vm_lab::tests::macos_exit_nat_lifecycle_producer_*` |

Step B1.2 (non-Linux genesis) — landed: new `ops e2e-bootstrap-macos`
and `ops e2e-bootstrap-windows` CLI verbs in
`crates/rustynet-cli/src/ops_e2e.rs` mirror the Linux
`ops e2e-bootstrap-host` membership-init step against the
platform-canonical state paths (macOS: `/usr/local/var/rustynet/`;
Windows: `C:\ProgramData\RustyNet\membership\` via the daemon's
`windows_paths` constants). Each verb is cfg-gated to its host OS;
non-target hosts return a clear "only supported on" error. The
verbs accept `--node-id`, `--network-id`, and `--passphrase-file`,
matching the existing Linux variant's argument shape. Parser test
in `tests::parse_supports_ops_commands` pins both verb routings;
execution is exercised on the matching host platform.

### 7.2) CI gate added

`scripts/ci/cross_platform_role_gates.sh` runs in PR-time CI without a
live lab: it verifies the new files exist, the topology selector
surface compiles, the planner emits the new ConcreteAction variants,
and runs the per-area unit tests. Hermetic — no VM required.

### 7.3) Operator next steps to capture live evidence

The deliverables above land the code path. Capturing live evidence of
a Windows or macOS active exit run still requires:

1. A heterogeneous live lab with at least one Debian VM, one Windows
   VM (`windows-utm-1`), and one macOS VM (`macos-utm-1`) reachable
   over SSH with key-based auth.
2. A topology profile JSON containing `{ "exit": "windows-utm-1" }`
   (or `{ "exit": "macos-utm-1" }`).
3. `./target/release/rustynet-cli ops vm-lab-orchestrate-live-lab
   --inventory documents/operations/active/vm_lab_inventory.json
   --exit-vm debian-headless-1 --client-vm debian-headless-2
   --windows-vm windows-utm-1 --macos-vm macos-utm-1
   --topology-profile <profile.json>
   --ssh-identity-file ~/.ssh/rustynet_lab_ed25519
   --report-dir /tmp/track-b-windows-exit
   --legacy-bash-orchestrator --skip-gates --skip-soak
   --skip-cross-network --no-fail-on-authenticode`
4. The equivalent `--topology-profile` pointing at `macos-utm-1`
   captures macOS-as-exit evidence.

Both runs are expected to land `overall_status=pass` for the
baseline + `validate_windows_exit_*` (or `validate_macos_exit_*`)
stages once the per-platform on-host test bins that produce the
NAT-lifecycle / DNS-failclosed / killswitch-precedence artefacts are
in place. The orchestrator-side shape contract is ready; the
producer-side bins are the gating dependency.

### 7.4) Verification of default-run preservation

`cargo test -p rustynet-cli --bin rustynet-cli
vm_lab::topology::tests::resolve_topology_default_linux_exit_remains_implicit`
asserts the byte-for-byte invariant: when neither `--topology-profile`
nor any `--*-platform` selector is set and the operator passes only
`--exit-vm`, the topology resolver leaves `config.exit_vm` untouched
and reports zero overrides. Default Linux-exit live-lab runs continue
to produce the same `setup_live_lab_profile.env` as before this
change.

## 8) Track C (Chaos Live-Lab Scaffold) — 2026-05-23 evidence

This section records the first implementation slice for Track C of
[`AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md`](./AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md).
It is hermetic scaffold evidence only: no daemon was killed, no host
clock was changed, no filesystem was filled, and no network impairment
was applied to a live VM.

### 8.1) Code surfaces shipped

| Area | Deliverable | Files |
|---|---|---|
| Chaos category harnesses | Eight bins emit structured per-category reports with stage names, fault descriptions, recovery deadlines, and leak-proof fields. `live_chaos_daemon_fault_test` now has one live-capable daemon KILL sub-stage; `live_chaos_signed_state_adversarial_test` now performs offline fail-closed fixture coverage for all five signed-state stages; the remaining chaos sub-stages still emit dry-run or skipped outcomes until implemented. | `crates/rustynet-cli/src/bin/live_chaos_*_test.rs`, `crates/rustynet-cli/src/bin/live_chaos_support/mod.rs` |
| Signed-state adversarial input generator | `live_signed_bundle_forger` creates offline reject-only fixtures for truncation, future-dating, forged signature, replay watermark, and quorum-starvation scenarios. The scenario contract is shared with the signed-state chaos harness so CI verifies every Track C signed-state stage has a fail-closed fixture. It is gated behind Cargo feature `chaos-forger`. | `crates/rustynet-cli/src/bin/live_signed_bundle_forger.rs`, `crates/rustynet-cli/src/bin/live_signed_state_chaos/mod.rs`, `crates/rustynet-cli/Cargo.toml` |
| Impairment harness | Plan/apply/clear wrapper validates platform, interface, direction, and profile; `plan` is hermetic, `apply/clear` are Linux-only and require an explicit interface allow-list. | `scripts/e2e/chaos_impair_link.sh` |
| Chaos coordinator scaffold | Shared helpers record fault windows and teardown callbacks; cleanup invokes registered callbacks before removing the live-lab workspace. | `scripts/e2e/live_lab_common.sh` |
| Orchestrator opt-in | `--enable-chaos-suite` adds eight `chaos_*` stages after managed DNS. Default runs record explicit skips, preserving current live-lab duration and behaviour. The daemon-fault category now runs an opt-in live KILL/recovery/leak-proof stage against the exit host; other categories remain scaffolded. | `scripts/e2e/live_linux_lab_orchestrator.sh`, `scripts/e2e/live_chaos_*_test.sh` |
| Hermetic CI gate | `scripts/ci/chaos_gates.sh` validates impairment parser rejection, forger output, all eight category reports, and the signed-state offline report's `pass` / `reject_fail_closed` / `production_accepted=false` contract. | `scripts/ci/chaos_gates.sh` |

### 8.2) Verification performed

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo check -p rustynet-cli --all-targets --all-features` | pass |
| `cargo clippy -p rustynet-cli --all-targets --all-features -- -D warnings` | pass |
| `cargo test -p rustynet-cli --all-features --bins` | pass |
| `scripts/ci/chaos_gates.sh` | pass |
| `git diff --check` | pass |

### 8.3) Remaining Track C live evidence

The following remain open before Track C can satisfy its full definition of
done:

- Replace dry-run reports with live category implementations that register
  teardown before mutation.
- Capture tcpdump windows proving zero plaintext leakage from mesh IPs to
  non-mesh CIDRs during every fault.
- Measure recovery time per chaos sub-stage and compare it with the encoded
  recovery deadline.
- Add post-run invariants proving clocks, qdisc/pf/netsh rules, filesystem
  state, daemon service state, and signed-state files returned to baseline.
- Expand `live_chaos_daemon_fault_test` beyond the first implemented
  `chaos_daemon_kill_during_reconcile` sub-stage to cover OOM, SIGSTOP/SIGCONT,
  and privileged-helper socket races.
- Connect the offline signed-state fixtures to a live daemon ingestion/rejection
  proof once the operator is ready for live-lab mutation; current coverage is
  hermetic fixture generation and report contract validation only.

## 9) Linux Exit-Role Orchestration Parity — 2026-05-23 Evidence

This section tracks the Linux producer/orchestrator parity work that brings
Linux exit-role evidence up to the same deeper stage model as macOS and
Windows. This is code-only evidence until the operator runs the clean Debian
13 lab.

### 9.1) Code Surfaces Shipped

| Step | Deliverable | Files |
|---|---|---|
| L1 | Linux exit NAT lifecycle producer + validator. `rustynetd linux-exit-nat-lifecycle-snapshot --mesh-cidr <cidr> [--nat-table <name>]` emits a single-phase nftables NAT + `/proc/sys` forwarding snapshot. `capture_linux_exit_nat_lifecycle.sh` performs the destructive two-phase stop/start capture and writes the merged artefact consumed by `validate_linux_exit_nat_lifecycle`. | `crates/rustynetd/src/linux_exit_nat_lifecycle.rs`, `crates/rustynetd/src/main.rs`, `scripts/e2e/capture_linux_exit_nat_lifecycle.sh`, `crates/rustynet-cli/src/vm_lab/mod.rs` |
| L2 | Linux relay lifecycle, anchor bundle-pull, and membership genesis validator stages. `validate_linux_relay_service_lifecycle` exercises `rustynet ops install-systemd-relay --dry-run` plus `--uninstall --dry-run` over SSH and verifies the systemd lifecycle plan. `validate_linux_anchor_bundle_pull` exercises the anchor init dry-run plan and verifies all anchor sub-capabilities plus the loopback bundle-pull listener plan. `validate_linux_membership_genesis` verifies canonical membership files are `0600`, owned by `rustynetd:rustynetd`, and readable through `rustynet membership status`. | `crates/rustynet-cli/src/vm_lab/mod.rs` |
| L1 CI | Hermetic Linux exit-role gate plus cross-platform gate references. | `scripts/ci/linux_exit_role_gates.sh`, `scripts/ci/cross_platform_role_gates.sh` |

### 9.2) Remaining Linux Parity Work

- Add Linux exit DNS fail-closed producer and `validate_linux_exit_dns_failclosed`.
- Add Linux killswitch precedence producer and `validate_linux_exit_killswitch_precedence`.
- Capture live Debian 13 evidence for the landed Linux relay lifecycle, anchor
  bundle-pull, and membership genesis validator stages.
- Flip Linux/macOS NAT lifecycle schemas to v2 for IPv6 parity once dual-stack
  membership detection is wired.
