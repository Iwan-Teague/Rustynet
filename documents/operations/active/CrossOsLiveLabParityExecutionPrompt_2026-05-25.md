# Cross-OS Live-Lab Parity — Phase 19-31 Execution Prompt

**Hand this entire document to a Claude Code agent. The agent must read it once and execute through to completion.**

Date authored: 2026-05-25
Origin: Track B Phases 4-18 are landed and proven on Linux (A2 fresh bootstrap, 5-node Debian mesh, epoch 5+ green). Phase 18 unblocked the macOS CLI/daemon socket allowlist. B2 mixed-OS enrollment surfaced ~12 additional cross-platform gaps; this prompt closes them.

---

## 1. Mission (uncompromising)

Make the Rustynet live lab pass end-to-end on macOS, Windows, AND Debian/Linux. Every role (admin, exit, client, relay, anchor, blind_exit) and every live-lab stage (anchor, relay-service-lifecycle, exit-handoff, lan-toggle, two-hop, role-switch-matrix, managed-dns, mixed-topology) must run for real on each OS — no skips, no scaffolds, no operator workarounds.

The user's exact words: "uncompromising goal", "no TODO or cut corners", "I want everything done properly and completely", "I want a good job done and I don't care how long it takes."

When you finish, the orchestrator should be able to bootstrap a mixed-OS 5-node fleet (Linux exit-1, Linux client, Linux relay, macOS aux, Windows extra) in one shot via `bash scripts/e2e/live_linux_lab_orchestrator.sh --profile ... --setup-only` and then the full live-lab stage matrix must execute green from `--skip-setup`.

## 2. Mandatory constraints (security + engineering baseline)

Read `CLAUDE.md` and `documents/SecurityMinimumBar.md` BEFORE touching code. These are non-negotiable:

- **Fail closed** on missing / invalid / stale / replayed / unauthorized state.
- **No custom crypto**. No protocol invention in production paths.
- **No TODO / FIXME / placeholders** in completed deliverables.
- **One hardened execution path** per security-sensitive workflow. No runtime fallback, downgrade, or legacy branch.
- **No shell construction with untrusted values**. Argv-only exec for privileged helpers.
- **No `sudo --no-verify` / no skipping hooks**.
- **Direct fast-forward to `main`** — no PR / feature-branch workflow (user instruction).
- **Don't add features beyond scope**. A bug fix doesn't need surrounding cleanup; a one-shot operation doesn't need a helper.
- **Don't add error handling / fallbacks for scenarios that can't happen**. Trust framework guarantees.
- **Comments only when WHY is non-obvious**. Well-named identifiers do not need explanatory comments. No "added for X flow" or "fixes bug Y" references.

## 3. Work style (mandatory)

- **One phase = one commit on `main`** pushed via `git push origin HEAD:main` (rebase first if remote moved).
- Each phase commit must pass ALL mandatory gates BEFORE pushing:
  - `cargo fmt --all -- --check`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `cargo test` for the affected crate (full workspace test for far-reaching changes)
  - `cargo audit --deny warnings`
  - `cargo deny check bans licenses sources advisories`
  - `./scripts/ci/membership_gates.sh`
  - `./scripts/ci/phase10_hp2_gates.sh`
  - Any phase-specific gate script under `scripts/ci/`
- **Each commit must immediately spawn a background reviewer sub-agent** (`Agent` tool, `subagent_type: general-purpose`, `run_in_background: true`). The reviewer's task: independently verify the commit against the phase's acceptance criteria + look for security regressions + check for stale doc-comments + count new TODO/FIXME (must be zero).
- **Fold every reviewer BLOCKER and HIGH finding into the NEXT commit** before starting an unrelated phase. MEDIUM findings can fold into the next same-track phase. LOW are cosmetic — fix opportunistically.
- **Trust but verify** sub-agent claims by spot-checking diffs.

## 4. Parallel execution rules

Use the `Agent` tool to spawn parallel work for phases that touch disjoint files. Send multiple `Agent` calls in a single message so they run concurrently.

**You may parallelize when**: target file sets are disjoint AND there is no dependency on a previous phase's output.

**You MUST serialize when**: phases touch the same file, or one phase's commit hash is referenced by another, or one phase is a fix for the previous phase's reviewer finding.

Parallel group dependencies are explicit in §7 below. Each parallel group is one round; spawn all of its phases at once, wait for all to land + their reviewers to complete, fold findings, then advance to the next round.

## 5. Lab inventory (live, validated 2026-05-25)

```
debian@192.168.65.3   exit-1     Linux   admin    SSH key + sudo OK, rustynetd active
debian@192.168.65.4   client-1   Linux   client   SSH key + sudo OK, rustynetd active
debian@192.168.65.6   client-2   Linux   client   SSH key + sudo OK, rustynetd active
debian@192.168.65.5   client-3   Linux   client   SSH key + sudo OK, rustynetd active
debian@192.168.65.7   client-4   Linux   client   SSH key + sudo OK, rustynetd active
mac@192.168.64.18     macos-client-1  macOS  client  SSH key OK, sudo OK (password "tempo"), rustynetd installed, brew wg at /opt/homebrew/bin/wg
windows@192.168.65.8  windows-client-1 Win11 client SSH key OK, RustyNet service installed, PowerShell shell, rustynet.exe + rustynetd.exe at C:\Program Files\RustyNet\
```

**SSH identity**: `~/.ssh/rustynet_lab_ed25519`. Pinned known_hosts at `profiles/live_lab/20260524T235302Z_5node_linux_A2_known_hosts` (extend as needed).

**SSH password (macOS, Windows)**: `tempo` (use `SSHPASS=tempo sshpass -e ssh ...` for password fallback if key auth not yet installed).

**Lab profile for current A2 mesh**: `profiles/live_lab/generated_vm_lab_20260524T235302Z_5node_linux_A2.env`.

**A2 mesh state**: epoch 6, 6 active nodes (5 Debian + macos-client-1 already admitted via B2 manual `rustynetd membership add-peer`). Owner signing key on exit-1 at `/etc/rustynet/membership.owner.key`, passphrase systemd-creds-encrypted at `/etc/rustynet/credentials/signing_key_passphrase.cred`. Approver-id pattern: `${node_id}-owner` (e.g. `exit-1-owner`).

If the macOS daemon's state on `192.168.64.18` is dirty, wipe `/usr/local/var/rustynet/membership/`, `/usr/local/var/rustynet/keys/`, `/usr/local/var/rustynet/secrets/`, `/usr/local/var/rustynet/trust/` and re-create with `install -d -m 0700 -o rustynetd -g rustynetd` before bootstrap.

The macOS daemon's privileged helper plist lives at `/Library/LaunchDaemons/com.rustynet.privileged-helper.plist`. The daemon plist is at `/Library/LaunchDaemons/com.rustynet.daemon.plist`. Both need `launchctl bootstrap system <path>` to activate.

## 6. Documentation you MUST read before coding

In this order:
1. `CLAUDE.md` (project-wide AI agent contract)
2. `documents/README.md`
3. `documents/Requirements.md`
4. `documents/SecurityMinimumBar.md`
5. `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md`
6. `documents/operations/active/MasterWorkPlan_2026-03-22.md`
7. `documents/operations/active/AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md`
8. The Phase 4-18 commits on `main` since 2026-05-23 (`git log --oneline --since=2026-05-23 | head -30`) — these are the immediate priors and the source of the pattern you must extend.

## 7. Phase list with parallelization groups

Each phase is an explicit, complete unit of work. Acceptance criteria are mandatory — every bullet must hold true before the phase commits.

### Round 1 (parallel: Phases 19, 20, 21 — disjoint macOS install/install-adapter work)

#### Phase 19 — macOS utun device opens via privileged helper (HARD)

**Problem**: `rustynetd` runs as user `rustynetd` (uid 500) on macOS. The macOS userspace-shared backend calls `utun_open` directly via socket(2)+ioctl(2), which requires root. Result: `Operation not permitted (os error 1)` for every utun open attempt → daemon enters `restrict_permanent` after 20 reconcile failures → mesh never comes up.

**Fix**: route utun creation through the privileged helper. The Linux backend already uses the privileged helper for setting up wireguard interfaces (`crates/rustynetd/src/privileged_helper.rs`). Mirror that path for macOS.

**Files (start here)**:
- `crates/rustynetd/src/privileged_helper.rs` (add a `MacosUtunOpen { name: String }` command + reviewed argv)
- `crates/rustynet-backend-wireguard/src/macos.rs` (or wherever the userspace-shared backend lives — search for `utun open failed`)
- `crates/rustynetd/src/macos_*.rs` (add macOS-specific entrypoint glue)

**Acceptance criteria**:
- The daemon (running as rustynetd) successfully opens a utun device named `utun42` (or any `utun*`) via the helper.
- The helper validates argv strictly (only accept `utun[0-9]+` names, deny anything else with `CWE-78` reasoning in the deny path).
- The helper runs as root and returns the open fd via SCM_RIGHTS (or equivalent fd-passing primitive).
- Unit tests pin: (a) name validation rejects `utun-evil`, `utun;rm -rf /`, empty, missing prefix; (b) successful open returns a valid fd.
- Live validation: deploy patched daemon to `mac@192.168.64.18`, restart, observe `state=ExitActive` (not `FailClosed`), `path_live_proven=true` after 30 s of peering.

**Reviewer instructions**: confirm CWE-78 argv validation is exhaustive (try injection vectors), confirm no unsafe Rust added, confirm fd-passing handles helper crash mid-transfer (must fail closed, not leak fd to wrong process). Cross-check `crates/rustynetd/src/linux_*.rs` for parallel patterns.

#### Phase 20 — macOS install adapter sets canonical plist args

**Problem**: the macOS install adapter (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs`) generates `/Library/LaunchDaemons/com.rustynet.daemon.plist` but omits `--wg-interface utun*`. Default interface name (`rustynet0`) is rejected by the macOS userspace-shared backend with `must start with utun`.

**Fix**: add `--wg-interface utun<deterministic-id>` to the generated plist. Deterministic id from node_id hash (must be stable across re-installs and ≤ 15 chars total since macOS `utun` name has a limit).

**Files**:
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs`
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install_tests.rs` if it exists

**Acceptance criteria**:
- Generated plist includes `--wg-interface utun<N>` where `<N>` is derived from node_id.
- Unit test pinning the deterministic-id derivation for a known node_id input.
- Unit test asserting `<N>` parses as a valid utun suffix `[0-9]+` and the full interface name is ≤ 15 chars.
- Live validation: re-run install on `mac@192.168.64.18`, confirm new plist has `--wg-interface utun*`, confirm daemon picks it up.

**Reviewer instructions**: confirm deterministic id doesn't collide with reserved utun ranges (utun0 is often used by macOS itself), confirm install adapter is idempotent (re-running doesn't break an existing install).

#### Phase 21 — macOS install adapter provisions enrollment.secret + full canonical state layout

**Problem**: A2 fresh bootstrap on Linux creates `/var/lib/rustynet/keys/enrollment.secret`, but the macOS install adapter doesn't create the macOS equivalent at `/usr/local/var/rustynet/keys/enrollment.secret`. Result: Track A anchor enrollment substages can't mint tokens on macOS anchor hosts.

**Fix**: add enrollment-secret provisioning to the macOS install adapter. Mirror the Linux install adapter's seeding sequence. Also provision any other state file the macOS install path is missing vs Linux.

**Files**:
- `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/macos_install.rs`
- Cross-reference: the Linux install path in the orchestrator's `stage_bootstrap_hosts` → `rn_bootstrap.sh` (search `scripts/e2e/`)

**Acceptance criteria**:
- After macOS install, `/usr/local/var/rustynet/keys/enrollment.secret` exists, mode 0600, owned by rustynetd.
- Audit all artifact paths the Linux bootstrap leaves on disk; for each one, confirm the macOS adapter produces the macOS equivalent.
- Unit tests assert each path is referenced in the install adapter's output.
- Live validation: install on `mac@192.168.64.18` from scratch (wipe state first), confirm all 7 canonical state files exist with correct mode + owner.

**Reviewer instructions**: enumerate the Linux artifact set vs macOS, flag any path that exists on one but not the other. Confirm no plaintext secret ever leaves `/usr/local/var/rustynet/` directory tree.

### Round 2 (serial after Round 1: Phase 22)

#### Phase 22 — Cross-platform `ops e2e-membership-set-capabilities`

**Problem**: `crates/rustynet-cli/src/ops_e2e.rs::execute_ops_e2e_membership_set_capabilities` shells `systemd-creds decrypt` and hardcodes Linux paths (`/etc/rustynet/credentials/`, `/var/lib/rustynet/membership.snapshot`). Result: Track B Phase 11+15 had to skip this verb on macOS/Windows; manual workarounds used in B2.

**Fix**: introduce a credential-unwrap abstraction with three backends:
- Linux: `systemd-creds decrypt` (existing).
- macOS: `security find-generic-password -a <account> -s <service> -w` (keychain lookup).
- Windows: DPAPI via `windows-rs` `ProtectedData.Unprotect` (requires runtime feature; if not feasible inline, expose a `rustynetd-windows-trust-cli unwrap-dpapi` helper and shell it).

The ops verb then resolves paths via the platform-aware `rustynetd::windows_paths` (Windows), `crates/rustynetd/src/macos_*` constants (macOS), or `rustynetd::linux_paths` (Linux).

**Files**:
- New: `crates/rustynet-control/src/credential_unwrap.rs` with `CredentialUnwrapBackend` trait + 3 backends.
- `crates/rustynet-cli/src/ops_e2e.rs::execute_ops_e2e_membership_set_capabilities` (rewrite to use the trait).
- `crates/rustynetd/src/key_material.rs` (if any existing keychain wiring is reusable, prefer extending it).

**Acceptance criteria**:
- The ops verb runs successfully on all three OSes against the canonical install layout.
- Unit tests pin each backend's argv construction (with deny tests for injection-prone characters in account/service names).
- Negative test: each backend fails closed with a precise error when the credential is missing or wrong format.
- No plaintext passphrase touches disk in any backend except as a temporary `O_TMPFILE` (Linux) or `tempfile_in_secure_root` (macOS / Windows) that's `unlink`'d immediately after fd dup.
- Live validation: run the verb on debian@192.168.65.3 (already works), mac@192.168.64.18 (new), windows@192.168.65.8 (new). All three must mutate the snapshot atomically.

**Reviewer instructions**: confirm no plaintext leaks (check for `mkstemp`, `NamedTempFile`, etc. — must use secure-temp pattern). Confirm DPAPI scope is `LocalMachine` not `CurrentUser` (so service-account DPAPI works). Confirm keychain lookup uses the rustynetd service account (`rustynetd`) on macOS, not whatever user `security` defaults to.

### Round 3 (parallel: Phases 23, 24 — disjoint orchestrator + macOS smoke)

#### Phase 23 — Orchestrator `bootstrap_host_worker` per-OS dispatch

**Problem**: `scripts/e2e/live_linux_lab_orchestrator.sh::bootstrap_host_worker` hardcodes `bash /tmp/rn_bootstrap.sh` and asserts Linux paths (`/usr/local/bin/rustynetd`, `getent group rustynetd`). Result: macOS or Windows targets in the inventory cause this stage to fail.

**Fix**: dispatch per `node_platform_for_label "$label"`:
- linux: existing bash + `rn_bootstrap.sh` path (no change).
- macos: scp source archive, run `rustynet ops e2e-bootstrap-macos --node-id <id> --network-id <id> --passphrase-file <path>` (Phase 21 must have provisioned the passphrase), then run the macOS install adapter.
- windows: scp source archive, run `Install-RustyNetWindowsService.ps1` + `rustynet ops e2e-bootstrap-windows --node-id <id> --network-id <id>`.

**Files**:
- `scripts/e2e/live_linux_lab_orchestrator.sh::bootstrap_host_worker` (per-OS switch)
- New: `scripts/e2e/rn_bootstrap_macos.sh` (small wrapper that runs `ops e2e-bootstrap-macos`)
- New: `scripts/e2e/rn_bootstrap_windows.ps1` (PowerShell wrapper)

**Acceptance criteria**:
- Existing Linux-only A2 bootstrap still passes (regression).
- Mixed-OS profile (1 Linux exit + 1 macOS + 1 Windows) completes `stage_bootstrap_hosts` with all 3 hosts reaching `state = ExitActive` or `state = Joined`.
- Each per-OS bootstrap is idempotent — re-running on an already-bootstrapped host is a no-op.
- Bash script unit-tests via `bats` or shellcheck where applicable.
- Live validation: invoke the orchestrator with a 3-OS mixed profile through `stage_bootstrap_hosts` only. Stop. Verify each daemon is up.

**Reviewer instructions**: confirm Windows PowerShell wrapper uses `Set-StrictMode -Version Latest` + `$ErrorActionPreference = 'Stop'` + no `-eq $null` (use `$null -eq` per MS best practice). Confirm no plaintext secret in bash heredoc or PowerShell `Write-Host`.

#### Phase 24 — macOS bring-up smoke + chase residual gaps to green

**Problem**: B2 surfaced 12 issues in one macOS bring-up attempt. Phases 19/20/21/22/23 address the load-bearing ones; this phase is the integration test that exposes the rest.

**Fix**: execute a full fresh-install macOS bring-up via the Phase 23 orchestrator path against `mac@192.168.64.18` (clean state first). Every error → file as a sub-phase + ship the fix in this phase's commit (or split into Phase 24a, 24b, ... if many). The work is iterative until the macOS daemon reaches `state=ExitActive path_live_proven=true membership_active_nodes=6`.

**Files**: wherever the residual errors point.

**Acceptance criteria**:
- macOS daemon on `mac@192.168.64.18` reaches `state=ExitActive`, `path_live_proven=true`, has a recent WireGuard handshake with at least one Debian peer (verified via `rustynet status | grep path_latest_live_handshake_unix`).
- `live_linux_mixed_topology_test` invoked with macOS in the topology reports `pass`, `host_count=3+`, `views[*].datapath.path_live_proven=true`.
- All gates green (full workspace).
- Each fix landed in this phase has a unit test where applicable.
- All issues encountered are catalogued in a phase log under `artifacts/live_lab/phase24-macos-smoke/<timestamp>.md` with: error message, file:line, fix description, commit SHA.

**Reviewer instructions**: cross-check the phase log against the actual commit's diff — every claimed fix must correspond to a real code change. Flag any "fixed by workaround" notes where the workaround isn't a real fix.

### Round 4 (parallel: Phases 25, 26, 27 — disjoint Windows install/install-adapter/DPAPI work)

#### Phase 25 — Orchestrator Windows bootstrap path

Already covered by Phase 23's Windows arm in the wrapper, but Phase 25 is the focused validation + iteration phase for the Windows-specific bootstrap_host_worker dispatch.

**Acceptance criteria**: 
- `stage_bootstrap_hosts` completes against a Windows-only profile (single windows-utm-1 target).
- The Windows daemon reaches `Get-Service RustyNet -Status Running` with the canonical install layout under `C:\ProgramData\RustyNet\` populated.

#### Phase 26 — Windows daemon named-pipe + parent allowlist

**Status (2026-05-25)**: code-complete on `codex/windows-named-pipe-acl`; live Windows proof still pending.

**Problem**: Windows daemon socket is a named pipe `\\.\pipe\rustynet`, not a Unix socket. Track B Phase 18 added the macOS allowlist; Windows needs analogous allowlist + named-pipe security descriptor validation.

**Fix**: add Windows-specific socket validator that checks the named-pipe ACL via `windows-rs` (or `winapi`) — must require `BUILTIN\Administrators` full control, `rustynetd` service account read/write, deny everyone else.

**Files**:
- `crates/rustynet-cli/src/main.rs::validate_control_socket_security` (Windows branch)
- `crates/rustynetd/src/daemon.rs::validate_parent_directory_security` (Windows branch — already has stub via `validate_windows_runtime_acl`; verify it covers the pipe parent)
- `crates/rustynetd/src/windows_paths.rs` (add canonical pipe path constant if missing)

**Acceptance criteria**:
- Windows CLI can introspect the daemon (`rustynet status` returns the canonical line).
- Unit tests pin the named-pipe ACL contract.

**Implemented**:
- Native named-pipe ACL inspection and authorized server path in `crates/rustynet-windows-native/src/lib.rs`.
- Shared Windows IPC policy and ACL report producer in `crates/rustynetd/src/windows_ipc.rs`.
- `rustynetd windows-named-pipe-acls-check` fail-closed validator in `crates/rustynetd/src/main.rs`.
- Windows CLI daemon control path now validates the named-pipe path and uses the local named-pipe transport in `crates/rustynet-cli/src/main.rs`.
- Live-lab stage `validate_windows_named_pipe_acls` added in `crates/rustynet-cli/src/vm_lab/mod.rs`.
- Bootstrap verifier now records named-pipe ACL validation status in `scripts/bootstrap/windows/Verify-RustyNetWindowsBootstrap.ps1`.

**Local proof**:
- `cargo fmt --all -- --check`
- `CARGO_TARGET_DIR=/private/tmp/rustynet-phase26-target cargo test -p rustynetd windows_ipc --all-features`
- `CARGO_TARGET_DIR=/private/tmp/rustynet-phase26-target cargo test -p rustynetd windows_named_pipe --all-features`
- `CARGO_TARGET_DIR=/private/tmp/rustynet-phase26-target cargo test -p rustynet-cli windows_named_pipe --all-features`
- `CARGO_TARGET_DIR=/private/tmp/rustynet-phase26-target cargo clippy -p rustynetd -p rustynet-cli -p rustynet-windows-native --all-targets --all-features -- -D warnings`

#### Phase 27 — Windows `ops e2e-membership-set-capabilities` (DPAPI completion)

Lands the Windows backend from Phase 22 if not already completed there.

### Round 5 (serial: Phase 28 — biggest, most invasive)

#### Phase 28 — Cross-platform shell-host abstraction for live-lab (Track 3, big)

**Problem**: `crates/rustynet-cli/src/bin/live_lab_bin_support/mod.rs::capture_root` wraps every command in `sudo -n sh -lc <body>`. Linux/macOS works (POSIX shell). Windows doesn't (PowerShell, no sudo). Result: 4 of 6 anchor substages skip on Windows; relay + exit-handoff macOS/Windows validators reach into the existing `capture_remote_stdout` (no shell wrap) as a workaround.

**Fix**: introduce a `RemoteShellHost` trait with primitives:
- `read_file(remote_path) -> Vec<u8>`
- `write_file(remote_path, bytes, mode) -> Result<()>` (mode is unix-style; Windows backend translates to ACL)
- `stat(remote_path) -> RemoteStat { size, mode, owner_uid_or_sid, gid_or_group_sid }`
- `run_argv(argv: &[&str], env: &[(&str, &str)], stdin: &[u8]) -> RemoteExitStatus`
- `tcp_send_recv(addr: &str, payload: &[u8], timeout: Duration) -> Vec<u8>` (drop-in for `nc` calls)

Three impls: `LinuxShellHost` (POSIX sh + sudo), `MacosShellHost` (POSIX sh + sudo), `WindowsShellHost` (PowerShell + no sudo). Dispatched per `host.platform`.

**Files**:
- New: `crates/rustynet-cli/src/bin/live_lab_bin_support/remote_shell.rs` (~600 lines).
- `crates/rustynet-cli/src/bin/live_lab_bin_support/mod.rs` (re-export the trait; keep `capture_root` as a thin shim during transition).
- New: `crates/rustynet-cli/src/bin/live_lab_bin_support/remote_shell_tests.rs` (~400 lines of tests).

**Acceptance criteria**:
- Trait covers every operation currently performed via `capture_root` / `capture_remote_stdout` in the 6 live-lab bins (anchor / relay / exit-handoff / mixed-topology / two-hop / role-switch).
- Each primitive has unit tests with mock backend.
- Linux backend uses the existing capture_root path (regression: no behavior change for Linux substages).
- Windows backend uses PowerShell-native primitives (read-file via `Get-Content -Encoding Byte` then base64, write-file via `[IO.File]::WriteAllBytes`, stat via `Get-Acl`, tcp_send_recv via `[System.Net.Sockets.TcpClient]`).
- The trait is the SINGLE seam for new live-lab substages — no new direct `capture_root` calls.

**Reviewer instructions**: confirm each primitive's Windows impl handles binary payloads correctly (PowerShell mangles binary stdout by default — must use `[Console]::OpenStandardOutput().Write` or base64). Confirm no shell construction with untrusted values in any backend.

### Round 6 (serial after Phase 28: Phase 29 — depends on the trait)

#### Phase 29 — Rewrite POSIX-only live-lab substages on RemoteShellHost

**Problem**: `validate_bundle_pull_loopback`, `start_inflight_bundle_pull`, `validate_invalid_token_rejected`, `validate_anchor_enrollment_endpoint`, `validate_anchor_downgrade_revocation`, `capture_role_audit_log_size`, `validate_bundle_pull_log_redaction` all use POSIX-shell-composed scripts via `capture_root`.

**Fix**: rewrite each on top of the Phase 28 `RemoteShellHost` trait so they work on Linux + macOS + Windows uniformly.

**Files**:
- `crates/rustynet-cli/src/bin/live_linux_anchor_test.rs` (rewrite the 7 helpers listed)
- `crates/rustynet-cli/src/bin/live_linux_relay_test.rs` (re-platform via trait)
- `crates/rustynet-cli/src/bin/live_linux_exit_handoff_test.rs` (re-platform via trait)
- `crates/rustynet-cli/src/bin/live_linux_mixed_topology_test.rs` (re-platform via trait)

**Acceptance criteria**:
- Every live-lab substage's per-platform dispatch arm in `run()` runs for real on Linux + macOS + Windows (no more `non-Linux skip` arms).
- Unit tests cover each rewritten helper with the mock backend.
- Live validation: full anchor live-lab stage executes 6/6 substages green on macOS AND Windows AND Linux.

#### Phase 30 — Windows bring-up smoke + chase residual gaps

Mirror of Phase 24, focused on Windows. Iterate until Windows daemon reaches `Status: Running`, `path_live_proven=true`, mixed-topology validator green with Windows in the topology.

### Round 7 (serial: Phase 31 — final integration)

#### Phase 31 — Full mixed-OS green live lab

**Acceptance criteria**:
- A new 5-node mixed-OS profile (Linux exit-1 + Linux client + Linux relay + macOS aux + Windows extra) bootstraps green via `stage_run_fresh_bootstrap_and_network_setup` in one shot.
- `--skip-setup` follow-on run executes the full live-lab stage list with EVERY stage green:
  - live_anchor (6/6 substages on Linux exit-1)
  - live_exit_handoff (Linux exit-1)
  - live_relay (Linux entry, since aux is macOS — or run again with macOS as relay)
  - live_two_hop, live_lan_toggle, live_managed_dns, live_role_switch_matrix
  - live_mixed_topology (all 3 OSes mutually visible + datapath fresh)
- Run report committed to `artifacts/live_lab/<timestamp>/run_summary.md` showing every stage PASS.
- Workspace gates green throughout.

## 8. Definition of done (when can you stop?)

All of these must hold true:

1. **Phase 31's full mixed-OS run passes end-to-end** on the live lab inventory.
2. **All workspace gates green** at HEAD: fmt, clippy `-D warnings`, audit, deny, membership_gates.sh, phase10_hp2_gates.sh, plus any `scripts/ci/phase*_gates.sh` you touched.
3. **No TODO/FIXME/placeholder** in any file under `crates/` or `scripts/` introduced by your phases (grep to verify).
4. **No `non-Linux skip`** rationale strings remaining in the live-lab bins — every substage runs for real on every OS or the substage itself is platform-conditional with explicit semantic justification (e.g., a Linux-systemd-specific stage that genuinely has no macOS equivalent).
5. **Every commit has a reviewer agent's findings folded in** (BLOCKERS + HIGH in the next commit, MEDIUM in the next same-track commit, LOW opportunistically).
6. **Documentation refreshed**: `documents/operations/active/AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md` and `documents/operations/active/README.md` updated to reflect the cross-OS parity completion. `MasterWorkPlan_2026-03-22.md` likewise.

## 9. How to use sub-agents

For each phase commit:

```
Agent(
  description: "Review Phase NN commit <sha>",
  subagent_type: "general-purpose",
  prompt: "Independent review of commit <sha> on main at /Users/iwan/Desktop/Rustynet. \n\nSubject: <commit subject>.\n\nChanges: <bulleted list>.\n\nWhat to check: <list per phase's reviewer instructions>.\n\nReport in under 500 words: blockers / high / medium / low / checks that hold up. file_path:line_number references. Don't propose fixes — identify issues.",
  run_in_background: true,
)
```

When the reviewer returns, summarize its findings to the user, fold BLOCKERS and HIGH into the next commit IMMEDIATELY. Do not start an unrelated phase until BLOCKERS land on main.

For parallel groups, send multiple Agent calls in ONE message:

```
[in same message]
Agent(description: "Phase 19 implementation", ...)
Agent(description: "Phase 20 implementation", ...)
Agent(description: "Phase 21 implementation", ...)
```

When the agents return, fold their commits sequentially (rebase + push), spawn reviewers for each, then move to the next round.

## 10. Estimated effort

Rough wall-clock with the LLM-assisted phase + reviewer pattern:
- Round 1 (Phases 19-21, parallel): ~2-3 days (Phase 19 is the long pole)
- Round 2 (Phase 22): ~2-3 days
- Round 3 (Phases 23-24, parallel): ~2-4 days (Phase 24 iterative)
- Round 4 (Phases 25-27, parallel): ~2-3 days
- Round 5 (Phase 28, big): ~4-7 days
- Round 6 (Phases 29-30, parallel): ~3-5 days
- Round 7 (Phase 31): ~1-2 days

Total: ~16-27 days focused single-engineer time. Could compress to ~10-15 days if Round 3 / Round 6 parallel work runs cleanly without surfacing new cross-platform gaps. Likely to expand if any phase surfaces a new layer of cross-platform gaps (Phase 24 and Phase 30 are the iteration phases where this happens).

## 11. Reporting cadence

After each phase commits + reviewer returns + findings fold, send a single-line user-facing update:

```
Phase NN (subject) — landed <sha>, reviewer (blockers: <N>, high: <N>, medium: <N>) — folded into Phase MM
```

After each Round completes, send a 3-5 line summary of what landed + what remains.

When Phase 31 passes the full mixed-OS green run, send the final report with the artifact directory path + a one-line per-OS readiness statement.

## 12. Authorization scope

The user has explicitly authorized:
- Touching production source (any file under `crates/`, `scripts/`, `documents/`).
- Pushing directly to `main` (no PR workflow per user instruction).
- Wiping + reprovisioning lab VM state (it's a throwaway lab — A2 just did exactly this).
- Long-running operations (cargo builds, orchestrator runs, daemon redeploys).
- Spawning sub-agents in parallel.

The user has NOT authorized:
- Modifying anything outside `/Users/iwan/Desktop/Rustynet`.
- Pushing to forks or branches other than `main`.
- Skipping mandatory gates.
- Force-pushes to main (rebase + push is fine; force-push is not).
- Removing existing test coverage in the name of "cleanup".

## 13. Begin

Start by reading the mandatory documents (§6), then probe the lab inventory (§5) to confirm reachability. Once preflight is green, send a Round 1 message with three parallel `Agent` tool calls for Phases 19, 20, 21. Each spawned agent should be given a self-contained prompt drawn from this document's §7 entry for its phase.

When you've internalized this prompt and the mandatory docs, send the user a one-line "Round 1 starting, parallel Phases 19/20/21 spawned" and pull the trigger.
