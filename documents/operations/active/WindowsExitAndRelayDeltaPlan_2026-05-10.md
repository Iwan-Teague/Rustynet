# Windows Exit-Node and Relay-Node Delta Plan

Date: 2026-05-10
Owner: Rustynet engineering
Branch / commit baseline: `main` @ `0c3d78e`
Status: active execution ledger
Audience: implementation agents (including lower-capability LLMs) picking up
this work without prior session context

This document is a **mechanical playbook**. Every task names the file, the
function, the test pattern to copy, and the definition of done. If you find
yourself making creative architectural decisions, stop and re-read this
document — almost everything has already been decided.

---

## 0) How to use this document

1. Read **§1 (Mission and ground rules)** before writing any code.
2. Read **§2 (Repository state right now)** to confirm you are on
   commit `0c3d78e` or later. If you are on an older commit, fast-forward
   `main` first: `git fetch origin && git reset --hard origin/main`.
3. Pick the lowest-numbered open subtask in **§5 / §6 / §7 / §8 / §9** that
   does not have an explicit blocker. Do not skip.
4. After every task, update **§11 (Progress ledger)** with the commit
   SHA and a one-line outcome. Do not silently mark something done.
5. Section **§10 (Patterns to reuse)** holds copy-paste templates. Use them
   verbatim where the task says "follow §10.X".

When this document and another document disagree, follow the precedence in
`CLAUDE.md` §2:
1. `documents/Requirements.md`
2. `documents/SecurityMinimumBar.md`
3. The active scope document (this file, for Windows exit/relay only)
4. Supporting design docs
5. `README.md` and operational runbooks

---

## 1) Mission and ground rules

The mission is to take Windows exit-node and Windows relay-node from
"runtime-host-capable only" to "release-gated, mixed-node-evidenced, and
posture-promoted" without weakening any existing security control.

### 1.1 Non-negotiable engineering constraints (verbatim from `CLAUDE.md`)

These override every choice in this plan. If a task here appears to ask you
to weaken any of them, stop and ask.

- Rust-first codebase. Non-Rust only for unavoidable OS integration boundaries.
- No custom cryptography and no custom VPN protocol invention.
- WireGuard remains an adapter behind stable backend abstractions.
- Default-deny across ACL, routes, and trust-sensitive flows.
- Fail closed when trust/security state is missing, invalid, stale, or
  unavailable.
- One hardened execution path per security-sensitive workflow. No runtime
  fallback, downgrade, or legacy branch.
- Argv-only privileged exec. No `cmd.exe /c …` and no PowerShell string
  interpolation with untrusted input on Windows.
- OS-secure key storage when available; encrypted-at-rest fallback with strict
  permission checks otherwise. Never log secrets.
- Each implemented security control must include a code enforcement point
  AND a verification method (unit test, integration test, negative test, or
  gate check).
- No TODO/FIXME/placeholders in completed deliverables.

### 1.2 Definition of "Windows works" (from `WindowsWorkingNodePlan_2026-04-17.md`)

All twelve must be true before any posture-promotion claim:

1. Windows service host starts a reviewed runtime path.
2. Backend label is no longer `windows-unsupported`.
3. A reviewed Windows backend exists behind the stable backend abstraction.
4. Windows node can join a Rustynet network.
5. Windows node can connect to Linux and/or macOS peers.
6. Route behavior is correct and fail-closed.
7. DNS behavior is correct and fail-closed.
8. Restart preserves expected safe state.
9. Reinstall from a clean Windows snapshot works.
10. Diagnostics and verification scripts collect authoritative evidence.
11. Fresh-install evidence exists for the current commit.
12. Docs and release gates move only after measured proof exists.

---

## 2) Repository state right now (2026-05-10, commit `0c3d78e`)

Run these to confirm before you start. If any answer is different, stop and
re-investigate; do not proceed against a drifted tree.

```
git rev-parse HEAD                    # → 0c3d78eb073ca915334f7a3dd360868a6796cbe5
git rev-parse --abbrev-ref HEAD       # → main
cargo test -p rustynetd --all-features 2>&1 | grep '^test result'
# → 683 lib + 60 bin + 3 integration, all passing
cargo test -p rustynet-relay --all-features 2>&1 | grep '^test result'
# → 76 lib + 54 bin
cargo test -p rustynet-control --all-features 2>&1 | grep '^test result'
# → 141 lib
cargo test -p rustynet-backend-wireguard --all-features 2>&1 | grep '^test result'
# → 77 lib + 8 bin
```

### 2.1 What is finished (do not touch unless you are extending it)

#### Exit node — code is ~95% done

- **NAT and forwarding** for Windows-as-exit live in
  `crates/rustynetd/src/phase10.rs::WindowsCommandSystem::apply_windows_exit_nat_forwarding`
  (around line 2770). It uses `New-NetNat`, `Set-NetIPInterface`, and
  `Get-NetNat`. IPv4-only mesh; IPv6 fail-closed by `validate_windows_nat_prefix`.
- **PowerShell scripts** are at the bottom of the same file (constants
  `WINDOWS_PS_REQUIRE_EXIT_CMDLETS`, `WINDOWS_PS_NEW_NAT`, `WINDOWS_PS_REMOVE_NAT`,
  `WINDOWS_PS_ASSERT_NAT`, `WINDOWS_PS_GET_FORWARDING`, `WINDOWS_PS_SET_FORWARDING`,
  `WINDOWS_PS_ASSERT_FORWARDING_ENABLED`, `WINDOWS_PS_ASSERT_KILLSWITCH`,
  `WINDOWS_PS_DETECT_DEFAULT_EGRESS_INTERFACE` in `daemon.rs`).
- **DNS leak protection** uses netsh advfirewall block rules on UDP/TCP port 53
  on `interfacetype=lan` (commit `2439f42`).
- **Killswitch verification queries OS state** (commit `80164f8`). The
  PowerShell script checks `Action`, `Direction`, `Enabled` per rule plus
  every profile's `DefaultOutboundAction`.
- **Egress interface detection** filters out the WireGuard tunnel adapter
  (commit `2439f42`).
- **Stage tracking + rollback** is in `Phase10Controller::apply_dataplane_generation`
  (around line 3456 of `phase10.rs`).
- **Generation invariants** pinned by tests
  `successive_apply_dataplane_generation_increments_monotonically`,
  `failed_apply_after_successful_does_not_regress_last_safe_generation`,
  `repeated_failed_applies_do_not_advance_last_safe_generation`.

#### Relay node — code is ~95% done

- **SCM service host** lives in `crates/rustynet-relay/src/main.rs::run_windows_relay_service_host`.
- **Env-file JSON config** parser is `parse_windows_relay_env_file` and
  loader `load_windows_relay_service_args` in the same file. 9 edge-case
  tests pin the contract.
- **Hardening checker** is `evaluate_windows_relay_service_hardening` and
  `build_windows_relay_service_hardening_report` in the same file.
- **Replay-store hardening** is in `crates/rustynet-relay/src/transport.rs`
  (commit `38ac236`): `MAX_CLOCK_SKEW_TOLERANCE_SECS` clamp, NonceStore
  in-place insert with persist-failure rollback, structured warnings.
- **Installer/uninstaller** PowerShell scripts at
  `scripts/bootstrap/windows/Install-RustyNetWindowsRelayService.ps1` and
  `Uninstall-RustyNetWindowsRelayService.ps1`. Static tests in
  `crates/rustynet-cli/src/vm_lab/mod.rs::windows_relay_service_helpers_exist_and_keep_reviewed_roots`.

#### Cross-cutting — code is ~95% done

- **Signed bundle verifiers** all enforce `version=1` (or `=2` for relay-fleet
  and peer-map by their own format) and outer-vs-payload cross-check (commits
  `0fa8faf`, `9283b72`, `3f5432f`).
- **Privileged helper** rejects path traversal in path and pfctl-anchor tokens
  (commit `ceeda2a`).
- **Windows backend tunnel-name validator** rejects `=`, control chars,
  whitespace, non-ASCII (commit `0c3d78e`).
- **DPAPI plaintext** wrapped in `Zeroizing` on the roundtrip self-test
  (commit `80164f8`).
- **STUN parser** has the full RFC 5389 adversarial-input regression suite
  (commit `afa6476`).

### 2.2 What is NOT finished

- **Live Windows lab access is broken** (`WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md`).
  This is the hard blocker — see §3.
- **No live SCM-context proof** of Windows-as-exit (`OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md`
  Phase W5 §2505): NetNat enable/disable, forwarding restore, leak proof, DNS
  fail-closed under load.
- **No live relay traffic proof** (`PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md`
  Phase C §939–944): wire daemon relay client to real relay infrastructure,
  prove relay-active with traffic.
- **No mixed-node, restart, or reinstall proof** for Windows.
- **No cross-network proof** (real ISP NAT, real public internet through
  Windows exit).
- **Posture promotion** — Windows is still tagged `runtime-host-capable only`
  in `documents/operations/PlatformSupportMatrix.md`.

### 2.3 Files you will touch

Memorise these — most of the work happens here.

| Subsystem | File |
|---|---|
| Daemon Windows dataplane (NAT, killswitch, DNS, IPv6 SLAAC) | `crates/rustynetd/src/phase10.rs` |
| Daemon Windows runtime hardening (paths, ACLs, key custody) | `crates/rustynetd/src/windows_*.rs` (15 files) |
| Daemon STUN client | `crates/rustynetd/src/stun_client.rs` |
| Daemon traversal / relay client | `crates/rustynetd/src/traversal.rs`, `crates/rustynetd/src/relay_client.rs` |
| Daemon entry / config | `crates/rustynetd/src/daemon.rs` |
| Privileged helper | `crates/rustynetd/src/privileged_helper.rs` |
| Windows backend (production WireGuard adapter) | `crates/rustynet-backend-wireguard/src/windows_command.rs` |
| Relay binary (SCM host, env-file, hardening) | `crates/rustynet-relay/src/main.rs`, `crates/rustynet-relay/src/transport.rs` |
| Control plane (signed bundles) | `crates/rustynet-control/src/lib.rs` |
| VM-lab orchestrator (Windows dispatch) | `crates/rustynet-cli/src/vm_lab/mod.rs`, `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows*.rs`, `crates/rustynet-cli/src/vm_lab/bootstrap/windows.rs` |
| Bootstrap PowerShell scripts | `scripts/bootstrap/windows/*.ps1` |
| Live-lab orchestrator wrapper | `scripts/e2e/live_linux_lab_orchestrator.sh` (Linux-only gate at `crates/rustynet-cli/src/vm_lab/mod.rs:4681` and `:4762`) |

---

## 3) The hard blocker: live Windows lab access

You cannot run any of §5 or §6's live-proof items until lab access is
unstuck. Owning ledger:
[`WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md`](./WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md).

### 3.1 What works today

- Local source sync to the Windows guest works.
- Guest-side PowerShell execution works.
- Real Rust code compiled successfully inside the Windows guest.

### 3.2 What is broken

- Headless `utmctl` cannot drive the guest reliably (the macOS host running
  UTM cannot script guest power/network from a non-interactive shell).
- The guest's POST-back readiness probe times out before the host orchestrator
  proceeds.
- SSH listener state on the guest after install is intermittent
  (`sshd_service_count=0`, `sshd_registry_present=False` in the
  `artifacts/windows_phase4/20260417T174942Z/phase4_evidence_summary.md` run).

### 3.3 Order of operations

You should NOT start exit/relay live-proof until the access path is one of:
1. Reliably driven by `utmctl` from a headless shell, OR
2. Driven via a different transport (SSH-over-VPN, QEMU monitor, OpenSSH-on-VM-with-known-host-key) such that the orchestrator can get a deterministic
   exit-code from the guest.

The Windows VM-lab access plan (`WindowsVmLabAccessOrchestrationRecoveryPlan_2026-04-16.md`)
owns the recovery work. Do NOT modify that plan from this document. Do
modify orchestrator code in `crates/rustynet-cli/src/vm_lab/` if and only if
the access plan asks you to.

If you are asked to work on §5 or §6 before §3 is unstuck, push back and
explain that no live-proof artifact can be generated until then. The unit
tests in §5/§6 can still be added without lab access — they exercise the
parser/structural layer, not the OS layer.

---

## 4) Operating rules for this work

### 4.1 Working tree rules

- Always run from `/Users/iwan/Desktop/Rustynet` on `main`. Do NOT operate
  from a `.claude/worktrees/...` path — past sessions have lost work to
  this exact mistake. If your shell is rooted in a worktree, prefix every
  command with `cd /Users/iwan/Desktop/Rustynet &&`.
- Before any edit: `git fetch origin && git status --short`. If status
  shows unrelated modifications, stash or stop — do not commit other
  people's work.
- After any edit, before any commit: `git diff --check` (whitespace),
  `cargo fmt --all -- --check`, `cargo clippy -p <crates> --all-targets --all-features -- -D warnings`,
  `cargo test -p <crate>`.

### 4.2 Commit rules

- Every commit author is `Iwan-Teague <teague.iwan@outlook.com>`. The git
  config is set; do not override.
- Always `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>` (or
  whichever model you are).
- Never use `--no-verify`.
- Never `git add -A`. List file paths explicitly so you don't accidentally
  commit untracked artifacts (e.g. `rustynet_blind_exit_pcb_report_*.docx`).
- One slice = one commit. Slice descriptions live in §5–§9 below.
- Do NOT push without an explicit request from the operator. The user will
  say "push" when ready.

### 4.3 Spawning sub-agents

When you spawn a sub-agent for parallel work:
- Use `isolation: "worktree"`, but instruct the sub-agent in the FIRST
  step to fast-forward to current main:
  ```
  git fetch /Users/iwan/Desktop/Rustynet main
  git reset --hard FETCH_HEAD
  git log -1 --format='%H'   # must show current main HEAD
  ```
  The worktree mechanism gives stale HEADs (observed twice in commits
  prior to `0c3d78e`).
- Tell the sub-agent NOT to commit. You merge their diff with
  `git apply --3way` after they finish — this works even when their
  worktree HEAD is older than main.
- Tell the sub-agent NOT to update any ledger. You consolidate.
- Each sub-agent gets a SINGLE in-scope file. Cross-file scopes invite
  conflicts.

### 4.4 If a sub-agent runs out of budget

This happened in commits `3f5432f`, `ceeda2a`, `0c3d78e`. Recovery:
1. The sub-agent's worktree still has their partial work on disk (uncommitted).
2. Extract their diff: `git diff HEAD -- <file>` from inside their worktree.
3. Apply with `git apply --3way` to current main.
4. Run `cargo test` to find what they didn't finish.
5. Finish the gaps yourself. Acknowledge the sub-agent's contribution in
   the commit body.

### 4.5 The validate-edits-persist rule

When using the `Edit` tool, re-read the file or grep for your change after
every Edit. The harness has rolled back agent edits before. If a change
disappears, redo it. Don't trust that Edit succeeded just because it
returned success.

---

## 5) Track A: Windows exit-node — what's left

### A.1 Live SCM-context proof of NetNat lifecycle

**Blocked on §3.** Do not start until lab access works.

**Goal:** prove that the daemon's exit-serving NAT path actually works on
a real Windows host under the SCM-launched service context (the exec
context where the daemon really runs in production), not just from an
operator-launched PowerShell.

**Steps:**
1. Bring up `windows-utm-1` per `WindowsLabVmStabilityAndSessionModel_2026-04-30.md`.
2. Install the daemon as a service via
   `scripts/bootstrap/windows/Install-RustyNetWindowsService.ps1`.
3. Configure the daemon as an exit node (`exit_serving=true`,
   `mesh_cidr=100.64.0.0/10`, etc.). The reviewed config keys live in
   `crates/rustynetd/src/daemon.rs::DaemonConfig` (search for
   `pub struct DaemonConfig`).
4. Bring the daemon up; trigger an apply that sets the exit-serving role.
5. From the lab orchestrator, capture:
   - `Get-NetNat -Name RustyNetExit-rustynet0` — must return one entry with
     `InternalIPInterfaceAddressPrefix = 100.64.0.0/10`.
   - `Get-NetIPInterface -InterfaceAlias rustynet0 -AddressFamily IPv4 |
     Select-Object -ExpandProperty Forwarding` — must equal `Enabled`.
   - `Get-NetIPInterface -InterfaceAlias <egress alias> -AddressFamily IPv4 |
     Select-Object -ExpandProperty Forwarding` — must equal `Enabled`.
6. Stop the daemon. Confirm:
   - `Get-NetNat -Name RustyNetExit-rustynet0` returns nothing.
   - Forwarding restored to its pre-apply state on both interfaces.
7. Save the captured PowerShell objects (as JSON) under
   `artifacts/windows_exit/<commit>/scm_context_nat_lifecycle.json`.

**Definition of done:**
- Artifact exists at the path above for the current `HEAD`.
- A README in the artifact directory points at the commit and the daemon
  config used.
- The orchestrator stage `validate_windows_exit_nat_lifecycle` (new — see
  §A.5) reads and validates the artifact.

### A.2 Live DNS leak proof

**Blocked on §3 and §A.1.**

**Goal:** prove that with the daemon running as a Windows-as-exit, no
client DNS query can leak to the upstream LAN/router DNS — the new
RustyNetDNS-BlockLanUdp / RustyNetDNS-BlockLanTcp rules from commit
`2439f42` must dominate the killswitch's LAN-allow rule.

**Steps:**
1. With the daemon up and exit-serving (continue from §A.1's setup), pick
   a peer mesh client (Linux) and configure its DNS resolver to deliberately
   point at a NON-tunnel address (e.g. `1.1.1.1`).
2. From that client, run `dig +tries=1 +time=2 example.com @1.1.1.1` and
   tcpdump on the Windows exit's egress LAN interface for UDP/TCP port 53.
3. The query MUST NOT appear on the egress LAN interface — the dns-block
   rule should drop it. Capture the tcpdump (empty pcap) plus the
   `Get-NetFirewallRule -Name RustyNetDNS-BlockLanUdp |
   Select-Object DisplayName, Action, Direction, Enabled, Profile` output.
4. Repeat for TCP/53 (`dig +tcp ...`).
5. As a positive control, send the query through the WireGuard tunnel
   (point the client resolver at the daemon's mesh-side resolver address)
   and confirm it resolves.
6. Save artifacts under `artifacts/windows_exit/<commit>/dns_leak_proof/`:
   - `firewall_block_rules.json`
   - `udp_block_pcap.txt` (tshark text rendering)
   - `tcp_block_pcap.txt`
   - `tunnel_path_resolves.json` (positive control)

**Definition of done:**
- All four artifacts exist for the current `HEAD`.
- The new orchestrator stage `validate_windows_exit_dns_failclosed` (new —
  see §A.5) reads them and asserts the empty-pcap + positive-control
  invariants.
- The existing `windows_dns_failclosed_check` subcommand (in
  `crates/rustynetd/src/main.rs`) is invoked as part of this stage and its
  output is also archived.

### A.3 Live killswitch precedence proof

**Blocked on §3 and §A.1.**

**Goal:** prove the new `assert_killswitch` from commit `80164f8` actually
catches an external `netsh advfirewall reset` between apply and assertion.

**Steps:**
1. With the daemon up and exit-serving, run a baseline assertion:
   `rustynetd windows-killswitch-assert` (you may need to add this
   subcommand if it doesn't exist — see §A.4).
2. From an Administrator PowerShell on the same Windows host, run
   `netsh advfirewall reset` (or
   `netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound`).
3. Re-run `rustynetd windows-killswitch-assert`. It MUST return non-zero
   with a clear "killswitch verification failed" message.
4. Capture both invocations + the netsh reset confirmation under
   `artifacts/windows_exit/<commit>/killswitch_precedence/`.

**Definition of done:**
- Artifact exists.
- The non-zero exit code is reflected in the orchestrator stage's pass/fail.
- An automated regression test exists at the orchestrator level that runs
  this sequence and fails the lab if drift is silently accepted.

### A.4 Add `windows-killswitch-assert` subcommand if missing

**Files:** `crates/rustynetd/src/main.rs`, `crates/rustynetd/src/phase10.rs`.

**Procedure:**
1. Search for `windows-killswitch-assert` in `crates/rustynetd/src/main.rs`.
   If present, skip this section.
2. If absent, add a CLI subcommand following the pattern of
   `windows-dns-failclosed-check` (also in `main.rs`). The subcommand
   should:
   - Construct a `WindowsCommandSystem` (see `phase10.rs::WindowsCommandSystem::new`)
     from the daemon's runtime config (interface name, egress alias, dns
     resolver bind addr).
   - Call `WindowsCommandSystem::assert_killswitch` directly.
   - On `Ok(())`, print a JSON report `{"overall_ok":true}` and exit 0.
   - On `Err(SystemError::KillSwitchAssertionFailed(reason))`, print
     `{"overall_ok":false, "reason":"..."}` and exit non-zero.
3. Test pattern: copy the `windows_dns_failclosed_*` subcommand tests in
   `daemon.rs` test module. Adapt names and assertions.
4. Definition of done: subcommand passes the `cargo test -p rustynetd` gate
   AND the live-proof step in §A.3 can invoke it without modification.

### A.5 Add three orchestrator stages for the live-proof artifacts

**File:** `crates/rustynet-cli/src/vm_lab/orchestrator/adapter/windows.rs`
(plus its `windows_install.rs` / `windows_traffic.rs` / `windows_membership.rs`
companions for stage helpers).

**Stages to add:**
- `validate_windows_exit_nat_lifecycle` — consumes the §A.1 artifact and
  asserts NetNat present-during-run / absent-after-stop.
- `validate_windows_exit_dns_failclosed` — consumes the §A.2 artifact and
  asserts the four invariants.
- `validate_windows_exit_killswitch_precedence` — consumes the §A.3
  artifact and asserts the non-zero exit on tampered firewall.

**Procedure:**
1. Read the existing stage `validate_windows_service_hardening` in
   `windows.rs` to understand the dispatcher contract (how stages take a
   `vm_lab` profile, an SSH transport, and return a typed result).
2. Add the three new stages following the same pattern. Each stage:
   - Pulls the artifact directory from the guest via the orchestrator's
     existing copy mechanism (search for `pull_windows_artifact`).
   - Validates the JSON / pcap content against the assertions in §A.1–§A.3.
   - Returns `StageOutcome::Pass` or `StageOutcome::Fail(reason)`.
3. Tests: each stage must have a unit test using fixture artifacts under
   `crates/rustynet-cli/tests/fixtures/windows_exit/<stage>/`. Pattern
   reference: `validate_windows_service_hardening` already has fixtures;
   copy the structure.

**Definition of done:**
- All three stages compile, lint clean, and have unit tests.
- The full live-lab dispatch chain at line ~5450 of `vm_lab/mod.rs`
  includes the three new stages for Windows exit roles.
- An end-to-end live run captures the artifacts AND the stage output AND
  passes.

### A.6 Cross-network exit proof (real ISP NAT, public internet)

**Blocked on §3, §A.1, §A.2, §A.3.**

This is `Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md`'s
remaining open work for Windows specifically. Owning ledger:
[`CrossNetworkRemoteExitNodePlan_2026-03-16.md`](./CrossNetworkRemoteExitNodePlan_2026-03-16.md).

**Goal:** prove a Linux mesh peer behind a real ISP NAT can reach the
public internet through a Windows exit node behind a different ISP NAT.

**Procedure:**
1. Two physically separated networks (or at minimum two distinct upstream
   NATs). The lab inventory may need a second guest-Windows VM with a
   distinct egress IP — see `documents/operations/active/UTMVirtualMachineInventory_2026-03-31.md`.
2. Bring up Windows-as-exit on Network B per §A.1.
3. Linux peer on Network A enrolls and joins the mesh.
4. From Linux peer: `curl https://api.ipify.org` (or any IP-echo). The
   returned IP must be Network B's public egress IP, not Network A's.
5. Capture:
   - `cross_network_remote_exit_report_<network_a_id>_to_<network_b_id>.json`
     (mirror the existing `cross_network_direct_remote_exit_report_*.json`
     shape under `artifacts/`).
   - tcpdump on Network B's WAN interface showing the request leaving from
     B's IP.
   - tcpdump on Network A's WAN interface showing only WireGuard UDP, no
     plaintext HTTPS.

**Definition of done:**
- Artifact validates against the `cross_network_remote_exit_schema_validation.md`
  schema.
- The Phase 6 checklist's "cross-network proof" item flips from `[ ]` to
  `[x]` for Windows.

### A.7 IPv6 exit serving (deferred — explicit fail-closed today)

**Status:** intentionally not in scope for this delta. Today's behaviour
(`validate_windows_nat_prefix` rejects IPv6 mesh prefixes) is the
fail-closed default. Documented at `phase10.rs:4531`. Do not implement
without an updated requirements doc.

---

## 6) Track B: Windows relay-node — what's left

### B.1 Wire daemon relay client to real relay infrastructure

**Owning ledger:** `PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md`
Phase C `[ ]` items at lines 757, 759, 761, 763.

**Files:**
- `crates/rustynetd/src/relay_client.rs`
- `crates/rustynetd/src/daemon.rs` (relay-fleet bundle loading at line 8744+)

**Procedure:**
1. Read `crates/rustynetd/src/relay_client.rs::RelayClient::establish_session`
   (line 413). It already validates tokens before I/O — do not change that.
2. Confirm the daemon path that selects a relay candidate:
   `select_runtime_relay_candidate_with_verified_fleet` in `daemon.rs`
   (line 10995). This already enforces signed-fleet membership.
3. The wire-up is: the daemon's reconcile loop must (a) load and verify
   the signed relay-fleet bundle on startup, (b) on direct-path failure
   pick a candidate via `select_runtime_relay_candidate_with_verified_fleet`,
   (c) use `RelayClient::establish_session_with_round_trip` with the
   relay-server transport. Search `daemon.rs` for the existing call sites
   (line 4614 and 4638) to understand the contract.
4. The "real relay infrastructure" in scope here is a `rustynet-relay`
   instance running on a separate VM (Linux or Windows). Bring one up.
   Use the operator-facing
   `scripts/bootstrap/windows/Install-RustyNetWindowsRelayService.ps1` if
   the relay should be on Windows; otherwise install rustynet-relay on
   Linux.
5. Issue a signed relay-fleet bundle (control plane CLI;
   `crates/rustynet-cli/src/bin/rustynet-windows-trust-cli.rs` is the
   pattern to copy from for control-plane-side tooling).
6. Configure the daemon with the bundle path; restart; observe the
   reconcile loop pick the relay candidate.

**Definition of done:**
- `cargo test -p rustynetd relay_client_*` is still green.
- A live run shows the relay session establish AND traffic through it.
  Capture under `artifacts/windows_relay/<commit>/relay_session_proof/`.

### B.2 Relay traffic / handshake proof

**Blocked on §B.1.**

**Procedure:**
1. With a relay running and a daemon configured to use it, force the direct
   path to fail (e.g. block the peer endpoint port at the host firewall).
2. Send a packet from peer A to peer B. WireGuard handshake must complete
   over the relay path.
3. Capture on the daemon's host: `rustynet netcheck --json` showing
   `relay_active=true` and a fresh handshake timestamp under
   `last_handshake_unix`.
4. Capture pcap on the relay showing forwarded packets matching the
   relay-allocated port (the `(src_node_id, dst_node_id) → relay_port`
   mapping is in `crates/rustynet-relay/src/transport.rs`).

**Definition of done:**
- `relay_active=true` in netcheck for at least 60 seconds of sustained
  traffic.
- Pcap proof shows packets demuxing through the relay-allocated port.
- Artifact saved under `artifacts/windows_relay/<commit>/relay_traffic_proof/`.

### B.3 Failover / failback / roaming proof

**Blocked on §B.1, §B.2.**

These are `PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md` Phase D
`[ ]` items at lines 773, 775, 777, 779.

**Direct → relay failover (line 773):**
1. With direct-path active, drop the peer endpoint port mid-traffic.
2. Daemon must transition to relay-active without packet loss exceeding
   the documented stability window
   (`crates/rustynetd/src/phase10.rs::A4B_DIRECT_LOSS_STABILITY_WINDOW_MS`).
3. Capture continuous netcheck output showing the path-mode transition.

**Relay → direct failback (line 775):**
1. Restore the direct-path port.
2. Daemon must transition back to direct on fresh handshake evidence.
3. The direct-liveness expiry test in `phase10.rs` already pins the
   in-memory contract; the live test pins it across an actual reprobe.

**Long-uptime session/token refresh (line 777):**
1. Run a daemon for 24h with relay-active.
2. Confirm relay session tokens are refreshed before
   `MAX_RELAY_SESSION_TOKEN_TTL_SECS` (search for the constant).
3. No service interruption, no token-refresh-failure log line.

**Network-change reprobe (line 779):**
1. Bounce the host's network adapter mid-session (disable + enable).
2. Daemon must detect the IP change and re-probe.
3. Path resolves correctly.

**Definition of done for §B.3:**
All four artifacts exist under `artifacts/windows_relay/<commit>/<scenario>/`.
Phase D `[ ]` items flip to `[x]` in the relay plan's progress ledger.

### B.4 Signed relay-fleet end-to-end proof

**Blocked on §B.1.**

**Procedure:**
1. Issue a relay-fleet bundle that includes one Windows-hosted relay and
   one Linux-hosted relay.
2. Configure two daemon instances, one of which can only reach the
   Windows relay (block direct-path AND the Linux relay's address from it).
3. Confirm that daemon picks the Windows relay and establishes a session.
4. Tamper a copy of the bundle (flip a byte in the signature). Confirm
   the daemon rejects the tampered bundle on next reload (the existing
   tests `load_relay_fleet_bundle_accepts_signed_fleet_and_rejects_tamper`
   pin the in-memory path; this proves it on disk reload).
5. Replay test: present the same bundle twice with no watermark advance.
   Daemon must accept (idempotent reload). Then present an older bundle.
   Daemon must reject (tests `load_relay_fleet_bundle_rejects_replay_and_stale`
   pin the in-memory path; live test pins on-disk reload).

**Definition of done:**
- Three artifacts under `artifacts/windows_relay/<commit>/signed_fleet/`:
  `windows_relay_selected.json`, `tampered_bundle_rejected.json`,
  `replay_old_bundle_rejected.json`.

### B.5 Live Windows relay execution proof

**Procedure:**
1. Install relay via `Install-RustyNetWindowsRelayService.ps1`.
2. Start the SCM service.
3. Confirm:
   - Service status: `Running`.
   - `Get-NetFirewallRule -Name RustyNetRelay-Allow*` returns the expected
     rules.
   - The relay's `--health-bind 127.0.0.1:9100` returns `200 OK` on `/health`.
   - `windows-service-hardening-check` (the existing subcommand in
     `rustynet-relay`) returns `overall_ok=true`.
4. Stop and uninstall via `Uninstall-RustyNetWindowsRelayService.ps1`.
5. Confirm runtime artifacts under `C:\ProgramData\RustyNet\relay\` are
   cleaned up except for the explicitly preserved evidence trail (search
   the uninstall script for `preserved_artifacts`).

**Definition of done:**
- Artifact `artifacts/windows_relay/<commit>/scm_lifecycle/` exists with
  service-state JSON, hardening-check JSON, and uninstall-cleanup JSON.

---

## 7) Track C: live-lab harness work to support §5/§6

### C.1 Replace the Linux-only live-lab gate

**File:** `crates/rustynet-cli/src/vm_lab/mod.rs`, lines `4681` and `4762`.

The `ensure_live_lab_profile_linux_only` calls there block the orchestrator
from running against any non-Linux profile. The
`OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md` Phase W4.1
removed this for the dispatcher path; double-check it stays removed for
the per-stage path you're building in §A.5.

**Procedure:**
1. Search for `ensure_live_lab_profile_linux_only` and confirm it is only
   called by stages that genuinely need Linux (route impairment via tc
   netem, systemd unit verification). Windows stages must NOT call it.
2. For mixed-OS labs (1 Windows + N Linux), the dispatcher must pick the
   correct adapter per node. The mechanism is already in place (the
   `factory.rs` chooser); verify your Windows stages register correctly.

**Definition of done:**
- `cargo test -p rustynet-cli vm-lab-orchestrate-live-lab` passes.
- A live-lab run with `windows-utm-1` filling the exit role (NOT just
  the lowest-privilege client slot) completes.

### C.2 Heterogeneous live-lab evidence

**Owning ledger:** `HeterogeneousLiveLabEvidence_2026-04-28.md`.

`OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md`'s Definition
of Done requires "4×Linux + 1×Windows live-lab to completion with the new
dispatcher, with the Windows node filling at least one non-trivial role".

**Definition of done for this slice:**
- The 4×Linux + 1×Windows-as-exit run completes and is archived under
  `artifacts/windows_phase4/<commit>/`.
- Phase W4.5 in the OS-agnostic plan is marked `[x]` (currently `[x]` for
  Windows-as-client; needs the same artifact for Windows-as-exit).

### C.3 Add Windows lab to CI gate scripts

**Files:** `scripts/ci/phase9_gates.sh`, `scripts/ci/phase10_gates.sh`,
`scripts/ci/membership_gates.sh`.

**Procedure:**
1. Each script has a Linux-only path. Search for `os_matrix` or
   `platform_matrix`. Add the Windows entry with the artifacts from §A and
   §B.
2. The script should fail closed if the Windows artifacts are missing or
   stale relative to the current commit.

**Definition of done:**
- Phase 5 release-readiness summary
  (`Phase5ReleaseReadinessSummary_2026-04-12.md`) shows Windows-row
  artifacts present and validated.

---

## 8) Track D: Posture promotion + release-gate doc updates

### D.1 PlatformSupportMatrix

**File:** `documents/operations/PlatformSupportMatrix.md`.

**Procedure:**
1. Today, Windows is `runtime-host-capable only`. Do NOT touch this row
   until ALL of §5, §6, §7 are complete and the artifacts validate.
2. When the matrix flips, the change is one row. Reference the artifact
   commit SHAs.

### D.2 WindowsWorkingNodePlan §"Definition Of Done"

**File:** `documents/operations/active/WindowsWorkingNodePlan_2026-04-17.md`,
section "Definition Of Done" (around line 336).

The four requirements:
- Windows is no longer merely `runtime-host-capable only`.
- A reviewed backend exists and is proven on Windows.
- Mixed-node evidence exists.
- Fresh-install evidence exists.

When all four are met, mark the plan archived: move the file from
`documents/operations/active/` to `documents/operations/archive/` (verify
that path exists; if not, ask the operator).

### D.3 OsAgnosticOrchestratorAndWindowsPeerDeltaPlan §"11) Definition of Done"

**File:** `documents/operations/active/OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md`,
line 3125+.

**Procedure:**
1. The §11 DoD enumerates the closing criteria. When all are true, mark
   the plan archived.
2. Phase W5 (`[ ]` at line 2505) flips when the live-lab run §C.2
   completes.

### D.4 Push-style release notes

**File:** there is no canonical release-notes file as of `0c3d78e`. When
posture flips, create `documents/operations/release-notes/<date>.md`. Use
the commit history from `git log --oneline 2439f42..` as the source.

---

## 9) Track E: backlog of code-level followups (do these alongside §5–§7)

These are low-blast-radius hardening items flagged in earlier commit
bodies. They can be tackled by sub-agents in parallel because they each
sit in a single file. Each one has a one-commit definition of done.

### E.1 Auto-tunnel watermark sig-tamper test

**File:** `crates/rustynetd/src/daemon.rs`.

**Status:** auto-tunnel verifier was hardened in commit `9283b72`. Existing
tests cover outer-vs-payload + version gate. Missing: sig-tamper at the
on-disk reload path with a watermark already persisted.

**Procedure:**
1. Find `load_auto_tunnel_bundle_rejects_equal_watermark_when_payload_digest_differs`.
2. Add `load_auto_tunnel_bundle_rejects_sig_tamper_at_reload` — same fixture,
   tamper the signature hex (one byte), confirm reject.

### E.2 Peer-map wire format v2 → v3 with version line

**Files:** `crates/rustynet-control/src/lib.rs::signed_peer_map`,
`verify_signed_peer_map`.

**Status:** in `0c3d78e` the verifier carries an explicit comment that
peer-map's wire format is line-pipe-delimited and cannot be version-gated
without a wire bump. The bump:
1. Define a v3 shape that prepends `version=3\n` before the line records.
2. Bump the constant `PEER_MAP_WIRE_VERSION` (you will likely need to add
   it).
3. Add a verifier path that handles both v2 (legacy, time-bounded
   acceptance) and v3 (canonical going forward). Note: this VIOLATES the
   "one hardened path" rule — only do it as a coordinated migration with
   explicit operator opt-in via a config flag.

This task is mostly a design decision plus a small code change. Do not
start without an operator-approved migration plan. If in doubt, leave the
TODO comment in place and skip.

### E.3 NonceStore microbenchmark

**File:** `crates/rustynet-relay/src/transport.rs`.

**Status:** commit `38ac236` removed the O(n²) clone-on-write but did not
add a benchmark. The existing
`nonce_store_insert_handles_large_batches_without_quadratic_clone`
asserts the structural property. A `criterion` benchmark would surface
real regressions.

**Procedure:**
1. Add `criterion` as a dev-dep if not already present (check `Cargo.toml`
   first — do not duplicate).
2. Add `benches/nonce_store.rs` with a benchmark that inserts 4096 nonces
   and asserts the throughput is in the expected range.
3. Wire into CI as a soft-fail (warn but don't block) initially.

### E.4 DPAPI roundtrip moved from per-load to startup

**File:** `crates/rustynetd/src/key_material.rs`.

**Status:** commit `80164f8` zeroized the roundtrip plaintext but the
roundtrip itself runs on every key load. Move it to a one-time startup
self-test stored in a `OnceCell`-equivalent. Reference: `daemon.rs` already
uses `OnceLock` in similar paths.

### E.5 Privileged-helper IPC frame fuzzing

**File:** `crates/rustynetd/src/privileged_helper.rs`.

**Status:** commit `ceeda2a` added path-traversal rejection but the IPC
frame parser itself has unit tests, not fuzz tests. Add a `cargo-fuzz`
target or a property-based test (`proptest` is already a dev-dep — search
for it in the workspace `Cargo.toml`).

**Procedure:**
1. Target: `decode_helper_request` with arbitrary byte input. Property:
   never panic, always return either Ok or a clear `Err`.
2. Run for ≥ 10 minutes on first commit; pin a corpus seed under
   `crates/rustynetd/fuzz/corpus/decode_helper_request/`.

### E.6 Windows backend feature/SKU detection unit test

**File:** `crates/rustynet-backend-wireguard/src/windows_command.rs`.

**Status:** `0c3d78e` hardened the alias validator. Did not add a test
for the SKU pre-flight (Home doesn't have NetNat / RemoteAccess). The
phase10 path has `WINDOWS_PS_REQUIRE_EXIT_CMDLETS`. Mirror that here for
WireGuard service / `wg.exe` availability.

### E.7 Force-fail-closed degraded state

**File:** `crates/rustynetd/src/phase10.rs::Phase10Controller::force_fail_closed`.

**Status:** documented in commit `80164f8` body. When `block_all_egress`
fails, state stays at the prior value rather than transitioning to
FailClosed (because the OS isn't actually blocked). The recovery happens
on next reconcile via `prune_owned_tables + rollback_obsolete_controls`.

If you want to harden further: add a `FailClosedDegraded` state variant.
Significant state-machine refactor; do not start without an architecture
sketch in a separate doc.

---

## 10) Patterns to reuse

### 10.1 Adding a Windows-side argv-only validator

Pattern reference: `validate_windows_interface_alias` in
`crates/rustynetd/src/phase10.rs:4509`.

Template:
```rust
fn validate_windows_<something>(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > 64 {
        return Err("<something> length must be between 1 and 64 characters");
    }
    if !value.is_ascii() {
        return Err("<something> must be ASCII");
    }
    if value.chars().any(|ch| ch.is_ascii_control()) {
        return Err("<something> must not contain control characters");
    }
    if value.contains('=') {
        return Err("<something> must not contain '='");
    }
    Ok(())
}
```

Always also add a unit test pair: accepts-real-names + rejects-dangerous-chars.

### 10.2 Adding a PowerShell helper script constant

Pattern reference: `WINDOWS_PS_ASSERT_KILLSWITCH` in `phase10.rs:2845`.

Template:
```rust
const WINDOWS_PS_<NAME>: &str = "& { param($Arg1, $Arg2) \
    $ErrorActionPreference = 'Stop'; \
    /* logic that uses $Arg1 / $Arg2 — never interpolate */ \
    /* every Get-* / Set-* / New-* uses -ErrorAction Stop */ \
}";
```

Three required tests for every PS constant:
- "uses_param_and_stop_error_action" — script body contains `param(...)`
  and `$ErrorActionPreference = 'Stop'`.
- "does_not_interpolate_known_data_values" — script body does NOT contain
  any operator-controlled value.
- "runtime_args_pass_values_as_separate_argv" — the runtime invocation
  builds argv where each value is a distinct argument.

### 10.3 Adding a signed-bundle verifier outer-vs-payload cross-check

Pattern reference: `verify_signed_endpoint_hint_bundle` in
`crates/rustynet-control/src/lib.rs:2947` (commit `0fa8faf`).

Template:
```rust
pub fn verify_signed_<bundle>(&self, bundle: &Signed<Bundle>) -> bool {
    // Version gate first — reject any payload not at the canonical version.
    if !endpoint_hint_payload_field_matches(&bundle.payload, "version", "1") {
        return false;
    }
    // Cross-check every outer-struct field against the signed payload.
    if !endpoint_hint_payload_field_matches(&bundle.payload, "<field_a>", &bundle.<field_a>.to_string()) {
        return false;
    }
    // ... one cross-check per field downstream consumers might trust ...

    // Then signature verification.
    let signature = match decode_hex_to_fixed::<64>(&bundle.signature_hex) {
        Ok(bytes) => Signature::from_bytes(&bytes),
        Err(_) => return false,
    };
    let key = match VerifyingKey::from_bytes(&self.<bundle>_verifying_key) {
        Ok(k) => k, Err(_) => return false,
    };
    key.verify(bundle.payload.as_bytes(), &signature).is_ok()
}
```

Three required tests for each verifier:
- `<bundle>_verifier_accepts_unmodified_bundle` (regression guard)
- `<bundle>_verifier_rejects_outer_<field>_mismatched_to_payload` (one
  per cross-checked field)
- `<bundle>_verifier_rejects_payload_with_unknown_version`

### 10.4 Adding an ordering-matrix replay test

Pattern reference: `load_auto_tunnel_bundle_rejects_strictly_older_generated_at_unix`
and friends (4 tests at commit `38ac236`).

Template — the four cells you must cover:
1. `*_rejects_strictly_older_<timestamp_field>` — older timestamp → replay
2. `*_rejects_same_<timestamp_field>_smaller_<tiebreak_field>` — same
   timestamp + smaller tiebreaker → replay
3. `*_accepts_strictly_newer_<timestamp_field>` — newer timestamp accepted
   regardless of digest mismatch
4. `*_accepts_same_<timestamp_field>_with_larger_<tiebreak_field>` —
   same timestamp + larger tiebreaker accepted regardless of digest

If your bundle uses a single ordering field (epoch, generation), drop
cells 2 and 4.

### 10.5 Spawning a sub-agent with isolation

```
Agent(
  subagent_type: "general-purpose",
  isolation: "worktree",
  prompt: """
You are a senior Rust systems/security engineer working in an ISOLATED
git worktree of /Users/iwan/Desktop/Rustynet.

**FIRST STEP — sync to current main:**
```
git log -1 --format='%H'
git fetch /Users/iwan/Desktop/Rustynet main
git reset --hard FETCH_HEAD
git log -1 --format='%H'   # must match expected HEAD
```
If you cannot land on the expected HEAD, STOP and report.

**Strict scope — do not touch files outside this list:**
- <single file path>

**Goal:** <one paragraph>

**Read first:** <list of files / commits>

**Apply contained fixes** — if a fix would touch many files, just
document it as a finding instead.

**Tests to add:** <names + one-line each>

**Verify each Edit persists** — re-grep after every change.

**Gates:** cargo fmt -p <crate>, cargo clippy ... -D warnings, cargo
test -p <crate>.

**Do not:** run cargo fmt --all, update any ledger, commit, push.

**Report back:** worktree path + branch + starting HEAD + diff stats +
test count delta.
"""
)
```

---

## 11) Progress ledger

Append a row each time a slice lands. Conventions: commit SHA, what
landed, where the artifact lives.

| Commit | Slice | Outcome |
|---|---|---|
| `2439f42` | Windows DNS leak gap closed, egress detection, +42 tests | Code only |
| `80164f8` | DPAPI plaintext zeroize, relay skew clamp, assert_killswitch OS verify, +71 tests | Code only |
| `0fa8faf` | Endpoint-hint outer-vs-payload + 33 tests | Code only |
| `9283b72` | Auto-tunnel outer-vs-payload + 6 tests | Code only |
| `38ac236` | Relay transport DoS/perf followups + 5 tests | Code only |
| `022d2b0` | DNS zone bundle replay/staleness contract + 11 tests | Code only |
| `afa6476` | STUN parser RFC 5389 adversarial-input + 17 tests | Code only |
| `3f5432f` | Version=1 gates on all signed-bundle verifiers + 5 tests | Code only |
| `ceeda2a` | Privileged-helper path traversal rejection + 12 tests | Code only |
| `0c3d78e` | Windows backend tunnel-name validator + 10 tests | Code only |
| `8d5de44` | Auto-tunnel sig-tamper reload + dormant daemon security tests restored | Code only |
| `dc614ce` | windows-killswitch-assert CLI help + fail-closed regression tests | Code only |
| `9394053` | Windows DPAPI self-test cached at startup instead of live-passphrase roundtrip on every key load | Code only |

§A.1 (live SCM-context NAT lifecycle) — TBD
§A.2 (live DNS leak proof) — TBD
§A.3 (live killswitch precedence) — TBD
§A.4 (windows-killswitch-assert subcommand) — `dc614ce` code-only CLI/test coverage; live §A.3 proof still blocked on Windows lab access
§A.5 (three orchestrator stages) — TBD
§A.6 (cross-network exit proof) — TBD
§B.1 (wire daemon to real relay) — TBD
§B.2 (relay traffic proof) — TBD
§B.3 (failover/failback/roaming) — TBD
§B.4 (signed relay-fleet end-to-end) — TBD
§B.5 (live Windows relay execution) — TBD
§C.1 (Linux-only gate cleanup) — TBD
§C.2 (heterogeneous live-lab evidence) — TBD
§C.3 (CI gate scripts add Windows) — TBD
§D.1–§D.4 (posture promotion + doc updates) — TBD
§E.4 (DPAPI roundtrip moved from per-load to startup) — `9394053` code-only custody hardening

---

## 12) Test-count baselines (snapshot at `0c3d78e`)

If you accidentally regress test counts, reset main and try again. Do not
delete tests to make a build pass.

```
rustynetd:                   683 lib + 60 bin + 3 integration
rustynet-relay:              76 lib + 54 bin
rustynet-control:            141 lib
rustynet-backend-wireguard:  77 lib + 8 bin
```

After each slice you implement, the only allowed delta is
`+N (new tests added by this slice)`. Negative deltas are bugs.

---

## 13) Known pitfalls (in order of how often they have actually happened)

1. **Working in a `.claude/worktrees/...` path instead of `/Users/iwan/Desktop/Rustynet`.**
   The user's shell is rooted in a worktree. `cd` does not persist between
   Bash invocations in this harness — every command needs an explicit
   `cd /Users/iwan/Desktop/Rustynet &&` prefix. We have lost work to this
   twice in pre-`0c3d78e` history.

2. **Sub-agent worktrees branched from a stale HEAD.** The agent harness
   gives you a worktree at some old commit (often `fe48ba0`). Always
   tell the sub-agent to `git fetch + git reset --hard FETCH_HEAD` as
   step 1.

3. **Sub-agent edits silently rolled back by checkpoint.** The harness
   has rolled back agent edits at least twice. After every Edit, re-grep
   to confirm the change is present.

4. **`git add -A` capturing untracked artifacts.** There are doc-reorg
   files and `.docx` files that periodically appear in the working tree.
   Always list paths explicitly when staging.

5. **Cargo gate parallelism mid-edit.** If two agents are running
   `cargo test -p X` against the same crate while another agent is
   editing, the test build can fail mid-flight. Worktree isolation
   prevents this — use it.

6. **Refusing to push.** `git push` is a shared-state action. Do NOT
   push without an explicit operator request.

7. **Adding a "fallback" branch in production.** "One hardened path per
   security-sensitive workflow" is non-negotiable. If a feature seems to
   need a fallback, you are looking at the wrong abstraction.

---

## 14) Glossary

- **Posture-promotion**: moving a platform from
  `runtime-host-capable only` to a fully release-gated row in
  `documents/operations/PlatformSupportMatrix.md`. Requires §D.1.
- **Live-proof artifact**: a JSON / pcap / log file under
  `artifacts/<area>/<commit>/...` that the orchestrator's stages can
  read and validate. The commit-bound directory name is mandatory.
- **Reviewed runtime path**: a path under
  `C:\ProgramData\RustyNet\{config,logs,trust,membership,keys,secrets}`
  on Windows or `/etc/rustynet`, `/var/lib/rustynet`, `/run/rustynet`,
  `/var/log/rustynet` on Linux. Validators in `windows_paths.rs` and
  the corresponding Linux helper enforce this.
- **Outer struct vs payload mismatch**: the verifier silently trusts a
  field on the outer struct without checking that the same value is in
  the signed payload. Closed for endpoint-hint (`0fa8faf`) and
  auto-tunnel (`9283b72`); peer-map remains open and is tracked in §E.2.
- **W4 / W5 phases**: phases of `OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md`.
  W4 is "per-stage capability gating + Windows mesh-join", W5 is the
  stretch goal of 5×Windows / heterogeneous topologies.
- **Phase A / B / C / D / E**: phases of `PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md`.
  C (relay runtime integration) and D (failover/failback hardening) are
  the relevant open phases for this plan.

---

## 15) When you finish a slice

1. Update §11 with the commit SHA and one-line outcome.
2. If your slice is a `[ ]` item in another active ledger
   (`PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md`,
   `OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md`,
   `WindowsWorkingNodePlan_2026-04-17.md`), flip it to `[x]` in that
   ledger and reference your commit SHA.
3. Run the full gate sweep before the commit:
   ```
   cargo fmt --all -- --check
   cargo clippy -p rustynet-control -p rustynet-relay -p rustynetd -p rustynet-cli -p rustynet-backend-wireguard --all-targets --all-features -- -D warnings
   cargo test -p <relevant crate(s)> --all-features
   git diff --check
   ```
4. Commit message: lead with `feat`/`fix`/`test`(`<area>`): one-line
   summary. Body: what changed, what tests landed, what gates passed,
   any followups noted but not fixed. Always
   `Co-Authored-By: Claude <model> <noreply@anthropic.com>`.
5. Do not push. Wait for the operator to say "push".

---

## 16) Closing the plan

This document is closed when:
- §11 has commit SHAs against every TBD entry from §A, §B, §C, §D.
- `documents/operations/PlatformSupportMatrix.md` has been updated.
- `WindowsWorkingNodePlan_2026-04-17.md` has been moved to
  `documents/operations/archive/`.
- `OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md`'s §11
  DoD checklist is fully `[x]` and that plan has been moved to archive.
- A line is added to `README.md` saying Windows is no longer
  `runtime-host-capable only`.

When you make that final move, do it in a single commit with a body that
links every artifact commit SHA back to its slice.
