# Ubuntu VM-Host — Lab-Control Verification Findings (2026-07-23)

Findings from a live verification pass confirming the `ubuntu-kvm-1` KVM host has
the same agent-driven lab control as the macOS/UTM host: VM status, per-guest IP
resolution, source sync, on-guest release build, install, daemon start, and a
real (non-dry) live-lab launch. This is a **capability-parity** check, not a
stage-proving run — see `LinuxVmHostPlan_2026-07-14.md` for the owning program.

Host: `ubuntu-kvm-1` (AMD Ryzen 7 7700X, 61 GiB, `kvm_amd nested=1`), reached over
Tailscale (`100.117.1.47`). Guests: `linux-x86-client-1` (192.168.121.137),
`linux-x86-exit-1` (192.168.121.26), both Debian 13 x86_64.

## What was proven working (live, this session)

- **VM discovery + per-guest IP** — `discover_hosts` and `get_vm_diagnostics`
  resolve both guests over SSH, same shape as a UTM guest.
- **Source sync** — current working tree (142 commits ahead of the box's stale
  git checkout) rsynced to both guests; verified by file/timestamp match.
- **On-guest release build** — real `cargo build --locked --release -p rustynetd
  -p rustynet-cli --features vm-lab` on both guests; identical artifacts landed
  (`rustynet-cli` 16,754,528 B; `rustynetd` 5,851,648 B).
- **Install** — `bootstrap-phase install-release` placed both binaries in
  `/usr/local/bin` on both guests.
- **Live-lab launch mechanics** — `launch_live_lab_on_host` starts a detached
  orchestrate run that survives the SSH drop, compiles, and enters the pipeline
  (reached the network-profile stage). **But the run does NOT complete** — it
  aborts at the first node-readiness gate (see BUG-BOX-5). So *launching* works;
  *orchestrating a lab to completion on box guests does not yet* — this is the
  one headline capability still blocked.

## RESOLVED — all five fixed + proven live (2026-07-23)

All five bugs are fixed and the parallel-lab workflow is proven end-to-end.
Fix commit `b689cd6` (+ review-follow-up `caeff99`), full workspace gates green
(fmt + clippy + `cargo test --workspace --all-targets --all-features` = 0 fail).
Design + adversarial review: `UbuntuHostLabControlRemediationPlan_2026-07-23.md`.

Live proof at `b689cd6`:
- **BUG-BOX-5**: box run `livelab-1784825618-b689cd6` logged
  `PASS discover_local_utm: ready=linux-x86-client-1, linux-x86-exit-1; unready=none`
  — the gate that previously errored *"did not report the selected aliases"* now
  probes and passes both libvirt guests. **27 `linux-x86` stage rows** landed in the
  box's ledger (previously zero). Run: 14 pass / 3 skip / **0 fail**.
- **BUG-BOX-4**: the box launcher auto-injected `--known-hosts-file` (I omitted it);
  the run survived the arg-gate that killed the pre-fix attempts.
- **Concurrency + BUG-BOX-1 tooling**: a Mac UTM run (`livelab-...5418`, 14 pass /
  3 skip / 0 fail) ran **simultaneously** with the box run on disjoint guests, and
  `vm-lab-run-matrix-compare --commit b689cd6 --include-hosts ubuntu-kvm-1` merged
  both ledgers → **54 linux stages, 0 fail, 0 conflict, VERDICT: PASS**.
- The `lab-state` MCP binary was rebuilt + atomically installed for BUG-BOX-1/3/4;
  it needs a client reconnect (`/mcp` → reconnect) to go live server-side.

## Bugs found — labelled by severity

All five are **pre-existing** and **not Ubuntu-specific**; the box work merely
exposed them by using freshly-provisioned guests, a second host, and libvirt
controllers. Ordered most-severe first.

### BUG-BOX-5 — HIGH — orchestrate node-readiness gate is UTM-only; blocks every live-lab run on libvirt (box) guests
- **This is the real blocker for "run a live lab on the box."**
- **Where:** the `--node` path (`execute_rust_native_orchestration`,
  `orchestrator/native.rs:28`) runs its node-readiness gate in
  `orchestrator/readiness.rs`, which at **`readiness.rs:57`** unconditionally calls
  `execute_ops_vm_lab_discover_local_utm` (UTM bundle-scan + `utmctl`), regardless
  of controller kind. For libvirt guests UTM discovery reports nothing, so
  `selected_local_utm_readiness_from_report` (`mod.rs:9712`) errors *"local UTM
  discovery did not report the selected aliases: linux-x86-client-1,
  linux-x86-exit-1"* (`readiness.rs:61`) and the run **aborts before setup**. The
  post-restart rediscovery (`readiness.rs:165`) has the same UTM-only assumption.
  (NB: `mod.rs:12222`/`:12478` is the *legacy bash* orchestrator's parallel gate —
  `--node` early-returns at `mod.rs:12089` and never reaches it; the fix goes in
  `readiness.rs`. Corrected after adversarial review — see the remediation plan.)
- **Confirmed live:** run `claude-boxproof-2` (pid 2992) reached the network-profile
  stage (`mgmt_shared_smoke_v1`) then died at exactly this gate. This is why the
  box's local ledgers have **zero** `linux-x86` rows — a run has never passed stage 1.
- **Contrast:** the standalone lifecycle commands (`vm-lab-start/stop/status`,
  `discover_hosts`) *were* made controller-aware (LinuxVmHostPlan increments 2–3);
  the orchestrate pipeline's own preflight was not.
- **Fix:** branch the orchestrate readiness gate by controller kind — for
  libvirt-backed selected aliases, resolve readiness via the libvirt discovery
  ladder (`resolve_libvirt_live_host` / `discover_hosts`) instead of the UTM
  bundle-scan, mirroring the dispatch the standalone commands already do. Not
  security-sensitive (pure lab tooling), but load-bearing for the LinuxVmHostPlan
  Tier-1 DoD (a live `--node` run producing a run-matrix row on box guests).

### BUG-BOX-1 — MEDIUM — `get_vm_diagnostics` artifact collection always fails
- **Where:** `crates/rustynet-mcp/src/bin/lab_state.rs:5891` invokes
  `vm-lab-collect-artifacts --vm <alias> --report-dir <dir>`, but the CLI parser
  at `crates/rustynet-cli/src/main.rs:4820` requires **`--output-dir`**
  (`required_path`).
- **Effect:** the artifact-collection half of `get_vm_diagnostics` **always**
  fails with exit 64 (`bad_args: missing required option: --output-dir`) on every
  guest and every host. The daemon-status half (`vm-lab-status`) still succeeds,
  so diagnostics are degraded, not dead. No security or data impact.
- **Fix:** change the MCP call to `--output-dir` (one line).

### BUG-BOX-2 — LOW-MEDIUM — `restart-runtime` bootstrap phase assumes a pre-existing service unit
- **Where:** `install-release` (`crates/rustynet-cli/src/vm_lab/mod.rs:40167`)
  installs only the two binaries; it never installs a systemd unit.
  `restart-runtime` (`mod.rs:40199`) then runs
  `systemctl restart rustynetd.service`, which fails **status 5** (systemd
  "unit not found") on a guest that never had the unit installed.
- **Confirmed live** on `linux-x86-client-1`: `/usr/local/bin/rustynetd` present,
  but `systemctl status rustynetd` → *"Unit rustynetd.service could not be found"*.
- **Blast radius — limited:** the **primary** deploy path
  (`vm-lab-orchestrate-live-lab`) installs the unit itself via
  `orchestrator/adapter/linux_install.rs` and works. Only the manual
  install/restart/verify convenience chain is broken.
- **Fix:** have `install-release` also install `scripts/systemd/rustynetd.service`
  (via `scripts/systemd/install_rustynetd_service.sh`), and make `restart-runtime`
  emit a clear "service unit not installed" message instead of the opaque status-5.

### BUG-BOX-4 — MEDIUM — `launch_live_lab_on_host` omits required `--known-hosts-file`, run self-destructs
- **Where:** `launch_live_lab_on_host` (`ops vm-lab-launch-on-host`) forwards
  `--report-dir` and `--ssh-identity-file` to the detached orchestrate run but
  does **not** supply `--known-hosts-file`. The `--node` orchestrator hard-requires
  it (`crates/rustynet-cli/src/main.rs`, node-topology parse):
  *"--known-hosts-file is required when --node flags are present."*
- **Effect:** a run launched with only node selectors compiles (debug), then dies
  within seconds at arg-validation, leaving **no** report dir — so a poll of
  `host_run_status` reads the *previous* run's ledger and can look like nothing
  happened. Confirmed live on `ubuntu-kvm-1`: `launch-1784820652687` (pid 2229)
  exited immediately with that error.
- **Workaround (this session):** pass `--known-hosts-file
  /home/ubuntu-server/.ssh/known_hosts` inside `orchestrator_args`, and pin both
  guest keys in the host's `~/.ssh/known_hosts` (`linux-x86-exit-1` was unpinned
  on the box — it had only ever been reached from the Mac).
- **Fix:** `launch_live_lab_on_host` should derive/forward `--known-hosts-file`
  (mirror the `--host-ssh-identity` default it already has → default to
  `$HOME/.ssh/known_hosts` on the host), or fail loudly **at launch** rather than
  producing a run that self-destructs. Note also the launcher runs `cargo run`
  (a debug recompile) rather than the release binary `build-release` already
  produced — a slower cold start worth aligning.

### BUG-BOX-3 — LOW — MCP lab tool calls time out client-side at ~60s on slow ops
- **What:** any genuinely-slow `lab-state` MCP tool (`bootstrap_vm`
  sync-source/build-release, `sync_host`, provisioning) times out at the MCP
  **client** at ~60s regardless of the `timeout_secs` argument. The underlying CLI
  process keeps running (confirmed via `ps aux`: the timed-out `sync-source` call
  was still alive and completed).
- **Severity:** operational limitation, not a repo-code defect — the client
  request-timeout ceiling.
- **Workaround (already in CLAUDE.md):** drive the CLI directly via Bash for slow
  ops. Logged here so it is not re-diagnosed as a box/network fault.

## Remaining to reach full parity (not bugs)

- Box git checkout is 142 commits stale and unpushed-HEAD blocks `sync_host` /
  `host_preflight` GO — orthogonal to guest-level control, which was driven via
  direct rsync. Resolves once the pending main-branch work is pushed.
- `eno1` is `NO-CARRIER` (WiFi-only host) → guests are NAT-only behind `virbr0`,
  cross-machine reach still rides Tailscale (ADR-004 dual-NIC target unmet).
- A Windows/WinNAT guest — the headline reason for this host — is not yet
  provisioned; only the two Linux guests exist.
