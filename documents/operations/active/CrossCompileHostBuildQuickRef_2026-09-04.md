# Host-Cross-Compile Build Quick Reference

**Status: UNTRUSTED — operator quick-ref draft, not owner-reviewed. Date 2026-09-04.**
Every flag, file:line, commit, and timing below was grep-verified in the working tree at `66a0fb7c` before writing; nothing is cited from memory.

## 1. What host-cross does, and when to use it

`--source-mode host-cross-binary` inverts the lab's default build flow. Instead of shipping source to every guest and compiling there, the orchestrator:

1. Probes each node's `(platform, arch)` over SSH (`uname -m`), maps it to a rustc triple, dedupes the set, and builds all needed binaries ONCE on the powerful lab host (`cargo`/`cargo zigbuild`) into a persistent `/tmp` target that stays warm across runs.
2. Ships the prebuilt binaries to each guest and stages them **into the guest's `target/release`** — the rest of the pipeline (install, verify, restart) proceeds unchanged, because everything downstream still finds binaries where a guest build would have left them.
3. Enforces a **glibc 2.31 floor** on Linux guests and fails closed on arch-probe failure, build failure, or an unmet floor — never falls back to a guest build silently.

Proven, live, on the `--node` engine (validation runs `manual-lab-hostcrossv5-1788504478` Linux 38 pass / 0 FAIL and `manual-lab-hostcrossmac2-1788508616` macOS 17 pass / 0 FAIL; `AutonomousManagerLog_2026-09-01.md` ticks 94–101):

- Linux `bootstrap_hosts`: ~5m45s native → **42s** with host-cross (tick 98).
- macOS `bootstrap_hosts`: 4min native → **58s** (tick 101).

**When to use:** an idle powerful host paired with slow/small guests. A 2-core guest building under SSH-starved load is exactly the case; a fleet-wide rebuild between code patches is the other. Skip it when the host is busy — the host build then just relocates the bottleneck.

**Defaults:** `--source-mode` defaults to `working-tree` (`LiveLabHandover_2026-08-14.md:281`); accepted values are parsed in `crates/rustynet-cli/src/vm_lab/capability.rs:850-860`.

## 2. Invocation

Direct orchestrate (from the machine that owns the guests):

```sh
cargo run -p rustynet-cli --features vm-lab -- ops vm-lab-orchestrate-live-lab \
  --node linux-x86-exit-1:exit --node linux-x86-client-1:client \
  --source-mode host-cross-binary \
  --ssh-identity-file ~/.ssh/id_ed25519 \
  --known-hosts-file ~/.ssh/known_hosts \
  --report-dir artifacts/live_lab/run-hostcross
```

`--node <alias>:<role>` is repeatable and defines the whole topology (the only selector that drives the Rust `--node` engine). Flag list: `crates/rustynet-cli/src/main.rs:20535`; values in `crates/rustynet-cli/src/vm_lab/orchestrator/stage/source_archive.rs:35-50`.

Detached on a remote lab host (`ops vm-lab-launch-on-host`): same orchestrator flags go in `orchestrator_args` verbatim (no single quotes or shell metacharacters); `host_ssh_identity` is the key ON THE HOST that reaches its guests (default `$HOME/.ssh/id_ed25519`), and `report_dir` is relative to the host's repo dir and must be fresh.

## 3. Gotchas

1. **Pinned-toolchain PATH.** The host build must run the pinned 1.88.0 toolchain: `rust-toolchain.toml` only takes effect through rustup's cargo, but Homebrew's cargo/clippy (1.97) shadows rustup in `PATH` (`LinuxVmHostPlan_2026-07-14.md:1543-1544`). Verify `cargo --version` resolves to rustup before a host-cross build.
2. **TWO guest install sites must receive the staged binaries.** A guest build lands in `target/release`; the installer then picks binaries up at one of two sites: `install_daemon` (site 1) or `install_daemon_from_workdir` (site 2, `macos.rs:123`, taken by macOS nodes with a configured `rustynet_src_dir` workdir). Only site 1 was wired at first; macOS silently built normally until tick 100 found and fixed the gap (`AutonomousManagerLog_2026-09-01.md:1318`). The v4→v5 fix `606d0b9c` completed the `target/release` staging for the ops_e2e path (tick 98).
3. **Attribution/provenance gate.** The archive stage refuses a dirty working tree unless `--allow-dirty` is passed, and writes `<report_dir>/state/source_archive_provenance.json` pinning the shipped archive's HEAD, sha256, and byte count — fail-closed, QH-08 Option A (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/source_archive.rs:302-353`). Never ship a run whose provenance does not name the commit you think you tested.
4. **Symlinked `--ssh-identity-file` is refused by `live_managed_dns_validation`** ("ssh identity file must not be a symlink") — a legitimate fail-closed check; point at the real key (tick 110, `AutonomousManagerLog_2026-09-01.md:1370`). Related trap: after a failed run, relaunching is refused by `enforce_launch_gate` (anti-rerun-till-green control); record the honest remedy first via `ops live-lab-record-stage-patch` (line 1371).
5. **glibc floor is enforced, not advisory.** Linux prebuilts carry a max-glibc record (2.31 floor enforced at build plan time; observed `glibc_max=2.29`); a guest below the floor fails closed rather than running a binary that segfaults.

## 4. Authoritative source

Design + history: `documents/operations/active/CrossCompileThenCloneDesign_2026-09-04.md` (design, status, live numbers). Landing trail: `documents/operations/active/AutonomousManagerLog_2026-09-01.md` ticks 94–101 — scaffold `3d816541` (fail-closed stub), landed `f3d5ff24` (arch probe, zigbuild, warm target, glibc floor), staging fix `606d0b9c`. Implementation: `crates/rustynet-cli/src/vm_lab/orchestrator/stage/host_cross_build.rs` (wired live by `native.rs` when `--source-mode` selects it).
