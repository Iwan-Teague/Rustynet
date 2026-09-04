# Cross-Compile-Then-Clone Design: Build Lab Binaries on the macOS Host

**Date:** 2026-09-04
**Status:** DESIGN — host-side macOS measurement DONE (§6.1, 2026-09-04): substantial speedup, **increment 1 = macOS-guest cross-clone recommended**. Still owed before any orchestrator change lands: isolated on-guest build number, Linux zigbuild measurement, §4.6 equivalence gate, and the `host-cross-binary` `source_mode` impl (§5). UNTRUSTED until the manager verifies each file:line claim and each number.

## 0) Problem Statement

Every `--node` live-lab run rebuilds the daemon toolchain **on every guest**, on every run, on every node, with guest-class CPUs. The build step is the single largest fixed cost in the loop: the Linux bootstrap budgets **900 s** for it (`crates/rustynet-cli/src/vm_lab/orchestrator/adapter/linux_install.rs:80` — `let build_timeout = Duration::from_secs(900); // cargo build can take a while`) and the standalone bootstrap phases time each cargo invocation at **7200 s** (`scripts/bootstrap/linux/rn_bootstrap.sh:542,543,551,554-556`). Windows has its own budget knob, `RUSTYNET_WINDOWS_BUILD_TIMEOUT_SECS` (`adapter/windows_install.rs:66,221-248`), sized on the same assumption.

The proposal: **cross-compile on the macOS host (Apple Silicon, fast, always warm) and clone the finished binaries to each guest**, per target triple. For the macOS UTM guest this is not even a cross-compile — the host and guest share `aarch64-apple-darwin`, so the host build **is** the guest binary (§2.1). For Linux and Windows guests it is a real cross-compile; §3 picks the toolchain per target and §4 argues correctness.

Goal: turn "N guests × 5–30 min of on-guest build per run" into "1 host incremental build (often <1 min warm) + N small scp transfers", while keeping a native on-guest build as the eventual **final verification** path so cross-binary evidence never silently substitutes for native evidence.

## 1) Current Path — Where the On-Guest Build Actually Happens

Ground truth, with citations (verified on this tree):

### 1.1 Orchestrator wiring (`--node` engine)

- **Run config:** `OrchestrationContext`/`RunConfig.source_mode` — `crates/rustynet-cli/src/vm_lab/orchestrator/context.rs:66` (field), defaults `"working-tree"` (`context.rs:461,498,526`).
- **Parse + plumb:** `adapter/../native.rs` parses `source_mode` at `native.rs:189-190` and `:346-347`, passes it at `:482`/`:955`, applies it via `with_source_mode` at `:995`; `plan.rs:225` (`with_source_mode`), `plan.rs:388` (inserts `PrepareSourceArchiveStage`).
- **Accepted values:** `orchestrator/stage/source_archive.rs:13` (`ArchiveSourceMode` enum) and `:31` (`parse_archive_source_mode`): `None`/`""`/`"working-tree"`/`"worktree"` → `WorkingTree`; `"head"`/`"local-head"` → `Head`; anything else (incl. `"repo-url"`) → error. Tests at `source_archive.rs:517-543`.
- **Source tarball:** `prepare_source_archive` stage calls `build_source_tarball` (`stage/source_archive.rs` ~`:256`/`:292`), which also records a git-provenance marker (commit + dirty state). Evidence records `source_mode` and provenance (`orchestrator/evidence.rs:83,119,583,661,925,940`).
- **Bootstrap stage:** `orchestrator/stage/install.rs` — `BootstrapHosts` stage (`StageId::BootstrapHosts`, id at `:48`, name `"bootstrap_hosts"` at `:51`, depends on `CleanupHosts` at `:53-54`, parallel fanout at `:59-62`). Its `execute` (`:63-90`) calls `ctx.install_daemon(&source, alias, ctx)` at `:90` through the per-OS adapter. Nodes **outside** `--rebuild-nodes` are skipped and reused intact (`install.rs:17-24, 68-79`), with a liveness probe `validate_reused_daemon` (`install.rs:116-131`) that fails loudly if a reused node is not daemon-ready.
- **Per-OS adapters:**
  - **Linux:** `adapter/linux_install.rs:48` `install_daemon` — scp's `rn_bootstrap.sh`, an env file, and the source tarball to `/tmp/rn_source.tar.gz` (`:82-99`, archive transfer budget 300 s at `:79`), then runs the bootstrap on-guest. Build timeout 900 s (`:80`).
  - **macOS:** `adapter/macos_install.rs:84` `install_daemon` — same shape; scp's `rn_macos_bootstrap.sh` + `Install-RustyNetMacosService.sh` + env, then runs the build on-guest.
  - **Windows:** `adapter/windows_install.rs` — pushes the source via `tar.exe`, then runs `Bootstrap-RustyNetWindows.ps1 -Phase build-release` (`:653`), polled through a JSON manifest at `C:\Windows\Temp\rustynet-stage\build-release\manifest.json` (`:77`); low-memory guests cap cargo parallelism (`:1753-1757` and tests `:2072,2391`).

### 1.2 The build itself — what gets built, per OS

**Linux** (`scripts/bootstrap/linux/rn_bootstrap.sh:542-560`; the script is the `BOOTSTRAP_SCRIPT` embedded by `linux_install.rs`):

```
cargo build --release -p rustynetd
cargo build --release -p rustynet-cli --features vm-lab --bin rustynet-cli
cargo build --release -p rustynet-relay --features daemon
# offline fallback (--offline variants) at :554-556 for killswitch-behind guests
install -m 0755 target/release/{rustynetd,rustynet-cli,rustynet-relay} → /usr/local/bin/{rustynetd,rustynet,rustynet-relay}   # :558-560
```

The scope is deliberately narrow — tests pin it: build **only** the installed cli binary with `vm-lab` (RNQ-17), never the whole package bin set, and always the relay binary (`linux_install.rs:660-690`, tests `bootstrap_script_builds_only_the_installed_cli_binary` at `:674-690`).

**macOS** (`scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh:864-905`): `cargo build --release --offline -p rustynetd -p rustynet-cli --features rustynet-cli/vm-lab` (online retry at `:869`), then relay (`:879-884`), then `install_binaries()` (`:891-905`) installs to the launchd service paths.

**Windows** (`bootstrap/windows.rs` + `Bootstrap-RustyNetWindows.ps1 -Phase build-release`): same three binaries; `rustynet-relay.exe` must exist for relay audits and the offline fallback (tests at `bootstrap/windows.rs:41192-41221`). Manifest schema v2 with `complete.marker` (parse/validation `bootstrap/windows.rs:1291-1380`, SSH report poll `:1797-1948`).

**Two more on-guest build sites** (also in scope for cross):

- `stage/cross_network.rs:379` — every netns-simulator node runs `cargo build --release -p rustynet-netns-probe` on-guest and installs to `/tmp/rustynet-netns-probe`. This crate is std-only and tiny, so it is cheap, but it is per-node work the host could pre-build too.
- `stage/deploy_relay.rs:26-35` — the relay deploy stage does **not** build; it assumes the bootstrap already installed `rustynet-relay` (`linux_install.rs:660-667` assert). Any cross scheme must keep producing that binary at `/usr/local/bin/rustynet-relay` before `deploy_relay` runs.

### 1.3 Toolchain prerequisites this design can eventually drop per-guest

The on-guest build is why every Linux guest needs rustup pinned to `rust-toolchain.toml` + shims on the default PATH (a non-login SSH shell never sources `~/.profile`; otherwise `ssh guest cargo build` exits 127 — `vm_lab/script_template.rs:787-800`), plus clang/llvm, gcc, pkg-config `openssl-devel` + `sqlite-devel` (`rn_bootstrap.sh:101-106,184-185`). A cross-clone path removes the *compiler* requirement (rustup, clang, gcc, pkg-config dev packages) while keeping the *runtime* requirements (nftables, wireguard-tools, etc.). Note `libsqlite3-sys` is `bundled` (`crates/rustynet-control/Cargo.toml:15`) and `ring` is in the lock (both cc-compiled C), while `openssl-sys` is **absent** from `Cargo.lock` — so the only C the cross build must handle is what cc-rs compiles from vendored sources (§4.3).

## 2) Cross-Compile Matrix per Guest

From `documents/operations/active/vm_lab_inventory.json` (entries; hosts = `mac-utm-1` Apple-Silicon local UTM, `ubuntu-kvm-1` x86_64 libvirt, `lenovo-bot` x86_64 libvirt):

| Guest(s) | OS | Rust target triple | Host builds it as |
| --- | --- | --- | --- |
| `macos-utm-1` | macOS 26.5 arm64 (UTM) | `aarch64-apple-darwin` | **identical triple — not a cross-compile at all** |
| `fedora-utm-1` | Fedora 44 aarch64 (UTM) | `aarch64-unknown-linux-gnu` | cross (zig) |
| `ubuntu-utm-1` | Ubuntu 26.04 aarch64 (UTM) | `aarch64-unknown-linux-gnu` | cross (zig) |
| `rocky-utm-1` | Rocky 10.2 aarch64 (UTM) | `aarch64-unknown-linux-gnu` | cross (zig) |
| `debian-headless-2/4`, `debian-lan-11` | Debian (MacBook-LAN devices) | `x86_64-unknown-linux-gnu` (verify `uname -m`) | cross (zig) |
| `linux-x86-client-1`, `linux-x86-exit-1` | Debian 13 trixie x86_64 (ubuntu-kvm-1) | `x86_64-unknown-linux-gnu` (glibc 2.41) | cross (zig) |
| `lenovo-client-1`, `lenovo-exit-1` | Debian 13 x86_64 (lenovo-bot) | `x86_64-unknown-linux-gnu` | cross (zig) |
| `windows-utm-1` | Windows 11 Pro (UTM) | `x86_64-pc-windows-gnu` (confirm guest bootstrap's toolchain, §4.5) | cross (zig or mingw) |
| `windows-x86-1` | Windows 11 25H2 x86_64 (ubuntu-kvm-1) | `x86_64-pc-windows-gnu` | cross (zig or mingw) |
| `fedora-x86-1` | Fedora 42 x86_64 (ubuntu-kvm-1) | `x86_64-unknown-linux-gnu` | cross (zig) |

### 2.1 The macOS guest is the trivial, biggest quick win

`macos-utm-1` runs the **same triple the host builds natively**. `cargo build --release -p rustynetd -p rustynet-cli --features rustynet-cli/vm-lab` on the M-series MacBook Pro produces a binary that is byte-equivalent-in-kind to what `Bootstrap-RustyNetMacos.sh:864-884` produces on the guest (same rust-toolchain channel, same triple, same features). Cross-compiling is unnecessary; only **clone** is needed: build on host → scp → install to the launchd paths (`install_binaries`, `Bootstrap-RustyNetMacos.sh:891-905`). This single guest eliminates the largest per-node build in the fleet (macOS guests are notoriously slow rust builders under UTM) with essentially **zero toolchain risk**. Ship this first as `source_mode`-adjacent phase 1 (§7).

### 2.2 Glibc floors (drives the zig pin, §4.2)

| Guest family | glibc |
| --- | --- |
| Debian 13 trixie (linux-x86-*, lenovo-*) | 2.41 |
| Fedora 44 / Rocky 10.2 | ~2.39+ |
| Ubuntu 26.04 | ~2.42 |

A floor of **glibc 2.31** (or even 2.28) covers every current guest with margin; the floor exists to protect against *future* guests that are older than the build host's headers. Step 0 of adoption: run `uname -m && ldd --version` on every entry and fill the real values into the table above — do not trust this design's numbers over a probe.

## 3) Toolchain Options and Recommendation

The prior attempt failed with `cc-rs: failed to find x86_64-linux-gnu-gcc` — i.e. rustc cross-linking worked but the **C** build (cc-rs driving a C compiler for `libsqlite3-sys`/`ring`, §1.3) had no cross CC. Any recommendation must solve C, not just Rust.

| Option | How it works | Setup on macOS | Reliability | Speed | Verdict |
| --- | --- | --- | --- | --- | --- |
| **cargo-zigbuild** | zig serves as linker **and** `zig cc` C compiler; explicit glibc floor pinning (`--target aarch64-unknown-linux-gnu.2.31`) | `brew install zig cargo-zigbuild` + `rustup target add <triples>` — no docker, no sysroots | High for gnu targets; ring + bundled sqlite are well-trodden zig-cc paths; solves the exact cc-rs failure | Fast (no emulation) | **RECOMMENDED for all Linux targets** |
| cross-rs (`cross`) | per-target docker images with real cross toolchains + sysroots | Docker Desktop on macOS (licensing, RAM, file-share latency) | Highest fidelity (distro sysroot) | Slower via VM/docker; x86_64 target builds run x86_64 images under emulation for C parts | Fallback if zigbuild hits a C wall on a specific crate |
| Homebrew gnu cross-toolchains (`aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu` formulas) | real binutils+gcc, set `CARGO_TARGET_<T>_LINKER` + `CC_<T>` | brew install; manual env plumbing | Works, but glibc *headers* track the formula's build, and cc-rs needs `CC_<triple>`/`AR_<triple>` set per crate; version pinning is manual | Fast | Acceptable plan B; more env surface to get wrong |
| Build inside a Linux container/VM | native build in a Linux env, copy out | docker or a small UTM Linux builder VM | High | Container build ≈ guest build cost, just relocated; VM adds copy step | Rejected as primary (it re-introduces the cost we are removing); keep as emergency path |

**Windows:** `x86_64-pc-windows-gnu` cross-builds from macOS today for compile-verification (prior art in repo docs/CI history). cargo-zigbuild also drives `windows-gnu` via zig's mingw support; pure `rustup target add x86_64-pc-windows-gnu` + `brew install mingw-w64` with `CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc` is the classic path. **Open question before adoption (§4.5):** which toolchain do the Windows guests themselves use in `Bootstrap-RustyNetWindows.ps1 -Phase build-release`? If guests build `*-windows-msvc`, a `windows-gnu` cross binary is a *different* toolchain artifact — §4.5 risk class. Phase the Windows cell last; macOS first, Linux second.

**Per-target pick:** Linux (both arches) → cargo-zigbuild with pinned glibc floor. Windows → mingw-w64/zig gnu, gated behind a dedicated correctness run. macOS → no toolchain at all (§2.1).

## 4) Correctness Analysis

### 4.1 Why cross binaries behave identically for the overwhelming majority of stages

A cross build with the **same target triple**, **same toolchain channel** (`rust-toolchain.toml` — rustc does not care which host it runs on for a given triple+channel), **same feature set**, and **same source commit** produces the same program semantics: same `cfg!(target_os/arch)` evaluation (derived from the triple, not the host), same std, same dependency graph, same codegen backend. The orchestrator's validation stages exercise daemon behavior (handshakes, dataplane, DNS, role transitions) — none of that depends on *where* rustc ran. This is why distributions cross-build release artifacts routinely.

### 4.2 Real risk 1 — glibc symbol version skew (Linux)

A gnu-target binary records the glibc symbols it imports *with version tags* of the build environment's glibc. Build against glibc 2.42 headers → binary demands ≥2.42 at runtime → fails on a 2.41 guest with `GLIBC_2.42' not found`. Mitigation: zig's explicit floor (`.2.31`) makes the build *prove* it only emits ≤floor symbols. Verification: `objdump -T binary | grep GLIBC_ | sort -u` (max version ≤ floor) per artifact, wired as an automated post-build check (§5.3).

### 4.3 Real risk 2 — C dependencies under cc-rs

`libsqlite3-sys` (bundled sqlite3.c) and `ring` (C + per-arch asm) both compile C. The historical failure was exactly here. zigbuild routes `cc` to `zig cc` with the right cross sysroot automatically; ring's asm assembles for the target arch. Residual risks: (a) a crate adds a C dep with unusual build logic (`bindgen` needs *libclang on the host* — fine, host-side); (b) asm/C behaves differently — no, same target triple = same target code. Action: adopt behind a lockfile-drift tripwire — if `Cargo.lock` gains a new cc-consuming crate, re-run the §4.6 equivalence gate before trusting cross again.

### 4.4 Real risk 3 — feature/cfg divergence and library linkage

- Feature sets must be passed identically (`vm-lab`, `daemon`, etc.) — the cross command is generated from the *same* strings the bootstrap uses (§5.2), so drift is impossible by construction.
- Dynamic vs static: keep gnu dynamic-glibc (do **not** switch to musl static — different libc semantics, new risk class for zero benefit). Verify `ldd` on the host-crossed binary lists only expected libs (glibc + nothing macOS-flavored).
- macOS: same triple ⇒ none of this applies; the only risk is feature-flag drift, eliminated by §5.2 construction.

### 4.5 Real risk 4 — Windows toolchain identity

If guests self-build with MSVC and the host clones a GNU binary, we changed compilers, not just build location: different CRT, different exception/unwind codegen, and `rustynet-windows-native` (WFP/DPAPI) may behave subtly differently. **Action:** determine the guest toolchain from `Bootstrap-RustyNetWindows.ps1`; if MSVC, either (a) keep Windows on native builds initially, or (b) evaluate `x86_64-pc-windows-msvc` cross via `cargo-xwin` (downloads MSVC CRT/SDK headers; works from macOS) as a separate gated experiment. Windows cross is explicitly **out of phase 1**.

### 4.6 Native build stays the final verification

Cross becomes the *bulk default*; the native path is never deleted:

1. **Equivalence gate (one-time per target, re-run on toolchain/lockfile change):** same commit, same node — run the stage suite on a guest with the cross-cloned binary and on a second (or reset) instance with a native build; compare per-stage outcomes. Cross-binary evidence is promoted only when stages match (and any divergence is root-caused).
2. **Periodic native re-verification:** e.g. one full native-build run per week of campaign time and always before release-significant evidence, per the existing "mandatory periodic full-validation gate" discipline (`LiveLabExecutionEfficiencyPlan_2026-06-20.md`).
3. **Evidence honesty:** every report row records `binary_provenance=cross(host,aarch64,darwin)→<triple>` vs `native` so a stage pass is never silently read as a native-build pass (§5.4).

## 5) Automation Design

### 5.1 New source/binary mode

Add a new mode value alongside `working-tree`/`head` in `parse_archive_source_mode` (`stage/source_archive.rs:31`): **`host-cross-binary`** (aliases `cross`). Semantics:

- `prepare_source_archive` still runs and still records git provenance — the source tree must keep shipping to guests because non-build stages read from it (e.g. `deploy_relay.rs:275` reads `scripts/systemd/rustynet-relay.service` relative to the source root). What changes is that the tarball is accompanied by **prebuilt binaries** and the on-guest build step is skipped.
- The host, once, builds the matrix of binaries for the run's assigned nodes: `{rustynetd, rustynet-cli(vm-lab), rustynet-relay(daemon)}` × target triples actually present in the topology (+ `rustynet-netns-probe` where cross-network stages are planned).

### 5.2 Where it plugs into the orchestrator

1. **`context.rs`** — `RunConfig` gains `host_cross: bool`/mode enum (near `source_mode`, `context.rs:66`), default **off** (fail-closed: nothing changes unless asked).
2. **`native.rs`** — parse the flag where `source_mode` is parsed (`:189-190`, `:346-347`), plumb through `:482`/`:955`/`:995` in the same style.
3. **New host-side build step** (new stage or part of `prepare_source_archive`): for each distinct triple in the assignment set, run `cargo zigbuild --release --target <triple>[.<glibc-floor>] <exact same -p/--features/--bin strings as the guest scripts>` on the host; artifacts land in a run-local dir. Reuse `node_in_rebuild_set` (`install.rs:17`) so `--rebuild-nodes` only builds triples of nodes actually being rebuilt.
4. **Adapters, per OS:**
   - **Linux** (`install_daemon`, `linux_install.rs:48`): additionally scp the three binaries (+probe) to `/tmp`, and set an env flag (e.g. `RN_PREBUILT_BINARIES=1`) read by `rn_bootstrap.sh`; the script's build block (`:542-556`) becomes `install -m 0755 /tmp/rn_prebuilt/{...} /usr/local/bin/{...}` (`:558-560`), everything else (service install, users, smoke) unchanged. The offline-fallback path is irrelevant in this mode (nothing to build) and must be skipped, not fallen into.
   - **macOS** (`macos_install.rs:84`): clone host-built (same-triple) binaries into the guest's build dir path that `install_binaries()` (`Bootstrap-RustyNetMacos.sh:891-905`) expects — or add the same env-flag shortcut — so launchd service install is untouched.
   - **Windows** (`windows_install.rs`): phase-2 only; the PS helper gains a `-UsePrebuiltBinaries` path that skips `build-release` while still writing the v2 manifest (`:77`) so downstream report-poll logic (`bootstrap/windows.rs:1291-1380,1797-1948`) is unchanged.
5. **Timeouts:** the 900 s build budget (`linux_install.rs:80`) and 7200 s phase budgets (`rn_bootstrap.sh:542` etc.) become *transfer+install* budgets in this mode (binary ≈ tens of MB; keep the existing 300 s archive budget class, `linux_install.rs:79`).

### 5.3 Provenance, gates, and downstream assumptions that must change

- **Binary-provenance record:** new post-build check stamps each artifact with: host git commit + dirty state, toolchain channel, triple, glibc floor, and the `objdump -T` glibc-max-version scan (§4.2). Evidence rows carry it (`evidence.rs` — alongside existing `source_mode` fields `:83,583,661,925,940`), and the run-matrix row records `binary_provenance` so no cross pass is ever mistaken for native proof (§4.6).
- **`bootstrap_vm` MCP flow unchanged:** the standalone `vm-lab-bootstrap-phase` tool path (sync-source/build-release/…) keeps building natively on guests — cross mode is an *orchestrator run* optimization, introduced behind its own flag, so the lower-level bootstrap contract does not silently change meaning.
- **Tests to add/update (same files):** `source_archive.rs` parse tests (`:517-543` pattern) for the new mode; `install.rs` reuse-gate tests (`:210-231` pattern) for "reused node in cross mode still gets cloned binaries if rebuild-set says so"; `linux_install.rs` script asserts (`:660-690`) extended for the prebuilt path; `evidence.rs` for provenance fields.
- **Guest toolchain provisioning may shrink later** (drop rustup/clang from `provision_guest_toolchain`) — deliberately *not* in phase 1; keep guests able to run the native path (§4.6).

### 5.4 MCP / AI-agent surface

- `rustynet-mcp-lab-state`: `start_live_lab_run` passes the new flag through to `vm-lab-orchestrate-live-lab` (same channel as `source_mode`/`skip_*` flags); `what_will_deploy` gains a note that cross mode ships binaries. No new server needed.
- `rustynet-ai-agent` `ai_lab_run`: add a pass-through selector (e.g. `host_cross_build: true`) so autonomous loop targets can opt in; run-matrix rows remain the evidence ledger (§5.3).

## 6) Measurement Plan (the stats the manager will run)

Run **per guest**, cold and warm, before/after adoption. All commands time only the build-or-clone segment; run each 3× and record median. Fill the table, then decide.

**Step 0 — probe reality:** on each guest: `uname -m; ldd --version | head -1; nproc; free -h` (record in the matrix, §2).

**Baseline A — on-guest build (current path), Linux guest (e.g. `linux-x86-client-1`):**

```bash
# COLD (wipe target; approximates a fresh/rebuilt node):
ssh <guest> 'cd ~/Rustynet && cargo clean'
/usr/bin/time -p ssh <guest> 'cd ~/Rustynet && cargo build --release -p rustynetd \
  -p rustynet-cli --features vm-lab --bin rustynet-cli -p rustynet-relay --features daemon'
# WARM (the common iterate case — target/ persists, source changed):
/usr/bin/time -p ssh <guest> 'cd ~/Rustynet && touch crates/rustynetd/src/main.rs && \
  cargo build --release -p rustynetd -p rustynet-cli --features vm-lab --bin rustynet-cli -p rustynet-relay --features daemon'
```

macOS guest: identical with `Bootstrap-RustyNetMacos.sh`'s exact feature string (`-p rustynetd -p rustynet-cli --features rustynet-cli/vm-lab`, `:864`). Windows: read the wall time from `build-release/manifest.json` timings after a `build-release` phase (or `RUSTYNET_WINDOWS_BUILD_TIMEOUT_SECS` run logs).

**Baseline B — host cross-build + clone (proposed path), same guests:**

```bash
brew install zig cargo-zigbuild && rustup target add aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu
# per triple:
/usr/bin/time -p cargo zigbuild --release --target x86_64-unknown-linux-gnu.2.31 \
  -p rustynetd -p rustynet-cli --features vm-lab --bin rustynet-cli -p rustynet-relay --features daemon
/usr/bin/time -p scp target/x86_64-unknown-linux-gnu/release/rustynetd <guest>:/tmp/rustynetd
ssh <guest> 'sudo install -m 0755 /tmp/rustynetd /usr/local/bin/rustynetd'
```

(macOS guest: plain `cargo build --release -p rustynetd -p rustynet-cli --features rustynet-cli/vm-lab` + scp — no zig.)

### Results table to fill in

| Guest | Triple | Native cold | Native warm | Host cross (1st/cold) | Host cross (warm) | scp (3 binaries) | Install+restart | Cross total | Speedup warm |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| macos-utm-1 | aarch64-apple-darwin | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___× |
| linux-x86-client-1 | x86_64-gnu | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___× |
| lenovo-client-1 | x86_64-gnu | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___× |
| fedora-utm-1 | aarch64-gnu | ___ | ___ | ___ | ___ | ___ | ___ | ___ | ___× |
| windows-utm-1 | x86_64-windows | ___ | ___ | (phase 2) | — | ___ | ___ | — | — |

**Decision rule (proposed, manager sets final):** adopt for a target when (a) cross total (build+transfer+install) ≤ **0.5×** native *warm* and ≤ **0.2×** native cold; (b) the §4.6 equivalence gate is green for that target; (c) provenance stamping works end-to-end. Multiply the per-run saving by fleet size × runs/week to state hours reclaimed; also measure one full `--node` orchestrate run before/after (the stage that should shrink is `bootstrap_hosts`, `install.rs:51`).

### 6.1 Measured results — macOS-guest side (2026-09-04, tick 84)

Host = this Mac (aarch64-apple-darwin, ~10 perf cores), pinned toolchain 1.88.0,
`CARGO_TARGET_DIR=/private/tmp/tpxc-host`. The macOS UTM guest is the **same
triple**, so its "cross build" is a plain host `cargo build` + `scp` — **no zig,
no cross toolchain, zero glibc risk** (§2.1 confirmed).

Measured on the host (rc 0 each):
- **rustynetd, release, cold: 28.85s** (`real`; user 123.87s across cores).
- **rustynetd + rustynet-cli --features vm-lab, release (warm rustynetd deps, cli
  cold): 1m50s** — the exact guest artifact set (`Bootstrap-RustyNetMacos.sh:864`,
  verified `--release -p rustynetd -p rustynet-cli --features rustynet-cli/vm-lab`).

On-guest-path proxy (the real production cost cross-clone replaces): the
`bootstrap_hosts` stage of run `labrun-1788432982031` took **7m53s**
(10:56:51→11:04:44Z) = source sync + toolchain check + **build** + install; build
is the dominant term.

**Decisive structural fact:** the macOS guest has **no persistent repo** —
`/Users/mac/Rustynet` does not exist between runs (probed 2026-09-04), so every
run's node rebuilds **cold**. The host target dir persists, so run-over-run the
host build is **warm/incremental** (seconds–1min) while the guest pays the full
cold build **every time**. Cross-clone wins by more the more runs you do.

| Guest | Triple | Native (bootstrap proxy) | Host cross (cold) | Host cross (warm) | scp+install |
| --- | --- | --- | --- | --- | --- |
| macos-utm-1 | aarch64-apple-darwin | build-dominated 7m53s bootstrap | 1m50s full set / 28.85s rustynetd | seconds–1min incremental | seconds |

**Preliminary decision: adopt cross-compile-clone for the macOS guest as
increment 1** — trivial (same triple: `cargo build` + `scp` + `install`, no cross
toolchain). The speedup is substantial and grows with run count (warm host vs
always-cold guest). Owed before it lands: (i) a direct isolated on-guest macOS
`cargo build` number to fill "native cold" exactly (needs rust+source staged on
the guest — deferred, proxied by the bootstrap number above); (ii) the §4.6
equivalence gate green for aarch64-apple-darwin; (iii) the `host-cross-binary`
`source_mode` implementation (§5). Linux (zigbuild) is increment 2 — measure it
on `debian-headless-*` once the current defect-hunt run frees them.

### 6.2 Measured — Linux zigbuild + the warm-repo nuance (2026-09-04, tick 85)

cargo-zigbuild works out of the box: `brew install zig cargo-zigbuild`; rustup
targets `x86_64/aarch64-unknown-linux-gnu` on pinned 1.88.0 (already present).

- **Host Linux cross-build** (`x86_64-unknown-linux-gnu.2.31`, COLD, same set
  `-p rustynetd -p rustynet-cli --features rustynet-cli/vm-lab`): **2m26s** (rc 0).
  Binaries: rustynetd 6.9M, rustynet-cli 16M.
- **Host Linux cross-build** (`aarch64-unknown-linux-gnu.2.31`, COLD — the actual
  reachable UTM Linux guest triple, measured tick 92): **2m10s** (rc 0), glibc
  floor max **2.29** (clean). Both Linux triples cross-build in ~2min on the host
  with a clean floor, so the aarch64 UTM guests (the fleet that is actually up)
  are covered, not just the down x86 guests.
- **glibc floor clean:** `objdump -T` shows max **GLIBC_2.29** (under the 2.31 pin;
  runs on any distro ≥ 2.29 — Debian 13 trixie ships 2.41). The §4.2 glibc-skew
  risk does NOT materialize with the zig floor pin — the single biggest correctness
  worry for the Linux target is empirically a non-issue on this binary.

**The warm-repo nuance (probed 2026-09-04) — refines the whole calculus:**
`debian-headless-2` HAS a persistent `~/Rustynet` with a **537M warm `target/`**
(nproc=4), UNLIKE the macOS guest (no persistent repo at all). Therefore:
- **macOS guest** rebuilds COLD every run → cross-clone wins big EVERY run →
  increment 1 unchanged.
- **Linux UTM guests** rebuild WARM (persistent `target/`) → incremental, fast →
  cross-clone's win is SMALLER for a *steady* aarch64 UTM guest. It still wins
  decisively for: (a) fresh/rebuilt nodes (`rebuild_nodes`, a newly provisioned
  guest); (b) the **x86 emulated guests** (`linux-x86-*`, `fedora-x86-1`,
  `windows-x86-1` — x86 on an aarch64 host is emulated, so a native build is slow;
  a host x86_64 zigbuild at 2m26s cold likely beats them by a wide margin); (c) the
  lenovo/libvirt guests. Quantify (b) with a cold native build on an x86 guest once
  one is up.

**Refined recommendation:** increment 1 = macOS cross-clone (biggest, every-run
win, zero toolchain risk). Increment 2 = Linux zigbuild **targeted at the COLD/x86
cases** (fresh nodes + emulated x86 guests), NOT the steady warm aarch64 UTM guests
where native-warm is already fast — so the `host-cross-binary` `source_mode` should
be *opt-in per node/run*, not a blanket default. Windows is increment 3.

## 7) Rollout Plan

1. **Phase 1 — macOS clone** (§2.1): no new toolchain, biggest win, exercises all the plumbing (flag, adapters, provenance, evidence) with zero cross risk.
2. **Phase 2 — Linux via cargo-zigbuild**, glibc floor 2.31; equivalence gate per arch; `objdump` check wired into the build step.
3. **Phase 3 — Windows**, only after resolving §4.5 (guest toolchain identity; msvc-vs-gnu decision, possibly `cargo-xwin`).
4. **Phase 4 (optional)** — pre-build `rustynet-netns-probe` for cross-network nodes (`cross_network.rs:379`).
5. Throughout: native builds remain available (flag off) and are mandatory for release-blocking evidence and periodic re-verification (§4.6). Ledger `CrossPlatformRoleParityRefresh_2026-07-23.md` rows must record binary provenance so cross-accelerated parity runs are comparable to native ones.

## 8) Open Questions

1. Guest-side truth check for §2 (arch/glibc per entry) — run Step 0 probes.
2. Which toolchain do Windows guests use in `build-release` today (§4.5)?
3. Does the orchestrator's source-archive step wipe guest `target/` (i.e. is the realistic on-guest baseline "cold" every run)? Determines which baseline column the decision rule keys on.
4. `ring`/future cc crates under zig — any crate needing `bindgen` on a *target* sysroot? (None today; lockfile tripwire covers tomorrow.)
5. Exact per-run fleet math: sum `bootstrap_hosts` stage durations from recent `live_lab_node_run_matrix.csv` rows to state reclaimed hours with real numbers (quote-aware CSV parsing — AGENTS §12.3).
