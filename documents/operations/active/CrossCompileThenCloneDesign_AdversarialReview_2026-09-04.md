# Adversarial Review: CrossCompileThenCloneDesign_2026-09-04.md

**Date:** 2026-09-04
**Status:** UNTRUSTED adversarial review. Every claim below was checked against the working tree at commit `6e1a353c` (branch `ai-edit/edit-1788534867314-26537-2`) by direct grep/read of the cited files, `git cat-file`/`git log`/`git merge-base` for the cited SHA, and `state/` run ledgers for the cited run ids. The design doc itself was NOT modified.

## Overall verdict

The design doc's architecture (§1–§4) and fail-closed story match the shipped code closely, but the document is stale in four load-bearing places — its status header, §5, the §6.2 remaining-work list, and roughly fifteen file:line citations — because the very increments it describes landed after those sections were written. Refresh before using it as a spec.

## Findings

### 1. HIGH — The status header contradicts §6.2, and the header is the stale half

**Doc claim:** The status line (line 4) says the `host-cross-binary` `source_mode` impl (§5) is "still owed", while §6.2 (lines 282–291) says "increment 4 landed — `install_daemon` scp's the host-built binaries + sets `RN_PREBUILT_BINARIES=1`" and "host-cross-binary is END-TO-END on Linux".

**What the code shows:** Increment 4 is real and shipped. `ArchiveSourceMode::HostCrossBinary` exists (`crates/rustynet-cli/src/vm_lab/orchestrator/stage/source_archive.rs:32`), is parsed from the literal `--source-mode host-cross-binary` (`source_archive.rs:48`), is wired into the orchestrator (`native.rs:594` branches on it), and a full 29 KB `stage/host_cross_build.rs` implements the host build with fail-closed checks. `linux_install.rs:81` pushes `RN_PREBUILT_BINARIES=1` / `RN_PREBUILT_DIR=/tmp/rn_prebuilt` into the bootstrap env, and `rn_bootstrap.sh:541-563` reads it and stages the prebuilt binaries into `target/release`, skipping the build.

**Consequence:** §5 ("Automation Design") reads as future work but describes (in slightly different shape) code that now exists. The doc should be re-sectioned: §5 is part-implemented (mode value, host build, Linux adapter) and part-open (provenance stamping, per-run floor config).

### 2. HIGH — §5.1's proposed `cross` alias does not exist

**Doc claim:** §5.1: add `host-cross-binary` "(aliases `cross`)" to `parse_archive_source_mode`.

**What the code shows:** `source_archive.rs:48` accepts only the exact string `host-cross-binary`. There is no `cross` alias; the error arm's message names `working-tree`, `local-head`, and `host-cross-binary` only (`source_archive.rs:50-54`). Any design text or operator doc telling users to pass `--source-mode cross` would fail closed at parse time. (Also note the doc's task framing conflated this enum with `capability.rs`'s `parse_source_mode_arg` — they are different enums; the mode lives in `source_archive.rs`, which the doc gets right.)

### 3. HIGH — §6.2's "Remaining: … the macOS adapter" is stale; the macOS adapter is wired

**Doc claim:** §6.2 line 291: remaining work includes "the macOS adapter".

**What the code shows:** Both macOS install sites already stage prebuilts: `macos_install.rs::install_daemon` (`:85`) pushes the same `RN_PREBUILT_BINARIES=1` env at `:129`, and `macos_install.rs::install_daemon_from_workdir` (`:234`) pushes it at `:275`. `Bootstrap-RustyNetMacos.sh` honors the flag (`:864-873` prebuilt staging, `:898-904` relay build skipped under the flag). `host_build_argv` supports darwin triples via a plain `build` subcommand (no zig), reserving `zigbuild` for linux/windows triples (`host_cross_build.rs`, `:150-168` area; the test at `:505` confirms a floor on a darwin triple is the only rejection). The doc's remaining-work list therefore overstates the gap — what actually remains on the macOS side is measurement/equivalence evidence, not adapter wiring.

### 4. HIGH — §6.2's pass counts are wrong: 38 claimed, 36 in the ledger

**Doc claim:** Run `state/manual-lab-hostcrossv5-1788504478`: "38 pass / 0 fail"; run `state/manual-lab-hostcross-1788500276`: "38 / 0 / 17".

**What the ledgers show:** Both run directories exist under the repo's `state/` and both `state/stages.tsv` files record **36 pass / 0 fail / 17 skipped** (53 stage rows each; awk-classified on the status column). The fail=0 and skip=17 components are correct; the pass count is 36, not 38, in **both** runs — the same off-by-two, so it is likely a transcription habit (perhaps counting two non-stage rows), not a ledger-read error, but as written the doc overstates the evidence.

**Verified correct within the same claim:** `bootstrap_hosts` in the v5 run really took **42 s** (`stages.tsv`: `06:50:09Z → 06:50:51Z`, status `pass`). The SHA `e41267b0` exists — "2026-09-04 Fix glibc-floor guard fail-open on Apple LLVM objdump paren format" — and is an ancestor of HEAD (`git merge-base --is-ancestor` exit 0). The substring parser it introduced is in the tree (`host_cross_build.rs:221-236`, "matched as a SUBSTRING anywhere in the text… robust to both GNU and LLVM formats") with tests at `:527-533`.

### 5. MEDIUM — Systematic line drift in every file the increments touched

The doc's §1 line cites were accurate when written but the prebuilt-path code shifted them. Verified current positions:

| Doc cite | Reality |
| --- | --- |
| `linux_install.rs:48` `install_daemon` | `:49` |
| `linux_install.rs:79` 300 s archive budget | `:90` (`archive_timeout`) |
| `linux_install.rs:80` 900 s build timeout | `:91` (comment text verbatim) |
| `linux_install.rs:82-99` scp to `/tmp/rn_source.tar.gz` | `:110` for the tarball path; block shifted |
| `linux_install.rs:660-690` tests, `:674-690` `bootstrap_script_builds_only_the_installed_cli_binary` | test now at `:725` |
| `rn_bootstrap.sh:542,543,551,554-556` 7200 s budgets | `:567,568,576` (online) and `:580-582` (`--offline`) |
| `rn_bootstrap.sh:542-560` build block; `:558-560` install | build `:565+`; install `:584-586`; prebuilt block `:541-563` now occupies the cited range |
| `source_archive.rs:31` `parse_archive_source_mode` | `:43` (enum at `:13` is correct) |
| `source_archive.rs:256/:292` `build_source_tarball` | `:111` |
| `source_archive.rs:517-543` parse tests | `parse_archive_source_mode_maps_known_values` at `:540` |
| `macos_install.rs:84` `install_daemon` | `:85` |
| `Bootstrap-RustyNetMacos.sh:864` build / `:869` retry / `:879-884` relay / `:891-905` install_binaries | prebuilt block `:864-873`; build `:881/:886`; relay `:898-904` — all shifted |

Un-drifted cites verified verbatim: `context.rs:66` (`source_mode` field) and defaults `:461,498,526`; `plan.rs:225` (`with_source_mode`) and `:388` (`PrepareSourceArchiveStage`); `evidence.rs` `source_mode` at `:83,119,583,661,925,940` — **all six exact**; `install.rs` `:48,51,54` (StageId/name/`CleanupHosts` dep), `:59-62` (`StageFanout::PerNode`), `:63-90` execute with `install_daemon` at `:90`, `:17` `node_in_rebuild_set`, `:116` `validate_reused_daemon`, reuse tests `:210-227` (doc says `:210-231`, close); `windows_install.rs` `:69` env-var const (doc `:66`, near), `:77` manifest path verbatim, `:653` `-Phase build-release`, `:221` budget resolution, tests `:2072` (`-Phase build-release` assert) and `:2391` (cargo-jobs default); `cross_network.rs:379` netns-probe on-guest build + `/tmp` install verbatim; `deploy_relay.rs:26-35` relay-binary assumption verbatim; `crates/rustynet-control/Cargo.toml:15` (`rusqlite` `features = ["bundled"]`, implying bundled `libsqlite3-sys`); `openssl-sys` absent from the root `Cargo.lock`; `rn_bootstrap.sh:101-106` (pkg-config openssl/sqlite checks) and `:184-185` (clang/llvm/openssl-devel/sqlite-devel package list); `vm_lab/script_template.rs` rustup-shims PATH comment block (~`:783-800`, doc says `:787-800`); inventory hosts `mac-utm-1`, `ubuntu-kvm-1`, `lenovo-bot` and **all fourteen** §2 guest aliases including `lenovo-exit-1`.

### 6. MEDIUM — `deploy_relay.rs:275` does not read the relay service file

**Doc claim:** §5.1: `deploy_relay.rs:275` reads `scripts/systemd/rustynet-relay.service` relative to the source root.

**What the code shows:** `deploy_relay.rs` contains no such read; its only mention is a doc comment at `:47`. The source-root read lives in the adapter layer — `linux_install.rs` (`:324` comment naming the exact relative path; the read is in the deploy helper) and `vm_lab/mod.rs`. The *substance* of the claim (the source tree must still ship because non-build stages read files from it) is correct; the citation is not.

### 7. LOW — `bootstrap/windows.rs` test-range cite not found

Doc cites tests at `bootstrap/windows.rs:41192-41221`. The real file is `crates/rustynet-cli/src/vm_lab/bootstrap/windows.rs`; lines `41192`/`41221` are past/blank in the current file — the relay-binary-existence tests are elsewhere. `:1291` (schema v2 comment) and `:1797` (`run_build_release_via_ssh_report`) check out, so the poll-path half of the cite is fine.

### 8. MEDIUM — glibc-floor semantics: doc and code agree, but only one of the doc's two explanations is precise

The code's floor is a **maximum permitted symbol version (a cap)**, not a minimum requirement: `check_glibc_floor` (`host_cross_build.rs:248-260`) passes when the binary's max `GLIBC_x` ≤ floor, fails closed when a symbol exceeds it, and returns `None` (pass) when no glibc symbols are present; a malformed floor string is an error (test `:567`). The hardcoded value lives at the call site — `native.rs:640-644`, `plan_host_builds(&nodes_pa, Some("2.31"))`, with the comment "every reachable lab guest ships glibc >= 2.31 … (Configurable in a later increment)". The doc's §4.2 states the cap semantics correctly ("makes the build *prove* it only emits ≤floor symbols"); its §2.2 wording ("a floor of glibc 2.31 covers every current guest") is looser but readable under the cap meaning. The doc's remaining-work claim of a *configurable* floor matches the code comment. One nuance neither states explicitly: a guest **older** than the floor still fails at runtime — the floor bounds what the build may emit, it does not make older guests work; §2.2's "protect against future guests that are older than the build host's headers" is the right idea and consistent.

### 9. Verified fail-closed enforcement (adversarial check a)

All three failure classes fail the run before deploy, with tests:

- **Arch probe failure:** `native.rs` runs `uname -m` per node over SSH and maps any error into `"host-cross: arch probe (uname -m) for '<alias>' …"` run abort (~`:615-625`); `target_triple` errors on unknown/mobile arches (test `host_cross_build.rs:467`).
- **Build failure:** `execute_host_builds` propagates a non-zero cargo exit as `"host build failed for {triple}"` (`:305`), fails on a **missing artifact** (`:316`, "fail closed"), and on objdump failure; module docs state the guarantee ("a host cross-build that would fault on a guest must never reach the install step", `native.rs:590-594`).
- **glibc-floor violation:** `check_glibc_floor` fails when max symbol exceeds the floor (test `:541-566`, including the "one below the max fails closed" case).

### 10. Considered, no issue (adversarial checks c–f)

- **(c) Same-arch builds still require zig.** `host_build_argv` routes *every* linux/windows triple through `zigbuild` — there is no same-arch short-circuit to a native build — so zig is a hard dependency even when the host's arch equals the target's (e.g. an aarch64 host building `aarch64-linux`). Only darwin triples bypass zig (plain `build`). The doc implies this (§3 recommends zigbuild for all Linux targets) but never states the same-arch cost; worth one sentence when the doc is refreshed. Not an error in the doc.
- **(d) Both install sites are prebuilt-wired.** Doc §1.1 only names `install_daemon`. The second macOS site, `install_daemon_from_workdir` (`macos_install.rs:234`), is also wired (`:275` pushes the same env). Linux has no `from_workdir` variant. Code complete; doc omits the second site.
- **(e) Cross-host distribution.** The host build runs **once on the orchestrating machine** (repo resolved from `std::env::current_dir()`, shared target root at `/tmp/rustynet-host-cross-target`), one build per distinct triple (`plan_host_builds` dedups via `BTreeSet`), then scp'd to each node regardless of which physical host owns it — so the multi-physical-host fleet (`ubuntu-kvm-1`, `lenovo-bot`) is handled correctly by construction. Doc §5.2 says "the host, once, builds the matrix" but never states the multi-physical-host consequence; minor documentation gap, no code issue.
- **(f) Provenance / dirty-tree gate.** `PrepareSourceArchiveStage::new(source_mode, allow_dirty)` (`plan.rs:388`); provenance JSON records `git_commit`, `git_dirty`, `allow_dirty`, `source_mode`, `sha256`, `bytes` with tests asserting each (source_archive tests ~`:530-545`). `binary_provenance` is genuinely still absent from both the run-matrix CSV and the orchestrator code, so the doc's remaining-work claim on that item is correct.

### 11. Unverifiable in this pass

- §6.1 timings: host-cold 28.85 s, 1m50s cli+rustynetd, `labrun-1788432982031` bootstrap_hosts 7m53s, and the pinned-1.88.0-toolchain claims (§6.2) — these reference run logs/measurements not re-derivable from the tree in this review; recorded as **unverified, not wrong**.
- §6.2's "ops e2e-bootstrap-host --skip-apt only installs" detail — consistent with the `rn_bootstrap.sh` prebuilt block reading as a pure staging path, but the specific e2e flag behavior was not traced.

## Self-check of this review's own citations

Four citations re-checked against the tree before finishing, each seen verbatim in tool output: `source_archive.rs:48` (`Some("host-cross-binary") => Ok(ArchiveSourceMode::HostCrossBinary)`), `native.rs:644` (`plan_host_builds(&nodes_pa, Some("2.31"))`), `macos_install.rs:129` (prebuilt env push), `rn_bootstrap.sh:541` (`RN_PREBUILT_BINARIES` gate). All four match.

## Verified-correct headline list

Mode parse + enum (`source_archive.rs:13,43,48`); orchestrator wiring (`native.rs:594`; `plan.rs:225,388`; `context.rs:66,461,498,526`); all six `evidence.rs` cites; `install.rs` stage skeleton and reuse-gate tests; fail-closed trio with tests; GNU+LLVM substring parser; SHA `e41267b0` (exists, ancestor, subject matches the doc's paren-format fix); both run dirs exist with 42 s `bootstrap_hosts`; `binary_provenance` still owed; configurable-floor still owed; Windows phase 2 not started (no prebuilt path in the Windows adapter); all fourteen inventory guest aliases; `openssl-sys` absent from `Cargo.lock`; bundled sqlite at `Cargo.toml:15`.
