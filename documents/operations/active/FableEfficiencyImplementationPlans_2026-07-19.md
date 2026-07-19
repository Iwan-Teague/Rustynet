# Fable Efficiency Implementation Plans — 2026-07-19

> **STATUS: UNSCHEDULED, PLAN-ONLY — NO CODE WRITTEN.** This document selects and designs one
> concrete fix for each of 11 findings from
> `EfficiencyAndAdvancedTechniqueOpportunityCatalog_2026-07-19.md` (the source catalog; it is
> cross-referenced, not modified, by this document). The catalog deliberately listed several
> candidate technique families per finding and chose none; this document's job is the opposite —
> pick the single best approach per finding and justify it, at the rigor bar modeled by
> `FableIntelligentSystemsProposals_2026-07-01.md` (FIS-0001..0030). Every current-behavior claim
> below was **re-verified against the working tree on 2026-07-19 by this pass** — line numbers are
> fresh, and drift against the catalog is called out explicitly where found. Scope is strictly
> efficiency / developer-tooling / architecture-hygiene: nothing here touches cryptography, key
> material, signature verification, ACL/policy evaluation, privileged subprocess execution,
> route/firewall/killswitch mutation, or DNS fail-closed behavior. Two findings (CCY-1, NAT-2) are
> deliberately narrowed to a sub-scope of their catalog entries, as noted in their sections.
> Effort sizes use the `SecurityRemediationPlan_2026-06-19.md` key: S ≤ half day, M ~1-2 days,
> L ≥ 3 days or needs a design decision.

**Plans at a glance:**

| ID | One-line chosen fix | Size |
|----|---------------------|------|
| BLD-1 | Target-gate `rustynet-windows-native` in the 2 crates where it is free; deepen xtask `--affected` to full transitive closure | S+S |
| BLD-2 | Adopt `cargo-nextest` as the test *runner* (measure first, no retries), keep `cargo test` as the §7 authoritative definition | S→M |
| BLD-3 | Drop the standalone `check` stage from xtask + CI; clippy becomes the single compile+lint pass | S |
| CLI-2 | `build.rs`-embedded rustc version in `rustynet-sysinfo`; delete the runtime subprocess spawn | S |
| CLI-3 | `std::thread::scope` fan-out of the 6 diagnostics probes; consolidate the 3 interface enumerations onto the diagnostics-module helpers | S+M |
| RLY-1 | Two-phase `get_mut`-then-insert in `RateLimiter::check_packet` (std-only, zero-alloc hot path) | S |
| CCY-3 | Delete the four dead `DaemonRuntime` gossip shadow fields outright (re-verification: they have **zero readers**) | S |
| WIN-3 | `set_nodelay(true)` on accept + small-frame single-write coalescing in llm-gateway and nas | S |
| NAT-3 | One shared STUN gather core (RTO ladder for all batched paths); serial authoritative path gains the same ladder, stays serial-by-invariant | M |
| CCY-1 | (narrow) 2s write timeout on the Unix admin-IPC response path, non-fatal disposition mirroring the anchor bundle-pull discipline | S |
| NAT-2 | (narrow) Reorder each ICE race round to send → wait → check so the final round gets a real observation window | S |

None marked OUT OF SCOPE — every chosen fix stays inside the excluded-surfaces boundary; each
section's constraint check names the nearest boundary explicitly.

---

## BLD-1: Consistent `rustynet-windows-native` target-gating + full-transitive `--affected` closure

- **Pipeline / area:** `crates/rustynet-crypto/Cargo.toml`, `crates/rustynet-backend-wireguard/Cargo.toml`
  (dependency gating); `crates/rustynet-xtask/src/main.rs` (`--affected` scoping).

- **Current behavior (re-verified):**
  - `rustynet-windows-native` is depended on by five crates with inconsistent gating: plain
    `[dependencies]` in `rustynet-crypto` (`crates/rustynet-crypto/Cargo.toml:16`),
    `rustynet-backend-wireguard` (`Cargo.toml:10`), and `rustynetd` (`Cargo.toml:17`);
    `[target.'cfg(windows)'.dependencies]` in `rustynet-control` (`Cargo.toml:23`) and
    `rustynet-relay` (`Cargo.toml:19`). Confirmed by section-aware read of all five manifests.
  - **Drift vs. catalog — the three ungated crates are not equally fixable.** Re-verification of
    every use site: `rustynet-crypto`'s sole reference is already
    `#[cfg(target_os = "windows")]`-gated (`crates/rustynet-crypto/src/lib.rs:16-19`; no other
    reference anywhere in the crate). `rustynet-backend-wireguard`'s sole reference is already
    `#[cfg(windows)]`-gated (`src/windows_command.rs:10-11`; nothing in `tests/`/`benches/`).
    But `rustynetd` consumes the crate **deliberately cross-platform**: the pure conversion fn
    `windows_adapter_snapshots_to_host_candidates` is compiled on every OS
    (`#[cfg_attr(not(target_os = "windows"), allow(dead_code))]`,
    `crates/rustynetd/src/dataplane_candidates.rs:237-240`) so its unit test
    (`dataplane_candidates.rs:626+`) runs on non-Windows hosts, and the test
    `dpapi_protect_stub_returns_err_on_non_windows` (`crates/rustynetd/src/key_material.rs:1690-1696`)
    exists specifically to prove the non-Windows DPAPI stub fails closed — it **requires**
    windows-native to compile on non-Windows. Target-gating `rustynetd` would delete a fail-closed
    guard test; the catalog's "needs matching guards" framing understates this.
  - `rustynet-cli` has **no** direct dependency on windows-native (grep of its `Cargo.toml`: zero
    hits) — it is ≥2 hops away (via `rustynetd`/`rustynet-crypto`/`rustynet-control`), yet is the
    workspace's largest crate (205,720 lines under `src/` excluding its 97 `src/bin/*.rs` targets;
    `rustynetd` is 85 files / 116,942 lines; root `Cargo.toml:74-77` documents `codegen-units=16`
    to avoid linker OOM on 2Gi lab VMs).
  - xtask's `--affected` is one-hop by deliberate design: doc comment
    (`crates/rustynet-xtask/src/main.rs:22-24`), implementation `compute_affected_set`
    (`main.rs:417-441` — direct crates + one reverse-dependency sweep, no fixpoint), and the pinned
    test `one_hop_only_no_transitive_explosion` (`main.rs:685-706`, asserting `cli` is *excluded*
    for a `leaf → daemon → cli` chain). Root-build-file changes already fall back to full workspace
    (`affected_scope`, `main.rs:351-357`).

- **Chosen approach:** Two independent, individually-shippable changes:
  1. **Move the windows-native dependency edge to `[target.'cfg(windows)'.dependencies]` in
     `rustynet-crypto` and `rustynet-backend-wireguard` only** — a two-line manifest change in each,
     zero Rust-code change (both crates' use sites are already fully cfg-gated, verified above).
     `rustynetd` **keeps** its unconditional edge, with a short manifest comment stating why (the
     cross-platform stub-fails-closed test and the universally-compiled adapter-snapshot conversion
     are deliberate); this is recorded as the intended end state, not a TODO.
  2. **Deepen `compute_affected_set` from one hop to the full transitive reverse-dependency
     closure**: replace the single sweep at `main.rs:435-440` with a worklist/fixpoint loop over the
     already-built `deps_of` map (the `cargo metadata` parse at `main.rs:358-397` needs no change).
     Rewrite `one_hop_only_no_transitive_explosion` into
     `transitive_closure_reaches_all_dependents` asserting `cli` **is** included for the
     `leaf → daemon → cli` model, and update the doc comments at `main.rs:22-28` and `336-339`.
     Keep the existing full-workspace fallbacks untouched.

- **Why this one:** Against the catalog's other candidates: the **abstract-types/FFI crate split**
  is a refactor of a security-relevant platform boundary (new manifests, moved types, §8 review)
  to save fingerprint churn that change (1) already eliminates for the two crates where it is
  literally free — poor cost/benefit until profiling shows the remaining `rustynetd` edge matters.
  **cargo-hakari** addresses third-party feature unification, not internal path-dep fan-out — wrong
  tool for this finding. On the `--affected` half, the catalog's own caveat ("full closure often
  *is* most of the workspace for low crates") is true but is an argument about *speed*, while the
  defect is *correctness*: today a developer trusting `--affected`'s PASS on a windows-native-only
  change gets zero signal about whether the shipped `rustynet-cli` binary still compiles. A scoped
  runner that silently under-tests is worse than one that is sometimes slower; for mid-graph crates
  (the common edit target) the closure remains much smaller than the workspace, so the speed win
  survives where it matters. These two candidates were genuinely close only in the sense that both
  are cheap — they fix different halves of the finding and both ship.

- **Cost / tradeoffs:** (1) is near-free; the one real risk is a latent non-Windows reference to
  windows-native appearing later in either crate — caught immediately by `cargo check` on any
  non-Windows host, and CI's macOS/Debian legs build exactly that. (2) makes `--affected` runs
  slower for edits to low/wide crates (`rustynet-crypto` edits will now correctly pull in
  `rustynet-cli`) — that is the point, but it does shrink the perceived benefit of `--affected` for
  exactly those crates; the honest posture is "scoped when safe, full when necessary." `rustynetd`'s
  unconditional edge remains, so editing windows-native still invalidates `rustynetd`→`rustynet-cli`
  fingerprints on every platform — this plan reduces, not eliminates, the fan-out (crypto's
  dependents `control`/`nas`/`cli` no longer rebuild through the crypto edge on non-Windows).

- **Constraint check:** No production Rust code changes at all in (1); (2) is dev-tooling only.
  The nearest excluded surface is the §8/§10.3 backend boundary (windows-native is an OS-boundary
  crate) — untouched: no types move, no cfg on Rust code changes, only manifest dependency-section
  placement. `scripts/ci/check_backend_boundary_leakage.sh` is unaffected. Not crypto, not key
  material, not privileged exec.

- **Incremental build path:**
  - Phase 1 (S): manifest change in `rustynet-crypto` + `rustynet-backend-wireguard`; verify with a
    bare `cargo build` **and** `cargo check --workspace --all-targets --all-features` on macOS
    (memory `vm_lab_command_gating_gotcha` documents why the bare default build must be checked
    separately, and CI covers the Linux leg).
  - Phase 2 (S): `compute_affected_set` fixpoint + test rewrite + doc-comment updates; run the
    xtask unit tests and one live `--affected` run on a windows-native-touching diff to confirm
    `rustynet-cli` now appears in the scope list.

- **How you'd know it worked:** (1) On a non-Windows host, `cargo tree -p rustynet-crypto` no
  longer lists `rustynet-windows-native`, and `touch crates/rustynet-windows-native/src/lib.rs &&
  cargo check -p rustynet-crypto` recompiles nothing windows-native-related. (2) A synthetic diff
  touching only `crates/rustynet-windows-native/` makes `--affected` print a scope containing
  `rustynet-cli`; the new unit test pins the closure semantics.

- **Prior art:** `rustynet-control`/`rustynet-relay`'s existing `[target.'cfg(windows)']` gating
  (the in-repo pattern being extended); cargo's own target-specific-dependency mechanism;
  `cargo metadata`-driven reverse-closure scoping as implemented by nextest's and bazel-style
  affected-target computation (full closure, never one hop).

---

## BLD-2: Adopt cargo-nextest as the test runner

- **Pipeline / area:** `crates/rustynet-xtask/src/main.rs` (test stage),
  `.github/workflows/cross-platform-ci.yml`, `scripts/ci/bootstrap_ci_tools.sh`; no crate code.

- **Current behavior (re-verified):** Zero "nextest" hits repo-wide. CI runs
  `cargo test --workspace --all-targets --all-features --locked` on all three legs
  (`cross-platform-ci.yml:25,54` and a scoped variant at `:145`); xtask's test stage is
  `with_scope(&["test"])` + `--all-targets --all-features` (`main.rs:139-140,173-186`), 5400s
  timeout chosen because the suite runs ~48-60min (`main.rs:35`). The workspace has 97
  `rustynet-cli/src/bin/*.rs` targets (25 containing `#[cfg(test)]` modules), 4 `rustynet-mcp`
  bins, 12 `[[bin]]` manifest entries elsewhere, and **6,761 `#[test]` functions** total (all
  re-counted this pass). `cargo test` runs the resulting ~100+ test binaries strictly one at a
  time (libtest parallelism is only *within* a binary). Measured evidence
  (`documents/operations/gate_timings.csv`, 357 rows): test stage 3912s (65min) cold at commit
  `231aa7f`, 213-256s warm/scoped. No `.cargo/config.toml` exists anywhere (no mold/lld/sccache) —
  confirmed; that adjacent gap is noted but not this finding's scope.

- **Chosen approach:** Adopt **cargo-nextest** as the *execution runner* for the workspace test
  stage, in three stages with a measurement gate:
  1. Pin a nextest version in `scripts/ci/bootstrap_ci_tools.sh` (install via
     `cargo install cargo-nextest --locked --version <pin>` or the prebuilt binary with checksum),
     and measure locally: `cargo nextest run --workspace --all-features` vs
     `cargo test --workspace --all-targets --all-features` on the same warm build, recording both
     wall-clocks. (Nextest builds and runs unit tests in lib *and* bin targets plus integration
     tests — the bin-target unit tests that dominate this workspace are covered; it does not run
     doctests, which is moot here because `--all-targets` already excludes doctests and neither CI
     nor xtask ever passes `--doc`.)
  2. Switch xtask's test stage args to `nextest run` + the same scope/feature args, preserving the
     existing process-group timeout watchdog unchanged (nextest is still one child process tree).
  3. Switch the three CI invocations, then update §7's fast-path notes (CLAUDE.md/AGENTS.md mirror)
     — `cargo test` **remains** the authoritative §7 gate definition; nextest is the runner the
     tooling uses, exactly as `xtask gates` already wraps the authoritative commands.
  **Retries stay off** (`--retries 0`, the default): auto-retrying flaky tests would mask real
  regressions, contradicting the repo's FAIL-LOUD evidence philosophy; flake classification is
  FIS-0006's job, not the runner's.

- **Why this one:** The catalog's alternatives lose on mechanism: **per-crate parallel `cargo test
  -p X` fan-out inside xtask** mostly serializes anyway — concurrent cargo invocations contend on
  the shared target-dir/build locks, and it reimplements scheduling + output aggregation nextest
  already does well; **splitting vm-lab bins out of the workspace** trades away the documented
  reason they are in-workspace ("CI gates run `--all-features`, so the lab code stays compiled and
  tested", CLAUDE.md §11.2) — a product-safety regression dressed as a speed win, rejected;
  **CI-level sharding** buys CI wall-clock only, not the local loop, and costs more machines. The
  workspace's shape — very many small test binaries — is nextest's exact best case (one global
  concurrent pool across binaries). The one honest counter-scenario the catalog names (per-test
  process-spawn overhead dominating on thousands of tiny tests) is precisely why Phase 1 is a
  measurement, not an assumption: if the measured win on this suite is <20% wall-clock, stop at
  Phase 1 and record the negative result in the catalog.

- **Cost / tradeoffs:** A new pinned external tool to install and keep updated on three CI legs and
  every dev/lab host that runs gates (bootstrap script handles CI; local devs get a clear error).
  Per-test process isolation changes semantics for any test relying on in-binary shared state
  (statics, `OnceLock` caches shared between `#[test]` fns) — usually *safer*, but a behavioral
  difference the Phase-1 run must diff for failures. Test output format changes (tooling that greps
  `cargo test` output — e.g. gate scripts asserting "N passed" — must be checked; the scoped
  single-test invocations in `scripts/ci/*_gates.sh` stay on plain `cargo test` and are untouched).
  Compile cost is unchanged — this fixes execution scheduling only.

- **Constraint check:** Pure dev/CI tooling; no production code path. Nearest boundary: §7 requires
  the gate definitions to remain individually invocable — preserved, `cargo test` stays the
  authoritative definition and nextest is an accelerated runner on top; the memory note that
  ops_phase1-style bin-target tests must actually run is covered because nextest enumerates
  bin-target unit tests. Not crypto/keys/ACL/privileged-exec/routing/DNS.

- **Incremental build path:**
  - Phase 1 (S): pin + install + side-by-side measurement on one host; diff pass/fail sets;
    record both timings in `gate_timings.csv` (distinct scope label).
  - Phase 2 (M): xtask test-stage switch behind the measurement's green light; keep
    `XTASK_TEST_TIMEOUT` semantics; verify the watchdog kills a hung nextest tree.
  - Phase 3 (S): CI legs + §7/§12 doc sync (AGENTS.md/CLAUDE.md mirror rule §14).

- **How you'd know it worked:** Same-commit warm-build comparison shows the test stage's
  wall-clock drop (target: ≥30% on the full suite, given ~100 serial binaries collapsing into one
  pool); identical test-set pass/fail (nextest's machine-readable list vs `cargo test`'s); the
  cold-build 65min figure in `gate_timings.csv` visibly shrinks on subsequent full runs.

- **Prior art:** cargo-nextest is the de-facto standard runner for large Rust workspaces
  (rust-analyzer, Oxide's omicron and its progenitor use it); in-repo precedent for
  "authoritative command stays, tooling wraps it" is `rustynet-xtask` itself (§7: "The individual
  commands above remain the authoritative gate definitions").

---

## BLD-3: Drop the standalone `check` stage; clippy is the single compile+lint pass

- **Pipeline / area:** `crates/rustynet-xtask/src/main.rs` (stage list),
  `.github/workflows/cross-platform-ci.yml` (three workspace-validation blocks).

- **Current behavior (re-verified):** xtask runs [fmt, check, clippy, test] strictly serially,
  each full-workspace `--all-targets --all-features` (`main.rs:145-186`), each stage a separate
  child process group with its own timeout (`run_stage`, `main.rs:207-245`); the ordering is
  documented as deliberate fail-fast (`main.rs:5-7`). Measured (`gate_timings.csv`): at clean-build
  commit `231aa7f`, check=626s and clippy=665s back-to-back on the identical tree — clippy reuses
  essentially nothing from check (different `RUSTC_WORKSPACE_WRAPPER` ⇒ different fingerprint
  bucket); warm same-commit reruns drop to 9s/11s. **Drift-adjacent fact the catalog did not
  surface:** CI's order is the *reverse* of xtask's — all three legs run
  `clippy` **before** `check` (`cross-platform-ci.yml:22-24,52-54`), so in CI the `check` pass
  cannot even claim the fail-fast rationale: it is a pure ~10-minute duplicate type-check of a tree
  clippy already fully compiled moments earlier.

- **Chosen approach:** Remove the `check` stage from xtask's `gates` stage list and delete the
  `cargo check --workspace --all-targets --all-features --locked` line from the three CI
  workspace-validation blocks. `cargo clippy ... -- -D warnings` becomes the single
  compile-correctness **and** lint gate in both runners. `cargo check` remains listed in §7 as an
  individually-invocable authoritative command (unchanged — it is still what a developer reaches
  for mid-edit, and `cargo check -p <crate>` remains the documented inner-loop step, §12.1/§13.1).
  Add one escape hatch: an xtask `--with-check` flag restoring the old stage order, documented as
  the fallback for a broken/poisoned clippy toolchain. Update the xtask doc comment and §7's
  fast-path description (AGENTS/CLAUDE mirror).

- **Why this one:** The empirical near-parity (626s vs 665s) is the decisive fact: clippy *is*
  rustc plus lint passes, so a compile error fails a clippy-only pipeline at approximately the same
  wall-clock point it fails `check` today (~6% later) — the documented fail-fast property is
  preserved in substance while ~10.5 minutes of duplicated cold-cache work per full run is
  eliminated outright. Against the runner-up, **running check ∥ clippy concurrently**: it saves
  wall-clock but zero CPU, doubles peak memory during the heaviest window — directly hostile to
  this repo's own documented constraint (2Gi lab VMs that already need `codegen-units=16` to link
  `rustynet-cli`, root `Cargo.toml:74-77`) — and requires reworking the one-process-group-per-stage
  timeout/kill design for two concurrent independently-killable children. That memory ceiling is
  the codebase-specific tiebreaker. **sccache** does not close the cross-wrapper cache miss (the
  wrapper is part of the key) and adds a daemon; **accept-and-only-optimize-`--affected`** leaves
  the CI-side duplicate untouched and (per BLD-1) `--affected` gives no benefit on the widest
  crates anyway.

- **Cost / tradeoffs:** A clippy-driver ICE or toolchain-version poison (a real occurrence here —
  memory note `toolchain_clippy_poison_2026-06-26`) would take out the runner's only compile gate;
  mitigated by `--with-check` and by `cargo check` remaining an authoritative standalone command.
  Error presentation changes slightly: compile errors now arrive interleaved with clippy lint
  output. Anyone whose muscle memory is "gates failed at check ⇒ type error, failed at clippy ⇒
  lint" loses that signal. CI wall-time saving is real but bounded (~10min/leg on cold cache; less
  on warm).

- **Constraint check:** Dev/CI tooling only. Nearest boundary: §7's requirement that
  fmt/check/clippy/test "remain individually-invocable authoritative gate definitions" — satisfied:
  no definition is removed or altered; only which commands the *runner and CI execute* changes,
  and the §7 doc edit says exactly that. Not crypto/keys/ACL/privileged-exec/routing/DNS.

- **Incremental build path:**
  - Phase 1 (S): xtask stage-list change + `--with-check` flag + doc-comment update; verify a
    seeded compile error still fails the (now-first) clippy stage promptly.
  - Phase 2 (S): CI yml edit on all three legs; observe one green run and one seeded-failure run.
  - Phase 3 (S): §7/§12.1 doc sync in CLAUDE.md + AGENTS.md (mirror rule §14), and record the
    before/after timings in `gate_timings.csv`.

- **How you'd know it worked:** `gate_timings.csv` rows for a clean build show the pre-test cost
  dropping from ~1292s (1+626+665) to ~666s (1+clippy) with the test stage unchanged; a deliberate
  type error in a scratch branch fails the pipeline at the clippy stage in comparable time to
  today's check stage; CI leg wall-clock drops by the former check duration.

- **Prior art:** Widely-adopted Rust CI convention of "clippy `-D warnings` as the single
  build+lint gate" (rust-analyzer, tokio CI run clippy without a separate check pass); in-repo
  precedent for pruning duplicate verification work is CLI-1's own catalog framing (preflight vs
  bootstrap double-verify) — same shape, tooling tier.

---

## CLI-2: Build-time rustc-version embedding in `rustynet-sysinfo`

- **Pipeline / area:** `crates/rustynet-sysinfo` (new `build.rs`, `src/lib.rs`);
  call site `crates/rustynet-cli/src/main.rs::execute_info`.

- **Current behavior (re-verified):** `execute_info` (`crates/rustynet-cli/src/main.rs:16654-16678`)
  calls `rustynet_sysinfo::rustc_version()` (`main.rs:16669`), which dispatches to one of **three
  byte-for-byte identical** per-OS `rustc_version_internal` copies
  (`crates/rustynet-sysinfo/src/lib.rs:1031-1040, 1042-1051, 1053-1062` — Linux/macOS/Windows all
  spawn `Command::new("rustc").arg("--version").output()`), so every `rustynet info` invocation
  pays a full subprocess exec for a fact fixed when the binary was built. The sole caller is
  `execute_info`. **Drift vs. catalog:** the catalog's claim of zero
  `OnceCell`/`OnceLock`/`LazyLock` hits across sysinfo/cli/rustynetd no longer holds for the wider
  set (`rustynet-cli/src/live_lab_stage_registry.rs:2140`, `rustynetd/src/windows_service.rs:466`,
  `rustynetd/src/key_material.rs:77` all use `OnceLock` now) — but it **does still hold for
  `rustynet-sysinfo` itself** (zero hits), which is the crate this finding targets. The crate has
  no `build.rs` today; the workspace's only build script is `crates/rustynet-mcp/build.rs`.
  The catalog's measurement (info ~16.9ms vs version ~3.9ms median, ≈4x from the one spawn) was not
  re-measured this pass (it requires a release build); the mechanism it measures is fully
  code-confirmed above and the plan does not depend on the exact ratio.

- **Chosen approach:** Add a minimal `build.rs` to `rustynet-sysinfo` that runs the compiler cargo
  itself provides — `Command::new(env::var_os("RUSTC").unwrap_or("rustc".into()))
  .arg("--version")` (argv-only, no shell, no network) — and emits
  `cargo:rustc-env=RUSTYNET_BUILD_RUSTC_VERSION=<trimmed stdout>` (empty on failure). Replace the
  three identical `rustc_version_internal` copies with one body returning
  `option_env`-style logic over the embedded constant:
  `pub fn rustc_version() -> Option<String>` keeps its signature and returns
  `Some(env!("RUSTYNET_BUILD_RUSTC_VERSION").to_owned())` filtered for non-empty. `execute_info`
  needs no change. Also emit `cargo:rerun-if-env-changed=RUSTC` so toolchain switches rebuild the
  constant.

- **Why this one:** The catalog's three families resolve cleanly here. **Process-lifetime
  `OnceLock` memoization** was checked concretely and has *nothing to memoize across*: no
  `execute_*` function calls any `rustynet_sysinfo` function twice in one invocation (re-confirmed
  for `rustc_version`: single caller), and the CLI is a short-lived process — the cache would be
  populated and thrown away once per run, saving nothing. **Short-TTL on-disk cache** adds a
  staleness window and filesystem state for a diagnostic nicety — disproportionate machinery.
  Build-time embedding is also the *semantically correct* answer, and this is worth stating as a
  deliberate behavior change rather than a silent one: today the command reports the rustc found on
  the **host running the CLI** at invocation time (absent entirely on a deployed node with no
  toolchain); after the change it reports the toolchain that **built the artifact** — which is what
  an `info` line about the binary should say, and it now appears on toolchain-less deployment hosts
  where today it vanishes. A dedicated dependency (`vergen`/`built`) buys nothing over five lines
  of `build.rs` and adds supply-chain surface — rejected under this repo's conservative dependency
  posture. `git_version()` (also spawned by `execute_info`) is deliberately left alone: "is git
  available on this host" is a genuine runtime host fact, not a build-time one — outside this
  finding's mechanism.

- **Cost / tradeoffs:** Every crate gains one build-script execution per cold build of
  `rustynet-sysinfo` (negligible; one rustc spawn at build time instead of every info call at run
  time). A `build.rs` is a new artifact class in this crate — reviewers must check it stays
  network-free and argv-only. The reported string changes meaning as described above (documented,
  intended). Cross-compilation nuance: `RUSTC` reports the host-invoked compiler driver, which for
  this workspace's build flows (native + lab-guest builds) is the toolchain of record.

- **Constraint check:** No trust/security state involved; the nearest boundaries are §4's
  argv-only-exec convention (kept — `build.rs` execs argv-only, no shell) and "no network during
  build" (kept — local compiler only). Not crypto/keys/ACL/privileged-exec/routing/DNS.
  `unsafe_code = forbid` unaffected.

- **Incremental build path:**
  - Phase 1 (S): `build.rs` + single `rustc_version_internal` + deletion of the two duplicate
    cfg copies; unit test asserting `rustc_version()` returns a non-empty string starting with
    `"rustc "`; `cargo run -p rustynet-xtask -- gates --skip-test -p rustynet-sysinfo`.
  - (No further phases — deliberately small.)

- **How you'd know it worked:** `strace`/`dtruss` (or a debug log around the call) shows zero
  `execve` of `rustc` during `rustynet info`; re-running the catalog's hyperfine comparison shows
  `info` converging toward the `version` baseline (~4x gap closed); the info line is now present
  when the binary is copied to a host with no rustc installed.

- **Prior art:** `vergen`/`built` crates (same mechanism, done inline instead);
  `crates/rustynet-mcp/build.rs` as the in-repo build-script precedent; cargo's documented
  `cargo:rustc-env` contract.

---

## CLI-3: Concurrent diagnostics probes + one interface-enumeration implementation

- **Pipeline / area:** `crates/rustynet-sysinfo/src/diagnostics.rs` (probe fan-out),
  `crates/rustynet-sysinfo/src/lib.rs` (`network_interfaces_internal`, `iface_list_internal`);
  CLI callers `execute_diagnostics`/`execute_iface_list` (`rustynet-cli/src/main.rs:18623, 17672`).

- **Current behavior (re-verified):**
  - **Sequential probes:** `observe_with` (`diagnostics.rs:333-342`) fills all six
    `DiagnosticsReport` fields in one struct literal calling `observe_interfaces` /
    `observe_routes` / `observe_dns` / `observe_listening_sockets` / `observe_firewall` /
    `observe_service` strictly in sequence on one thread; on macOS each is its own allowlisted
    subprocess (`READ_ONLY_COMMANDS`, `diagnostics.rs:95-112`) bounded by
    `DEFAULT_COMMAND_TIMEOUT = 3s` (`diagnostics.rs:74`); on Linux the interfaces probe is
    subprocess-free sysfs reading (`diagnostics.rs:386-388`). No field depends on another —
    the ordering is an artifact. (The catalog's ~155-160ms-vs-3.9ms measurement was not re-run
    this pass; the sequential-composition mechanism it measures is confirmed above.)
  - **Triplicated enumeration:** three separately-maintained interface enumerations exist in the
    crate and have already drifted: `network_interfaces_internal` (`lib.rs:1391-1432`; Linux sysfs,
    macOS `ifconfig`, Windows `ipconfig`; no MTU field at all), `iface_list_internal`
    (`lib.rs:3223-3341`; a second sysfs reader with MTU-default **1500**, a second macOS `ifconfig`
    parser that looks for `"HWaddr "` — a token macOS `ifconfig` does not emit (`ether ` is the
    real token), so its `mac_address` is silently always `None` on macOS — and a Windows
    **powershell Get-NetAdapter** path), and `diagnostics.rs`'s `observe_interfaces` family
    (`interface_details_from_sysfs_root` at `diagnostics.rs:357-384` with MTU-degrade-to-**0**
    semantics, `parse_ifconfig_interface_details` at `:398+` with fixture + malformed-input
    fail-safe tests, Windows `netsh`). Note also: the two `lib.rs` variants call
    `Command::new(...).output()` raw — **no timeout at all** — while the diagnostics module runs
    everything through the bounded, allowlisted `CommandRunner`.

- **Chosen approach:** Two changes, independently shippable:
  1. **Probe fan-out with `std::thread::scope`** in `observe_with`: spawn one scoped thread per
     probe, join all six, assemble the same `DiagnosticsReport`. Signature change:
     `observe_with(runner: &(dyn CommandRunner + Sync))` (add `Sync` to the trait object bound —
     `SystemCommandRunner` is stateless; test fakes must be checked for `Sync` at implementation
     time and adjusted with interior-mutability-free designs or a mutex if any records calls).
     Per-probe 3s timeout semantics are untouched; worst-case wall time collapses from Σ(probes)
     to max(probe).
  2. **Consolidate enumeration onto the diagnostics-module implementations** (the best-tested of
     the three: fixture + fail-safe tests, bounded runner): make `iface_list_internal` a thin
     wrapper over `interface_details_from_sysfs_root` / `parse_ifconfig_interface_details` via the
     bounded runner, and make `network_interfaces_internal` convert from the same
     `InterfaceDetail` results to its `NetworkInterface` shape at the edge. Linux + macOS first
     (identical data sources, pure dedup); Windows converges on the allowlisted
     `netsh interface ipv4 show interfaces` path, replacing the un-allowlisted
     `ipconfig`/`powershell -Command` spawns — recorded as a deliberate tool change with its own
     test fixtures.

- **Why this one:** For the fan-out, the catalog's alternative — extracting more fields from fewer
  tool invocations — reduces spawn *count* but couples parsers to combined output formats and
  still sums latencies; threads-per-probe is smaller, keeps each parser single-purpose, and
  `CommandRunner` is already the right seam. An async runtime would be wildly disproportionate for
  six blocking calls in a CLI. For the consolidation, direction matters: diagnostics' versions win
  because they already carry the parse/IO split convention, fixture tests, malformed-input
  fail-safe tests, the 3-second bound, and the read-only allowlist — consolidating the other way
  would spread the *worst* copies (the macOS `HWaddr` parser is live evidence of what
  unshared parsers do over time: it is a real bug this change deletes as a side effect, and the
  MTU-default drift `1500` vs `0` gets resolved to the documented degrade-to-0 semantics).
  These two sub-changes are close to independent; both ship because each fixes a distinct half of
  the finding (latency; drift).

- **Cost / tradeoffs:** Six short-lived threads per diagnostics call (trivial for a CLI; bounded).
  The `Sync` bound is a small public-API change inside the crate. Consolidation changes observable
  output in the drifted corners: `iface_list` on macOS starts reporting real MACs (was always
  `None`), MTU-default moves from fabricated 1500 to explicit 0-degrade, Windows switches
  enumeration tool — callers are human-facing diagnostic commands, but the changes must be
  release-noted, and the Windows tool change needs its own fixtures. Slightly higher instantaneous
  process load (six probes at once) on constrained hosts — bounded by probe count, not mesh size.

- **Constraint check:** Read-only observation surface: the `READ_ONLY_COMMANDS` allowlist and its
  mutating-verb-rejection tests (`diagnostics.rs:89-112` + tests) are untouched and *gain* two
  callers currently outside them. Nearest excluded surface is privileged subprocess execution —
  not implicated: every command here is unprivileged and read-only; concurrency uses
  `std::thread::scope` (safe Rust, `unsafe_code=forbid` holds). Not crypto/keys/ACL/routing/DNS.

- **Incremental build path:**
  - Phase 1 (S): thread-scope fan-out + `Sync` bound + a test with a deliberately-slow fake runner
    asserting wall-clock ≈ max not Σ.
  - Phase 2 (M): Linux+macOS enumeration consolidation with output-shape conversion + tests
    pinning the (intentionally) changed macOS MAC behavior.
  - Phase 3 (S/M): Windows convergence onto `netsh` with fixtures; delete the powershell/ipconfig
    spawns.

- **How you'd know it worked:** Re-run the catalog's measurement: `rustynet diagnostics` median
  drops from ~155-160ms toward the slowest single probe (~25-30ms + overhead) on the same host;
  grep confirms exactly one sysfs reader and one `ifconfig` parser remain in the crate; the new
  fake-runner test fails if anyone reverts to sequential composition.

- **Prior art:** FIS-0018/FIS-0011's fire-all-then-collect STUN redesign (same
  serial-sum→max-of-N shape, same repo); `std::thread::scope` (stabilized Rust 1.63) as the
  canonical bounded fan-out for blocking I/O.

---

## RLY-1: Zero-allocation hot path in `RateLimiter::check_packet`

- **Pipeline / area:** `crates/rustynet-relay/src/rate_limit.rs` (`check_packet`);
  call site `crates/rustynet-relay/src/transport.rs::forward_packet`.

- **Current behavior (re-verified):** `RateLimiter.buckets: HashMap<String, TokenBucket>`
  (`rate_limit.rs:8-14`); `check_packet` is
  `self.buckets.entry(node_id.to_owned()).or_insert_with(...)` (`rate_limit.rs:28-35`) —
  `HashMap::entry` takes the key by value, so the `&str → String` heap allocation + copy happens on
  **every** forwarded frame before the lookup runs, bucket-exists or not. Sole hot caller:
  `forward_packet` (`transport.rs:506`, the per-datagram path; rate-limit call at
  `transport.rs:543-548`), reached from the per-session tokio forward task under
  `transport.write().await` (`main.rs:597-605`). The same-file precedent the catalog cites is
  confirmed live: `RelaySession.paired_session_id` is a cached `Copy` id revalidated with
  plain `&str` comparisons precisely to avoid per-frame owned-key rebuilds (`transport.rs:315`,
  fast path `:560-571`, fallback + cache-fill `:572-601`). Adjacent cold sites re-verified: the
  cleanup-tick prune builds `HashSet<String>` by cloning every session's node_id
  (`transport.rs:679-684`) feeding `retain_active_nodes` (`rate_limit.rs:47-53`); the per-hello
  session-count check is at `transport.rs:421-427`. The relay perf instrumentation exists:
  `examples/perfprobe_relay.rs` with `rustynet-alloc-meter` (`perfprobe_relay.rs:22-23,81-95`);
  `DataplanePerfBacklog §1.5` recorded this allocation as the forward loop's last alloc/op.

- **Chosen approach:** Two-phase borrowed-key lookup, std-only:
  ```rust
  pub fn check_packet(&mut self, node_id: &str, packet_size_bytes: usize) -> bool {
      if !self.buckets.contains_key(node_id) {
          self.buckets
              .insert(node_id.to_owned(), TokenBucket::new(self.max_pps, self.max_bps));
      }
      let bucket = self
          .buckets
          .get_mut(node_id)
          .expect("bucket inserted above"); // or restructure to avoid expect, see below
      bucket.check_and_consume(1, packet_size_bytes * 8)
  }
  ```
  written in the `if let Some(bucket) = self.buckets.get_mut(node_id)` early-return form so no
  `expect` appears at all (§10.2): hot path = one `get_mut(&str)` via `Borrow<str>`, zero
  allocation; cold path (first frame of a new node_id) = one `to_owned` + insert, once per
  distinct node_id per bucket lifetime. Phase 2 (optional, same file): the cleanup-tick prune
  borrows instead of cloning — collect `HashSet<&str>` from `self.sessions` into a local, then
  call `self.rate_limiter.retain_active_nodes(...)` (disjoint field borrows make this compile
  without restructuring).

- **Why this one:** It is the catalog's own "smallest possible diff, no new supply-chain surface"
  option, and the alternatives lose concretely: **hashbrown raw-entry** would promote a transitive
  dep to direct for an API that is historically unstable-surface even within hashbrown — real
  supply-chain/maintenance cost to save one hash-recompute per cold insert (the two-phase form
  double-hashes only on the once-per-node cold path, which is noise); **the interned `Copy`
  handle** (the `paired_session_id`-style fix) removes even the cold-path alloc but touches
  session lifecycle, hello handling, and bucket pruning, and carries the catalog's own flagged
  semantic hazard (keying by `SessionId` instead of node would fragment the shared-per-node bucket
  across up to 8 sessions — a rate-limit weakening if fumbled) — that risk buys nothing measurable
  over the two-phase form, whose hot path is already zero-alloc; **`Arc<str>` node ids** thread a
  type change through ~a dozen comparison sites for the same end state. Two-phase wins on risk
  and diff size with an identical steady-state profile.

- **Cost / tradeoffs:** The cold path hashes the key twice (contains/get + insert) — once per new
  node_id ever, irrelevant. The `entry()` idiom's elegance is lost; a comment must explain *why*
  the two-phase form exists (borrowed-key hot path) so a future cleanup doesn't "simplify" it back
  to `entry(to_owned())`. No semantic change: bucket stays keyed by node_id (shared across a
  node's sessions), pruning contract unchanged.

- **Constraint check:** Explicitly does not touch `TokenBucket::check_and_consume`/`refill` (the
  rate-limit math) — the nearest security-adjacent surface, named per the catalog's own note; the
  change is purely how the bucket is *found*. No unwrap/expect in the final form (§10.2). Relay is
  transport-layer; no backend/domain boundary involved. Not crypto/keys/ACL/privileged-exec/
  routing/DNS.

- **Incremental build path:**
  - Phase 1 (S): rewrite `check_packet`; existing `rate_limit.rs` unit tests must pass unchanged
    (behavioral identity); add one test asserting a pre-existing bucket is found via `&str` (e.g.
    bucket_count stays 1 across repeated `check_packet` calls with the same id — already implied
    by existing tests, made explicit).
  - Phase 2 (S, optional): borrow-based prune at `transport.rs:679-684`.

- **How you'd know it worked:** `cargo run --release -p rustynet-relay --example perfprobe_relay`
  shows steady-state allocs/op drop from ~1 to 0 in the forward loop (the exact instrument that
  found the issue, `DataplanePerfBacklog §1.5`); `cargo test -p rustynet-relay` green with no test
  edits needed beyond the one addition.

- **Prior art:** `RelaySession.paired_session_id` in the same file (avoid-owned-key-per-frame,
  `transport.rs:560-601`); std's documented `Borrow<str>` lookup contract for `HashMap<String,_>`;
  the get-or-insert two-phase idiom used throughout rustc/servo codebases pre-raw-entry.

---

## CCY-3: Delete the dead `DaemonRuntime` gossip shadow fields

- **Pipeline / area:** `crates/rustynetd/src/daemon.rs` (`DaemonRuntime` struct + five mirror
  sites); canonical owner `crates/rustynetd/src/gossip_runtime.rs::GossipNode` (untouched).

- **Current behavior (re-verified, with material drift from the catalog):** `GossipNode` owns the
  canonical state (`gossip_runtime.rs:170-173`: `gossip_sequence`, `seen_gossip_sequences`,
  `last_minted_bundle`, `next_gossip_mint_at` — **four** fields, not the catalog's three).
  `DaemonRuntime` declares private shadow copies of the same four (`daemon.rs:3704-3707`,
  initialized `:4091-4094`) and mirrors them back at **five** sites: `attach_gossip_runtime`
  (`:5156-5159` — itself `#[allow(dead_code)]` with zero production callers, per its own comment),
  `drain_gossip_inbound` (`:5201-5204`, the "mirror the canonical state back ... so status queries
  and other call sites that read these fields see the latest values" comment), `maybe_run_gossip_mint`
  (`:5232-5235`), a gossip-ingest IPC handler (`:7893`), and the enrollment-consume handler
  (`:7985-7986`). **The decisive re-verification finding: the shadow fields have zero readers.**
  Exhaustive grep of every access to the four fields across `crates/rustynetd/src` and
  `crates/rustynetd/tests`: all 15 `self.<field>` hits in `daemon.rs` are assignments; no
  expression-position read exists anywhere (the one test hit,
  `tests/gossip_three_peer_mesh.rs:275`, reads `GossipNode`'s own field directly). The mirror
  comment describes readers that do not exist. Why no lint ever caught it: rustc's `dead_code`
  lint treats a field *assignment* as a use — verified this pass with a scratch compile (a
  write-only private field produces no warning) — so `-D warnings` structurally cannot flag this
  class of dead state.

- **Chosen approach:** Delete the four shadow fields, their initializers, and all five mirror
  blocks outright. No reader redirection is needed (there are none). Should a status/IPC read for
  any of these values be wanted later, it is added as an accessor delegating to
  `self.gossip_node.as_ref()` — a one-line pattern noted in a comment where the fields used to be,
  so the next author reaches for the canonical owner instead of re-growing a mirror.

- **Why this one:** The catalog's first candidate ("single source of truth: delete the shadows,
  read through `gossip_node`") was chosen there on hygiene grounds; re-verification makes it
  strictly stronger — there is no refactor of readers to do, only dead state to remove, which
  collapses the cost side of the comparison to near-zero. The other candidates dissolve:
  **ArcSwap/watch publish-subscribe** solves a cross-thread publication problem that does not exist
  (the daemon is single-threaded here, CCY-1) and would preserve machinery for readers that don't
  exist; **persistent collections (`im`/`rpds`)** optimize a clone the deletion removes entirely —
  the catalog itself listed it only for completeness. Deletion also removes the per-loop-pass
  `SeenSequenceState` HashMap clone + `GossipBundle` clone (up to ~40/sec when idle via
  `drain_gossip_inbound`) — a small real saving the catalog honestly declined to call a
  bottleneck; the correctness win (no silently-stale second copy, and the compiler now hard-errors
  E0609 on any future accidental shadow read) is the actual point.

- **Cost / tradeoffs:** Almost none — the risk is a hidden reader this pass's grep missed (e.g.
  macro-generated access); mitigated by the compiler itself: after deletion, any surviving reader
  fails the build. History loses the "mirroring the user spec verbatim" struct-comment intent
  (`daemon.rs:3695-3703`) — the replacement comment should record that the spec's fields live on
  `GossipNode` and were de-duplicated deliberately.

- **Constraint check:** The catalog's own note holds on re-read: `seen_gossip_sequences` /
  `last_minted_bundle` are already-verified in-memory caches downstream of signature/replay
  checks (`ingest_inbound_bundle` does the verification inside `GossipNode`) — the trust boundary
  is untouched; this deletes an unused copy, not a check. Nearest excluded surface is signature
  verification (gossip ingest) — not modified. Not crypto/keys/ACL/privileged-exec/routing/DNS.

- **Incremental build path:**
  - Phase 1 (S): delete fields + initializers + five mirror blocks; `cargo check -p rustynetd`
    proves zero readers existed; full `cargo test -p rustynetd` + the gossip integration test
    (`gossip_three_peer_mesh`) green.
  - (No further phases.)

- **How you'd know it worked:** The build itself is the proof (E0609 would name any reader);
  `grep -c "seen_gossip_sequences" crates/rustynetd/src/daemon.rs` drops to 0; gossip integration
  tests unchanged and green; a follow-up `drain_gossip_inbound` read of the loop shows no clone
  calls remaining after ingest.

- **Prior art:** In-repo: the `MeshStatus` validator false-green lesson (memory note
  `mesh_traffic_investigation_2026-06-26`) — state that exists but is not actually consulted is a
  standing trap; external: the "make illegal states unrepresentable" school (single ownership over
  mirrored state, Rust API guidelines).

---

## WIN-3: `TCP_NODELAY` + small-frame write coalescing in llm-gateway and nas

- **Pipeline / area:** `crates/rustynet-llm-gateway/src/main.rs` (accept loop `:71-87`,
  `write_frame` `:515-520`, `stream_completion` `:413+`); `crates/rustynet-nas/src/main.rs`
  (accept loop `:111-116`, `write_frame` `:414-419`).

- **Current behavior (re-verified):** Zero `set_nodelay`/`TCP_NODELAY` hits in either crate — in
  fact zero in the entire `crates/` + `third_party/` tree, so Nagle stays enabled on every
  accepted session. Both daemons' `write_frame` issues two separate `write_all` calls per frame
  (4-byte big-endian length, then body — llm `main.rs:515-520`, nas `main.rs:414-419`).
  llm-gateway streams one frame per token fragment (`stream_completion`, `Event::Token` write at
  `main.rs:479`) with the per-fragment enforcement re-check between events (`:463-478`) — the
  load-bearing mid-stream severance property. Both daemons are thread-per-connection
  (`std::thread::spawn` at llm `:77`, nas `:116`). Also re-confirmed: llm-gateway wires
  `MockEngine` unconditionally and has no HTTP client dependency, so the catalog's "connection
  pooling can't be graded yet" half remains true — that half is recorded as N/A-for-now here,
  matching the catalog, and no pooling work is planned.

- **Chosen approach:** Two coupled changes, applied identically in both daemons:
  1. `stream.set_nodelay(true)` immediately after accept (log-and-continue on error — a failed
     setsockopt must not kill the session), llm `main.rs:73-77` and nas `main.rs:113-116`.
  2. Coalesce small frames into one write: `write_frame` builds a single
     `Vec<u8>` of `4 + body.len()` and issues one `write_all` when
     `body.len() <= FRAME_COALESCE_MAX` (proposed 8 KiB — covers every llm event and all nas
     control-plane frames), and falls back to the existing header-then-body pair above the
     threshold (nas data chunks are ≤4 MiB by protocol; copying 4 MiB per frame to save a 4-byte
     segment would be a net loss).
  These are one change, not two: with Nagle *on*, the kernel hides the two-write split by
  coalescing; enabling nodelay *without* coalescing would make the split strictly worse (the
  4-byte length prefix departs as its own segment on every frame). Ship them together.

- **Why this one:** Against the catalog's candidates: **`write_vectored`** avoids the small copy
  but stable std has no `write_all_vectored`, so a correct implementation needs a manual
  partial-write loop — more code for a copy that is ≤8 KiB on the coalesced path; the scratch-Vec
  form is simpler and the copy is noise next to the syscall it eliminates. **Async
  `Stream`/reqwest-based engine rework** is explicitly out of scope (the catalog itself scoped it
  out; no real engine exists to pool against). **Sync HTTP client selection for the future
  engine** is premature for the same reason. On the nodelay tradeoff the catalog flags
  (more, smaller packets vs. bandwidth-conscious mobile posture): the coalescing half is what
  neutralizes it — after (2), one token event = one write = at most one small segment, which is
  the *same* packet count Nagle would eventually emit, minus the added RTT-coupled delay; the
  bandwidth cost of nodelay is therefore bounded to the genuine per-event packet, not a regression
  multiplier. nas gets nodelay too for uniformity and for its small control frames; its bulk
  chunks already exceed segment size, so the effect there is neutral — stated honestly rather
  than claimed as a win.

- **Cost / tradeoffs:** Latency-vs-bandwidth: on paths where multiple token events arrive within
  one RTT, Nagle *was* merging them into fewer segments; nodelay+coalescing sends one segment per
  event — more packets on chatty streams, the real price paid for removing the Nagle/delayed-ACK
  stall. One extra copy (≤8 KiB) per coalesced frame. A new constant to document
  (`FRAME_COALESCE_MAX`). No protocol change — bytes on the wire are identical, only their
  segmentation/timing changes.

- **Constraint check:** The per-frame identity/enforcement re-checks between emitted events
  (llm `main.rs:463-478` — the §4-adjacent mid-stream revocation-severance property the catalog
  names as load-bearing) are not touched; nothing here reorders or batches *across* events, only
  within a single frame's header+body. Tunnel-only bind validation untouched. Not
  crypto/keys/ACL/privileged-exec/routing/DNS; std-only.

- **Incremental build path:**
  - Phase 1 (S): both `write_frame`s + both accept sites + unit test for the coalescing threshold
    (frame bytes identical either path — encode/decode round-trip across the boundary).
  - Phase 2 (S, evidence): a loopback-with-`tc netem`-delay measurement (or lab two-node run)
    timing first-token-to-last-token spacing on a streamed completion before/after — the
    Nagle stall is invisible on bare loopback, so the measurement must add RTT.
  - (Engine pooling: no phase — N/A until a real engine client exists.)

- **How you'd know it worked:** Under injected RTT (e.g. 50ms netem), per-token inter-arrival at
  the client drops from RTT-coupled (~stalled on ACK) to production-rate; `ss -i`/packet capture
  shows no 4-byte-only segments on the coalesced path and `nodelay` set on the session; nas
  chunk-transfer throughput unchanged (regression guard).

- **Prior art:** Universal practice in latency-sensitive streaming servers (gRPC, redis, SSH all
  set TCP_NODELAY and coalesce writes); in-repo, the relay's zero-copy forward pass
  (`DataplanePerfBacklog §1.5`) as the same "remove per-frame overhead" discipline one tier down.

---

## NAT-3: One shared STUN gather core; retry ladder for every path

- **Pipeline / area:** `crates/rustynetd/src/stun_client.rs` (canonical module),
  `crates/rustynetd/src/traversal.rs::CandidateGatherer` (delegates),
  callers `crates/rustynetd/src/daemon.rs::poll_stun_results` (`:5339-5384`) and
  `crates/rustynetd/src/dataplane_candidates.rs::gather_srflx_for_family` (`:357`).

- **Current behavior (re-verified):** Three gathering paths, exactly as cataloged:
  1. `CandidateGatherer::query_stun_servers_batched` (`traversal.rs:296+`, FIS-0011): fire-all,
     single demux receive loop, **with** RTO retransmit ladder (`STUN_INITIAL_RTO=250ms`
     `traversal.rs:419`, `STUN_MAX_REQUEST_ATTEMPTS=3` `:422`), own hand-written STUN wire format.
  2. `StunClient::gather_mapped_endpoints_batched` (`stun_client.rs:122-194`, FIS-0018): an
     independent reimplementation of fire-all + demux-by-source+tx-id, **no retransmit ladder** —
     each server sent exactly once (`:136`); one lost datagram silently forfeits that server for
     the cycle. Production caller: `dataplane_candidates.rs:357`.
  3. `StunClient::gather_mapped_endpoints_with_round_trip` (`stun_client.rs:198-240`):
     sequential by documented invariant — "the authoritative round-trip transport is a hard
     singleton (queries must stay sequential)" (`:212-217`) — mitigated by `per_server_slice()` =
     timeout/N (`:278-281`). Production caller: `poll_stun_results` (`daemon.rs:5363-5372`),
     driving `Phase10Controller::authoritative_transport_round_trip` (`phase10.rs:5952-5961`) into
     the userspace-shared worker's one-in-flight request/reply slot
     (`userspace_shared/runtime.rs:241-256`, `acquire_round_trip_slot` + `round_trip_in_flight`).
  The wire format already has a designated canonical home: `rustynet-netns-probe` is byte-pinned
  to `stun_client.rs` (CLAUDE.md §11.2), which fixes the direction of consolidation.

- **Chosen approach:** Consolidate + harden, deferring true multiplexing:
  1. **Extract one shared gather core into `stun_client.rs`** (the pin target): a
     `StunGatherCore` (or free-function set) owning tx-id generation, binding-request build,
     response parse, the fire-all/demux-by-source+tx-id receive loop, **and** the FIS-0011 RTO
     ladder (250ms initial, doubling, ≤3 sends, shared deadline) — parameterized over the existing
     `StunQuerySocket` trait. `gather_mapped_endpoints_batched` becomes a thin call into it
     (path 2 thereby *gains* the retransmit ladder); `CandidateGatherer::query_stun_servers_batched`
     delegates to the same core (adapting its socket type to `StunQuerySocket`), deleting
     traversal.rs's duplicate wire format and scheduler.
  2. **Give the serial path (3) the same per-attempt ladder inside each server's slice**: within
     `per_server_slice()`, issue up to `STUN_MAX_REQUEST_ATTEMPTS` round-trips with the RTO
     schedule (each `round_trip` call already takes a timeout argument — pass the RTO instead of
     the whole slice) so one dropped datagram no longer forfeits a server's entire slice. The
     sequential structure and the singleton invariant are **preserved untouched**.
  3. **Record true tx-id multiplexing over the singleton transport as a deferred L follow-up**,
     with the concrete blocker named: it requires redesigning the worker's request/reply protocol
     (`RuntimeRequest::AuthoritativeRoundTrip` + the one-in-flight slot) into pending-transaction
     bookkeeping inside the dataplane worker loop — risk concentrated in the mission-canonical
     transport for a latency win that FIS-0018's budget-slicing already bounds to ≤ one configured
     timeout total.

- **Why this one:** The finding is two-headed (serial path; drifted duplicates), and the heads
  have very different risk profiles. The **drift** head is a pure win to fix now: the
  loss-fragility of path 2 is a correctness-under-loss defect the shared core erases, and
  consolidation is what prevents the *next* silent divergence (the mechanism by which this finding
  arose). The **serial** head's full fix (multiplexing) concentrates its entire risk in the
  userspace-shared worker — the hot dataplane pump — to shave a worst case already hard-bounded by
  budget slicing, and the improvement is invisible in the same-LAN lab this repo proves against;
  by this repo's economics (hardened one-path-per-workflow, live-proven evidence) that is a
  deferral, not a rejection — the section records it with its blocker so a future pass starts from
  the real constraint. Health-ordered server ranking (catalog candidate 2) was rejected: it adds
  persistent state to improve only the common case, which the ladder + slicing already make
  acceptable, and it does nothing for loss. This is the one finding where the runner-up
  (multiplexing) is genuinely close on paper; the tiebreaker is where the risk lands — a
  drifted-duplicate cleanup risks parse regressions caught by fixtures, while a worker-protocol
  redesign risks the packet path.

- **Cost / tradeoffs:** Path 2's gather can now send up to 3× the datagrams per cycle under loss
  (bounded, tiny — 20-byte requests). Path 3's per-server slice is subdivided by the ladder, so
  against a *slow but responsive* server the effective first-attempt wait shrinks (an RTO-sized
  window instead of the full slice) — a server with RTT > 250ms now needs the retransmit to
  answer; the RFC-shaped doubling ladder makes this converge, but it is a real behavior change to
  test against high-latency fixtures. Consolidation is a moderate intra-crate refactor with
  byte-format-identical output required (the netns-probe pin and the existing fixture tests are
  the safety net). The serial-sum latency itself is only mitigated, not eliminated — stated
  plainly.

- **Constraint check:** STUN here is unauthenticated public candidate discovery — no
  crypto/keys/signatures involved. The load-bearing invariant the catalog names — the srflx
  candidate must reflect the exact socket carrying peer traffic, which is why path 3 exists — is
  preserved by construction (the sequential singleton round-trip is untouched structurally).
  Nearest excluded surface: none closer than the dataplane worker, which this plan deliberately
  declines to touch (that is the deferred phase's whole point). Not
  ACL/privileged-exec/routing/DNS.

- **Incremental build path:**
  - Phase 1 (M): extract the shared core into `stun_client.rs` + migrate path 2 onto it (ladder
    gained); port the existing stun_client and traversal fixture tests to the core; add a
    drop-first-datagram fake-socket test proving path 2 now survives single-loss.
  - Phase 2 (S): migrate `CandidateGatherer` onto the core; delete traversal.rs's duplicate wire
    format; determinism tests pin identical candidate output on an all-responsive fixture.
  - Phase 3 (S): per-attempt ladder inside path 3's slice + a slow-server fake-round-trip test.
  - Phase 4 (L, deferred, needs a design decision): worker-protocol multiplexing, gated on
    evidence that the bounded serial gather is actually observed hurting reconnect latency on a
    real cross-network path.

- **How you'd know it worked:** Grep shows one STUN wire-format implementation in `rustynetd`;
  the new single-loss test fails on the pre-change path-2 code and passes after; a fake round-trip
  transport with one dead server shows path 3's total gather ≤ timeout with the other servers
  answered (unchanged) and a lossy-but-alive server now producing a candidate (new); netns-probe's
  byte-pin tests stay green.

- **Prior art:** FIS-0011 (the in-repo RTO ladder being generalized — RFC 5389/8489 §7.2.1
  retransmission, sized down); FIS-0018 (the budget-sliced serial fallback this plan hardens
  rather than replaces); the netns-probe wire-pin convention (CLAUDE.md §11.2) fixing the
  canonical module.

---

## CCY-1 (narrow): Write timeout on the Unix admin-IPC response path

- **Pipeline / area:** `crates/rustynetd/src/daemon.rs` — `write_response` (`:14806-14811`) and
  its single call site in `run_daemon`'s Unix IPC accept block (`:10071`).
  **Scope note:** per the task boundary, only the write-timeout half of the catalog's CCY-1 is
  planned here; the message-passing/thread-decomposition candidates touching the daemon's
  reconcile/trust-apply ordering are explicitly not designed in this pass.

- **Current behavior (re-verified):** The accept block (`daemon.rs:10007-10075`, directly inside
  `run_daemon`) sets a 2s read timeout on accept (`:10009-10013`); `read_command_envelope`
  re-sets it to 5s (`:14797-14803`); the response is written by `write_response` —
  `stream.write_all(...)` on the `UnixStream` with **no write timeout configured anywhere**
  (`:14806-14811`). The crate's `set_write_timeout` precedents are exactly where the catalog
  said: the anchor bundle-pull TCP stream (`:1183-1195`, 2s read + 2s write, error-wrapped) and
  the NAT-PMP UDP socket (`:9380-9385`, 2s + 2s). Because DNS drain, reconcile, and gossip all
  run strictly after this block in the same single-threaded loop pass (`:10078+`; the Windows leg
  instead uses a dedicated control-pipe thread + mpsc, `:9662-9675`), a local client that stops
  reading its response stalls the entire control plane **unboundedly** on the write side.
  **Adjacent fact found during re-verification, outside this narrow scope:** per-request *read*
  failures are currently fatal to the whole daemon — `read_command_envelope(&stream)
  .map_err(DaemonError::Io)?` (`:10014`) propagates out of `run_daemon`, so a client that
  connects and sends nothing (5s timeout), disconnects immediately (empty line →
  `UnexpectedEof`, `ipc.rs:323-332`), or sends garbage, terminates rustynetd. This is recorded
  and handed off separately (spawned follow-up task); it is *not* fixed here, but it constrains
  the design below: the new write-timeout error must not inherit the same fatal disposition.

- **Chosen approach:**
  1. In `write_response`, set the timeout before writing, mirroring the precedent sites verbatim
     in shape and constant:
     ```rust
     stream
         .set_write_timeout(Some(Duration::from_secs(2)))
         .map_err(|err| format!("ipc response write-timeout setup failed: {err}"))?;
     stream
         .write_all(format!("{}\n", response.to_wire()).as_bytes())
         .map_err(|err| format!("write failed: {err}"))
     ```
  2. At the single call site (`:10071`), change the disposition from fatal `?` to
     log-and-continue, mirroring the discipline `poll_anchor_bundle_pull_once` already documents
     and implements two screens up ("Per-request failures ... are logged and swallowed ... one
     malformed request must not kill the daemon", `:1274-1276`):
     `if let Err(err) = write_response(stream, response) { log::warn!("ipc_response_write_failed
     reason={err}"); }` — the connection is dropped (stream moved into the call), the loop
     continues, `processed` still counts the request.
  Step 2 is in-scope because it is what makes step 1 a fix at all: with the fatal `?` retained, a
  2s write timeout would convert "unbounded control-plane stall" into "whole-daemon exit on one
  stalled client" — trading one availability failure for a worse one.

- **Why this one:** The candidate space inside the narrow scope is small and the precedent
  decides it: the repo already has exactly one pattern for bounding blocking I/O on this thread
  (`set_write_timeout(2s)` at the two cited sites) and exactly one pattern for per-request error
  disposition on a daemon-embedded listener (`poll_anchor_bundle_pull_once`) — this plan is the
  composition of the two, no new mechanism. A longer timeout (5s, matching the read side) was
  considered and rejected: the response is a single small line to a local Unix socket — if 2s of
  blocked write occurs, the client is wedged, and 2s is already the constant chosen for the
  network-facing analogues, so consistency wins. Offloading the write to a helper thread (a mini
  version of the Windows control-pipe pattern) would bound the stall to zero instead of 2s but
  introduces cross-thread response plumbing on the Unix path — exactly the decomposition work the
  task boundary excludes; 2s bounded is sufficient to protect DNS/reconcile cadence.

- **Cost / tradeoffs:** A genuinely slow-but-honest local client (blocked >2s mid-read of a
  response) now gets a dropped connection and must retry — acceptable for a local admin socket
  whose responses are single lines. The main loop can still lose up to ~2s to a wedged writer
  (bounded, vs. unbounded today; per-pass, since each pass accepts at most one connection). The
  read-side fatal-`?` hazard remains — explicitly out of scope here, tracked separately.

- **Constraint check:** This touches the admin-IPC *response write* only — after
  `authorize_local_peer`/`authorize_remote_command` have already decided the request; no
  authorization logic, no command handling, no signed-state path is modified, so the nearest
  excluded surfaces (ACL evaluation; signature verification in the remote-envelope path) are
  named and untouched. Fail-closed posture: a write failure yields a dropped connection and a
  logged denial-of-service-shaped event, never a skipped check. §10.2: no unwrap/expect
  introduced.

- **Incremental build path:**
  - Phase 1 (S): both edits + a unit/integration test: a fake client that connects, sends a valid
    command, and reads nothing — assert the daemon loop survives (subsequent request on a fresh
    connection answered) and the pass completes within ~2s + slack. The existing IPC tests
    (`daemon.rs:16091+`) stay green.
  - (No further phases in this scope.)

- **How you'd know it worked:** The stalled-reader test above: before the change it hangs the
  loop indefinitely (test times out); after, the loop answers the follow-up request within the
  bound. Manual probe: `rustynet status` from a second terminal while a first connection sits
  wedged mid-response returns normally.

- **Prior art:** In-repo: `handle_anchor_bundle_pull_stream`'s paired 2s read/write timeouts
  (`daemon.rs:1183-1195`), `nat_pmp_round_trip`'s (`:9380-9385`), and
  `poll_anchor_bundle_pull_once`'s logged-and-swallowed per-request error contract (`:1270-1316`);
  the Windows control-pipe thread (`:9662-9675`) as the fuller decomposition this narrow fix
  deliberately does not attempt.

---

## NAT-2 (narrow): A real observation window for every ICE race round

- **Pipeline / area:** `crates/rustynetd/src/traversal.rs::execute_ice_pair_race`
  (`:1860-2002`), specifically the round loop `:1944-1992`. **Scope note:** per the task
  boundary, only the round-timing/observation-window mechanism is planned; the route-application
  cost inside `send_probe` (NAT-1's territory, `phase10.rs:97-109`) is not touched.

- **Current behavior (re-verified):** Each loop iteration: (1) waits `round_delay − elapsed`
  where `round_delay = round_spacing_ms × round` (`:1945-1953`; defaults
  `DEFAULT_TRAVERSAL_PROBE_ROUND_SPACING_MS = 80`, `SIMULTANEOUS_OPEN_ROUNDS = 3`,
  `MAX_PAIRS = 24`, `traversal.rs:62-64`), (2) sends every pair (`:1959-1965`), (3) checks
  `runtime.latest_handshake_unix()` **immediately** (`:1966-1968`) — so each round's check can
  only observe the *previous* round's probes, and after the final round (index 2) the loop falls
  straight into `relay_or_fail_closed_for_race` (`:1994-2001`) with the just-sent probes given
  zero window. Total genuinely-observed probing time: `(rounds−1) × spacing` = 160ms at defaults.
  **Correction to the catalog:** its polling candidate calls `latest_handshake_unix()` "cheap on
  command backends, a state read not a process spawn" — false: the production impl
  (`Phase10PeerRuntime`, `phase10.rs:111-116`) resolves to
  `backend.peer_latest_handshake_unix(...)`, which on command backends spawns
  `wg show <iface> latest-handshakes` per call (`linux_command.rs:302-320,420-426`; macOS/Windows
  analogues at `macos_command.rs:627`, `windows_command.rs:478`). Only the userspace-shared
  backend answers in-process. This changes the polling candidate's economics, below.

- **Chosen approach:** Reorder each round to **send → wait(spacing) → check**:
  ```rust
  for round in 0..self.config.simultaneous_open_rounds {
      for pair in &pairs { runtime.send_probe(...)?; total_attempts += 1; }
      waiter.wait(Duration::from_millis(self.config.round_spacing_ms));
      let latest = runtime.latest_handshake_unix()?;
      if handshake_advanced(...) && handshake_is_fresh(...) { /* Direct, unchanged */ }
      observed_latest = ...; // unchanged merge
  }
  ```
  The `round_delay`/`elapsed` bookkeeping (`:1943-1953`) collapses into the single
  post-send wait; the entry `waiter.wait(schedule.wait_duration)` (`:1880`), the candidate
  filtering/prioritization/rerank/demotion pipeline (`:1882-1939`), and the fallback call
  (`:1994-2001`) are all untouched. Update the "fire ALL pairs ... then poll" doc comment
  (`:1954-1958`) to describe the new ordering. The 80ms constant stays (already operator-tunable
  via `TraversalEngineConfig.round_spacing_ms`, validated non-zero at `:1582-1585`).

- **Why this one:** Three candidates from the catalog. **A single post-loop wait+check** (smallest
  textual diff) fixes only the final round and leaves the misleading structure in place — every
  future reader re-derives the off-by-one; the reorder is the same size and makes each round's
  budget mean what it says. **Fine-grained sub-interval polling** buys earlier success detection
  (a handshake at t+10ms detected at ~t+10-20ms instead of t+80ms) but, per the correction above,
  each poll is a `wg show` subprocess on the command backends — the default macOS backend and the
  only Windows backend — so a 10-20ms poll cadence multiplies privileged-helper/subprocess traffic
  4-8× per round in exactly the environments least able to afford it; deferred to an optional
  phase capped at one mid-round check (2 polls/round) if reconnect-latency evidence justifies it.
  **RTT-adaptive spacing** needs new plumbing from STUN gathering into the engine config, and
  STUN-server RTT is not representative of the peer path (the catalog's own caveat) — rejected for
  this pass; the config knob already exists for operators with known-slow paths. The reorder is
  the smallest change that makes the finding's headline sentence false.

- **Cost / tradeoffs:** The all-rounds-fail path now takes `rounds × spacing` = 240ms instead of
  160ms before arming relay/fail-closed — +80ms added specifically to the declare-failure case
  (the catalog's candidate-(a) cost, accepted: it is the price of not discarding an entire round
  of up to 24 probes unobserved). Success-path detection latency is unchanged (~one spacing after
  the effective round's sends, same as today's next-round check). Tests that pin the current
  wait/check sequence (the `RecordingWaiter` assertions in the `:3420-3480` harness) must be
  updated to the new ordering — a deliberate re-pin, not collateral.

- **Constraint check:** The decision still resolves to Direct / Relay / FailClosed in bounded
  time — the fail-closed default (§3/§4) is preserved and the bound merely grows by one spacing;
  `handshake_is_fresh`'s freshness check is unmodified. Nearest excluded surface:
  route/firewall mutation inside `send_probe` — explicitly not touched (the reorder changes
  *when* existing calls happen, never *what* they do, and does not add or remove any
  `send_probe`/reconfigure call: per-round send count is identical). Not
  crypto/keys/ACL/privileged-exec-content/DNS.

- **Incremental build path:**
  - Phase 1 (S): the reorder + doc comment + test re-pin, plus one new test on the existing
    fake harness (`WaitDrivenHandshakeRuntime`/`RecordingWaiter`, `:3422-3462`): a runtime whose
    handshake becomes observable only after the **final** round's post-send wait must yield a
    `Direct` decision — this exact case is relay-fallback today, making the test the
    before/after discriminator.
  - Phase 2 (S, optional, evidence-gated): one mid-round check (spacing/2) behind the same
    waiter abstraction, only if cross-network lab evidence shows connection-establishment
    latency worth the extra `wg show` per round.
  - Phase 3 (lab): a focused cross-network live-lab stage run (netem-delayed path >80ms RTT)
    demonstrating a direct connection that today systematically falls to relay now lands Direct —
    the catalog notes this class of defect is invisible on the same-LAN lab, so the evidence run
    must inject delay.

- **How you'd know it worked:** The new unit test flips from red (current code) to green;
  in the delayed-path lab stage, the run-matrix row for the traversal stage records a Direct
  decision where the pre-change baseline recorded `DirectProbeExhaustedRelayArmed`; total race
  wall-clock in logs shows ≤ `rounds × spacing + ε`.

- **Prior art:** RFC 8445 §16 (ICE pacing: checks are paced *and* answered within their
  transaction window — the send-then-observe shape this restores); FIS-0009/FIS-0013 landed in
  this same function (prior-ranking rerank, incumbent demotion — evidence this seam absorbs
  small, well-tested behavioral deltas); the `SimultaneousOpenWaiter` test harness as the
  in-repo instrument for pinning timing semantics without real sleeps.

---

## Closing note

Every section above was re-grounded against the working tree this pass; the notable drifts found
versus the source catalog (each folded into its section): BLD-1 — `rustynetd` cannot be
target-gated without deleting a deliberate fail-closed stub test, so the consistent-gating fix is
scoped to the two crates where it is free; CLI-2 — the zero-memoization claim now holds only for
`rustynet-sysinfo` itself, and the three `rustc_version_internal` cfg copies are byte-identical;
CCY-3 — the shadow state is four fields, not three, and has **zero readers** (write-only fields
evade `dead_code`, verified), turning a refactor into a deletion; BLD-3 — CI runs clippy *before*
check, so CI's check pass cannot even claim fail-fast; NAT-2 — `latest_handshake_unix` **is** a
subprocess spawn on command backends, correcting the catalog's polling-candidate economics; CCY-1 —
per-request read errors on the admin socket are fatal to the daemon today (recorded and handed off
as a separate follow-up task, out of this pass's narrow scope). Nothing here is scheduled; each
section's Phase 1 is independently shippable, and §7 gates plus the named tests/measurements are
the acceptance bar when any of it is picked up.
