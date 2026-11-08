#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
//! Developer task runner for the Rustynet workspace.
//!
//! Currently provides one subcommand, `gates`, a fail-fast replacement
//! for chaining the mandatory Rust gates by hand. It runs them in
//! dependency order (fmt → clippy → test) and STOPS at the first
//! failure, so a compile or lint error surfaces in minutes instead of
//! after the whole test suite. Clippy is the single compile-correctness
//! AND lint pass: clippy is rustc plus lint passes, so a compile error
//! fails the clippy stage at essentially the same wall-clock point a
//! standalone `cargo check` stage would have — while a separate check
//! stage would duplicate the entire compile (check and clippy share no
//! incremental cache: different `RUSTC_WORKSPACE_WRAPPER`, different
//! fingerprint bucket). `--with-check` restores the old
//! fmt → check → clippy → test order as the escape hatch for a
//! broken/poisoned clippy toolchain; `cargo check` also remains an
//! authoritative individually-invocable gate command (CLAUDE.md §7).
//! Each stage runs under a timeout watchdog: if a stage hangs past its
//! budget it is killed (whole process group) and the tail of its
//! output is printed, so a stuck test names itself instead of stalling
//! the loop indefinitely.
//!
//! All output is streamed live (tee) so progress is visible while the
//! gate runs; the last lines are also retained for the failure report.
//!
//! Usage:
//!   cargo run -p rustynet-xtask -- gates                  # full workspace
//!   cargo run -p rustynet-xtask -- gates -p rustynet-cli  # scope to a crate
//!   cargo run -p rustynet-xtask -- gates --skip-test      # gates without tests
//!   cargo run -p rustynet-xtask -- gates --with-check     # restore the standalone check stage
//!   cargo run -p rustynet-xtask -- gates --affected       # changed crates + all dependents
//!   cargo run -p rustynet-xtask -- gates --affected --base origin/main
//!   cargo run -p rustynet-xtask -- affected-crates [--base HEAD] # print crate list for scripts
//!
//! `--affected` scopes clippy/test (and check, under `--with-check`) to the workspace crates touched
//! since `--base` (default `origin/main`, including uncommitted and
//! untracked changes) plus the full transitive closure of their
//! reverse-dependents, so every crate whose build a change can break is
//! covered while unrelated crates are skipped. If a build file changed —
//! any `Cargo.toml` (root or crate-level: dependency and feature edits
//! change workspace-wide feature unification), `Cargo.lock`, any
//! `build.rs`, or a `rust-toolchain*` file — or no workspace crate is
//! affected, it falls back to the full workspace to stay safe. `fmt`
//! always runs workspace-wide (it is cheap).
//!
//! `affected-crates` is the machine-readable form of `--affected` for the
//! shell gate scripts: it prints the `-p <crate>` package names (one per
//! line) that `gates --affected` would scope to. Exit 0 = the printed
//! crates are the scope; exit 3 = gate the FULL workspace instead (the
//! fallback rule fired or crate detection failed); exit 2 = usage error.
//! Its default base is `HEAD`, not `origin/main`: the box gate scripts
//! apply a lane patch as uncommitted changes over a committed base, so
//! the diff against `HEAD` is exactly the patch under test.
//!
//! The test stage executes through cargo-nextest (`cargo nextest run`,
//! version pinned in `bootstrap_ci_tools`), which runs the workspace's
//! ~100 test binaries against one global concurrent pool instead of
//! `cargo test`'s one-binary-at-a-time scheduling. Retries are off
//! (`--retries 0`) so a flaky test fails loudly instead of being masked.
//! `cargo test --workspace --all-targets --all-features` remains the
//! authoritative gate definition (CLAUDE.md §7); nextest is only the
//! runner this tooling uses.
//!
//! Per-stage timeouts (seconds) are overridable via env:
//!   XTASK_FMT_TIMEOUT (default 120)
//!   XTASK_CHECK_TIMEOUT (default 1200 — stage only runs under --with-check)
//!   XTASK_CLIPPY_TIMEOUT (default 1500)
//!   XTASK_TEST_TIMEOUT (default 5400 — full --all-targets suite is ~48-60min)
//!
//! Each stage's wall-clock is appended to
//! `documents/operations/gate_timings.csv` (timestamp, commit, dirty, stage,
//! scope, duration, outcome) so gate cost can be tracked over time. Recording
//! is best-effort and never fails the gate.
//!
//! Exit codes: 0 all gates passed, 1 a gate failed, 124 a gate timed out.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;

const TIMEOUT_EXIT_CODE: i32 = 124;
/// Lines of tee'd output retained for the failure/timeout report.
const TAIL_LINES: usize = 40;
/// The cargo-nextest version the repo pins (BLD-2). Keep in sync with
/// `PINNED_NEXTEST_VERSION` in `rustynet-cli/src/bin/bootstrap_ci_tools.rs`
/// and the inline Windows-leg pin in `.github/workflows/cross-platform-ci.yml`.
/// 0.9.114 is the newest nextest whose MSRV (1.88) the pinned security
/// toolchain (1.88.0) can compile.
const PINNED_NEXTEST_VERSION: &str = "0.9.114";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let exit_code = dispatch(&args);
    std::process::exit(exit_code);
}

/// Subcommand dispatch. Extracted from `main` (AQ-08 step 8) so the
/// no-arguments and unknown-subcommand exit codes stay unit-testable;
/// `split_first` replaces the `args[1..]` slice lookup.
fn dispatch(args: &[String]) -> i32 {
    match args.split_first() {
        Some((first, rest)) if first == "gates" => run_gates(rest),
        Some((first, rest)) if first == "affected-crates" => run_affected_crates(rest),
        Some((first, _)) => {
            eprintln!("xtask: unknown subcommand: {first}");
            eprintln!("usage: xtask gates [--skip-test] [--with-check] [cargo scope args...]");
            eprintln!("       xtask affected-crates [--base <ref>]  (default base: HEAD)");
            2
        }
        None => {
            eprintln!("usage: xtask gates [--skip-test] [--with-check] [cargo scope args...]");
            eprintln!("       xtask affected-crates [--base <ref>]  (default base: HEAD)");
            2
        }
    }
}

/// Full-workspace exit code for `affected-crates`: the crate list must not
/// be used, the caller gates the whole workspace instead (fail-safe — the
/// same fallback `gates --affected` takes).
const AFFECTED_CRATES_FULL_WORKSPACE_EXIT: i32 = 3;

/// `affected-crates`: print the workspace crates a gate script should run
/// for the current diff — the same set `gates --affected` scopes to — as
/// one `-p` package name per line. Machine-readable by design: nothing but
/// the crate names goes to stdout, the human-readable notice goes to
/// stderr, and the full-workspace fallback is an exit code (3), not a
/// line a script could mis-parse. Exit 0 = use the printed crates; exit 3
/// = gate the full workspace (fallback rule fired: lockfile, build.rs,
/// any Cargo.toml, or toolchain file changed, or no crate detected — or
/// detection itself failed, same fail-safe as `gates --affected`);
/// exit 2 = usage error. Default base is `HEAD` because the box gate
/// scripts apply a lane patch as uncommitted changes over a committed
/// base, so `git diff HEAD` is exactly the patch under test.
fn run_affected_crates(rest: &[String]) -> i32 {
    let mut base = "HEAD".to_owned();
    let mut iter = rest.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--base" => match iter.next() {
                Some(value) => base = value.clone(),
                None => {
                    eprintln!("xtask: --base requires a value");
                    return 2;
                }
            },
            other => {
                eprintln!("xtask: unknown argument for affected-crates: {other}");
                return 2;
            }
        }
    }
    match affected_scope(&base) {
        Ok(Some(packages)) => {
            for name in packages.chunks(2).filter_map(|c| c.get(1)) {
                println!("{name}");
            }
            0
        }
        Ok(None) => {
            eprintln!(
                "==> [affected] full workspace required (lockfile/build.rs/Cargo.toml/toolchain \
                 change or no crate affected)"
            );
            AFFECTED_CRATES_FULL_WORKSPACE_EXIT
        }
        Err(err) => {
            eprintln!("!!! [affected] detection failed, falling back to full workspace: {err}");
            AFFECTED_CRATES_FULL_WORKSPACE_EXIT
        }
    }
}

struct Stage {
    label: &'static str,
    timeout: Duration,
    args: Vec<String>,
}

/// Entry count in `target/debug/deps` above which the gate prunes the build
/// cache before running anything else.
///
/// Cargo never removes stale per-codegen-unit object files, so `deps/` grows
/// without bound across rebuilds. Measured on this checkout on 2026-08-06 it
/// had reached 1,063,921 entries (1,042,787 `.o` files, 157.7 GiB), and at
/// that size every *first* execution of a freshly built binary inside that
/// directory stalled for 20-30 s at 0.00 s CPU while the platform assessed
/// it — the same trivial binary written to a sibling directory started in
/// 0.33 s, so the cost tracks the directory's entry count and not the
/// binary's size. Because cargo-nextest executes every test binary just to
/// enumerate its tests, that toll is paid once per binary before a single
/// test runs: the full suite took ~2 h wall for 75 s of actual test time,
/// and compilation was slowed too.
///
/// One full workspace build produces roughly 16k entries and a from-scratch
/// rebuild costs about 3 minutes, so this limit allows roughly a dozen build
/// generations before pruning, and pruning costs far less than tolerating
/// the stall.
const DEFAULT_DEPS_ENTRY_LIMIT: usize = 200_000;

/// Decide whether the build cache should be pruned before gating.
///
/// Kept free of I/O so the policy is testable directly. A limit of zero
/// disables pruning entirely, which is the documented escape hatch for a
/// caller that would rather keep a large incremental cache.
fn should_prune_build_cache(entry_count: usize, limit: usize, opted_out: bool) -> bool {
    !opted_out && limit != 0 && entry_count > limit
}

/// Count the entries in `target/debug/deps`, or `None` when it does not exist
/// yet (a clean checkout has nothing to prune).
fn deps_entry_count() -> Option<usize> {
    std::fs::read_dir("target/debug/deps")
        .ok()
        .map(|entries| entries.count())
}

/// Prune the build cache when it has grown large enough to slow the gate
/// down more than a rebuild would cost. Returns true when a prune ran.
fn prune_build_cache_if_oversized() -> bool {
    let opted_out = std::env::var("XTASK_SKIP_TARGET_PRUNE")
        .map(|value| value != "0")
        .unwrap_or(false);
    let limit = std::env::var("XTASK_DEPS_ENTRY_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(DEFAULT_DEPS_ENTRY_LIMIT);
    let Some(count) = deps_entry_count() else {
        return false;
    };
    if !should_prune_build_cache(count, limit, opted_out) {
        return false;
    }
    eprintln!(
        "xtask: target/debug/deps holds {count} entries (limit {limit}); \
         running `cargo clean` first because a bloated deps directory slows \
         every binary launch far more than a rebuild costs. \
         Set XTASK_SKIP_TARGET_PRUNE=1 to keep the cache."
    );
    match Command::new("cargo").arg("clean").status() {
        Ok(status) if status.success() => {
            eprintln!("xtask: build cache pruned");
            true
        }
        Ok(status) => {
            eprintln!("xtask: cargo clean failed ({status}); continuing without pruning");
            false
        }
        Err(err) => {
            eprintln!("xtask: cargo clean could not run ({err}); continuing without pruning");
            false
        }
    }
}

fn run_gates(rest: &[String]) -> i32 {
    let mut skip_test = false;
    let mut with_check = false;
    let mut affected = false;
    let mut base = "origin/main".to_owned();
    let mut scope: Vec<String> = Vec::new();
    let mut iter = rest.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--skip-test" => skip_test = true,
            "--with-check" => with_check = true,
            "--affected" => affected = true,
            "--base" => match iter.next() {
                Some(value) => base = value.clone(),
                None => {
                    eprintln!("xtask: --base requires a value");
                    return 2;
                }
            },
            other => scope.push(other.to_owned()),
        }
    }

    if affected {
        match affected_scope(&base) {
            Ok(Some(packages)) => {
                println!(
                    "==> [affected] scoping to: {}",
                    packages
                        .chunks(2)
                        .filter_map(|c| c.get(1))
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                scope.extend(packages);
            }
            Ok(None) => {
                println!(
                    "==> [affected] lockfile/build.rs/Cargo.toml/toolchain change or no crate detected — full workspace"
                );
            }
            Err(err) => {
                eprintln!("!!! [affected] detection failed, falling back to full workspace: {err}");
            }
        }
    }

    // Only default to `--workspace` when the caller did not pass an
    // explicit package selector; otherwise `--workspace` would override
    // the requested `-p <crate>` scope and rebuild everything.
    let scoped = scope
        .iter()
        .any(|a| a == "-p" || a == "--package" || a.starts_with("--package="));
    let with_scope = |base: &[&str]| -> Vec<String> {
        let mut v: Vec<String> = base.iter().map(|s| (*s).to_owned()).collect();
        if !scoped {
            v.push("--workspace".to_owned());
        }
        v.push("--all-targets".to_owned());
        v.push("--all-features".to_owned());
        v.extend(scope.iter().cloned());
        v
    };

    // Prune before any stage runs: a bloated deps directory taxes both
    // compilation and every test-binary launch, so pruning first is what
    // makes the rest of this run fast rather than merely tidy.
    prune_build_cache_if_oversized();

    let mut stages = vec![Stage {
        label: "fmt",
        timeout: timeout_from_env("XTASK_FMT_TIMEOUT", 120),
        args: vec![
            "fmt".to_owned(),
            "--all".to_owned(),
            "--".to_owned(),
            "--check".to_owned(),
        ],
    }];
    // The standalone check stage is off by default: clippy is rustc plus
    // lint passes, so it already provides the compile-correctness gate at
    // ~the same wall-clock cost as check alone, and running both doubles
    // the full compile (no shared incremental cache across the clippy
    // wrapper). `--with-check` restores it as the fallback for a
    // broken/poisoned clippy toolchain.
    if with_check {
        stages.push(Stage {
            label: "check",
            timeout: timeout_from_env("XTASK_CHECK_TIMEOUT", 1200),
            args: with_scope(&["check"]),
        });
    }
    stages.push(Stage {
        label: "clippy",
        timeout: timeout_from_env("XTASK_CLIPPY_TIMEOUT", 1500),
        args: {
            let mut a = with_scope(&["clippy"]);
            a.push("--".to_owned());
            a.push("-D".to_owned());
            a.push("warnings".to_owned());
            a
        },
    });
    if !skip_test {
        // The test stage executes through cargo-nextest (BLD-2): the workspace
        // is ~100 small test binaries and `cargo test` runs them strictly one
        // at a time, while nextest schedules them against one global concurrent
        // pool. `cargo test --workspace --all-targets --all-features` remains
        // the authoritative gate definition (CLAUDE.md §7); nextest is the
        // runner this tooling uses. `--retries 0` is nextest's default, but it
        // is passed explicitly so a future nextest config file can never
        // silently enable flaky-test retries (FAIL-LOUD: a retry would mask a
        // real regression). Fail fast here — before ~20min of fmt/check/clippy
        // — if the runner is missing, with the pinned install command.
        if !cargo_nextest_available() {
            eprintln!(
                "xtask: cargo-nextest is required for the test stage but is not installed.\n\
                 install it with: cargo install cargo-nextest --locked --version {PINNED_NEXTEST_VERSION}\n\
                 (CI installs it via scripts/ci/bootstrap_ci_tools.sh; `cargo test` remains\n\
                 the authoritative gate definition and can still be run by hand.)"
            );
            return 2;
        }
        stages.push(Stage {
            label: "test",
            // The full --all-targets workspace suite (compile + run) is ~48min
            // warm and tips past 60min on a cold cache under `cargo test`, so
            // 3600 was too tight — a slightly-slow run had the whole process
            // group killed mid-suite (the binary "Running" at the cutoff, e.g.
            // the 0-test real_wireguard_exitnode_e2e harness, looked like the
            // culprit but wasn't). 5400 (90min) gives headroom while still
            // catching a hang; nextest should only bring the wall-clock down.
            timeout: timeout_from_env("XTASK_TEST_TIMEOUT", 5400),
            args: {
                let mut a = with_scope(&["nextest", "run"]);
                a.push("--retries".to_owned());
                a.push("0".to_owned());
                a
            },
        });
    }

    let run_meta = TimingRunMeta::resolve(affected, &scope);
    for stage in &stages {
        let (outcome, elapsed) = run_stage(stage);
        run_meta.record(stage.label, elapsed, outcome_label(&outcome));
        match outcome {
            StageOutcome::Pass => {}
            StageOutcome::Fail(code) => return code,
            StageOutcome::Timeout => return TIMEOUT_EXIT_CODE,
        }
    }
    println!("\n==> all gates passed");
    0
}

enum StageOutcome {
    Pass,
    Fail(i32),
    Timeout,
}

fn run_stage(stage: &Stage) -> (StageOutcome, u64) {
    println!(
        "\n==> [{}] starting (timeout {}s): cargo {}",
        stage.label,
        stage.timeout.as_secs(),
        stage.args.join(" ")
    );
    let started = Instant::now();

    let mut child = match Command::new("cargo")
        .args(&stage.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Put the child (and the cargo→rustc/test subprocess tree) in
        // its own process group so a timeout can kill the whole tree,
        // not just the cargo parent.
        .process_group(0)
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            eprintln!("!!! [{}] failed to spawn cargo: {err}", stage.label);
            return (StageOutcome::Fail(1), started.elapsed().as_secs());
        }
    };

    let pgid = Pid::from_raw(child.id() as i32);
    let tail = Arc::new(Mutex::new(VecDeque::<String>::with_capacity(TAIL_LINES)));
    let mut readers = Vec::new();
    if let Some(out) = child.stdout.take() {
        readers.push(spawn_tee(out, tail.clone(), false));
    }
    if let Some(err) = child.stderr.take() {
        readers.push(spawn_tee(err, tail.clone(), true));
    }

    let timed_out = wait_with_timeout(&mut child, pgid, stage.timeout);
    let status = child.wait();
    for reader in readers {
        let _ = reader.join();
    }
    let elapsed = started.elapsed().as_secs();

    if timed_out {
        eprintln!(
            "!!! [{}] TIMEOUT after {elapsed}s — process group killed",
            stage.label
        );
        print_tail(&tail);
        return (StageOutcome::Timeout, elapsed);
    }
    match status {
        Ok(status) if status.success() => {
            println!("==> [{}] PASS ({elapsed}s)", stage.label);
            (StageOutcome::Pass, elapsed)
        }
        Ok(status) => {
            let code = status.code().unwrap_or(1);
            eprintln!("!!! [{}] FAILED (rc={code}, {elapsed}s)", stage.label);
            print_tail(&tail);
            (StageOutcome::Fail(code), elapsed)
        }
        Err(err) => {
            eprintln!("!!! [{}] wait failed: {err}", stage.label);
            print_tail(&tail);
            (StageOutcome::Fail(1), elapsed)
        }
    }
}

/// True when `cargo nextest --version` runs successfully, i.e. the
/// cargo-nextest subcommand binary is installed and on PATH. Probed the
/// same way the test stage will invoke it (through `cargo`), so a pass
/// here means the stage's spawn cannot fail on a missing runner.
fn cargo_nextest_available() -> bool {
    Command::new("cargo")
        .args(["nextest", "--version"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Poll the child until it exits or the timeout elapses. On timeout,
/// SIGTERM then SIGKILL the whole process group. Returns true if the
/// stage timed out.
fn wait_with_timeout(child: &mut std::process::Child, pgid: Pid, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return false,
            Ok(None) => {}
            Err(_) => return false,
        }
        if Instant::now() >= deadline {
            let _ = killpg(pgid, Signal::SIGTERM);
            thread::sleep(Duration::from_secs(3));
            let _ = killpg(pgid, Signal::SIGKILL);
            return true;
        }
        thread::sleep(Duration::from_millis(200));
    }
}

/// Stream a child pipe to our own stdout/stderr line by line while
/// retaining the last `TAIL_LINES` lines for the failure report.
fn spawn_tee<R: std::io::Read + Send + 'static>(
    reader: R,
    tail: Arc<Mutex<VecDeque<String>>>,
    is_stderr: bool,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let buffered = BufReader::new(reader);
        for line in buffered.lines() {
            let Ok(line) = line else { break };
            if is_stderr {
                let mut handle = std::io::stderr().lock();
                let _ = writeln!(handle, "{line}");
            } else {
                let mut handle = std::io::stdout().lock();
                let _ = writeln!(handle, "{line}");
            }
            if let Ok(mut tail) = tail.lock() {
                if tail.len() == TAIL_LINES {
                    tail.pop_front();
                }
                tail.push_back(line);
            }
        }
    })
}

fn print_tail(tail: &Arc<Mutex<VecDeque<String>>>) {
    eprintln!("    --- last {TAIL_LINES} lines ---");
    if let Ok(tail) = tail.lock() {
        for line in tail.iter() {
            eprintln!("    {line}");
        }
    }
}

/// Compute `-p <pkg>` args for workspace crates changed since `base`
/// plus their full transitive reverse-dependents. Returns `Ok(None)` to signal
/// "run the full workspace" — used when a build file changed (see
/// `should_fallback_full_workspace`) or no workspace crate is affected,
/// so we never under-test.
fn affected_scope(base: &str) -> Result<Option<Vec<String>>, String> {
    let workspace_root = cargo_workspace_root()?;
    affected_scope_in(&workspace_root, base)
}

/// Resolve the CARGO WORKSPACE root — the directory holding the gating
/// workspace's `Cargo.toml` — NOT the git root. Since the in-tree
/// migration the Rustynet workspace lives at `projects/rustynet` inside
/// the suite superproject, so `git rev-parse --show-toplevel` points at
/// the superproject, where cargo finds no manifest and `cargo metadata`
/// fails — which made `--affected` fall back to the full workspace on
/// EVERY run (fail-safe, but it never saved any compute).
/// `cargo locate-project --workspace` finds the real workspace manifest
/// from any cwd inside the workspace, in both layouts.
fn cargo_workspace_root() -> Result<String, String> {
    let out = Command::new("cargo")
        .args(["locate-project", "--workspace", "--message-format", "plain"])
        .output()
        .map_err(|e| format!("cargo locate-project spawn failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo locate-project failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let manifest = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let root = std::path::Path::new(&manifest)
        .parent()
        .ok_or_else(|| format!("cargo locate-project: no parent dir for {manifest}"))?;
    Ok(root.to_string_lossy().into_owned())
}

/// Directory-free core of `affected_scope` (workspace root resolved by
/// the caller) so the fallback policy is testable in a throwaway git
/// repo instead of mutating the real checkout. `workspace_root` is both
/// the cwd for the git calls and the `cargo metadata` root; in the in-tree
/// layout the git root is the superproject ABOVE it, and git prints
/// changed paths relative to the GIT root, so every path is normalised to
/// workspace-relative before matching.
fn affected_scope_in(workspace_root: &str, base: &str) -> Result<Option<Vec<String>>, String> {
    // The caller may hand us a path with symlink components — std::env::temp_dir
    // on macOS returns /var/folders/... while /var is a symlink to private/var —
    // but git prints fully resolved paths, so both roots must be canonicalised
    // or the workspace/git prefix comparison below fails on every call.
    let workspace_root = std::fs::canonicalize(workspace_root)
        .map_err(|e| format!("canonicalize workspace root {workspace_root} failed: {e}"))?
        .to_string_lossy()
        .into_owned();
    let git_root = git_capture_in(workspace_root.as_str(), &["rev-parse", "--show-toplevel"])?
        .trim()
        .to_owned();
    if git_root.is_empty() {
        return Err("could not resolve git root".to_owned());
    }
    let git_root = std::fs::canonicalize(&git_root)
        .map_err(|e| format!("canonicalize git root {git_root} failed: {e}"))?
        .to_string_lossy()
        .into_owned();
    let ws_git_prefix: String = if git_root == workspace_root {
        String::new()
    } else {
        let rel = std::path::Path::new(&workspace_root)
            .strip_prefix(&git_root)
            .map_err(|e| {
                format!("workspace root {workspace_root} not under git root {git_root}: {e}")
            })?
            .to_string_lossy()
            .into_owned();
        format!("{rel}/")
    };
    let changed: Vec<String> = changed_files_in(&workspace_root, base)
        .into_iter()
        .map(|p| {
            p.strip_prefix(ws_git_prefix.as_str())
                .unwrap_or(&p)
                .to_owned()
        })
        .collect();
    if changed.is_empty() {
        return Ok(None);
    }
    if should_fallback_full_workspace(&changed) {
        return Ok(None);
    }

    let meta = cargo_metadata(&workspace_root)?;
    let packages = meta
        .get("packages")
        .and_then(|v| v.as_array())
        .ok_or("cargo metadata: missing packages array")?;

    let ws_names: std::collections::BTreeSet<String> = packages
        .iter()
        .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(str::to_owned))
        .collect();
    // (workspace-relative crate dir, package name)
    let mut dir_of: Vec<(String, String)> = Vec::new();
    // package name -> workspace dependency names
    let mut deps_of: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let root_prefix = format!("{workspace_root}/");
    for pkg in packages {
        let Some(name) = pkg.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        if let Some(manifest) = pkg.get("manifest_path").and_then(|m| m.as_str())
            && let Some(rel) = manifest.strip_prefix(&root_prefix)
            && let Some(dir) = rel.strip_suffix("/Cargo.toml")
        {
            dir_of.push((dir.to_owned(), name.to_owned()));
        }
        let deps: Vec<String> = pkg
            .get("dependencies")
            .and_then(|d| d.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|d| d.get("name").and_then(|n| n.as_str()))
                    .filter(|n| ws_names.contains(*n))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        deps_of.insert(name.to_owned(), deps);
    }

    let affected = compute_affected_set(&dir_of, &deps_of, &changed);
    if affected.is_empty() {
        return Ok(None);
    }

    let mut args = Vec::new();
    for name in affected {
        args.push("-p".to_owned());
        args.push(name);
    }
    Ok(Some(args))
}

/// Pure core of `--affected`: given workspace crate directories
/// (`dir_of`: repo-relative dir → package name), the intra-workspace
/// dependency graph (`deps_of`: package → its workspace deps), and the
/// list of changed files, return the set of directly-changed crates
/// plus the full transitive closure of their reverse-dependents —
/// every crate that depends on a changed crate directly or through
/// intermediaries. One hop would silently under-test: a change to a
/// low crate can break a consumer two or more hops up.
fn compute_affected_set(
    dir_of: &[(String, String)],
    deps_of: &std::collections::BTreeMap<String, Vec<String>>,
    changed: &[String],
) -> std::collections::BTreeSet<String> {
    let mut affected: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for file in changed {
        for (dir, name) in dir_of {
            if file == dir || file.starts_with(&format!("{dir}/")) {
                affected.insert(name.clone());
            }
        }
    }
    if affected.is_empty() {
        return affected;
    }
    // Fixpoint: keep adding every workspace crate that depends on an
    // already-affected crate until the set stops growing, so transitive
    // dependents (leaf -> daemon -> cli) are all reached.
    loop {
        let mut grew = false;
        for (name, deps) in deps_of {
            if !affected.contains(name) && deps.iter().any(|dep| affected.contains(dep)) {
                affected.insert(name.clone());
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    affected
}

/// Conservative full-workspace fallback rule shared by `--affected` and
/// `affected-crates`: when one of these changed files is present,
/// crate-level scoping is unsafe and the caller must gate the whole
/// workspace. A `Cargo.lock` change can re-vendor anything; any
/// `build.rs` runs arbitrary codegen its crate's source diff cannot show;
/// a crate-level `Cargo.toml` edit (new dependency or feature) changes
/// workspace-wide feature unification, not just that crate; and a
/// toolchain file changes what every crate is compiled with. Kept free of
/// I/O so the policy is testable directly.
fn should_fallback_full_workspace(changed: &[String]) -> bool {
    changed.iter().any(|file| {
        let name = file.rsplit('/').next().unwrap_or(file);
        matches!(name, "Cargo.toml" | "Cargo.lock" | "build.rs")
            || file.starts_with("rust-toolchain")
    })
}

fn git_capture(args: &[&str]) -> Result<String, String> {
    git_capture_in(".", args)
}

fn git_capture_in(dir: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| format!("git {args:?} spawn failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Files changed since `base`, including committed, staged, unstaged,
/// and untracked. Best-effort: a missing `base` ref is tolerated.
/// Repo-root-relative paths, resolved from `repo_root` so the affected
/// scope can be computed for a directory other than the current one.
fn changed_files_in(repo_root: &str, base: &str) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for args in [
        vec!["diff", "--name-only", base],
        vec!["diff", "--name-only", "HEAD"],
        vec!["ls-files", "--others", "--exclude-standard"],
    ] {
        if let Ok(out) = git_capture_in(repo_root, &args) {
            for line in out.lines() {
                let line = line.trim();
                if !line.is_empty() {
                    set.insert(line.to_owned());
                }
            }
        }
    }
    set.into_iter().collect()
}

fn cargo_metadata(repo_root: &str) -> Result<serde_json::Value, String> {
    let out = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(repo_root)
        .output()
        .map_err(|e| format!("cargo metadata spawn failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("parse cargo metadata: {e}"))
}

fn timeout_from_env(var: &str, default_secs: u64) -> Duration {
    let secs = std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(default_secs);
    Duration::from_secs(secs)
}

const GATE_TIMINGS_CSV_HEADER: &str =
    "timestamp_utc,git_commit,git_dirty,stage,scope,duration_secs,outcome";

fn outcome_label(outcome: &StageOutcome) -> &'static str {
    match outcome {
        StageOutcome::Pass => "pass",
        StageOutcome::Fail(_) => "fail",
        StageOutcome::Timeout => "timeout",
    }
}

/// Per-run context shared by every stage's timing row: where the tracked CSV
/// lives, the commit + dirty state under test, and a description of the gate
/// scope. Resolved once; reused for each stage.
struct TimingRunMeta {
    repo_root: Option<String>,
    commit: String,
    dirty: &'static str,
    scope: String,
}

impl TimingRunMeta {
    fn resolve(affected: bool, scope: &[String]) -> Self {
        let repo_root = git_capture(&["rev-parse", "--show-toplevel"])
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());
        let commit = git_capture(&["rev-parse", "--short", "HEAD"])
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "unknown".to_owned());
        let dirty = match git_capture(&["status", "--porcelain"]) {
            Ok(out) if !out.trim().is_empty() => "dirty",
            Ok(_) => "clean",
            Err(_) => "unknown",
        };
        let scope = if affected {
            "affected".to_owned()
        } else if scope.is_empty() {
            "workspace".to_owned()
        } else {
            scope.join(" ")
        };
        Self {
            repo_root,
            commit,
            dirty,
            scope,
        }
    }

    /// Append one stage's timing to the tracked CSV. Best-effort: a write
    /// failure warns but never fails the gate.
    fn record(&self, stage: &str, duration_secs: u64, outcome: &str) {
        let Some(root) = self.repo_root.as_deref() else {
            return;
        };
        let path = std::path::Path::new(root)
            .join("documents")
            .join("operations")
            .join("gate_timings.csv");
        let row = format_timing_row(
            &utc_timestamp(),
            &self.commit,
            self.dirty,
            stage,
            &self.scope,
            duration_secs,
            outcome,
        );
        if let Err(err) = append_timing_row(&path, &row) {
            eprintln!(
                "!!! [timing] could not record gate timing to {}: {err}",
                path.display()
            );
        }
    }
}

fn append_timing_row(path: &std::path::Path, row: &str) -> std::io::Result<()> {
    let need_header = !path.exists();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    if need_header {
        writeln!(file, "{GATE_TIMINGS_CSV_HEADER}")?;
    }
    writeln!(file, "{row}")
}

/// Render one CSV record. String fields are sanitised (commas / newlines →
/// `;`) so a stray separator can never split or break a row.
fn format_timing_row(
    timestamp: &str,
    commit: &str,
    dirty: &str,
    stage: &str,
    scope: &str,
    duration_secs: u64,
    outcome: &str,
) -> String {
    let clean = |value: &str| value.replace([',', '\n', '\r'], ";");
    format!(
        "{},{},{},{},{},{},{}",
        clean(timestamp),
        clean(commit),
        clean(dirty),
        clean(stage),
        clean(scope),
        duration_secs,
        clean(outcome),
    )
}

/// UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`) via `date -u`, matching the repo's
/// other CSV ledgers. Falls back to unix-epoch seconds if `date` is absent.
fn utc_timestamp() -> String {
    if let Ok(out) = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        && out.status.success()
    {
        let stamp = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if !stamp.is_empty() {
            return stamp;
        }
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_DEPS_ENTRY_LIMIT, compute_affected_set, format_timing_row, should_prune_build_cache,
    };
    use std::collections::BTreeMap;

    /// A deps directory at or below the limit must never trigger a prune:
    /// the prune costs a full rebuild, so it may only fire once the
    /// directory is genuinely oversized.
    #[test]
    fn build_cache_is_not_pruned_at_or_below_the_limit() {
        assert!(!should_prune_build_cache(0, 100, false));
        assert!(!should_prune_build_cache(99, 100, false));
        assert!(
            !should_prune_build_cache(100, 100, false),
            "exactly at the limit is not over it"
        );
    }

    /// Above the limit the prune must fire, otherwise the directory grows
    /// without bound and every binary launch pays the assessment stall.
    #[test]
    fn build_cache_is_pruned_above_the_limit() {
        assert!(should_prune_build_cache(101, 100, false));
        assert!(should_prune_build_cache(
            1_063_921,
            DEFAULT_DEPS_ENTRY_LIMIT,
            false
        ));
    }

    /// Both escape hatches must hold even for a pathologically large
    /// directory: an explicit opt-out, and a zero limit meaning "disabled".
    #[test]
    fn build_cache_prune_can_be_disabled() {
        assert!(
            !should_prune_build_cache(1_063_921, DEFAULT_DEPS_ENTRY_LIMIT, true),
            "XTASK_SKIP_TARGET_PRUNE must suppress the prune"
        );
        assert!(
            !should_prune_build_cache(1_063_921, 0, false),
            "a zero limit must disable pruning entirely"
        );
    }

    /// The default must sit above a healthy full build (~16k entries) so
    /// routine work never triggers a rebuild, and below the measured
    /// pathological size that caused the stall.
    ///
    /// Asserted through the predicate rather than by comparing the constant
    /// directly: a bare constant comparison is evaluated at compile time and
    /// rejected by `clippy::assertions_on_constants`, and pinning the
    /// behaviour is what this test is actually for.
    #[test]
    fn default_deps_entry_limit_sits_between_healthy_and_pathological() {
        assert!(
            !should_prune_build_cache(16_421, DEFAULT_DEPS_ENTRY_LIMIT, false),
            "a single healthy full build (~16.4k entries) must not trigger a prune"
        );
        assert!(
            should_prune_build_cache(1_063_921, DEFAULT_DEPS_ENTRY_LIMIT, false),
            "the measured pathological size must trigger a prune"
        );
    }

    fn dirs() -> Vec<(String, String)> {
        vec![
            ("crates/control".to_owned(), "control".to_owned()),
            ("crates/cli".to_owned(), "cli".to_owned()),
            ("crates/daemon".to_owned(), "daemon".to_owned()),
            ("crates/unrelated".to_owned(), "unrelated".to_owned()),
        ]
    }

    fn graph() -> BTreeMap<String, Vec<String>> {
        // cli depends on control + daemon; daemon depends on control.
        let mut g = BTreeMap::new();
        g.insert("control".to_owned(), vec![]);
        g.insert("daemon".to_owned(), vec!["control".to_owned()]);
        g.insert(
            "cli".to_owned(),
            vec!["control".to_owned(), "daemon".to_owned()],
        );
        g.insert("unrelated".to_owned(), vec![]);
        g
    }

    #[test]
    fn changed_leaf_crate_pulls_in_one_hop_dependents() {
        let changed = vec!["crates/control/src/lib.rs".to_owned()];
        let affected = compute_affected_set(&dirs(), &graph(), &changed);
        // control changed; daemon and cli depend on control directly.
        assert!(affected.contains("control"));
        assert!(affected.contains("daemon"));
        assert!(affected.contains("cli"));
        assert!(!affected.contains("unrelated"));
    }

    #[test]
    fn changed_top_crate_has_no_dependents() {
        let changed = vec!["crates/cli/src/main.rs".to_owned()];
        let affected = compute_affected_set(&dirs(), &graph(), &changed);
        assert_eq!(affected.len(), 1);
        assert!(affected.contains("cli"));
    }

    #[test]
    fn transitive_closure_reaches_all_dependents() {
        // A change to a crate whose only direct dependent is `daemon`
        // MUST also pull in `cli` (which depends on daemon): `cli` links
        // the changed code transitively, so skipping it would let
        // `--affected` report PASS while the shipped binary no longer
        // compiles. Model: leaf -> daemon -> cli.
        let dirs = vec![
            ("crates/leaf".to_owned(), "leaf".to_owned()),
            ("crates/daemon".to_owned(), "daemon".to_owned()),
            ("crates/cli".to_owned(), "cli".to_owned()),
        ];
        let mut g = BTreeMap::new();
        g.insert("leaf".to_owned(), vec![]);
        g.insert("daemon".to_owned(), vec!["leaf".to_owned()]);
        g.insert("cli".to_owned(), vec!["daemon".to_owned()]);
        let changed = vec!["crates/leaf/src/lib.rs".to_owned()];
        let affected = compute_affected_set(&dirs, &g, &changed);
        assert!(affected.contains("leaf"));
        assert!(affected.contains("daemon"));
        assert!(
            affected.contains("cli"),
            "closure must reach transitive dependents"
        );
    }

    #[test]
    fn non_crate_changes_yield_empty_set() {
        let changed = vec![
            "documents/README.md".to_owned(),
            "scripts/ci/x.sh".to_owned(),
        ];
        let affected = compute_affected_set(&dirs(), &graph(), &changed);
        assert!(affected.is_empty());
    }

    #[test]
    fn timing_row_is_a_single_seven_field_record() {
        let row = format_timing_row(
            "2026-05-31T12:00:00Z",
            "9e3e346",
            "clean",
            "test",
            "workspace",
            2403,
            "timeout",
        );
        assert_eq!(
            row,
            "2026-05-31T12:00:00Z,9e3e346,clean,test,workspace,2403,timeout"
        );
    }

    #[test]
    fn timing_row_sanitises_separators_in_fields() {
        // A scope with a comma must not split the record into extra columns.
        let row = format_timing_row("t", "c", "clean", "check", "-p a,-p b", 10, "pass");
        assert_eq!(
            row.matches(',').count(),
            6,
            "exactly six separators -> seven fields"
        );
        assert!(row.contains("-p a;-p b"), "comma sanitised to ';'");
    }
}

/// AQ-08 step 8 witness tests: `dispatch` must keep the pre-patch exit
/// codes for the error paths (empty argv and unknown subcommand both exit
/// 2, exactly as the old inline `match` did).
#[cfg(test)]
mod aq08_step8_differential {
    use super::*;

    #[test]
    fn dispatch_empty_argv_exits_two() {
        assert_eq!(dispatch(&[]), 2);
    }

    #[test]
    fn dispatch_unknown_subcommand_exits_two() {
        assert_eq!(dispatch(&["bogus".to_owned()]), 2);
        assert_eq!(dispatch(&["gate".to_owned(), "--skip-test".to_owned()]), 2);
    }
}

/// Plan item 7 (computed reverse-dependency selection for the gate
/// scripts) witnesses. Two layers:
/// 1. the pure fallback policy `should_fallback_full_workspace` — a
///    lockfile, any `build.rs`, any `Cargo.toml` (root or crate-level:
///    dependency/feature edits change workspace-wide feature
///    unification), or a toolchain file change must signal the FULL
///    workspace; ordinary source/doc changes must not;
/// 2. `affected_scope_in` end-to-end in a throwaway git repo with two
///    real crates (`na`, `nb`, `nb` path-depends on `na`), so the
///    cargo-metadata closure and the fallback rule are tested without
///    touching the real checkout. An old build of this crate fails
///    `affected_scope_in_falls_back_on_build_rs_change` and
///    `affected_scope_in_falls_back_on_manifest_change`: the old rule
///    only checked the ROOT `Cargo.toml`/`Cargo.lock`/`rust-toolchain*`
///    and scoped a build.rs or crate-manifest change to the closure.
#[cfg(test)]
mod plan7_affected_crates {
    use super::{
        AFFECTED_CRATES_FULL_WORKSPACE_EXIT, affected_scope_in, dispatch, run_affected_crates,
        should_fallback_full_workspace,
    };
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TEMP_REPO_SEQ: AtomicUsize = AtomicUsize::new(0);

    /// Throwaway git repo removed on drop, so a failing assert can never
    /// leak scratch files into the checkout under test.
    struct TestRepo(PathBuf);

    impl Drop for TestRepo {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write(path: &PathBuf, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|e| panic!("mkdir {parent:?} failed: {e}"));
        }
        std::fs::write(path, content).unwrap_or_else(|e| panic!("write {path:?} failed: {e}"));
    }

    /// Minimal two-crate workspace: `nb` path-depends on `na`, so the
    /// cargo-metadata reverse-dependency closure has one hop to find.
    /// Committed once so `--base HEAD` has a base to diff against.
    fn make_test_workspace() -> TestRepo {
        let seq = TEMP_REPO_SEQ.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("xtask-affected-test-{}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap_or_else(|e| panic!("mkdir {root:?} failed: {e}"));
        write(
            &root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"na\", \"nb\"]\nresolver = \"2\"\n",
        );
        write(
            &root.join("na/Cargo.toml"),
            "[package]\nname = \"na\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(&root.join("na/src/lib.rs"), "");
        write(
            &root.join("nb/Cargo.toml"),
            "[package]\nname = \"nb\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nna = { path = \"../na\" }\n",
        );
        write(&root.join("nb/src/lib.rs"), "");
        for args in [
            vec!["init", "-q", "."],
            vec!["add", "-A"],
            vec![
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "init",
            ],
        ] {
            let out = std::process::Command::new("git")
                .args(&args)
                .current_dir(&root)
                .output()
                .unwrap_or_else(|e| panic!("git {args:?} spawn failed in {root:?}: {e}"));
            assert!(
                out.status.success(),
                "git {args:?} failed in {:?}: {}",
                root,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        TestRepo(root)
    }

    fn root_str(repo: &TestRepo) -> String {
        repo.0.to_string_lossy().into_owned()
    }

    #[test]
    fn lockfile_or_toolchain_change_requires_full_workspace() {
        assert!(should_fallback_full_workspace(&["Cargo.lock".to_owned()]));
        assert!(should_fallback_full_workspace(&[
            "rust-toolchain".to_owned()
        ]));
        assert!(should_fallback_full_workspace(&[
            "rust-toolchain.toml".to_owned()
        ]));
    }

    #[test]
    fn any_manifest_change_requires_full_workspace() {
        // Root AND crate-level: a crate manifest edit can add a dependency
        // or feature, which changes workspace-wide feature unification.
        assert!(should_fallback_full_workspace(&["Cargo.toml".to_owned()]));
        assert!(should_fallback_full_workspace(&[
            "crates/rustynet-cli/Cargo.toml".to_owned()
        ]));
    }

    #[test]
    fn build_rs_change_requires_full_workspace() {
        assert!(should_fallback_full_workspace(&["build.rs".to_owned()]));
        assert!(should_fallback_full_workspace(&[
            "crates/rustynet-crypto/build.rs".to_owned()
        ]));
    }

    #[test]
    fn ordinary_changes_do_not_require_full_workspace() {
        assert!(!should_fallback_full_workspace(&[
            "crates/rustynet-cli/src/main.rs".to_owned()
        ]));
        assert!(!should_fallback_full_workspace(&[
            "documents/README.md".to_owned(),
            "scripts/ci/gate.sh".to_owned(),
        ]));
        // The rule matches by FILE NAME, but a directory merely named like
        // a trigger (no Cargo.toml/build.rs file) must not fire it.
        assert!(!should_fallback_full_workspace(&[
            "crates/build.rs-support/docs/x.md".to_owned()
        ]));
    }

    #[test]
    fn empty_change_list_requires_nothing() {
        assert!(!should_fallback_full_workspace(&[]));
    }

    #[test]
    fn affected_scope_in_scopes_to_changed_crate_and_dependents() {
        let repo = make_test_workspace();
        let lib = repo.0.join("na/src/lib.rs");
        write(&lib, "pub fn x() {}\n");
        let scope =
            affected_scope_in(&root_str(&repo), "HEAD").expect("scope computation succeeds");
        assert_eq!(
            scope,
            Some(vec![
                "-p".to_owned(),
                "na".to_owned(),
                "-p".to_owned(),
                "nb".to_owned()
            ]),
            "changed crate na must pull in its dependent nb"
        );
    }

    #[test]
    fn affected_scope_in_falls_back_on_build_rs_change() {
        let repo = make_test_workspace();
        write(&repo.0.join("na/build.rs"), "fn main() {}\n");
        let scope =
            affected_scope_in(&root_str(&repo), "HEAD").expect("scope computation succeeds");
        assert_eq!(
            scope, None,
            "a new build.rs must signal FULL WORKSPACE, not a closure"
        );
    }

    #[test]
    fn affected_scope_in_falls_back_on_manifest_change() {
        let repo = make_test_workspace();
        let manifest = repo.0.join("na/Cargo.toml");
        let mut content = std::fs::read_to_string(&manifest).unwrap_or_default();
        content.push_str("\n[features]\ndefault = []\n");
        write(&manifest, &content);
        let scope =
            affected_scope_in(&root_str(&repo), "HEAD").expect("scope computation succeeds");
        assert_eq!(
            scope, None,
            "a crate-level Cargo.toml change must signal FULL WORKSPACE"
        );
    }

    #[test]
    fn affected_scope_in_falls_back_when_nothing_detected() {
        let repo = make_test_workspace();
        write(&repo.0.join("docs/note.md"), "x\n");
        let scope =
            affected_scope_in(&root_str(&repo), "HEAD").expect("scope computation succeeds");
        assert_eq!(scope, None, "non-crate changes must not scope to any crate");
    }

    #[test]
    fn affected_scope_in_is_none_with_no_changes() {
        let repo = make_test_workspace();
        let scope =
            affected_scope_in(&root_str(&repo), "HEAD").expect("scope computation succeeds");
        assert_eq!(scope, None, "a clean tree has no affected crates");
    }

    #[test]
    fn affected_crates_usage_errors_exit_two() {
        assert_eq!(
            dispatch(&["affected-crates".to_owned(), "--base".to_owned()]),
            2
        );
        assert_eq!(
            dispatch(&["affected-crates".to_owned(), "bogus".to_owned()]),
            2
        );
    }

    #[test]
    fn full_workspace_signal_is_exit_three() {
        assert_eq!(AFFECTED_CRATES_FULL_WORKSPACE_EXIT, 3);
        // A usage error (2) must never be mistakable for the
        // full-workspace signal (3) a gate script branches on.
        assert_ne!(
            AFFECTED_CRATES_FULL_WORKSPACE_EXIT,
            run_affected_crates(&["--base".to_owned()])
        );
    }

    #[test]
    #[cfg(unix)]
    fn affected_scope_in_tolerates_symlinked_workspace_root() {
        let repo = make_test_workspace();
        let link = repo.0.with_extension("symlink");
        std::os::unix::fs::symlink(&repo.0, &link).expect("symlink created");
        write(&repo.0.join("na/src/lib.rs"), "pub fn x() {}\n");
        let scope = affected_scope_in(&link.to_string_lossy(), "HEAD")
            .expect("affected scope must resolve under a symlinked workspace root");
        let _ = std::fs::remove_file(&link);
        assert_eq!(
            scope,
            Some(vec![
                "-p".to_owned(),
                "na".to_owned(),
                "-p".to_owned(),
                "nb".to_owned()
            ]),
            "a symlinked workspace root must still resolve to the closure"
        );
    }
}
