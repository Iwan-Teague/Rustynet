//! Developer task runner for the Rustynet workspace.
//!
//! Currently provides one subcommand, `gates`, a fail-fast replacement
//! for chaining the mandatory Rust gates by hand. It runs them in
//! dependency order (fmt → check → clippy → test) and STOPS at the
//! first failure, so a compile or lint error surfaces in minutes
//! instead of after the whole test suite. Each stage runs under a
//! timeout watchdog: if a stage hangs past its budget it is killed
//! (whole process group) and the tail of its output is printed, so a
//! stuck test names itself instead of stalling the loop indefinitely.
//!
//! All output is streamed live (tee) so progress is visible while the
//! gate runs; the last lines are also retained for the failure report.
//!
//! Usage:
//!   cargo run -p rustynet-xtask -- gates                  # full workspace
//!   cargo run -p rustynet-xtask -- gates -p rustynet-cli  # scope to a crate
//!   cargo run -p rustynet-xtask -- gates --skip-test      # gates without tests
//!   cargo run -p rustynet-xtask -- gates --affected       # only changed crates + 1-hop dependents
//!   cargo run -p rustynet-xtask -- gates --affected --base origin/main
//!
//! `--affected` scopes check/clippy/test to the workspace crates touched
//! since `--base` (default `origin/main`, including uncommitted and
//! untracked changes) plus their direct reverse-dependents (one hop).
//! This catches the vast majority of breakage a change can cause while
//! skipping unrelated crates. If a root build file (`Cargo.toml`,
//! `Cargo.lock`, `rust-toolchain*`) changed, or no workspace crate is
//! affected, it falls back to the full workspace to stay safe. `fmt`
//! always runs workspace-wide (it is cheap).
//!
//! Per-stage timeouts (seconds) are overridable via env:
//!   XTASK_FMT_TIMEOUT (default 120)
//!   XTASK_CHECK_TIMEOUT (default 1200)
//!   XTASK_CLIPPY_TIMEOUT (default 1500)
//!   XTASK_TEST_TIMEOUT (default 2400)
//!
//! Exit codes: 0 all gates passed, 1 a gate failed, 124 a gate timed out.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;

const TIMEOUT_EXIT_CODE: i32 = 124;
/// Lines of tee'd output retained for the failure/timeout report.
const TAIL_LINES: usize = 40;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let exit_code = match args.first().map(String::as_str) {
        Some("gates") => run_gates(&args[1..]),
        Some(other) => {
            eprintln!("xtask: unknown subcommand: {other}");
            eprintln!("usage: xtask gates [--skip-test] [cargo scope args...]");
            2
        }
        None => {
            eprintln!("usage: xtask gates [--skip-test] [cargo scope args...]");
            2
        }
    };
    std::process::exit(exit_code);
}

struct Stage {
    label: &'static str,
    timeout: Duration,
    args: Vec<String>,
}

fn run_gates(rest: &[String]) -> i32 {
    let mut skip_test = false;
    let mut affected = false;
    let mut base = "origin/main".to_owned();
    let mut scope: Vec<String> = Vec::new();
    let mut iter = rest.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--skip-test" => skip_test = true,
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
                    "==> [affected] root/build files changed or no crate detected — full workspace"
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

    let mut stages = vec![
        Stage {
            label: "fmt",
            timeout: timeout_from_env("XTASK_FMT_TIMEOUT", 120),
            args: vec![
                "fmt".to_owned(),
                "--all".to_owned(),
                "--".to_owned(),
                "--check".to_owned(),
            ],
        },
        Stage {
            label: "check",
            timeout: timeout_from_env("XTASK_CHECK_TIMEOUT", 1200),
            args: with_scope(&["check"]),
        },
        Stage {
            label: "clippy",
            timeout: timeout_from_env("XTASK_CLIPPY_TIMEOUT", 1500),
            args: {
                let mut a = with_scope(&["clippy"]);
                a.push("--".to_owned());
                a.push("-D".to_owned());
                a.push("warnings".to_owned());
                a
            },
        },
    ];
    if !skip_test {
        stages.push(Stage {
            label: "test",
            timeout: timeout_from_env("XTASK_TEST_TIMEOUT", 2400),
            args: with_scope(&["test"]),
        });
    }

    for stage in &stages {
        match run_stage(stage) {
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

fn run_stage(stage: &Stage) -> StageOutcome {
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
            return StageOutcome::Fail(1);
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
        return StageOutcome::Timeout;
    }
    match status {
        Ok(status) if status.success() => {
            println!("==> [{}] PASS ({elapsed}s)", stage.label);
            StageOutcome::Pass
        }
        Ok(status) => {
            let code = status.code().unwrap_or(1);
            eprintln!("!!! [{}] FAILED (rc={code}, {elapsed}s)", stage.label);
            print_tail(&tail);
            StageOutcome::Fail(code)
        }
        Err(err) => {
            eprintln!("!!! [{}] wait failed: {err}", stage.label);
            print_tail(&tail);
            StageOutcome::Fail(1)
        }
    }
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
/// plus their one-hop reverse-dependents. Returns `Ok(None)` to signal
/// "run the full workspace" — used when a root build file changed or no
/// workspace crate is affected, so we never under-test.
fn affected_scope(base: &str) -> Result<Option<Vec<String>>, String> {
    let repo_root = git_capture(&["rev-parse", "--show-toplevel"])?
        .trim()
        .to_owned();
    if repo_root.is_empty() {
        return Err("could not resolve repo root".to_owned());
    }
    let changed = changed_files(base);
    if changed.is_empty() {
        return Ok(None);
    }
    for file in &changed {
        if matches!(file.as_str(), "Cargo.toml" | "Cargo.lock")
            || file.starts_with("rust-toolchain")
        {
            return Ok(None);
        }
    }

    let meta = cargo_metadata(&repo_root)?;
    let packages = meta
        .get("packages")
        .and_then(|v| v.as_array())
        .ok_or("cargo metadata: missing packages array")?;

    let ws_names: std::collections::BTreeSet<String> = packages
        .iter()
        .filter_map(|p| p.get("name").and_then(|n| n.as_str()).map(str::to_owned))
        .collect();
    // (repo-relative crate dir, package name)
    let mut dir_of: Vec<(String, String)> = Vec::new();
    // package name -> workspace dependency names
    let mut deps_of: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    let root_prefix = format!("{repo_root}/");
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
/// plus their one-hop reverse-dependents.
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
    // One hop: add every workspace crate that directly depends on a
    // directly-changed crate.
    let direct: Vec<String> = affected.iter().cloned().collect();
    for (name, deps) in deps_of {
        if deps.iter().any(|dep| direct.contains(dep)) {
            affected.insert(name.clone());
        }
    }
    affected
}

fn git_capture(args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
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
fn changed_files(base: &str) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for args in [
        vec!["diff", "--name-only", base],
        vec!["diff", "--name-only", "HEAD"],
        vec!["ls-files", "--others", "--exclude-standard"],
    ] {
        if let Ok(out) = git_capture(&args) {
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

#[cfg(test)]
mod tests {
    use super::compute_affected_set;
    use std::collections::BTreeMap;

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
    fn one_hop_only_no_transitive_explosion() {
        // A change to a crate whose only dependent is `daemon` must NOT
        // transitively pull in `cli` (which depends on daemon) — we stop
        // at one hop. Model: leaf -> daemon -> cli.
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
            !affected.contains("cli"),
            "one-hop must not reach transitive dependents"
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
}
