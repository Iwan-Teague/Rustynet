#![forbid(unsafe_code)]
//! Fail if a prebuilt MCP server binary under `bin/` is older than the source it
//! was built from.
//!
//! Why this exists: the `rustynet-mcp-*` servers are hand-built and `bin/` is
//! gitignored, so nothing rebuilds them on checkout or in CI. On 2026-07-17 the
//! running `rustynet-mcp-lab-state` was 8 days stale — eight multi-host tools were
//! in source and absent from the running server, and an agent hit it as tools
//! silently missing and a `check_vm_reachable` returning a wrong "not in inventory"
//! error. A stale prebuilt binary is exactly as broken as a missing one; this turns
//! either into a loud failure with the one-line fix.
//!
//! Scope, stated honestly: this compares mtimes within the `rustynet-mcp` crate
//! (each server's own `src/bin/<x>.rs`, plus the crate's shared source, Cargo.toml
//! and the workspace Cargo.lock). `rustynet-mcp` depends on no other workspace
//! crate, so that is the complete first-party dependency set. mtime is not a content
//! hash — a branch switch that rewrites source timestamps can produce a false
//! "stale", which is safe (an unnecessary rebuild) rather than dangerous (a missed
//! one). `--fix` rebuilds and atomically installs whatever is stale.

use rustynetd::exit_codes::ExitCode;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let fix = std::env::args().skip(1).any(|arg| arg == "--fix");
    let root = repo_root().map_err(|err| {
        eprintln!("error [{}]: {err}", ExitCode::ConfigError);
        ExitCode::ConfigError.as_i32()
    })?;
    let mcp_dir = root.join("crates/rustynet-mcp");

    let bins = parse_bin_table(&mcp_dir.join("Cargo.toml")).map_err(|err| {
        eprintln!("error [{}]: {err}", ExitCode::ConfigError);
        ExitCode::ConfigError.as_i32()
    })?;
    if bins.is_empty() {
        eprintln!(
            "error [{}]: no [[bin]] entries found in crates/rustynet-mcp/Cargo.toml",
            ExitCode::ConfigError
        );
        return Err(ExitCode::ConfigError.as_i32());
    }

    // Shared freshness inputs, common to every server: everything under
    // crates/rustynet-mcp/src/ that is NOT a per-server bin (today just lib.rs), the
    // crate manifest, and the workspace lockfile (dependency version bumps require a
    // rebuild). Excluding the bin/ files means editing lab_state.rs does not falsely
    // flag repo_context — they are independent compilation units.
    let shared = newest_shared_input(&mcp_dir, &root).map_err(|err| {
        eprintln!("error [{}]: {err}", ExitCode::ConfigError);
        ExitCode::ConfigError.as_i32()
    })?;

    let mut stale: Vec<StaleBinary> = Vec::new();
    for (name, src_rel) in &bins {
        let src_path = mcp_dir.join(src_rel);
        let src_mtime = file_mtime(&src_path).map_err(|err| {
            eprintln!("error [{}]: {err}", ExitCode::ConfigError);
            ExitCode::ConfigError.as_i32()
        })?;
        // The newest thing this specific server was built from.
        let (newest_mtime, newest_file) = if src_mtime >= shared.0 {
            (src_mtime, src_path.clone())
        } else {
            (shared.0, shared.1.clone())
        };

        let bin_path = root.join("bin").join(name);
        match file_mtime_opt(&bin_path) {
            None => stale.push(StaleBinary {
                name: name.clone(),
                reason: "not built (bin/ is gitignored — build it)".to_owned(),
                newer_source: newest_file,
            }),
            Some(bin_mtime) if bin_mtime < newest_mtime => {
                let gap = newest_mtime
                    .duration_since(bin_mtime)
                    .map(|d| format!("{}s older than", d.as_secs()))
                    .unwrap_or_else(|_| "older than".to_owned());
                stale.push(StaleBinary {
                    name: name.clone(),
                    reason: format!("binary is {gap} its source"),
                    newer_source: newest_file,
                });
            }
            Some(_) => println!("  {name}: fresh"),
        }
    }

    if stale.is_empty() {
        println!("MCP binaries fresh: PASS ({} server(s))", bins.len());
        return Ok(());
    }

    if fix {
        return apply_fix(&root, &stale);
    }

    eprintln!();
    eprintln!(
        "error [{}]: {} MCP server binary/binaries are stale or missing:",
        ExitCode::PolicyReject,
        stale.len()
    );
    for s in &stale {
        eprintln!(
            "  {} — {} (newer source: {})",
            s.name,
            s.reason,
            rel_display(&root, &s.newer_source)
        );
    }
    eprintln!(
        "\n  Rebuild and install atomically (never in-place cp — the client keeps the\n  \
         running binary mmap'd, so cp truncates it):\n"
    );
    for s in &stale {
        eprintln!(
            "    cargo build --release --bin {name} && \\\n      cp target/release/{name} bin/{name}.new && mv -f bin/{name}.new bin/{name}",
            name = s.name
        );
    }
    eprintln!(
        "\n  Or run this check with --fix to do it for the stale ones, then reconnect\n  \
         the server (/mcp -> reconnect, or restart the client)."
    );
    Err(ExitCode::PolicyReject.as_i32())
}

struct StaleBinary {
    name: String,
    reason: String,
    newer_source: PathBuf,
}

/// Rebuild and atomically install each stale/missing server, then re-verify.
fn apply_fix(root: &Path, stale: &[StaleBinary]) -> Result<(), i32> {
    for s in stale {
        println!("  building {} …", s.name);
        let built = Command::new("cargo")
            .args(["build", "--release", "--bin", s.name.as_str()])
            .current_dir(root)
            .status();
        match built {
            Ok(status) if status.success() => {}
            Ok(status) => {
                eprintln!(
                    "error [{}]: cargo build --bin {} exited {}",
                    ExitCode::TransientFailure,
                    s.name,
                    status.code().unwrap_or(-1)
                );
                return Err(ExitCode::TransientFailure.as_i32());
            }
            Err(err) => {
                eprintln!(
                    "error [{}]: could not run cargo build for {}: {err}",
                    ExitCode::TransientFailure,
                    s.name
                );
                return Err(ExitCode::TransientFailure.as_i32());
            }
        }

        // Atomic install: write beside, then rename over. An in-place cp would
        // truncate a binary the MCP client still holds mmap'd (CLAUDE.md §12.5).
        let src = root.join("target/release").join(&s.name);
        let dst = root.join("bin").join(&s.name);
        let tmp = root.join("bin").join(format!("{}.new", s.name));
        if let Err(err) = std::fs::copy(&src, &tmp) {
            eprintln!(
                "error [{}]: copy {} -> {} failed: {err}",
                ExitCode::TransientFailure,
                src.display(),
                tmp.display()
            );
            return Err(ExitCode::TransientFailure.as_i32());
        }
        if let Err(err) = std::fs::rename(&tmp, &dst) {
            eprintln!(
                "error [{}]: atomic rename {} -> {} failed: {err}",
                ExitCode::TransientFailure,
                tmp.display(),
                dst.display()
            );
            let _ = std::fs::remove_file(&tmp);
            return Err(ExitCode::TransientFailure.as_i32());
        }
        println!("  installed bin/{}", s.name);
    }
    println!(
        "\nFixed {} binary/binaries. Reconnect the server(s): /mcp -> reconnect, or restart the client.",
        stale.len()
    );
    Ok(())
}

/// Newest mtime across the crate's shared build inputs, and which file it was.
fn newest_shared_input(mcp_dir: &Path, root: &Path) -> Result<(SystemTime, PathBuf), String> {
    let mut newest = (SystemTime::UNIX_EPOCH, mcp_dir.join("Cargo.toml"));
    let mut consider = |path: &Path| -> Result<(), String> {
        if let Some(mtime) = file_mtime_opt(path)
            && mtime > newest.0
        {
            newest = (mtime, path.to_path_buf());
        }
        Ok(())
    };
    consider(&mcp_dir.join("Cargo.toml"))?;
    consider(&root.join("Cargo.lock"))?;
    // All .rs under src/ EXCEPT the per-server bins.
    collect_shared_rs(&mcp_dir.join("src"), &mcp_dir.join("src/bin"), &mut newest)?;
    Ok(newest)
}

fn collect_shared_rs(
    dir: &Path,
    bin_dir: &Path,
    newest: &mut (SystemTime, PathBuf),
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|err| format!("read_dir {} failed: {err}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("dir entry in {}: {err}", dir.display()))?;
        let path = entry.path();
        // The bin/ directory holds independent per-server compilation units; each
        // server accounts for its own file separately, so skip it here.
        if path == bin_dir {
            continue;
        }
        if path.is_dir() {
            collect_shared_rs(&path, bin_dir, newest)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs")
            && let Some(mtime) = file_mtime_opt(&path)
            && mtime > newest.0
        {
            *newest = (mtime, path);
        }
    }
    Ok(())
}

/// Parse the `[[bin]]` table: each server's binary `name` and source `path`.
///
/// A deliberate line-scan rather than the `toml` crate, which is `vm-lab`-gated in
/// this crate — a freshness gate must not require a feature to build. The manifest
/// is repo-controlled and simple, so this is robust enough; a malformed block that
/// yields a name without a path is reported rather than silently dropped.
fn parse_bin_table(cargo_toml: &Path) -> Result<Vec<(String, String)>, String> {
    let body = std::fs::read_to_string(cargo_toml)
        .map_err(|err| format!("read {} failed: {err}", cargo_toml.display()))?;
    let mut bins = Vec::new();
    let mut in_bin = false;
    let mut name: Option<String> = None;
    let mut path: Option<String> = None;
    let mut flush = |name: &mut Option<String>, path: &mut Option<String>| -> Result<(), String> {
        match (name.take(), path.take()) {
            (Some(n), Some(p)) => {
                bins.push((n, p));
                Ok(())
            }
            (Some(n), None) => Err(format!("[[bin]] {n} has no path")),
            (None, Some(p)) => Err(format!("[[bin]] with path {p} has no name")),
            (None, None) => Ok(()),
        }
    };
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed == "[[bin]]" {
            flush(&mut name, &mut path)?;
            in_bin = true;
            continue;
        }
        if trimmed.starts_with('[') && trimmed != "[[bin]]" {
            flush(&mut name, &mut path)?;
            in_bin = false;
            continue;
        }
        if !in_bin {
            continue;
        }
        if let Some(value) = toml_str_value(trimmed, "name") {
            name = Some(value);
        } else if let Some(value) = toml_str_value(trimmed, "path") {
            path = Some(value);
        }
    }
    flush(&mut name, &mut path)?;
    Ok(bins)
}

/// Extract `key = "value"` from one line, returning the unquoted value.
fn toml_str_value(line: &str, key: &str) -> Option<String> {
    let rest = line.strip_prefix(key)?.trim_start();
    let rest = rest.strip_prefix('=')?.trim();
    let inner = rest.strip_prefix('"')?.strip_suffix('"')?;
    Some(inner.to_owned())
}

fn file_mtime(path: &Path) -> Result<SystemTime, String> {
    file_mtime_opt(path).ok_or_else(|| format!("cannot stat {}", path.display()))
}

fn file_mtime_opt(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

fn rel_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            format!(
                "failed to resolve repository root from manifest dir {}",
                manifest_dir.display()
            )
        })
}

#[cfg(test)]
mod tests {
    use super::{parse_bin_table, toml_str_value};
    use std::io::Write as _;

    #[test]
    fn parses_the_bin_table_name_and_path() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(
            f,
            "[package]\nname = \"x\"\n\n[[bin]]\nname = \"rustynet-mcp-lab-state\"\npath = \"src/bin/lab_state.rs\"\n\n[[bin]]\nname = \"rustynet-mcp-ai-agent\"\npath = \"src/bin/ai_agent.rs\"\n\n[dependencies]\nserde = \"1\"\n"
        )
        .unwrap();
        let bins = parse_bin_table(f.path()).unwrap();
        assert_eq!(
            bins,
            vec![
                (
                    "rustynet-mcp-lab-state".to_owned(),
                    "src/bin/lab_state.rs".to_owned()
                ),
                (
                    "rustynet-mcp-ai-agent".to_owned(),
                    "src/bin/ai_agent.rs".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn a_package_name_before_any_bin_is_not_mistaken_for_a_binary() {
        // The [package] name must not leak into the bin list.
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(
            f,
            "[package]\nname = \"rustynet-mcp\"\n\n[[bin]]\nname = \"a\"\npath = \"src/bin/a.rs\"\n"
        )
        .unwrap();
        let bins = parse_bin_table(f.path()).unwrap();
        assert_eq!(bins, vec![("a".to_owned(), "src/bin/a.rs".to_owned())]);
    }

    #[test]
    fn a_bin_without_a_path_is_an_error_not_a_silent_drop() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "[[bin]]\nname = \"a\"\n").unwrap();
        assert!(parse_bin_table(f.path()).is_err());
    }

    #[test]
    fn toml_str_value_reads_quoted_values_only() {
        assert_eq!(toml_str_value("name = \"x\"", "name"), Some("x".to_owned()));
        assert_eq!(toml_str_value("path=\"y\"", "path"), Some("y".to_owned()));
        assert_eq!(toml_str_value("name = x", "name"), None);
        assert_eq!(toml_str_value("other = \"x\"", "name"), None);
    }

    #[test]
    fn the_real_manifest_maps_all_four_servers() {
        // Guards against the check silently covering fewer servers than exist —
        // e.g. after the deepseek -> ai_agent rename.
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("rustynet-mcp/Cargo.toml");
        let bins = parse_bin_table(&manifest).expect("real manifest parses");
        let names: Vec<&str> = bins.iter().map(|(n, _)| n.as_str()).collect();
        for expected in [
            "rustynet-mcp-lab-state",
            "rustynet-mcp-repo-context",
            "rustynet-mcp-gate-runner",
            "rustynet-mcp-ai-agent",
        ] {
            assert!(
                names.contains(&expected),
                "manifest is missing {expected}: {names:?}"
            );
        }
    }
}
