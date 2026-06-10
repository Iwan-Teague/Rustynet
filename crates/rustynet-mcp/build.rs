//! Build script: bakes the Rustynet repo root AND build provenance (git commit,
//! dirty flag, build time) into the binary at compile time.
//!
//! The MCP servers use the repo root to find documents/ and crates/ regardless
//! of the client's CWD, and report the provenance as `serverInfo.version` so a
//! stale binary (an old ./bin launched while the tree moved on) is detectable.

use std::path::Path;
use std::process::Command;

fn main() {
    // CARGO_MANIFEST_DIR = .../Rustynet/crates/rustynet-mcp
    // Go up two levels to get the repo root.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR unset");
    let manifest_dir = Path::new(&manifest_dir);
    let repo_root = manifest_dir
        .parent() // crates/
        .and_then(|p| p.parent()) // Rustynet/
        .expect("Failed to resolve repo root from CARGO_MANIFEST_DIR");

    println!(
        "cargo:rustc-env=RUSTYNET_REPO_BAKED={}",
        repo_root.display()
    );

    // ── Build provenance ──────────────────────────────────────────────
    // No `rerun-if-changed` is emitted, so Cargo's default applies: this script
    // re-runs whenever a package file changes — i.e. on every meaningful rebuild
    // of this crate — keeping the baked SHA/time fresh. A git SHA that lags HEAD
    // therefore means the binary's own source lags, which is exactly the signal.
    let sha =
        git(repo_root, &["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());
    // `-dirty` when the tracked working tree is modified (untracked files — e.g.
    // proposal docs — don't count, they aren't part of any binary).
    let dirty = match git(
        repo_root,
        &["status", "--porcelain", "--untracked-files=no"],
    ) {
        Some(s) if !s.is_empty() => "-dirty",
        _ => "",
    };
    println!("cargo:rustc-env=RUSTYNET_GIT_SHA={sha}{dirty}");

    // Build time in UTC. `date` is present on the macOS/Linux build hosts; UTC
    // keeps the string comparable regardless of the host's local timezone.
    let build_time = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=RUSTYNET_BUILD_TIME={build_time}");
}

/// Run a git subcommand in `dir`, returning trimmed stdout on success.
fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}
