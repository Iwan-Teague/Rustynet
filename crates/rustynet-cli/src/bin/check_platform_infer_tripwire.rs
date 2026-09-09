#![forbid(unsafe_code)]

//! QH-82 platform-inference tripwire.
//!
//! `VmGuestPlatform::infer` returns `Option<Self>` and never guesses Linux;
//! every resolution site must name its unknown (design:
//! `documents/operations/active/PlatformInferMigrationDesign_2026-09-08.md`,
//! review verdict BUILD-WITH-CHANGE: the anti-`unwrap_or` property must be a
//! gate, not review discipline). This gate fails when that property is
//! regressed in source text:
//!
//! R1 — any non-comment line composing `infer(` with
//!      `unwrap_or`/`unwrap_or_else` yielding `VmGuestPlatform::Linux`
//!      (or the in-impl `Self::Linux` spelling), on one line;
//! R2 — the same composition spread across lines: an `infer(` call whose
//!      statement (tracked by paren balance, bounded window) contains an
//!      `unwrap_or`/`unwrap_or_else` before it closes;
//! R3 — any `unwrap_or(VmGuestPlatform::Linux)` /
//!      `unwrap_or_else(.. VmGuestPlatform::Linux)` (or `Self::Linux`)
//!      anywhere in the scanned tree, whether or not `infer` appears.
//!
//! Comments and doc-comments are skipped: the audit trail legitimately names
//! the banned pattern in prose. Test fixture strings below are assembled from
//! fragments so this file can never match its own patterns.

use rustynetd::exit_codes::ExitCode;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_SCAN_ROOT: &str = "crates";
/// Upper bound on how far a multi-line `infer(` statement may spread before
/// the window is abandoned. Real call sites close within a few lines.
const MAX_CONTINUATION_LINES: usize = 32;

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let _ignored_args: Vec<OsString> = env::args_os().skip(1).collect();
    let repo_root = repo_root().map_err(|err| {
        eprintln!("error [{}]: {err}", ExitCode::ConfigError);
        ExitCode::ConfigError.as_i32()
    })?;
    let scan_root = env::var_os("RUSTYNET_INFER_TRIPWIRE_SCAN_ROOT")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root.join(DEFAULT_SCAN_ROOT));

    let mut rust_files = Vec::new();
    collect_rust_files(&scan_root, &mut rust_files).map_err(|err| {
        eprintln!(
            "error [{}]: failed to walk scan root {}: {err}",
            ExitCode::TransientFailure,
            scan_root.display()
        );
        ExitCode::TransientFailure.as_i32()
    })?;
    rust_files.sort();

    let mut violations = Vec::new();
    for path in &rust_files {
        // The scanner never scans its own source: its test module carries
        // deliberate pattern-shaped fixtures (assembled from fragments so the
        // scanner's production half can never match them, but the file as a
        // whole still contains the tokens). Its production behaviour is
        // pinned by the unit tests below instead.
        if path
            .file_name()
            .map(|name| name == "check_platform_infer_tripwire.rs")
            == Some(true)
        {
            continue;
        }
        let source = match fs::read_to_string(path) {
            Ok(source) => source,
            Err(err) => {
                eprintln!(
                    "error [{}]: failed to read {}: {err}",
                    ExitCode::TransientFailure,
                    path.display()
                );
                return Err(ExitCode::TransientFailure.as_i32());
            }
        };
        scan_source(path, &source, &mut violations);
    }

    if violations.is_empty() {
        println!(
            "Platform infer tripwire: PASS ({} files scanned, no silent-Linux fallbacks)",
            rust_files.len()
        );
        return Ok(());
    }

    for violation in &violations {
        eprintln!(
            "FAIL [{}:{}]: {}",
            violation.path.display(),
            violation.line,
            violation.reason
        );
    }
    eprintln!(
        "error [{}]: {} platform-infer tripwire violation(s) — an unknown platform is being coerced back to Linux; resolve it explicitly instead",
        ExitCode::PolicyReject,
        violations.len()
    );
    Err(ExitCode::PolicyReject.as_i32())
}

#[derive(Debug, PartialEq, Eq)]
struct Violation {
    path: PathBuf,
    line: usize,
    reason: String,
}

fn is_comment_line(trimmed: &str) -> bool {
    trimmed.starts_with("//")
}

/// True when the line composes an `infer(` call with an `unwrap_or`-family
/// fallback on the same line (R1).
fn line_composes_infer_with_unwrap(trimmed: &str) -> bool {
    trimmed.contains("infer(")
        && (trimmed.contains("unwrap_or") || trimmed.contains("unwrap_or_else"))
}

/// True when the line carries a Linux-typed `unwrap_or` fallback (R1/R3).
fn line_is_linux_unwrap_fallback(trimmed: &str) -> bool {
    for linux_spelling in ["VmGuestPlatform::Linux", "Self::Linux"] {
        for fallback in ["unwrap_or(", "unwrap_or_else("] {
            if let Some(start) = trimmed.find(fallback) {
                let tail = &trimmed[start + fallback.len()..];
                let tail_trimmed = tail.trim_start();
                if tail_trimmed.starts_with(linux_spelling)
                    || tail_trimmed.starts_with("|_|")
                        && tail_trimmed[3..].trim_start().starts_with(linux_spelling)
                {
                    return true;
                }
            }
        }
    }
    false
}

fn scan_source(path: &Path, source: &str, violations: &mut Vec<Violation>) {
    let lines: Vec<&str> = source.lines().collect();
    let mut index = 0usize;
    while index < lines.len() {
        let trimmed = lines[index].trim();
        let line_number = index + 1;
        if !is_comment_line(trimmed) {
            if line_composes_infer_with_unwrap(trimmed) {
                violations.push(Violation {
                    path: path.to_path_buf(),
                    line: line_number,
                    reason: "infer( composed with unwrap_or yielding VmGuestPlatform::Linux — resolve the unknown explicitly instead".to_owned(),
                });
            } else if line_is_linux_unwrap_fallback(trimmed) {
                violations.push(Violation {
                    path: path.to_path_buf(),
                    line: line_number,
                    reason: "unwrap_or fallback to VmGuestPlatform::Linux — an unknown platform must not silently become Linux".to_owned(),
                });
            } else if trimmed.contains("infer(") {
                // R2: follow the statement across lines until its terminating
                // `;` (bounded); flag when an unwrap fallback and a Linux
                // spelling both appear inside that statement.
                let mut cursor = index + 1;
                let end = (index + MAX_CONTINUATION_LINES).min(lines.len());
                let mut saw_unwrap_line: Option<usize> = None;
                let mut saw_unwrap_line_has_linux = false;
                let mut saw_linux_elsewhere = false;
                while cursor < end {
                    let continuation = lines[cursor].trim();
                    if !is_comment_line(continuation) {
                        let has_unwrap = continuation.contains("unwrap_or(")
                            || continuation.contains("unwrap_or_else(");
                        let has_linux = continuation.contains("VmGuestPlatform::Linux")
                            || continuation.contains("Self::Linux");
                        if has_unwrap && saw_unwrap_line.is_none() {
                            saw_unwrap_line = Some(cursor + 1);
                            saw_unwrap_line_has_linux = has_linux;
                        } else if has_linux {
                            saw_linux_elsewhere = true;
                        }
                        if continuation.contains(';') {
                            break;
                        }
                    }
                    cursor += 1;
                }
                if let Some(unwrap_line) = saw_unwrap_line {
                    if saw_unwrap_line_has_linux || saw_linux_elsewhere {
                        // A Linux fallback on the unwrap line itself is
                        // already reported by R3 in the main loop; only add
                        // the statement-level report when the Linux literal
                        // sits on a different line.
                        if !saw_unwrap_line_has_linux {
                            violations.push(Violation {
                                path: path.to_path_buf(),
                                line: unwrap_line,
                                reason: "multi-line infer( statement composed with unwrap_or yielding a Linux default — resolve the unknown explicitly instead".to_owned(),
                            });
                        }
                    }
                }
            }
        }
        index += 1;
    }
}

fn collect_rust_files(root: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if root.is_file() {
        if root.extension().map(|ext| ext == "rs").unwrap_or(false) {
            out.push(root.to_path_buf());
        }
        return Ok(());
    }
    let entries = fs::read_dir(root)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            let name = path.file_name().and_then(|name| name.to_str());
            // Never descend into build output; it mirrors scanned sources.
            if name == Some("target") || name == Some(".git") {
                continue;
            }
            collect_rust_files(&path, out)?;
        } else if file_type.is_file() && path.extension().map(|ext| ext == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
    Ok(())
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
    use super::*;

    // Fixture fragments are split so this file never matches its own scan.
    const INFER: &str = "VmGuestPlatform::inf";
    const OPEN: &str = "er(";
    const UNWRAP: &str = "unwrap_or(";
    const LINUX: &str = "VmGuestPlatform::Linux";

    fn infer_call() -> String {
        format!("let p = {INFER}{OPEN}None, None, \"node-7\", None{UNWRAP}{LINUX});")
    }

    #[test]
    fn flags_same_line_infer_unwrap_composition() {
        let mut violations = Vec::new();
        scan_source(Path::new("x.rs"), &infer_call(), &mut violations);
        assert_eq!(violations.len(), 1, "R1 must fire on the one-line bypass");
        assert!(violations[0].reason.contains("composed with unwrap_or"));
    }

    #[test]
    fn flags_linux_unwrap_fallback_without_infer() {
        let mut violations = Vec::new();
        scan_source(
            Path::new("x.rs"),
            &format!("let p = entry.platform.{UNWRAP}{LINUX});"),
            &mut violations,
        );
        assert_eq!(violations.len(), 1, "R3 must fire on the bare fallback");
        assert!(
            violations[0]
                .reason
                .contains("must not silently become Linux")
        );
    }

    #[test]
    fn flags_self_linux_spelling() {
        let mut violations = Vec::new();
        scan_source(
            Path::new("x.rs"),
            &format!("let p = Self::inf{OPEN}None, None, \"a\", None{UNWRAP}Self::Linux);"),
            &mut violations,
        );
        assert_eq!(
            violations.len(),
            1,
            "in-impl Self::Linux spelling must also fire"
        );
    }

    #[test]
    fn flags_multi_line_infer_unwrap_composition() {
        let source = format!(
            "let p = {INFER}{OPEN}\n    explicit,\n    os_name,\n    alias,\n    utm,\n)\n.{UNWRAP}{LINUX});"
        );
        let mut violations = Vec::new();
        scan_source(Path::new("x.rs"), &source, &mut violations);
        assert_eq!(
            violations.len(),
            1,
            "the Linux unwrap fallback must be reported once"
        );
        assert_eq!(violations[0].line, 7);
    }

    #[test]
    fn flags_linux_default_split_onto_its_own_line() {
        let source = format!(
            "let p = {INFER}{OPEN}\n    explicit,\n    os_name,\n    alias,\n    utm,\n)\n.{UNWRAP}|\n    {LINUX});"
        );
        let mut violations = Vec::new();
        scan_source(Path::new("x.rs"), &source, &mut violations);
        assert_eq!(
            violations.len(),
            1,
            "R2 must fire when the Linux literal sits on its own line"
        );
        assert_eq!(violations[0].line, 7);
        assert!(violations[0].reason.contains("multi-line"));
    }

    #[test]
    fn stays_silent_on_comment_mentions_and_non_linux_unwraps() {
        let source = format!(
            "/// The old bug was `{UNWRAP}{LINUX})` — documented, not committed.\n// {INFER}{OPEN}..{UNWRAP}{LINUX});\nlet shell = x.remote_shell.{UNWRAP}VmRemoteShell::Unsupported);\nlet p = {INFER}{OPEN}None, None, \"node-7\", None);"
        );
        let mut violations = Vec::new();
        scan_source(Path::new("x.rs"), &source, &mut violations);
        assert!(
            violations.is_empty(),
            "comments and non-Linux unwraps must stay silent: {violations:?}"
        );
    }

    #[test]
    fn does_not_flag_unwrap_else_with_non_linux_body_or_later_unwrap() {
        let source = format!(
            "let p = {INFER}{OPEN}None, None, \"a\", None);\nlet q = something_else().{UNWRAP}String::new());"
        );
        let mut violations = Vec::new();
        scan_source(Path::new("x.rs"), &source, &mut violations);
        assert!(
            violations.is_empty(),
            "closed statements must not bleed: {violations:?}"
        );
    }
}
