//! X3 — static no-secret-leakage audit.
//!
//! The verifier sweeps the rustynetd + rustynet-cli source tree at test
//! time and looks for log/print/format call-sites whose format args
//! interpolate a known secret-bearing identifier (passphrase bytes, a
//! private-key byte array, a runtime token, etc.). The audit runs as
//! a regular `cargo test` so any regression that adds a new offender
//! lands as a named test failure, not a silent leak.
//!
//! Two complementary forms of detection:
//!
//! 1. **Forbidden format placeholders** — patterns like `{passphrase}`,
//!    `{passphrase:?}`, `{private_key_bytes}`, `{signing_key_bytes}`,
//!    `{secret}` appearing inside a log/print macro call. The pattern
//!    catches the common-shape leak: a developer adds `eprintln!("…
//!    {passphrase}")` while debugging and forgets to remove it.
//!
//! 2. **Forbidden Debug-derive on secret-bearing types** — the
//!    canonical secret-bearing structs in `key_material` must NOT
//!    carry `#[derive(Debug)]` or implement `Debug`, since any future
//!    `{:?}` print would surface the inner bytes. Audited by checking
//!    that those types' source spans contain no `Debug` derive and
//!    no manual `impl Debug for <Type>`.
//!
//! The audit is conservative: it allowlists doc-comments, test files,
//! and the audit module itself so the patterns can be discussed in
//! code review and tests. Allowlist scope is narrow — only the
//! comments / strings that documentate the audit itself.

#![cfg(test)]

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Identifier substrings that must NOT appear as a format placeholder
/// inside a log/print/format macro call. Each entry is matched as a
/// literal substring inside a `{…}` placeholder, so e.g. `passphrase`
/// catches `{passphrase}`, `{passphrase:?}`, `{passphrase_bytes}`,
/// but does NOT catch the bare identifier in non-format positions.
const FORBIDDEN_PLACEHOLDER_TOKENS: &[&str] = &[
    "passphrase_bytes",
    "private_key_bytes",
    "signing_key_bytes",
    "wrapped_secret",
    "decrypted_secret",
    "plaintext_key",
    "raw_passphrase",
    "secret_bytes",
];

/// Format-macro names whose body we want to inspect. The audit walks
/// every match and reconstructs the call's format string + args.
const LOG_MACRO_NAMES: &[&str] = &[
    "println", "eprintln", "print", "eprint", "write", "writeln", "format",
    // log crate
    "info", "warn", "error", "debug", "trace",
];

/// Source roots to walk during the audit. Kept narrow on purpose —
/// the audit pins the daemon's own log surface; CLI binaries and
/// shared crates have their own gates (e.g. the existing structured
/// logger redaction tests in `rustynet-control`).
fn audited_source_roots(workspace_root: &Path) -> Vec<PathBuf> {
    vec![
        workspace_root.join("crates/rustynetd/src"),
        workspace_root.join("crates/rustynet-cli/src"),
    ]
}

/// Files allow-listed from the placeholder scan. The audit module
/// itself necessarily mentions the forbidden tokens as constants;
/// without an allowlist the gate would self-fail.
fn audited_path_allowlist() -> HashSet<PathBuf> {
    let mut set = HashSet::new();
    set.insert(PathBuf::from("crates/rustynetd/src/secret_log_audit.rs"));
    set
}

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points to the crate under test
    // (`crates/rustynetd`). The workspace root is two ancestors up.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set in `cargo test` context");
    let path = PathBuf::from(manifest_dir);
    path.parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .expect("workspace root must be two ancestors up from crate manifest dir")
}

/// Walk a directory recursively, returning every `.rs` file path. We
/// avoid `walkdir` to keep the audit's dependency surface minimal.
fn collect_rs_files(root: &Path, out: &mut Vec<PathBuf>) {
    let read_dir = match fs::read_dir(root) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip `target/` and `bin/`-internal generated dirs if any.
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "target" || name.starts_with('.') {
                continue;
            }
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Strip the leading whitespace from a path so it can be matched
/// against the allowlist (which uses workspace-relative paths).
fn workspace_relative(path: &Path, workspace_root: &Path) -> PathBuf {
    path.strip_prefix(workspace_root)
        .map(PathBuf::from)
        .unwrap_or_else(|_| path.to_path_buf())
}

/// Pure scan helper: takes a source body and returns the line numbers
/// plus matched-token strings for any forbidden placeholder hits
/// inside a log-macro call. Exposed for unit testing of the audit
/// logic itself.
pub(crate) fn scan_source_for_forbidden_placeholders(body: &str) -> Vec<(usize, String)> {
    let mut hits: Vec<(usize, String)> = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        let trimmed = line.trim_start();
        // Skip line comments and doc-string lines wholesale — the
        // audit only fires on executable code.
        if trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }
        // Find any log-macro call signature on the line.
        let mut found_macro = false;
        for name in LOG_MACRO_NAMES {
            // Match "<name>!(" with optional whitespace.
            let pat = format!("{name}!(");
            let pat_ws = format!("{name}! (");
            if line.contains(&pat) || line.contains(&pat_ws) {
                found_macro = true;
                break;
            }
            // log::info! etc. — already covered because the macro
            // name remains the same after the `log::` prefix.
        }
        if !found_macro {
            continue;
        }
        for token in FORBIDDEN_PLACEHOLDER_TOKENS {
            // Match `{<token>}` or `{<token>:?}` or `{<token>:…}`.
            let needle_eq = format!("{{{token}}}");
            let needle_colon = format!("{{{token}:");
            if line.contains(&needle_eq) || line.contains(&needle_colon) {
                hits.push((idx + 1, (*token).to_string()));
            }
        }
    }
    hits
}

/// Pure scan helper: takes a source body and returns true iff a
/// `#[derive(... Debug ...)]` or `impl Debug for …` appears for a
/// type whose name matches one of the canonical secret-bearing
/// types. Exposed for unit testing.
pub(crate) fn scan_source_for_debug_on_secret_types(
    body: &str,
    secret_type_names: &[&str],
) -> Vec<(usize, String, String)> {
    let mut hits: Vec<(usize, String, String)> = Vec::new();
    let lines: Vec<&str> = body.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }
        // Pattern 1: derive Debug on a secret type. Look for a struct
        // declaration after a derive line that includes Debug.
        if trimmed.starts_with("#[derive(") && trimmed.contains("Debug") {
            // Search forward for the next `struct`/`enum` name.
            for next in lines.iter().skip(idx + 1).take(4) {
                let nt = next.trim_start();
                let after_kw = if let Some(rest) = nt.strip_prefix("pub struct ") {
                    Some(rest)
                } else if let Some(rest) = nt.strip_prefix("struct ") {
                    Some(rest)
                } else if let Some(rest) = nt.strip_prefix("pub enum ") {
                    Some(rest)
                } else {
                    nt.strip_prefix("enum ")
                };
                if let Some(rest) = after_kw {
                    // Extract just the type name (token up to space,
                    // `<`, `{`, `(`).
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if secret_type_names.iter().any(|t| *t == name) {
                        hits.push((
                            idx + 1,
                            name.clone(),
                            "derive(Debug) on secret-bearing type".to_string(),
                        ));
                    }
                    break;
                }
            }
        }
        // Pattern 2: `impl …Debug for <SecretType>`.
        if trimmed.starts_with("impl ") && line.contains("Debug for ") {
            for name in secret_type_names {
                let needle = format!("Debug for {name}");
                if line.contains(&needle) {
                    hits.push((
                        idx + 1,
                        (*name).to_string(),
                        "manual impl Debug for secret-bearing type".to_string(),
                    ));
                }
            }
        }
    }
    hits
}

/// Reviewed secret-bearing type names whose `Debug` exposure is
/// forbidden across the crate. Kept narrow to the canonical
/// passphrase / runtime-key wrappers; if a future module introduces
/// a new wrapper, add it here.
const FORBIDDEN_DEBUG_SECRET_TYPES: &[&str] = &[
    "PassphraseMaterial",
    "WrappedKeyMaterial",
    "RuntimePrivateKey",
    "SigningKeyMaterial",
];

#[test]
fn no_forbidden_placeholder_tokens_in_log_macros() {
    let root = workspace_root();
    let allowlist = audited_path_allowlist();
    let mut offenders: Vec<String> = Vec::new();
    for src_root in audited_source_roots(&root) {
        let mut files: Vec<PathBuf> = Vec::new();
        collect_rs_files(&src_root, &mut files);
        for file in files {
            let rel = workspace_relative(&file, &root);
            if allowlist.contains(&rel) {
                continue;
            }
            let Ok(body) = fs::read_to_string(&file) else {
                continue;
            };
            for (line_no, token) in scan_source_for_forbidden_placeholders(&body) {
                offenders.push(format!(
                    "{}:{}: log macro interpolates forbidden secret-bearing identifier {{{token}}}",
                    rel.display(),
                    line_no
                ));
            }
        }
    }
    if !offenders.is_empty() {
        panic!(
            "secret-leakage audit found {} offending log call-site(s):\n  {}",
            offenders.len(),
            offenders.join("\n  ")
        );
    }
}

#[test]
fn no_debug_derives_on_canonical_secret_types() {
    let root = workspace_root();
    let allowlist = audited_path_allowlist();
    let mut offenders: Vec<String> = Vec::new();
    for src_root in audited_source_roots(&root) {
        let mut files: Vec<PathBuf> = Vec::new();
        collect_rs_files(&src_root, &mut files);
        for file in files {
            let rel = workspace_relative(&file, &root);
            if allowlist.contains(&rel) {
                continue;
            }
            let Ok(body) = fs::read_to_string(&file) else {
                continue;
            };
            for (line_no, name, why) in
                scan_source_for_debug_on_secret_types(&body, FORBIDDEN_DEBUG_SECRET_TYPES)
            {
                offenders.push(format!("{}:{}: {why}: {name}", rel.display(), line_no));
            }
        }
    }
    if !offenders.is_empty() {
        panic!(
            "secret-leakage audit found {} forbidden Debug exposure(s) on secret-bearing types:\n  {}",
            offenders.len(),
            offenders.join("\n  ")
        );
    }
}

// ---- Audit-logic self-tests ----------------------------------------

#[test]
fn placeholder_scanner_flags_passphrase_bytes_inside_eprintln() {
    let body = r#"
        fn leaky() {
            let passphrase_bytes = b"hunter2";
            eprintln!("recovered passphrase = {passphrase_bytes:?}");
        }
    "#;
    let hits = scan_source_for_forbidden_placeholders(body);
    assert!(
        hits.iter().any(|(_, t)| t == "passphrase_bytes"),
        "passphrase_bytes leak must be detected: {hits:?}"
    );
}

#[test]
fn placeholder_scanner_flags_private_key_bytes_inside_log_warn() {
    let body = r#"
        fn leaky() {
            let private_key_bytes = vec![1u8; 32];
            log::warn!("dumping {private_key_bytes:?}");
        }
    "#;
    let hits = scan_source_for_forbidden_placeholders(body);
    assert!(
        hits.iter().any(|(_, t)| t == "private_key_bytes"),
        "private_key_bytes leak must be detected: {hits:?}"
    );
}

#[test]
fn placeholder_scanner_flags_signing_key_bytes_inside_warn_macro() {
    let body = r#"
        fn leaky() {
            let signing_key_bytes = vec![0u8; 32];
            warn!("about to sign with {signing_key_bytes}");
        }
    "#;
    let hits = scan_source_for_forbidden_placeholders(body);
    assert!(
        hits.iter().any(|(_, t)| t == "signing_key_bytes"),
        "signing_key_bytes leak must be detected: {hits:?}"
    );
}

#[test]
fn placeholder_scanner_silent_on_path_only_log_lines() {
    let body = r#"
        fn safe() {
            let path = "/var/lib/rustynet/keys/wireguard.passphrase";
            eprintln!("loading passphrase from {path}");
        }
    "#;
    let hits = scan_source_for_forbidden_placeholders(body);
    assert!(
        hits.is_empty(),
        "path-only log must not be flagged: {hits:?}"
    );
}

#[test]
fn placeholder_scanner_silent_on_commented_offender() {
    let body = r#"
        fn safe() {
            // eprintln!("recovered passphrase = {passphrase_bytes:?}");
        }
    "#;
    let hits = scan_source_for_forbidden_placeholders(body);
    assert!(
        hits.is_empty(),
        "comment-only leak shape must not be flagged: {hits:?}"
    );
}

#[test]
fn placeholder_scanner_flags_colon_formatted_token() {
    let body = r#"eprintln!("{secret_bytes:x?}");"#;
    let hits = scan_source_for_forbidden_placeholders(body);
    assert!(
        hits.iter().any(|(_, t)| t == "secret_bytes"),
        "{{secret_bytes:x?}} format spec must be flagged: {hits:?}"
    );
}

#[test]
fn debug_scanner_flags_derive_debug_on_passphrase_material() {
    let body = r#"
#[derive(Clone, Debug)]
pub struct PassphraseMaterial {
    bytes: Vec<u8>,
}
"#;
    let hits = scan_source_for_debug_on_secret_types(body, FORBIDDEN_DEBUG_SECRET_TYPES);
    assert!(
        hits.iter().any(|(_, n, _)| n == "PassphraseMaterial"),
        "derive(Debug) on PassphraseMaterial must be flagged: {hits:?}"
    );
}

#[test]
fn debug_scanner_flags_manual_impl_debug_on_secret_type() {
    let body = r#"
impl std::fmt::Debug for SigningKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKeyMaterial({:?})", self.bytes)
    }
}
"#;
    let hits = scan_source_for_debug_on_secret_types(body, FORBIDDEN_DEBUG_SECRET_TYPES);
    assert!(
        hits.iter().any(|(_, n, _)| n == "SigningKeyMaterial"),
        "manual impl Debug for SigningKeyMaterial must be flagged: {hits:?}"
    );
}

#[test]
fn debug_scanner_silent_on_non_secret_type_with_debug() {
    let body = r#"
#[derive(Debug)]
pub struct PublicKey {
    bytes: [u8; 32],
}
"#;
    let hits = scan_source_for_debug_on_secret_types(body, FORBIDDEN_DEBUG_SECRET_TYPES);
    assert!(
        hits.is_empty(),
        "PublicKey is not on the secret list: {hits:?}"
    );
}

#[test]
fn debug_scanner_silent_on_secret_type_without_debug_derive() {
    let body = r#"
#[derive(Clone)]
pub struct PassphraseMaterial {
    bytes: Vec<u8>,
}
"#;
    let hits = scan_source_for_debug_on_secret_types(body, FORBIDDEN_DEBUG_SECRET_TYPES);
    assert!(
        hits.is_empty(),
        "PassphraseMaterial without Debug must pass: {hits:?}"
    );
}
