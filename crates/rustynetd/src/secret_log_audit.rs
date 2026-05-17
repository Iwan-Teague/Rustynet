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

/// Reviewed secret-bearing type names whose `Display` (and
/// `ToString`) exposure is forbidden across the crate. A `Display`
/// impl is just as dangerous as `Debug` because `format!("{}", x)`
/// or `x.to_string()` would surface inner bytes.
const FORBIDDEN_DISPLAY_SECRET_TYPES: &[&str] = &[
    "PassphraseMaterial",
    "WrappedKeyMaterial",
    "RuntimePrivateKey",
    "SigningKeyMaterial",
];

/// Returns true iff the given line is a call to one of the
/// `LOG_MACRO_NAMES` macros. Used by the encoder scanners to scope
/// their detection to log/print/format call-sites only.
fn line_calls_log_macro(line: &str) -> bool {
    for name in LOG_MACRO_NAMES {
        let pat = format!("{name}!(");
        let pat_ws = format!("{name}! (");
        if line.contains(&pat) || line.contains(&pat_ws) {
            return true;
        }
    }
    false
}

/// Returns true iff `arg` contains any of the forbidden placeholder
/// tokens as a substring. Used to flag encoder calls whose argument
/// expression mentions a secret-bearing identifier.
fn arg_mentions_forbidden_token(arg: &str) -> Option<&'static str> {
    FORBIDDEN_PLACEHOLDER_TOKENS
        .iter()
        .find(|&token| arg.contains(token))
        .copied()
}

/// Pure scan helper: looks for `hex::encode(<expr>)` or
/// `format!("{:02x}…", <expr>)` shapes inside a log/print macro
/// call where `<expr>` mentions a forbidden secret-bearing
/// identifier. Returns `(line_no, encoder_call, forbidden_token)`.
pub(crate) fn scan_source_for_hex_encoded_secret_log_sites(
    body: &str,
) -> Vec<(usize, String, String)> {
    let mut hits: Vec<(usize, String, String)> = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }
        if !line_calls_log_macro(line) {
            continue;
        }
        // Pattern A: `hex::encode(<expr>)` — scan every occurrence on
        // the line and inspect the argument expression up to the
        // matching `)`.
        let mut search_from = 0usize;
        while let Some(rel) = line[search_from..].find("hex::encode(") {
            let start = search_from + rel + "hex::encode(".len();
            // Find matching close-paren with depth counting.
            let bytes = line.as_bytes();
            let mut depth = 1usize;
            let mut i = start;
            while i < bytes.len() && depth > 0 {
                match bytes[i] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    break;
                }
                i += 1;
            }
            let arg = &line[start..i.min(bytes.len())];
            if let Some(token) = arg_mentions_forbidden_token(arg) {
                hits.push((idx + 1, format!("hex::encode({arg})"), token.to_string()));
            }
            search_from = i.saturating_add(1);
        }
        // Pattern B: inline `format!("{:02x}…", <expr…>)` or any
        // log-macro call whose format string contains `{:02x}` /
        // `{:x}` placeholders and whose args mention a forbidden
        // token. We scan the whole remainder of the line after the
        // macro name for both signals jointly.
        let has_hex_fmt = line.contains("{:02x}")
            || line.contains("{:x}")
            || line.contains("{:02X}")
            || line.contains("{:X}");
        if has_hex_fmt && let Some(token) = arg_mentions_forbidden_token(line) {
            let already_flagged = hits.iter().any(|(l, _, t)| *l == idx + 1 && t == token);
            if !already_flagged {
                hits.push((
                    idx + 1,
                    "format!(\"{:02x}…\", …)".to_string(),
                    token.to_string(),
                ));
            }
        }
    }
    hits
}

/// Pure scan helper: looks for `base64::*encode(<expr>)` or
/// `STANDARD.encode(<expr>)` shapes inside a log/print macro call
/// where `<expr>` mentions a forbidden secret-bearing identifier.
/// Returns `(line_no, encoder_call, forbidden_token)`.
pub(crate) fn scan_source_for_base64_encoded_secret_log_sites(
    body: &str,
) -> Vec<(usize, String, String)> {
    let mut hits: Vec<(usize, String, String)> = Vec::new();
    // Candidate encoder-call prefixes. Order matters only for
    // dedup; we scan each independently.
    let candidates: &[&str] = &[
        "base64::engine::general_purpose::STANDARD.encode(",
        "base64::engine::general_purpose::URL_SAFE.encode(",
        "base64::engine::general_purpose::STANDARD_NO_PAD.encode(",
        "base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(",
        "base64::encode(",
        "STANDARD.encode(",
        "URL_SAFE.encode(",
        "STANDARD_NO_PAD.encode(",
        "URL_SAFE_NO_PAD.encode(",
    ];
    for (idx, line) in body.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }
        if !line_calls_log_macro(line) {
            continue;
        }
        for prefix in candidates {
            let mut search_from = 0usize;
            while let Some(rel) = line[search_from..].find(prefix) {
                let start = search_from + rel + prefix.len();
                let bytes = line.as_bytes();
                let mut depth = 1usize;
                let mut i = start;
                while i < bytes.len() && depth > 0 {
                    match bytes[i] {
                        b'(' => depth += 1,
                        b')' => depth -= 1,
                        _ => {}
                    }
                    if depth == 0 {
                        break;
                    }
                    i += 1;
                }
                let arg = &line[start..i.min(bytes.len())];
                if let Some(token) = arg_mentions_forbidden_token(arg) {
                    let call = format!("{}{arg})", prefix);
                    hits.push((idx + 1, call, token.to_string()));
                }
                search_from = i.saturating_add(1);
            }
        }
    }
    hits
}

/// Pure scan helper: mirrors `scan_source_for_debug_on_secret_types`
/// but for `Display` (and `fmt::Display`) impls on the canonical
/// secret-bearing types. Returns `(line_no, type_name, reason)`.
pub(crate) fn scan_source_for_display_on_secret_types(
    body: &str,
    secret_type_names: &[&str],
) -> Vec<(usize, String, String)> {
    let mut hits: Vec<(usize, String, String)> = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }
        // Pattern 1: derive Display on a secret type. Display is not
        // a stdlib derive, but third-party derive macros exist
        // (`derive_more::Display`) — flag the shape anyway.
        if trimmed.starts_with("#[derive(") && trimmed.contains("Display") {
            for next in body.lines().skip(idx + 1).take(4) {
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
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if secret_type_names.iter().any(|t| *t == name) {
                        hits.push((
                            idx + 1,
                            name.clone(),
                            "derive(Display) on secret-bearing type".to_string(),
                        ));
                    }
                    break;
                }
            }
        }
        // Pattern 2: `impl …Display for <SecretType>` and the same
        // for `ToString`. We treat `Display for X` and
        // `fmt::Display for X` uniformly (the `Display` token
        // suffices) but require the preceding `impl ` to scope to
        // trait-impl declarations.
        if trimmed.starts_with("impl ") {
            for name in secret_type_names {
                let display_needle = format!("Display for {name}");
                let to_string_needle = format!("ToString for {name}");
                if line.contains(&display_needle) {
                    hits.push((
                        idx + 1,
                        (*name).to_string(),
                        "manual impl Display for secret-bearing type".to_string(),
                    ));
                }
                if line.contains(&to_string_needle) {
                    hits.push((
                        idx + 1,
                        (*name).to_string(),
                        "manual impl ToString for secret-bearing type".to_string(),
                    ));
                }
            }
        }
    }
    hits
}

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

// ---- Hex-encoder workspace sweep + self-tests ----------------------

#[test]
fn no_hex_encoded_secret_log_sites_in_workspace() {
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
            for (line_no, call, token) in scan_source_for_hex_encoded_secret_log_sites(&body) {
                offenders.push(format!(
                    "{}:{}: log macro encodes forbidden secret-bearing identifier via {call} ({token})",
                    rel.display(),
                    line_no
                ));
            }
        }
    }
    if !offenders.is_empty() {
        panic!(
            "secret-leakage audit found {} hex-encoder offender(s):\n  {}",
            offenders.len(),
            offenders.join("\n  ")
        );
    }
}

#[test]
fn hex_scanner_flags_hex_encode_of_passphrase_bytes() {
    let body = r#"
        fn leaky() {
            let passphrase_bytes = vec![0u8; 32];
            log::warn!("p = {}", hex::encode(passphrase_bytes));
        }
    "#;
    let hits = scan_source_for_hex_encoded_secret_log_sites(body);
    assert!(
        hits.iter().any(|(_, _, t)| t == "passphrase_bytes"),
        "hex::encode(passphrase_bytes) must be detected: {hits:?}"
    );
}

#[test]
fn hex_scanner_silent_on_hex_encode_of_safe_identifier() {
    let body = r#"
        fn safe() {
            let public_key_bytes = vec![0u8; 32];
            eprintln!("hash = {}", hex::encode(public_key_bytes));
        }
    "#;
    let hits = scan_source_for_hex_encoded_secret_log_sites(body);
    assert!(
        hits.is_empty(),
        "public_key_bytes is not on the forbidden list: {hits:?}"
    );
}

#[test]
fn hex_scanner_flags_inline_format_02x_pattern() {
    let body = r#"
        fn leaky() {
            let private_key_bytes = vec![0u8; 32];
            eprintln!("{:02x}{:02x}", private_key_bytes[0], private_key_bytes[1]);
        }
    "#;
    let hits = scan_source_for_hex_encoded_secret_log_sites(body);
    assert!(
        hits.iter().any(|(_, _, t)| t == "private_key_bytes"),
        "inline {{:02x}} over private_key_bytes must be detected: {hits:?}"
    );
}

#[test]
fn hex_scanner_silent_on_commented_offender() {
    let body = r#"
        fn safe() {
            // log::warn!("p = {}", hex::encode(passphrase_bytes));
        }
    "#;
    let hits = scan_source_for_hex_encoded_secret_log_sites(body);
    assert!(
        hits.is_empty(),
        "commented hex-encoder offender must not be flagged: {hits:?}"
    );
}

// ---- Base64-encoder workspace sweep + self-tests -------------------

#[test]
fn no_base64_encoded_secret_log_sites_in_workspace() {
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
            for (line_no, call, token) in scan_source_for_base64_encoded_secret_log_sites(&body) {
                offenders.push(format!(
                    "{}:{}: log macro encodes forbidden secret-bearing identifier via {call} ({token})",
                    rel.display(),
                    line_no
                ));
            }
        }
    }
    if !offenders.is_empty() {
        panic!(
            "secret-leakage audit found {} base64-encoder offender(s):\n  {}",
            offenders.len(),
            offenders.join("\n  ")
        );
    }
}

#[test]
fn base64_scanner_flags_legacy_base64_encode_of_signing_key_bytes() {
    let body = r#"
        fn leaky() {
            let signing_key_bytes = vec![0u8; 32];
            log::warn!("k = {}", base64::encode(signing_key_bytes));
        }
    "#;
    let hits = scan_source_for_base64_encoded_secret_log_sites(body);
    assert!(
        hits.iter().any(|(_, _, t)| t == "signing_key_bytes"),
        "base64::encode(signing_key_bytes) must be detected: {hits:?}"
    );
}

#[test]
fn base64_scanner_flags_standard_engine_encode_of_passphrase_bytes() {
    let body = r#"
        fn leaky() {
            let passphrase_bytes = vec![0u8; 32];
            eprintln!("p = {}", STANDARD.encode(passphrase_bytes));
        }
    "#;
    let hits = scan_source_for_base64_encoded_secret_log_sites(body);
    assert!(
        hits.iter().any(|(_, _, t)| t == "passphrase_bytes"),
        "STANDARD.encode(passphrase_bytes) must be detected: {hits:?}"
    );
}

#[test]
fn base64_scanner_flags_fully_qualified_general_purpose_encode() {
    let body = r#"
        fn leaky() {
            let wrapped_secret = vec![0u8; 32];
            log::error!("w = {}", base64::engine::general_purpose::STANDARD.encode(wrapped_secret));
        }
    "#;
    let hits = scan_source_for_base64_encoded_secret_log_sites(body);
    assert!(
        hits.iter().any(|(_, _, t)| t == "wrapped_secret"),
        "fully-qualified general_purpose::STANDARD.encode(wrapped_secret) must be detected: {hits:?}"
    );
}

#[test]
fn base64_scanner_silent_on_encode_of_safe_identifier() {
    let body = r#"
        fn safe() {
            let public_key_bytes = vec![0u8; 32];
            eprintln!("pk = {}", base64::encode(public_key_bytes));
        }
    "#;
    let hits = scan_source_for_base64_encoded_secret_log_sites(body);
    assert!(
        hits.is_empty(),
        "public_key_bytes is not on the forbidden list: {hits:?}"
    );
}

// ---- Display-impl workspace sweep + self-tests ---------------------

#[test]
fn no_display_impls_on_canonical_secret_types() {
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
                scan_source_for_display_on_secret_types(&body, FORBIDDEN_DISPLAY_SECRET_TYPES)
            {
                offenders.push(format!("{}:{}: {why}: {name}", rel.display(), line_no));
            }
        }
    }
    if !offenders.is_empty() {
        panic!(
            "secret-leakage audit found {} forbidden Display exposure(s) on secret-bearing types:\n  {}",
            offenders.len(),
            offenders.join("\n  ")
        );
    }
}

#[test]
fn display_scanner_flags_impl_display_on_passphrase_material() {
    let body = r#"
impl Display for PassphraseMaterial {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "PassphraseMaterial(…)")
    }
}
"#;
    let hits = scan_source_for_display_on_secret_types(body, FORBIDDEN_DISPLAY_SECRET_TYPES);
    assert!(
        hits.iter().any(|(_, n, _)| n == "PassphraseMaterial"),
        "impl Display for PassphraseMaterial must be flagged: {hits:?}"
    );
}

#[test]
fn display_scanner_flags_impl_fmt_display_on_signing_key_material() {
    let body = r#"
impl fmt::Display for SigningKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKeyMaterial(…)")
    }
}
"#;
    let hits = scan_source_for_display_on_secret_types(body, FORBIDDEN_DISPLAY_SECRET_TYPES);
    assert!(
        hits.iter().any(|(_, n, _)| n == "SigningKeyMaterial"),
        "impl fmt::Display for SigningKeyMaterial must be flagged: {hits:?}"
    );
}

#[test]
fn display_scanner_flags_impl_to_string_on_runtime_private_key() {
    let body = r#"
impl ToString for RuntimePrivateKey {
    fn to_string(&self) -> String {
        String::from("RuntimePrivateKey(…)")
    }
}
"#;
    let hits = scan_source_for_display_on_secret_types(body, FORBIDDEN_DISPLAY_SECRET_TYPES);
    assert!(
        hits.iter().any(|(_, n, _)| n == "RuntimePrivateKey"),
        "impl ToString for RuntimePrivateKey must be flagged: {hits:?}"
    );
}

#[test]
fn display_scanner_silent_on_non_secret_type_with_display() {
    let body = r#"
impl Display for PublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.bytes))
    }
}
"#;
    let hits = scan_source_for_display_on_secret_types(body, FORBIDDEN_DISPLAY_SECRET_TYPES);
    assert!(
        hits.is_empty(),
        "PublicKey is not on the secret list: {hits:?}"
    );
}

#[test]
fn display_scanner_silent_on_secret_type_without_display_impl() {
    let body = r#"
pub struct PassphraseMaterial {
    bytes: Vec<u8>,
}
"#;
    let hits = scan_source_for_display_on_secret_types(body, FORBIDDEN_DISPLAY_SECRET_TYPES);
    assert!(
        hits.is_empty(),
        "PassphraseMaterial without Display must pass: {hits:?}"
    );
}

// ---- Secret-material equality scanner ------------------------------
//
// Replaces the shell `grep -rn '(token|csrf|...)\s*(==|!=)'` block that
// previously lived in `scripts/ci/security_regression_gates.sh`. The
// shell version was fragile (no audit trail for `// EXCEPTION:`
// comments, false-positives on integer counters like `nonce == 0`,
// no self-tests). This scanner runs as a regular `cargo test`, keeps
// a typed allowlist with one-line justifications, and ships with its
// own self-tests so the gate's behaviour cannot silently regress.

/// Identifier substrings whose equality (`==`/`!=`) comparison
/// triggers the gate. Convention: time-side-channel-sensitive
/// secret material that must go through `subtle::ConstantTimeEq`
/// (helper name `ct_eq`) instead of `==`.
const FORBIDDEN_SECRET_EQUALITY_TOKENS: &[&str] = &[
    "token",
    "csrf",
    "session_key",
    "nonce",
    "mac",
    "hmac",
    "session_id",
    "signature",
];

/// Reviewed allowlist of `(file_path_suffix, line_number, justification)`
/// triples where an `==`/`!=` on a forbidden token is intentionally
/// not a security issue (e.g. integer counter zero-check, all-zero
/// sentinel rejection on a public field). Updating this list is a
/// deliberate act — every entry must carry a one-line justification.
///
/// The path is matched by suffix (`file_path_label.ends_with(path)`)
/// so workspace-prefix moves do not silently invalidate entries.
const REVIEWED_SECRET_EQUALITY_EXCEPTIONS: &[(&str, u32, &str)] = &[
    (
        "crates/rustynet-control/src/lib.rs",
        1480,
        "nonce counter zero-check on relay fleet bundle u64 input (not secret material)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        1542,
        "canonical-payload u64 round-trip equality for nonce field (structural check, not secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        1904,
        "all-zero sentinel rejection on relay session token nonce field (not a secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        1937,
        "canonical-payload string equality on relay session token (structural canonicalisation check, signature handled separately via ct_eq)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        2763,
        "nonce counter zero-check on relay fleet request u64 input (not secret material)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        2917,
        "all-zero sentinel rejection on coordination session_id byte array (per-byte zero check, not a secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        2922,
        "all-zero sentinel rejection on coordination nonce byte array (per-byte zero check, not a secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        3055,
        "all-zero sentinel rejection on coordination session_id byte array (per-byte zero check, not a secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        3058,
        "all-zero sentinel rejection on coordination nonce byte array (per-byte zero check, not a secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        3990,
        "all-zero sentinel rejection on coordination session_id byte array (per-byte zero check, not a secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        3995,
        "all-zero sentinel rejection on coordination nonce byte array (per-byte zero check, not a secret compare)",
    ),
    (
        "crates/rustynet-relay/src/transport.rs",
        374,
        "public-scope label string equality on relay hello (relay token scope is a public domain string, not secret material)",
    ),
];

/// Returns true iff the given `(file_path_label, line_number)` matches
/// any entry in `REVIEWED_SECRET_EQUALITY_EXCEPTIONS`. Suffix-match
/// on the path keeps entries stable across workspace-prefix changes.
fn equality_hit_is_allowlisted(file_path_label: &str, line_number: usize) -> bool {
    REVIEWED_SECRET_EQUALITY_EXCEPTIONS
        .iter()
        .any(|(path, line, _why)| {
            file_path_label.ends_with(path) && (*line as usize) == line_number
        })
}

/// Pure scan helper: returns the line numbers + matched-token strings
/// for any source line that compares a forbidden secret-bearing
/// identifier with `==` or `!=` outside the canonical constant-time
/// helper (`ct_eq`) and outside the reviewed allowlist. Comment
/// lines (`//`, `/*`) are skipped wholesale.
pub(crate) fn scan_source_for_secret_material_equality(
    body: &str,
    file_path_label: &str,
) -> Vec<(usize, String)> {
    let mut hits: Vec<(usize, String)> = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }
        // `ct_eq` is the canonical constant-time helper used through-
        // out the workspace; its presence on the line means the
        // developer already routed the compare correctly even if a
        // forbidden token also appears in the same expression.
        if line.contains("ct_eq") {
            continue;
        }
        for token in FORBIDDEN_SECRET_EQUALITY_TOKENS {
            // Find the token, then require a subsequent `==` or `!=`
            // anywhere later on the same line. Substring matching is
            // intentional — the allowlist absorbs the known false-
            // positives (integer counter zero-checks, etc.).
            let Some(pos) = line.find(token) else {
                continue;
            };
            let rest = &line[pos + token.len()..];
            if !(rest.contains("==") || rest.contains("!=")) {
                continue;
            }
            if equality_hit_is_allowlisted(file_path_label, line_no) {
                continue;
            }
            hits.push((line_no, (*token).to_string()));
            // One hit per line is enough; further tokens on the same
            // line would just produce duplicate offender entries.
            break;
        }
    }
    hits
}

/// Workspace sweep test — mirrors the scope the retired shell `grep`
/// block walked (`crates/rustynet-relay/src/` + `crates/rustynet-
/// control/src/`). The audit module itself is allow-listed because
/// it necessarily mentions the forbidden tokens in constants and
/// test bodies.
#[test]
fn no_secret_material_equality_in_workspace() {
    let root = workspace_root();
    let allowlist = audited_path_allowlist();
    let sweep_roots = [
        root.join("crates/rustynet-relay/src"),
        root.join("crates/rustynet-control/src"),
    ];
    let mut offenders: Vec<String> = Vec::new();
    for src_root in &sweep_roots {
        let mut files: Vec<PathBuf> = Vec::new();
        collect_rs_files(src_root, &mut files);
        for file in files {
            let rel = workspace_relative(&file, &root);
            if allowlist.contains(&rel) {
                continue;
            }
            let Ok(body) = fs::read_to_string(&file) else {
                continue;
            };
            let label = rel.display().to_string();
            for (line_no, token) in scan_source_for_secret_material_equality(&body, &label) {
                offenders.push(format!(
                    "{label}:{line_no}: raw equality on secret-bearing identifier `{token}` — use subtle::ConstantTimeEq (`ct_eq`) or allow-list with justification in REVIEWED_SECRET_EQUALITY_EXCEPTIONS"
                ));
            }
        }
    }
    if !offenders.is_empty() {
        panic!(
            "secret-material equality audit found {} offending compare site(s):\n  {}",
            offenders.len(),
            offenders.join("\n  ")
        );
    }
}

#[test]
fn secret_equality_scanner_flags_token_equality_with_double_equals() {
    let body = "if request_token == expected_token { /* ... */ }";
    let hits = scan_source_for_secret_material_equality(body, "crates/example/src/lib.rs");
    assert!(
        hits.iter().any(|(_, t)| t == "token"),
        "raw `==` on token must be flagged: {hits:?}"
    );
}

#[test]
fn secret_equality_scanner_flags_csrf_inequality() {
    let body = "if header_csrf != session_csrf { reject(); }";
    let hits = scan_source_for_secret_material_equality(body, "crates/example/src/lib.rs");
    assert!(
        hits.iter().any(|(_, t)| t == "csrf"),
        "raw `!=` on csrf must be flagged: {hits:?}"
    );
}

#[test]
fn secret_equality_scanner_silent_on_line_with_ct_eq() {
    let body = "let ok = bool::from(received_mac.ct_eq(&expected_mac));";
    let hits = scan_source_for_secret_material_equality(body, "crates/example/src/lib.rs");
    assert!(
        hits.is_empty(),
        "ct_eq compare on mac must not be flagged: {hits:?}"
    );
}

#[test]
fn secret_equality_scanner_silent_on_allowlisted_line() {
    // Synthesise a body whose first executable line offends, then
    // claim a path+line that matches a real allowlist entry. The
    // scanner must suppress the hit because the (path, line) pair
    // matches REVIEWED_SECRET_EQUALITY_EXCEPTIONS.
    let body = "if nonce == 0 { return; }";
    let hits = scan_source_for_secret_material_equality(
        body,
        "workspace/crates/rustynet-control/src/lib.rs",
    );
    // The body's line 1 is not 1480, so this body alone won't match;
    // pad with blank lines so the offending line lands on 1480.
    let padded = format!("{}{}", "\n".repeat(1479), body);
    let hits_padded = scan_source_for_secret_material_equality(
        &padded,
        "workspace/crates/rustynet-control/src/lib.rs",
    );
    assert!(
        !hits.is_empty(),
        "sanity: unallowlisted nonce==0 line must still fire: {hits:?}"
    );
    assert!(
        hits_padded.is_empty(),
        "allowlisted (path, line=1480) must suppress the nonce==0 hit: {hits_padded:?}"
    );
}

#[test]
fn secret_equality_scanner_silent_on_unrelated_integer_compare() {
    let body = "if request_count == 0 { return; }\nlet retries = max_retries;";
    let hits = scan_source_for_secret_material_equality(body, "crates/example/src/lib.rs");
    assert!(
        hits.is_empty(),
        "unrelated integer compare must not be flagged: {hits:?}"
    );
}

#[test]
fn reviewed_exception_list_entries_have_justifications() {
    for (path, line, why) in REVIEWED_SECRET_EQUALITY_EXCEPTIONS {
        assert!(
            !path.is_empty(),
            "allowlist entry at line {line} has empty path"
        );
        assert!(
            *line > 0,
            "allowlist entry for {path} has zero/invalid line number"
        );
        assert!(
            why.len() >= 16,
            "allowlist entry {path}:{line} justification too short (need >= 16 chars): {why:?}"
        );
    }
}
