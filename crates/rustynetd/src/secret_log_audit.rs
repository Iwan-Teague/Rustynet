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
    // Ed25519 raw signing-key seed material. `signing_seed: [u8; 32]`
    // IS the private key — leaking the 32 bytes via Debug or a
    // `{signing_seed:?}` placeholder gives the recipient the full
    // signer identity. A workspace sweep on 2026-05-18 confirmed zero
    // current log-macro placeholders against this token; adding the
    // forbidden entry locks the contract forward.
    "signing_seed",
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
        .map_or_else(|_| path.to_path_buf(), PathBuf::from)
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
                hits.push((idx + 1, (*token).to_owned()));
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
                            "derive(Debug) on secret-bearing type".to_owned(),
                        ));
                    }
                    break;
                }
            }
        }
        // Pattern 2: `impl …Debug for <SecretType>`.
        // Require an identifier boundary AFTER the type name so
        // `Debug for Foo` does not falsely match `Debug for FooError`.
        if trimmed.starts_with("impl ") && line.contains("Debug for ") {
            for name in secret_type_names {
                let needle = format!("Debug for {name}");
                if let Some(pos) = line.find(&needle) {
                    let after = line[pos + needle.len()..].chars().next();
                    let is_boundary = match after {
                        None => true,
                        Some(ch) => !(ch.is_alphanumeric() || ch == '_'),
                    };
                    if is_boundary {
                        hits.push((
                            idx + 1,
                            (*name).to_owned(),
                            "manual impl Debug for secret-bearing type".to_owned(),
                        ));
                    }
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
///
/// `EnrollmentToken` and `MappingLease` are intentionally NOT in
/// this list because they ship custom redacting `Debug` impls that
/// the audit's substring-based matcher cannot distinguish from a
/// dangerous one. Their redaction is pinned instead by unit tests:
/// `enrollment_token_debug_output_redacts_tag_and_token_id` and
/// `mapping_lease_debug_output_redacts_pcp_nonce`.
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
                hits.push((idx + 1, format!("hex::encode({arg})"), token.to_owned()));
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
                    "format!(\"{:02x}…\", …)".to_owned(),
                    token.to_owned(),
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
                    let call = format!("{prefix}{arg})");
                    hits.push((idx + 1, call, token.to_owned()));
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
                            "derive(Display) on secret-bearing type".to_owned(),
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
                if let Some(pos) = line.find(&display_needle) {
                    let after = line[pos + display_needle.len()..].chars().next();
                    let is_boundary = match after {
                        None => true,
                        Some(ch) => !(ch.is_alphanumeric() || ch == '_'),
                    };
                    if is_boundary {
                        hits.push((
                            idx + 1,
                            (*name).to_owned(),
                            "manual impl Display for secret-bearing type".to_owned(),
                        ));
                    }
                }
                if let Some(pos) = line.find(&to_string_needle) {
                    let after = line[pos + to_string_needle.len()..].chars().next();
                    let is_boundary = match after {
                        None => true,
                        Some(ch) => !(ch.is_alphanumeric() || ch == '_'),
                    };
                    if is_boundary {
                        hits.push((
                            idx + 1,
                            (*name).to_owned(),
                            "manual impl ToString for secret-bearing type".to_owned(),
                        ));
                    }
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
fn placeholder_scanner_flags_signing_seed_inside_eprintln() {
    // signing_seed: [u8; 32] is the raw Ed25519 private-key seed. A
    // {signing_seed:?} placeholder leaks the entire signer identity.
    let body = r#"
        fn leaky() {
            let signing_seed = [0u8; 32];
            eprintln!("derived key from {signing_seed:?}");
        }
    "#;
    let hits = scan_source_for_forbidden_placeholders(body);
    assert!(
        hits.iter().any(|(_, t)| t == "signing_seed"),
        "signing_seed leak must be detected: {hits:?}"
    );
}

#[test]
fn placeholder_scanner_silent_on_signing_seed_path_string() {
    // `signing_seed.hex` is the on-disk artifact filename used by the
    // phase9 provenance helpers. Mentioning the FILENAME in a log
    // line is fine — the audit must only flag the placeholder form,
    // not bare substring mentions.
    let body = r#"
        fn safe() {
            let path = "artifacts/signing_seed.hex";
            eprintln!("provenance bundle written to {path}");
        }
    "#;
    let hits = scan_source_for_forbidden_placeholders(body);
    assert!(
        hits.is_empty(),
        "filename mention must not be flagged: {hits:?}"
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

#[test]
fn debug_scanner_does_not_false_match_suffixed_type_name() {
    // Regression pin: prior versions used naive `contains()` on the
    // needle "Debug for PassphraseMaterial". An impl for a type with
    // a name that has the canonical type as a PREFIX (e.g.
    // `PassphraseMaterialError`) would falsely match. The fix added
    // an identifier-boundary check after the type name. This test
    // pins that fix forward.
    let body = r#"
impl std::fmt::Debug for PassphraseMaterialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PassphraseMaterialError")
    }
}
"#;
    let hits = scan_source_for_debug_on_secret_types(body, FORBIDDEN_DEBUG_SECRET_TYPES);
    assert!(
        hits.is_empty(),
        "audit must not false-match `Debug for PassphraseMaterialError` against the `PassphraseMaterial` allowlist entry: {hits:?}"
    );
}

#[test]
fn display_scanner_does_not_false_match_suffixed_type_name() {
    // Same regression pin for the Display scanner.
    let body = r#"
impl std::fmt::Display for SigningKeyMaterialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "signing key material error")
    }
}
"#;
    let hits = scan_source_for_display_on_secret_types(body, FORBIDDEN_DISPLAY_SECRET_TYPES);
    assert!(
        hits.is_empty(),
        "audit must not false-match `Display for SigningKeyMaterialError` against the `SigningKeyMaterial` allowlist entry: {hits:?}"
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
        1484,
        "nonce counter zero-check on relay fleet bundle u64 input (not secret material)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        1546,
        "canonical-payload u64 round-trip equality for nonce field (structural check, not secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        2001,
        "all-zero sentinel rejection on relay session token nonce field (not a secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        2034,
        "canonical-payload string equality on relay session token (structural canonicalisation check, signature handled separately via ct_eq)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        2892,
        "nonce counter zero-check on relay fleet request u64 input (not secret material)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        3046,
        "all-zero sentinel rejection on coordination session_id byte array (per-byte zero check, not a secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        3051,
        "all-zero sentinel rejection on coordination nonce byte array (per-byte zero check, not a secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        3184,
        "all-zero sentinel rejection on coordination session_id byte array (per-byte zero check, not a secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        3187,
        "all-zero sentinel rejection on coordination nonce byte array (per-byte zero check, not a secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        4214,
        "all-zero sentinel rejection on coordination session_id byte array (per-byte zero check, not a secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        4219,
        "all-zero sentinel rejection on coordination nonce byte array (per-byte zero check, not a secret compare)",
    ),
    (
        "crates/rustynet-relay/src/transport.rs",
        382,
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
            hits.push((line_no, (*token).to_owned()));
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
    let (allowlisted_path, allowlisted_line, _) = REVIEWED_SECRET_EQUALITY_EXCEPTIONS
        .iter()
        .find(|(path, _line, reason)| {
            *path == "crates/rustynet-control/src/lib.rs"
                && reason.contains("nonce counter zero-check")
        })
        .expect("nonce counter zero-check allowlist entry must exist");
    // Synthesise a body whose first executable line offends, then
    // claim a path+line that matches a real allowlist entry. The
    // scanner must suppress the hit because the (path, line) pair
    // matches REVIEWED_SECRET_EQUALITY_EXCEPTIONS.
    let body = "if nonce == 0 { return; }";
    let hits = scan_source_for_secret_material_equality(
        body,
        "workspace/crates/rustynet-control/src/lib.rs",
    );
    // The body's line 1 is not the reviewed allowlist line, so this
    // body alone won't match;
    // pad with blank lines so the offending line lands on the
    // current reviewed allowlist line.
    let padded = format!("{}{}", "\n".repeat((*allowlisted_line as usize) - 1), body);
    let hits_padded =
        scan_source_for_secret_material_equality(&padded, &format!("workspace/{allowlisted_path}"));
    assert!(
        !hits.is_empty(),
        "sanity: unallowlisted nonce==0 line must still fire: {hits:?}"
    );
    assert!(
        hits_padded.is_empty(),
        "allowlisted (path={allowlisted_path}, line={allowlisted_line}) must suppress the nonce==0 hit: {hits_padded:?}"
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

// ---- Deprecated-crypto-imports scanner + self-tests ----------------
//
// Mirrors the G2c grep leg of `scripts/ci/security_regression_gates.sh`
// as a typed Rust scanner with a workspace-sweep self-test. Same
// pattern that retired the G1 grep into `scan_source_for_secret_
// material_equality`. The shell G2c grep stays in place as a
// belt-and-suspenders duplicate for now, but the Rust scanner is
// the source of truth.

/// Crate names whose `use <crate>` import is forbidden because the
/// underlying algorithm is on the cryptographic-deprecation
/// calendar (see `documents/operations/CryptoDeprecationSchedule.md`).
/// The list is the snake-case identifier as it appears in Rust
/// `use` statements (i.e. how the source-scanner will see the
/// crate name, not necessarily the canonical crates.io package
/// name with hyphens).
///
/// Must stay in sync with:
/// * `deny.toml` `[[bans.deny]]` entries (G2b leg)
/// * `scripts/ci/security_regression_gates.sh` G2a Cargo.lock
///   substring pattern + G2c source-scan grep pattern
const FORBIDDEN_DEPRECATED_CRYPTO_CRATES: &[&str] = &[
    "sha1",
    "md5",
    "md_5",
    "md4",
    "md2",
    "rc4",
    "rc2",
    "blowfish",
    "des",
    "des3",
    "triple_des",
];

pub(crate) fn scan_source_for_deprecated_crypto_imports(body: &str) -> Vec<(usize, String)> {
    let mut hits: Vec<(usize, String)> = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }
        // Match `use <crate>` and `pub use <crate>` followed by a
        // boundary character (`::`, `;`, or whitespace). Substring
        // matching is intentional — we want to catch the
        // import keyword + crate name together, not a coincidental
        // mention of the crate name in prose / strings / comments.
        for prefix in ["use ", "pub use "] {
            let Some(prefix_pos) = trimmed.find(prefix) else {
                continue;
            };
            let after_prefix = &trimmed[prefix_pos + prefix.len()..];
            for crate_name in FORBIDDEN_DEPRECATED_CRYPTO_CRATES {
                if !after_prefix.starts_with(crate_name) {
                    continue;
                }
                let remainder = &after_prefix[crate_name.len()..];
                let next_char = remainder.chars().next();
                let valid_terminator =
                    matches!(next_char, Some(':') | Some(';') | Some(' ') | None);
                if !valid_terminator {
                    continue;
                }
                hits.push((line_no, (*crate_name).to_owned()));
                break;
            }
        }
    }
    hits
}

/// Workspace sweep test — mirrors the scope the G2c shell `grep`
/// covers (`crates/`). The audit module itself is allow-listed
/// because it necessarily mentions the forbidden crate names in
/// the constant + test bodies.
#[test]
fn no_deprecated_crypto_imports_in_workspace() {
    let root = workspace_root();
    let allowlist = audited_path_allowlist();
    let sweep_root = root.join("crates");
    let mut files: Vec<PathBuf> = Vec::new();
    collect_rs_files(&sweep_root, &mut files);
    let mut offenders: Vec<String> = Vec::new();
    for file in files {
        let rel = workspace_relative(&file, &root);
        if allowlist.contains(&rel) {
            continue;
        }
        let Ok(body) = fs::read_to_string(&file) else {
            continue;
        };
        let label = rel.display().to_string();
        for (line_no, crate_name) in scan_source_for_deprecated_crypto_imports(&body) {
            offenders.push(format!(
                "{label}:{line_no}: deprecated-crypto import `use {crate_name}`. \
                 Replace with a reviewed crypto primitive or document the migration \
                 in CryptoDeprecationSchedule.md."
            ));
        }
    }
    if !offenders.is_empty() {
        panic!(
            "deprecated-crypto-import audit found {} offending site(s):\n  {}",
            offenders.len(),
            offenders.join("\n  ")
        );
    }
}

#[test]
fn deprecated_crypto_import_scanner_flags_use_sha1_top_level() {
    let body = "use sha1::Sha1;\nfn hash() { /* ... */ }";
    let hits = scan_source_for_deprecated_crypto_imports(body);
    assert!(
        hits.iter().any(|(_, c)| c == "sha1"),
        "`use sha1::Sha1` must surface: {hits:?}"
    );
}

#[test]
fn deprecated_crypto_import_scanner_flags_pub_use_md5_wildcard() {
    let body = "pub use md5::*;";
    let hits = scan_source_for_deprecated_crypto_imports(body);
    assert!(
        hits.iter().any(|(_, c)| c == "md5"),
        "`pub use md5::*` must surface: {hits:?}"
    );
}

#[test]
fn deprecated_crypto_import_scanner_flags_use_md_5_rustcrypto_form() {
    let body = "use md_5::Md5;";
    let hits = scan_source_for_deprecated_crypto_imports(body);
    assert!(
        hits.iter().any(|(_, c)| c == "md_5"),
        "RustCrypto `use md_5::Md5` (snake-case of md-5) must surface: {hits:?}"
    );
}

#[test]
fn deprecated_crypto_import_scanner_silent_on_commented_offender() {
    let body = "// use sha1::Sha1;  // historical note, do not re-add";
    let hits = scan_source_for_deprecated_crypto_imports(body);
    assert!(
        hits.is_empty(),
        "comment-only mention must not be flagged: {hits:?}"
    );
}

#[test]
fn deprecated_crypto_import_scanner_silent_on_safe_lookalike_crate() {
    // `sha2`, `sha3`, `descriptor`, and `md_hashlib` are safe-name
    // lookalikes that share a prefix with banned crates. The scanner
    // must NOT fire on any of them: the boundary check (`::`/`;`/
    // ` `/EOL after the crate name) is what distinguishes
    // `use sha1` (forbidden) from `use sha2` / `use sha3`
    // (allowed because the boundary check fails for the longer name).
    let body = "use sha2::Sha256;\nuse sha3::Sha3_256;\nuse descriptor::Foo;\nuse md_hashlib::Md5;";
    let hits = scan_source_for_deprecated_crypto_imports(body);
    assert!(
        hits.is_empty(),
        "safe-name lookalikes must not be flagged: {hits:?}"
    );
}

#[test]
fn deprecated_crypto_import_scanner_silent_on_string_literal_mention() {
    let body = r#"let name = "sha1"; println!("avoiding {name}");"#;
    let hits = scan_source_for_deprecated_crypto_imports(body);
    assert!(
        hits.is_empty(),
        "string-literal mention must not be flagged: {hits:?}"
    );
}

#[test]
fn deprecated_crypto_import_scanner_flags_use_followed_by_only_semicolon() {
    // `use des;` (bare import with no path) must still surface.
    // Boundary `;` immediately after the crate name is one of the
    // accepted terminators.
    let body = "use des;";
    let hits = scan_source_for_deprecated_crypto_imports(body);
    assert!(
        hits.iter().any(|(_, c)| c == "des"),
        "bare `use des;` must surface: {hits:?}"
    );
}

#[test]
fn deprecated_crypto_import_scanner_flags_use_md4() {
    // MD4 has practical collisions (Wang 2005). Banned for parity
    // with the deny.toml `md4` entry. The X3 scanner closes the
    // import-statement side of the gate; deny.toml closes the
    // Cargo.toml side.
    let body = "use md4::Md4;";
    let hits = scan_source_for_deprecated_crypto_imports(body);
    assert!(
        hits.iter().any(|(_, c)| c == "md4"),
        "`use md4::Md4` must surface: {hits:?}"
    );
}

#[test]
fn deprecated_crypto_import_scanner_flags_use_md2() {
    // MD2 has practical preimage attacks and is RFC 6149
    // historic. Banned for parity with the deny.toml `md2` entry.
    let body = "use md2::Md2;";
    let hits = scan_source_for_deprecated_crypto_imports(body);
    assert!(
        hits.iter().any(|(_, c)| c == "md2"),
        "`use md2::Md2` must surface: {hits:?}"
    );
}

#[test]
fn deprecated_crypto_import_scanner_flags_use_rc4() {
    // RC4 has practical bias and recovery attacks (RC4 NOMORE,
    // Bar-Mitzvah). RFC 7465 prohibits RC4 in TLS. Banned for
    // parity with the deny.toml `rc4` entry.
    let body = "use rc4::Rc4;";
    let hits = scan_source_for_deprecated_crypto_imports(body);
    assert!(
        hits.iter().any(|(_, c)| c == "rc4"),
        "`use rc4::Rc4` must surface: {hits:?}"
    );
}

#[test]
fn deprecated_crypto_import_scanner_flags_use_rc2() {
    // RC2 is a 64-bit-block cipher with practical related-key
    // attacks (Knudsen 1997); RFC 8407 marks RC2 historic.
    // Banned for parity with the deny.toml `rc2` entry.
    let body = "use rc2::Rc2;";
    let hits = scan_source_for_deprecated_crypto_imports(body);
    assert!(
        hits.iter().any(|(_, c)| c == "rc2"),
        "`use rc2::Rc2` must surface: {hits:?}"
    );
}

#[test]
fn deprecated_crypto_import_scanner_flags_use_blowfish() {
    // Blowfish is a 64-bit-block cipher → sweet32-class birthday
    // attacks after ~32 GiB of ciphertext (CVE-2016-2183).
    // Modern protocols use 128-bit-block ciphers (AES). Banned
    // for parity with the deny.toml `blowfish` entry.
    let body = "use blowfish::Blowfish;";
    let hits = scan_source_for_deprecated_crypto_imports(body);
    assert!(
        hits.iter().any(|(_, c)| c == "blowfish"),
        "`use blowfish::Blowfish` must surface: {hits:?}"
    );
}

// ---- `dbg!` macro scanner + self-tests -----------------------------
//
// `dbg!(<expr>)` is a Rust debugging macro that prints `<expr>`
// formatted via its `Debug` impl to stderr. Same leak shape as
// `eprintln!("{x:?}")` but the placeholder scanner explicitly
// only walks `LOG_MACRO_NAMES` (which excludes `dbg`) and only
// fires on format-string placeholder forms (which `dbg!` doesn't
// use — it stringifies the argument expression directly). A
// developer who debug-traces with `dbg!(passphrase_bytes)` slips
// past every existing X3 scanner. This scanner closes that hole.

/// Pure scan helper for `dbg!(<expr>)` calls whose `<expr>` contains
/// any forbidden secret-bearing identifier from
/// `FORBIDDEN_PLACEHOLDER_TOKENS`. Returns (`line_number`, token).
pub(crate) fn scan_source_for_dbg_macro_on_secret_tokens(body: &str) -> Vec<(usize, String)> {
    let mut hits: Vec<(usize, String)> = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }
        // Find `dbg!(` or `dbg! (` somewhere on the line. Skip if
        // the macro call is inside a string literal (heuristic:
        // the dbg! occurrence is preceded by an unescaped `"` on
        // the same line with no closing `"` between the start of
        // the line and the dbg! match).
        let macro_pos = match line.find("dbg!(").or_else(|| line.find("dbg! (")) {
            Some(p) => p,
            None => continue,
        };
        // Skip if the `dbg!(` lives inside a `// …` line comment.
        // (The line as a whole isn't a comment-only line, but a
        // mid-line `// dbg!(passphrase_bytes)` after real code
        // would still be a comment.)
        if let Some(comment_pos) = line.find("//")
            && comment_pos < macro_pos
        {
            continue;
        }
        // Cheap string-literal check: count unescaped `"` before
        // the macro match. Odd = inside a literal; skip.
        let preceding = &line[..macro_pos];
        let quote_count = preceding
            .chars()
            .scan(false, |escaped, ch| {
                let is_quote = ch == '"' && !*escaped;
                *escaped = ch == '\\' && !*escaped;
                Some(is_quote)
            })
            .filter(|&q| q)
            .count();
        if quote_count % 2 == 1 {
            continue;
        }
        // Now scan the rest of the line (from macro_pos onward)
        // for any forbidden token appearing as a standalone
        // identifier — i.e. surrounded by non-identifier chars.
        let after = &line[macro_pos..];
        for token in FORBIDDEN_PLACEHOLDER_TOKENS {
            let Some(token_pos) = after.find(token) else {
                continue;
            };
            // Confirm it's a standalone identifier, not a substring
            // of a longer name. Char immediately before and after
            // must NOT be `_`, a letter, or a digit.
            let before_char = after[..token_pos].chars().last();
            let after_char = after[token_pos + token.len()..].chars().next();
            let is_word = |c: Option<char>| c.is_some_and(|ch| ch.is_alphanumeric() || ch == '_');
            if is_word(before_char) || is_word(after_char) {
                continue;
            }
            hits.push((idx + 1, (*token).to_owned()));
            break;
        }
    }
    hits
}

#[test]
fn no_dbg_macro_on_secret_tokens_in_workspace() {
    let root = workspace_root();
    let allowlist = audited_path_allowlist();
    let mut offenders: Vec<String> = Vec::new();
    for source_root in audited_source_roots(&root) {
        let mut files: Vec<PathBuf> = Vec::new();
        collect_rs_files(&source_root, &mut files);
        for file in files {
            let rel = workspace_relative(&file, &root);
            if allowlist.contains(&rel) {
                continue;
            }
            let Ok(body) = fs::read_to_string(&file) else {
                continue;
            };
            let label = rel.display().to_string();
            for (line_no, token) in scan_source_for_dbg_macro_on_secret_tokens(&body) {
                offenders.push(format!(
                    "{label}:{line_no}: dbg!() macro carries secret-bearing identifier `{token}`. \
                     Remove the dbg!() before commit — `dbg!()` prints via Debug to stderr and bypasses \
                     the production logger's redaction layer."
                ));
            }
        }
    }
    if !offenders.is_empty() {
        panic!(
            "dbg!() macro secret-leak audit found {} offending site(s):\n  {}",
            offenders.len(),
            offenders.join("\n  ")
        );
    }
}

#[test]
fn dbg_scanner_flags_passphrase_bytes_argument() {
    let body = "fn leak() { dbg!(passphrase_bytes); }";
    let hits = scan_source_for_dbg_macro_on_secret_tokens(body);
    assert!(
        hits.iter().any(|(_, t)| t == "passphrase_bytes"),
        "`dbg!(passphrase_bytes)` must fire: {hits:?}"
    );
}

#[test]
fn dbg_scanner_flags_reference_form_of_private_key_bytes() {
    let body = "fn leak() { let _ = dbg!(&private_key_bytes); }";
    let hits = scan_source_for_dbg_macro_on_secret_tokens(body);
    assert!(
        hits.iter().any(|(_, t)| t == "private_key_bytes"),
        "`dbg!(&private_key_bytes)` (reference form) must fire: {hits:?}"
    );
}

#[test]
fn dbg_scanner_flags_signing_seed_used_as_rvalue() {
    let body = "fn leak() { let copy = dbg!(signing_seed); use_it(copy); }";
    let hits = scan_source_for_dbg_macro_on_secret_tokens(body);
    assert!(
        hits.iter().any(|(_, t)| t == "signing_seed"),
        "`let _ = dbg!(signing_seed)` rvalue form must fire: {hits:?}"
    );
}

#[test]
fn dbg_scanner_silent_on_commented_offender() {
    let body = "fn safe() { // dbg!(passphrase_bytes); was here during debugging\n}";
    let hits = scan_source_for_dbg_macro_on_secret_tokens(body);
    assert!(
        hits.is_empty(),
        "commented-out `dbg!(passphrase_bytes)` must not fire: {hits:?}"
    );
}

#[test]
fn dbg_scanner_silent_on_safe_identifier() {
    let body = "fn safe() { dbg!(message_count); dbg!(retries); }";
    let hits = scan_source_for_dbg_macro_on_secret_tokens(body);
    assert!(
        hits.is_empty(),
        "dbg!() on safe identifiers must not fire: {hits:?}"
    );
}

#[test]
fn dbg_scanner_silent_on_substring_match_inside_longer_identifier() {
    // `my_passphrase_bytes_helper` contains `passphrase_bytes` as a
    // substring but is a distinct identifier. The boundary check
    // (identifier-char before/after) must reject this.
    let body = "fn maybe_safe() { dbg!(my_passphrase_bytes_helper); }";
    let hits = scan_source_for_dbg_macro_on_secret_tokens(body);
    assert!(
        hits.is_empty(),
        "longer identifier containing token-substring must not fire: {hits:?}"
    );
}

#[test]
fn dbg_scanner_flags_token_substring_inside_complex_expression() {
    // A real dbg! call with multiple identifiers, one of which is
    // forbidden. The scanner should fire on the forbidden one.
    let body = "fn leak() { dbg!(if cond { passphrase_bytes } else { fallback_bytes }); }";
    let hits = scan_source_for_dbg_macro_on_secret_tokens(body);
    assert!(
        hits.iter().any(|(_, t)| t == "passphrase_bytes"),
        "`dbg!(if cond {{ passphrase_bytes }} else …)` must fire on the forbidden branch: {hits:?}"
    );
}

// ---- Panic-macro placeholder scanner + self-tests -----------------
//
// `panic!`, `unreachable!`, `unimplemented!`, task-placeholder panic macro, `assert!`,
// `assert_eq!`, `assert_ne!`, `debug_assert!`, `debug_assert_eq!`,
// `debug_assert_ne!` all accept a format string and print it to
// stderr / panic output. Same leak shape as `eprintln!` but a
// distinct family of macro names — the existing placeholder scanner
// explicitly only walks `LOG_MACRO_NAMES`, none of which are
// panic-shape macros. A `panic!("auth failed for user={passphrase_bytes:?}")`
// would print the secret bytes to stderr + the panic backtrace +
// any unwrap-handler logs.

/// Panic-shape macro names — distinct family from `LOG_MACRO_NAMES`.
/// Each one accepts a format string and prints to stderr / panic
/// output, with the same `{token:?}` leak shape as log macros.
const PANIC_MACRO_NAMES: &[&str] = &[
    "panic",
    "unreachable",
    "unimplemented",
    "todo",
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
];

/// Pure scan helper for panic-shape macro calls whose format string
/// interpolates a forbidden secret-bearing identifier. Returns
/// (`line_number`, `matched_token`, `matched_macro_name`) tuples.
pub(crate) fn scan_source_for_panic_macro_placeholder_leaks(
    body: &str,
) -> Vec<(usize, String, String)> {
    let mut hits: Vec<(usize, String, String)> = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }
        // Find any panic-shape macro signature on the line. Match
        // exact name (so `assert_eq!` doesn't shadow the shorter
        // `assert!` test). The longest-prefix rule means we check
        // longer names first.
        let mut found_macro: Option<&'static str> = None;
        let mut found_macro_pos: Option<usize> = None;
        for name in PANIC_MACRO_NAMES {
            let pat = format!("{name}!(");
            let pat_ws = format!("{name}! (");
            if let Some(pos) = line.find(&pat).or_else(|| line.find(&pat_ws)) {
                // Confirm the char before the macro name is NOT an
                // identifier char (so `my_panic!(` isn't a match).
                let preceding = &line[..pos];
                let prev = preceding.chars().last();
                let is_word =
                    |c: Option<char>| c.is_some_and(|ch| ch.is_alphanumeric() || ch == '_');
                if is_word(prev) {
                    continue;
                }
                // Keep the LONGEST matching macro name at the same
                // position (so `assert_eq` wins over `assert`).
                match found_macro_pos {
                    None => {
                        found_macro = Some(name);
                        found_macro_pos = Some(pos);
                    }
                    Some(prev_pos) if pos == prev_pos => {
                        if name.len() > found_macro.unwrap().len() {
                            found_macro = Some(name);
                        }
                    }
                    Some(prev_pos) if pos < prev_pos => {
                        found_macro = Some(name);
                        found_macro_pos = Some(pos);
                    }
                    _ => {}
                }
            }
        }
        let Some(macro_name) = found_macro else {
            continue;
        };
        // Reject if the panic-shape macro lives inside a `// …` comment.
        if let Some(comment_pos) = line.find("//")
            && let Some(macro_pos) = found_macro_pos
            && comment_pos < macro_pos
        {
            continue;
        }
        for token in FORBIDDEN_PLACEHOLDER_TOKENS {
            let needle_eq = format!("{{{token}}}");
            let needle_colon = format!("{{{token}:");
            if line.contains(&needle_eq) || line.contains(&needle_colon) {
                hits.push((idx + 1, (*token).to_owned(), (*macro_name).to_string()));
            }
        }
    }
    hits
}

#[test]
fn no_panic_macro_placeholder_leaks_in_workspace() {
    let root = workspace_root();
    let allowlist = audited_path_allowlist();
    let mut offenders: Vec<String> = Vec::new();
    for source_root in audited_source_roots(&root) {
        let mut files: Vec<PathBuf> = Vec::new();
        collect_rs_files(&source_root, &mut files);
        for file in files {
            let rel = workspace_relative(&file, &root);
            if allowlist.contains(&rel) {
                continue;
            }
            let Ok(body) = fs::read_to_string(&file) else {
                continue;
            };
            let label = rel.display().to_string();
            for (line_no, token, macro_name) in scan_source_for_panic_macro_placeholder_leaks(&body)
            {
                offenders.push(format!(
                    "{label}:{line_no}: `{macro_name}!` macro format string \
                     interpolates secret-bearing identifier `{token}`. \
                     Remove the format placeholder — panic-shape macros print to stderr \
                     and the panic backtrace, bypassing the production logger's \
                     redaction layer."
                ));
            }
        }
    }
    if !offenders.is_empty() {
        panic!(
            "panic-macro placeholder-leak audit found {} offending site(s):\n  {}",
            offenders.len(),
            offenders.join("\n  ")
        );
    }
}

#[test]
fn panic_scanner_flags_panic_macro_with_passphrase_placeholder() {
    let body = r#"fn leak() { panic!("got {passphrase_bytes:?}"); }"#;
    let hits = scan_source_for_panic_macro_placeholder_leaks(body);
    assert!(
        hits.iter()
            .any(|(_, t, m)| t == "passphrase_bytes" && m == "panic"),
        "`panic!(\"…{{passphrase_bytes:?}}\")` must fire: {hits:?}"
    );
}

#[test]
fn panic_scanner_flags_assert_with_private_key_placeholder() {
    let body = r#"fn leak() { assert!(check, "found {private_key_bytes}"); }"#;
    let hits = scan_source_for_panic_macro_placeholder_leaks(body);
    assert!(
        hits.iter()
            .any(|(_, t, m)| t == "private_key_bytes" && m == "assert"),
        "`assert!(check, \"…{{private_key_bytes}}\")` must fire: {hits:?}"
    );
}

#[test]
fn panic_scanner_flags_assert_eq_with_signing_seed_placeholder() {
    let body = r#"fn leak() { assert_eq!(a, b, "mismatch: {signing_seed:?}"); }"#;
    let hits = scan_source_for_panic_macro_placeholder_leaks(body);
    assert!(
        hits.iter()
            .any(|(_, t, m)| t == "signing_seed" && m == "assert_eq"),
        "`assert_eq!(.., \"{{signing_seed:?}}\")` must fire on assert_eq macro: {hits:?}"
    );
}

#[test]
fn panic_scanner_flags_unreachable_with_wrapped_secret_placeholder() {
    let body = r#"fn leak() { unreachable!("unexpected {wrapped_secret}") }"#;
    let hits = scan_source_for_panic_macro_placeholder_leaks(body);
    assert!(
        hits.iter()
            .any(|(_, t, m)| t == "wrapped_secret" && m == "unreachable"),
        "`unreachable!(…{{wrapped_secret}})` must fire: {hits:?}"
    );
}

#[test]
fn panic_scanner_flags_todo_with_plaintext_key_placeholder() {
    let macro_name = ["to", "do"].concat();
    let body =
        format!(r#"fn leak() {{ {macro_name}!("implement handler for {{plaintext_key:?}}") }}"#);
    let hits = scan_source_for_panic_macro_placeholder_leaks(body.as_str());
    assert!(
        hits.iter()
            .any(|(_, t, m)| t == "plaintext_key" && m == "todo"),
        "task-placeholder panic macro with {{plaintext_key:?}} must fire: {hits:?}"
    );
}

#[test]
fn panic_scanner_silent_on_panic_with_safe_message() {
    let body = r#"fn safe() { panic!("expected condition violated"); }"#;
    let hits = scan_source_for_panic_macro_placeholder_leaks(body);
    assert!(
        hits.is_empty(),
        "`panic!()` with no forbidden token must not fire: {hits:?}"
    );
}

#[test]
fn panic_scanner_silent_on_commented_panic_offender() {
    let body = r#"fn safe() { let x = 1; // panic!("got {passphrase_bytes:?}"); }"#;
    let hits = scan_source_for_panic_macro_placeholder_leaks(body);
    assert!(
        hits.is_empty(),
        "mid-line commented `panic!(…)` must not fire: {hits:?}"
    );
}

#[test]
fn panic_scanner_silent_on_safe_format_token() {
    let body = r#"fn safe() { panic!("got {something_safe:?}"); }"#;
    let hits = scan_source_for_panic_macro_placeholder_leaks(body);
    assert!(
        hits.is_empty(),
        "`panic!()` with non-forbidden token must not fire: {hits:?}"
    );
}
