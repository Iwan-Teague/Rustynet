//! X3 — static no-secret-leakage audit.
//!
//! The verifier sweeps EVERY workspace member crate's `src/` tree at
//! test time and looks for log/print/format call-sites whose format
//! args interpolate a known secret-bearing identifier (passphrase
//! bytes, a private-key byte array, a runtime token, etc.). The audit
//! runs as a regular `cargo test` so any regression that adds a new
//! offender lands as a named test failure, not a silent leak.
//!
//! # Audit scope (AQ-141)
//!
//! The audited roots are ALL cargo workspace member crates listed in
//! the root `Cargo.toml` (`audited_source_roots` /
//! `WORKSPACE_MEMBER_CRATE_DIRS`), enforced against drift by
//! `audited_roots_track_workspace_membership`. A GREEN run of these
//! gates means exactly: "these scanners found nothing under these
//! roots" — it is NOT a claim about code outside the workspace:
//! `third_party/` (vendored path deps), `gui/`,
//! `crates/rustynet-lab-monitor/`, and `fuzz/` are NOT workspace
//! members (the root manifest `exclude`s the first two; the others
//! declare their own workspaces) and are NOT audited here. Widening
//! the scope was AQ-141: before it, the audit walked only 5 crates
//! while the AQ-108 v2 display sweep found secret-bearing Debug
//! surfaces in crates the audit never visited (notably
//! `rustynet-backend-wireguard` and `rustynet-llm-gateway`). Two
//! sibling sweeps keep their own, separately documented roots: the
//! secret-equality sweep and the deprecated-crypto-import sweep —
//! their scope statements live on their own sweep functions.
//!
//! Two complementary forms of detection:
//!
//! 1. **Forbidden format placeholders** — patterns like `{passphrase}`,
//!    `{passphrase:?}`, `{private_key_bytes}`, `{signing_key_bytes}`,
//!    `{secret}` appearing inside a log/print macro call. The pattern
//!    catches the common-shape leak: a developer adds `eprintln!("…
//!    {passphrase}")` while debugging and forgets to remove it.
//!
//! 2. **Forbidden Debug/Display exposure on secret-bearing types** —
//!    the canonical secret-bearing types must NOT expose their bytes via
//!    `#[derive(Debug)]`/`derive(Display)` or an UNREVIEWED manual impl,
//!    since any future `{:?}`/`{}` print would surface the inner bytes.
//!    A hand-written impl that REDACTS every secret field is allowed, but
//!    only with an entry in `REVIEWED_REDACTING_DEBUG_IMPLS` /
//!    `REVIEWED_REDACTING_DISPLAY_IMPLS` (name + path + justification +
//!    a named liveness-witness test pinning the impl's redacted output —
//!    AQ-126); derive-shaped hits are never reviewable. A vocabulary
//!    coverage backstop additionally requires every secret-vocabulary
//!    `struct`/`enum` declaration under the audited roots to be
//!    explicitly classified (AQ-115/F3). That backstop is
//!    vocabulary-derived: it proves classified coverage of the DECLARED
//!    vocabulary, not that no secret-bearing type exists outside it — the
//!    known blind spots are documented on `SECRET_VOCABULARY_NAME_TOKENS`
//!    (AQ-126).
//!
//! The audit is conservative: it allowlists doc-comments, test files,
//! and the audit module itself so the patterns can be discussed in
//! code review and tests. Allowlist scope is narrow — only the
//! comments / strings that documentate the audit itself.

#![cfg(test)]

use std::collections::{BTreeSet, HashSet};
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

/// Cargo-workspace member crate directories, as listed in the root
/// `Cargo.toml` `members` array. This is the single in-file source of
/// truth for the audit's scope; `audited_source_roots` derives the
/// walked directories from it and
/// `audited_roots_track_workspace_membership` cross-checks it against
/// the manifest itself so a newly added workspace member cannot ship
/// unaudited (AQ-141). Deliberately NOT here (not workspace members,
/// separately gated): `gui`, `crates/rustynet-lab-monitor` (both
/// `exclude`d in the root manifest), `fuzz` (own workspace), and
/// `third_party/*` (vendored path deps).
const WORKSPACE_MEMBER_CRATE_DIRS: &[&str] = &[
    "crates/rustynet-dns-zone",
    "crates/rustynet-local-security",
    "crates/rustynet-control",
    "crates/rustynetd",
    "crates/rustynet-cli",
    "crates/rustynet-relay",
    "crates/rustynet-nas",
    "crates/rustynet-llm-gateway",
    "crates/rustynet-policy",
    "crates/rustynet-advisor",
    "crates/rustynet-crypto",
    "crates/rustynet-windows-native",
    "crates/rustynet-backend-api",
    "crates/rustynet-backend-wireguard",
    "crates/rustynet-backend-stub",
    "crates/rustynet-backend-userspace",
    "crates/rustynet-sysinfo",
    "crates/rustynet-operator",
    "crates/rustynet-mcp",
    "crates/rustynet-xtask",
    "crates/rustynet-netns-probe",
];

/// Source roots to walk during the audit: every cargo workspace member
/// crate's `src/` tree (AQ-141). The list was previously only the five
/// crates that historically held most secret material — the AQ-108 v2
/// display sweep (2026-09-22) found secret-bearing Debug surfaces in
/// workspace crates the audit never visited (12 findings suite-wide,
/// ten outside these roots, including `rustynet-backend-wireguard`'s
/// `WindowsWireguardBackend` holding `runtime_private_key` behind a
/// derived Debug and `rustynet-llm-gateway`'s `SessionToken`) — a gap
/// INSIDE the crate family this audit claims to cover. Keeping an
/// explicit, cited list (rather than walking `crates/` dynamically)
/// keeps the scope auditable in review; the liveness test below keeps
/// the list from drifting out of sync with the manifest.
fn audited_source_roots(workspace_root: &Path) -> Vec<PathBuf> {
    WORKSPACE_MEMBER_CRATE_DIRS
        .iter()
        .map(|dir| workspace_root.join(dir).join("src"))
        .collect()
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

/// THE single shared type-declaration grammar (AQ-201 R3): an optional
/// `pub` qualifier — plain, or `pub(<path>)` where `<path>` is non-empty
/// and made of lowercase ASCII letters or spaces — followed by
/// `struct `/`enum ` and the type name. Returns the text after the
/// keyword, or `None` when the line is not a type declaration in that
/// grammar. Both derive scanners and
/// `scan_source_for_secret_vocabulary_type_declarations` call this
/// function, so the grammar is written down exactly once. Documented
/// limits (review R3, pinned by tests below): a second space after the
/// visibility qualifier, and a raw-identifier type name (`r#…`), do not
/// match.
fn strip_type_decl_prefix(trimmed: &str) -> Option<&str> {
    let after_pub = trimmed.strip_prefix("pub").unwrap_or(trimmed);
    let after_visibility = if let Some(rest) = after_pub.strip_prefix('(') {
        let close = rest.find(')')?;
        let inner = &rest[..close];
        if inner.is_empty() || !inner.chars().all(|c| c.is_ascii_lowercase() || c == ' ') {
            return None;
        }
        &rest[close + 1..]
    } else {
        after_pub
    };
    let after_visibility = after_visibility.strip_prefix(' ')?;
    after_visibility
        .strip_prefix("struct ")
        .or_else(|| after_visibility.strip_prefix("enum "))
}

/// AQ-201 R3: the ONE type-name extractor, shared by both derive scanners
/// and the vocabulary scanner. ASCII by policy: Rust identifiers may be
/// Unicode, but the audit registries and vocabulary tokens are ASCII, so
/// the name ends at the first byte that is not ASCII alphanumeric or `_`.
/// A Unicode-suffixed name (`PrivateKey\u{fc}`) is therefore read as its
/// ASCII prefix and still matches the registry — the over-catch direction
/// is the correct one for an audit scanner.
fn extract_decl_type_name(after_keyword: &str) -> &str {
    let end = after_keyword
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(after_keyword.len());
    &after_keyword[..end]
}

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
        // AQ-135: any attribute line that derives Debug counts — not just a bare
        // `#[derive(...)]`, so `#[cfg_attr(..., derive(Debug))]` is caught too.
        if trimmed.starts_with("#[") && trimmed.contains("derive(") && trimmed.contains("Debug") {
            // Search forward for the next `struct`/`enum` name.
            for next in lines.iter().skip(idx + 1).take(4) {
                if let Some(rest) = strip_type_decl_prefix(next.trim_start()) {
                    // Extract just the type name via the shared ASCII
                    // extractor (AQ-201 R3).
                    let name = extract_decl_type_name(rest);
                    if secret_type_names.contains(&name) {
                        hits.push((
                            idx + 1,
                            name.to_owned(),
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

/// Canonical secret-bearing type names whose ANY `Debug` exposure is
/// forbidden across the audited roots, EXCEPT a hand-written impl that is
/// explicitly reviewed as redacting (see `REVIEWED_REDACTING_DEBUG_IMPLS`).
///
/// AQ-115/F3 policy (supersedes the "no-Debug-at-all + dedicated-tests-only"
/// posture that followed RSA-0026): the lists are POPULATED with every type in
/// the audited crates whose NAME carries one of the declared vocabulary tokens
/// below — which is NOT the same as every secret-bearing type, and the
/// difference is not hypothetical: `BlindCircuitKey` and `EncryptedKeyBlob`
/// both derive `Debug` over secret-adjacent bytes today and are invisible here
/// because `key` and `blob` are not declared tokens (see the vocabulary note).
/// Claiming otherwise would be the exact over-claim this module exists to stop.
/// A `derive(Debug)`-shaped hit is
/// NEVER reviewable, and a manual impl is only suppressible by a reviewed
/// `(name, path, justification)` entry whose impl provably redacts every
/// secret field. Three tests keep the gate honest:
/// - `forbidden_secret_type_lists_contain_only_real_types` — fails closed on
///   phantom names (the RSA-0026 failure mode: four invented names guarded
///   nothing while appearing to guard something);
/// - `production_forbidden_lists_flag_planted_exposures` — proves every entry
///   is LIVE against planted derives/impls (anti-empty, anti-rot);
/// - `every_secret_vocabulary_type_is_classified` — a coverage backstop
///   requiring every secret-vocabulary `struct`/`enum` declaration under the
///   audited roots to be explicitly classified. AQ-126: this scopes the
///   backstop to the DECLARED vocabulary — see
///   `SECRET_VOCABULARY_NAME_TOKENS` for what that vocabulary deliberately
///   does not cover.
///
/// Each entry below cites its definition site; adding a type here requires
/// the same evidence. Passphrase material remains held as
/// `Zeroizing<String>` / `Zeroizing<Vec<u8>>` locals (no named struct to
/// forbid) and is covered by the `FORBIDDEN_PLACEHOLDER_TOKENS` log-macro
/// scan.
const FORBIDDEN_DEBUG_SECRET_TYPES: &[&str] = &[
    // rustynet-crypto
    "SecretKey", // crates/rustynet-crypto/src/lib.rs:43 — [u8;32] private key, zeroizing Drop :61
    "Ed25519SigningProvider", // crates/rustynet-crypto/src/lib.rs:1191 — holds SigningKey seed :1195
    "MlKemSharedSecret", // crates/rustynet-crypto/src/mlkem.rs:246 — raw ML-KEM-768 shared secret (the HKDF input of the tunnel PSK), Zeroizing; NO Debug today, listed to guard forward (no reviewed impl)
    // rustynetd
    "EnrollmentToken", // crates/rustynetd/src/enrollment_token.rs:104 — bearer token_id+tag, zeroizing Drop :123
    "ConsumedTokenLedger", // crates/rustynetd/src/enrollment_token.rs:363 — keys are consumed token ids (bearer halves)
    "LocalRelaySessionTokenIssuer", // crates/rustynetd/src/relay_client.rs:113 — holds Arc<SigningKey> :114; NO Debug today, listed to guard forward (no reviewed impl)
    // rustynet-cli (vm_lab scenario provisioning)
    "RelayTokenFile", // crates/rustynet-cli/src/vm_lab/orchestrator/stage/cross_network/scenario/provisioning.rs:1486 — name+base64 payload of an issued relay session token (bearer material); NO Debug (deliberately), listed to guard forward (no reviewed impl)
    // rustynet-control
    "TokenClaims",             // crates/rustynet-control/src/lib.rs:108 — subject+nonce
    "SignedTokenClaims",       // crates/rustynet-control/src/lib.rs:146 — signature bytes
    "ThrowawayCredential", // crates/rustynet-control/src/lib.rs:592 — credential id+storage policy
    "RelaySessionToken", // crates/rustynet-control/src/lib.rs:1756 — nonce+signature bytes, ct_eq only
    "BlindRelayLegTokenV2", // crates/rustynet-control/src/blind_relay.rs:341 — handles+nonce+signature
    "BlindRelayPopTranscript", // crates/rustynet-control/src/blind_relay.rs:859 — token digest+challenge+handles
    "BlindRelayHelloV2", // crates/rustynet-control/src/blind_relay.rs:1009 — hello nonce+signature
    // rustynet-relay
    "AddressValidationKeyRing", // crates/rustynet-relay/src/blind_relay_listener.rs:374 — HMAC keys (Zeroizing<[u8;32]>)
    // rustynet-llm-gateway
    "SessionToken", // crates/rustynet-llm-gateway/src/session.rs:74 — wire form is canonical payload + ed25519 signature = usable bearer material; sibling RelaySessionToken (control lib.rs:1756) redacts instead. Redacting Debug LANDED (impl session.rs:82, signature field REDACTED, witness session_token_debug_redacts_signature session.rs:444; reviewed in REVIEWED_REDACTING_DEBUG_IMPLS). Listed to keep the type forbidden for any future derive(Debug) re-introduction — same forward-guard shape as every other entry here.
];

/// Canonical secret-bearing type names whose `Display`/`ToString` exposure is
/// forbidden. Same list as `FORBIDDEN_DEBUG_SECRET_TYPES`: NONE of these
/// types implements `Display`/`ToString` today, so
/// `REVIEWED_REDACTING_DISPLAY_IMPLS` is empty — the list enforces "never add
/// one unreviewed".
const FORBIDDEN_DISPLAY_SECRET_TYPES: &[&str] = &[
    // rustynet-crypto
    "SecretKey",              // crates/rustynet-crypto/src/lib.rs:43
    "Ed25519SigningProvider", // crates/rustynet-crypto/src/lib.rs:1191
    // rustynetd
    "EnrollmentToken",              // crates/rustynetd/src/enrollment_token.rs:104
    "ConsumedTokenLedger",          // crates/rustynetd/src/enrollment_token.rs:363
    "LocalRelaySessionTokenIssuer", // crates/rustynetd/src/relay_client.rs:113
    // rustynet-control
    "TokenClaims",             // crates/rustynet-control/src/lib.rs:108
    "SignedTokenClaims",       // crates/rustynet-control/src/lib.rs:146
    "ThrowawayCredential",     // crates/rustynet-control/src/lib.rs:592
    "RelaySessionToken",       // crates/rustynet-control/src/lib.rs:1756
    "BlindRelayLegTokenV2",    // crates/rustynet-control/src/blind_relay.rs:341
    "BlindRelayPopTranscript", // crates/rustynet-control/src/blind_relay.rs:859
    "BlindRelayHelloV2",       // crates/rustynet-control/src/blind_relay.rs:1009
    // rustynet-relay
    "AddressValidationKeyRing", // crates/rustynet-relay/src/blind_relay_listener.rs:374
    // rustynet-llm-gateway
    "SessionToken", // crates/rustynet-llm-gateway/src/session.rs:74 — forward guard: no Display/ToString today; never add one unreviewed (AQ-141)
];

/// Reviewed `(type_name, path_suffix, justification, witness_test)` entries
/// for manual, REDACTING `Debug` impls on the forbidden secret-bearing
/// types. A scanner hit whose reason is a `derive(...)` shape is NEVER
/// suppressible (derives cannot redact); a manual-impl hit is suppressed
/// only when the name and swept-file path suffix both match an entry here.
/// Every justification must state what the impl prints and cite the
/// decl/impl sites. AQ-126: the fourth field names the test that pins the
/// impl's redacted OUTPUT (it constructs a real instance and asserts the
/// secret bytes are absent).
///
/// AQ-201 aq201d (review r86 §4): the witness gate runs on COMPILED GROUND
/// TRUTH for entries in THIS crate. The witness must appear in the
/// rustynetd lib test binary's own `--list --format terse` output, under
/// the fully-qualified module path derived from the path suffix, and must
/// NOT be `#[ignore]`d (live = all tests minus the `--ignored` listing).
/// AQ-213: entries in SIBLING crates are arbitrated by the SAME compiled
/// ground truth, executed in each owning crate: `witness_listing.rs` is
/// `#[path]`-shared into every sibling's lib test binary and its per-crate
/// gate judges that crate's slice rows against its own listing, while this
/// module's master gate enforces the one-to-one partition between the
/// sibling registry entries and the slice table plus the canonical wiring
/// anchor in each owning crate's lib.rs. Stated residual: a witness whose
/// assertions are gutted while its name survives is caught by the owning
/// crate's suite and review, not here; and the compiled listing carries no
/// file identity, so a witness living in a real submodule FILE of the
/// declared module also matches.
const REVIEWED_REDACTING_DEBUG_IMPLS: &[(&str, &str, &str, &str)] = &[
    (
        "SecretKey",
        "crates/rustynet-crypto/src/lib.rs",
        "Debug prints only 'SecretKey(REDACTED [32 bytes])'; the [u8;32] key bytes are never emitted and the type is zeroizing-on-drop (decl lib.rs:43, impl lib.rs:55, Drop lib.rs:61)",
        "secret_key_debug_redacts",
    ),
    (
        "Ed25519SigningProvider",
        "crates/rustynet-crypto/src/lib.rs",
        "Debug redacts the SigningKey seed and prints only the public verifying_key hex (decl lib.rs:1191, impl lib.rs:1198)",
        "ed25519_signing_provider_debug_redacts_seed",
    ),
    (
        "EnrollmentToken",
        "crates/rustynetd/src/enrollment_token.rs",
        "Debug redacts token_id+tag (zeroized bearer halves) and prints only a token_id prefix/tag length/expiry (decl :104, impl :112, Drop :123)",
        "enrollment_token_debug_output_redacts_tag_and_token_id",
    ),
    (
        "ConsumedTokenLedger",
        "crates/rustynetd/src/enrollment_token.rs",
        "Debug (AQ-115/F3) prints only consumed_count; ledger keys are consumed token ids — bearer halves (decl :363, impl right after the struct)",
        "consumed_token_ledger_debug_output_redacts_consumed_token_ids",
    ),
    (
        "TokenClaims",
        "crates/rustynet-control/src/lib.rs",
        "Debug redacts subject+nonce (decl :108, impl :134)",
        "token_claims_debug_redacts_sensitive_fields",
    ),
    (
        "SignedTokenClaims",
        "crates/rustynet-control/src/lib.rs",
        "Debug redacts signature_hex (decl :146, impl :164)",
        "signed_token_claims_debug_redacts_signature_hex",
    ),
    (
        "ThrowawayCredential",
        "crates/rustynet-control/src/lib.rs",
        "Debug redacts id+storage_policy (decl :592, impl :605)",
        "throwaway_credential_debug_redacts_sensitive_fields",
    ),
    (
        "RelaySessionToken",
        "crates/rustynet-control/src/lib.rs",
        "Debug redacts relay_id+nonce+signature byte fields; equality is ct_eq only (decl :1756, impl :1777)",
        "relay_session_token_debug_redacts_sensitive_fields",
    ),
    (
        "BlindRelayLegTokenV2",
        "crates/rustynet-control/src/blind_relay.rs",
        "Debug redacts circuit_handle+leg_handle+nonce+signature (decl :341, impl :369)",
        "blind_relay_leg_token_v2_debug_redacts_secret_fields",
    ),
    (
        "BlindRelayPopTranscript",
        "crates/rustynet-control/src/blind_relay.rs",
        "Debug redacts token_digest+relay_challenge+handles+nonces (decl :859, impl :873)",
        "blind_relay_pop_transcript_debug_redacts_secret_fields",
    ),
    (
        "BlindRelayHelloV2",
        "crates/rustynet-control/src/blind_relay.rs",
        "Debug redacts all four secret byte fields (decl :1009, impl :1016)",
        "blind_relay_hello_v2_debug_redacts_secret_fields",
    ),
    (
        "AddressValidationKeyRing",
        "crates/rustynet-relay/src/blind_relay_listener.rs",
        "Debug prints only epoch+key count; the HMAC keys are Zeroizing<[u8;32]> (decl :374, impl :379)",
        "address_validation_key_ring_debug_redacts_hmac_keys",
    ),
    (
        "AddressValidationArtifact",
        "crates/rustynet-relay/src/transport.rs",
        "Debug prints only 'AddressValidationArtifact(REDACTED [32 bytes])'; the HMAC tag bytes are never emitted (decl :224, impl :236)",
        "address_validation_artifact_debug_redacts_tag_bytes",
    ),
    (
        "WindowsWireguardBackend",
        "crates/rustynet-backend-wireguard/src/windows_command.rs",
        "Debug redacts the in-memory decrypted WireGuard runtime_private_key and the runner; paths, port, peers/routes counts and context are non-secret (decl windows_command.rs:27, impl :51)",
        "windows_backend_debug_redacts_runtime_private_key",
    ),
    (
        "SessionToken",
        "crates/rustynet-llm-gateway/src/session.rs",
        "Debug keeps peer/audience/expiry metadata and redacts the ed25519 signature (decl session.rs:74, impl :82)",
        "session_token_debug_redacts_signature",
    ),
];

/// Reviewed redacting `Display`/`ToString` impls on the forbidden types.
/// EMPTY today: none of the forbidden types implements `Display`/`ToString`.
/// Add an entry only for a reviewed impl that provably redacts every secret
/// field, with the decl/impl sites cited and a live witness test named in
/// the fourth field (same contract as `REVIEWED_REDACTING_DEBUG_IMPLS`).
const REVIEWED_REDACTING_DISPLAY_IMPLS: &[(&str, &str, &str, &str)] = &[];

/// Reviewed `(type_name, path_suffix, justification)` entries for
/// secret-VOCABULARY-named types (`SECRET_VOCABULARY_NAME_TOKENS` matches
/// their names) that are NOT secret-bearing: name-only matches, counters,
/// paths, diagnostics, kind enums, error enums, and test doubles. Backed by
/// `every_secret_vocabulary_type_is_classified`, which fails when any
/// vocabulary declaration under the audited roots is absent from ALL of:
/// the forbidden lists, the reviewed-redacting registries, or this table.
const REVIEWED_SECRET_VOCABULARY_TYPE_EXEMPTIONS: &[(&str, &str, &str)] = &[
    (
        "SigningPassphraseHostProfile",
        "crates/rustynet-cli/src/main.rs",
        "host-profile enum; name-only vocabulary match, carries no secret bytes",
    ),
    (
        "SigningPassphraseOpsConfig",
        "crates/rustynet-cli/src/main.rs",
        "ops config holding passphrase PATHS, never passphrase bytes",
    ),
    (
        "RelaySelfSignedCodeSigning",
        "crates/rustynet-cli/src/ops_e2e.rs",
        "e2e code-signing feature type; name-only match",
    ),
    (
        "WriteLiveLinuxSecretsNotInLogsReportConfig",
        "crates/rustynet-cli/src/ops_live_lab_orchestrator.rs",
        "report COUNTERS config for the secrets-not-in-logs gate",
    ),
    (
        "CheckSecretsHygieneConfig",
        "crates/rustynet-cli/src/ops_phase1.rs",
        "hygiene-gate config over PathBufs",
    ),
    (
        "SecretPattern",
        "crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/secrets_not_in_logs_eval.rs",
        "regex/eval scanner value type of the secrets gate itself",
    ),
    (
        "SecretHit",
        "crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/secrets_not_in_logs_eval.rs",
        "scanner hit record (path+line), not secret bytes",
    ),
    (
        "SecretsNotInLogsCheckEntry",
        "crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/secrets_not_in_logs_eval.rs",
        "gate checklist entry descriptor",
    ),
    (
        "SecretsNotInLogsReport",
        "crates/rustynet-cli/src/vm_lab/orchestrator/role_validation/secrets_not_in_logs_eval.rs",
        "gate report aggregate",
    ),
    (
        "LiveSecretsNotInLogsValidationStage",
        "crates/rustynet-cli/src/vm_lab/orchestrator/stage/live_secrets_not_in_logs_validation.rs",
        "unit-struct stage marker",
    ),
    (
        "NegativeControlEnrollmentTokenReplayStage",
        "crates/rustynet-cli/src/vm_lab/orchestrator/stage/negative_control_enrollment_replay.rs",
        "unit-struct stage marker",
    ),
    (
        "BlindRelayTokenKindV2",
        "crates/rustynet-control/src/blind_relay.rs",
        "kind/variant enum; name-only match, no bearer bytes",
    ),
    (
        "CredentialDescriptor",
        "crates/rustynet-control/src/credential_unwrap.rs",
        "account/service NAME descriptor",
    ),
    (
        "ThrowawayCredentialState",
        "crates/rustynet-control/src/lib.rs",
        "state-machine labels over redacting ThrowawayCredential",
    ),
    (
        "CredentialKind",
        "crates/rustynet-control/src/lib.rs",
        "kind enum",
    ),
    (
        "CredentialError",
        "crates/rustynet-control/src/lib.rs",
        "error enum carrying status text, not secret bytes",
    ),
    (
        "CredentialAuditEvent",
        "crates/rustynet-control/src/lib.rs",
        "append-only audit-trail record; id is an opaque reference",
    ),
    (
        "CredentialRevocationEvent",
        "crates/rustynet-control/src/lib.rs",
        "revocation audit record",
    ),
    (
        "ThrowawayCredentialStore",
        "crates/rustynet-control/src/lib.rs",
        "Debug is transitive over the redacting per-credential entries",
    ),
    (
        "ReusableCredentialPolicy",
        "crates/rustynet-control/src/lib.rs",
        "policy flags",
    ),
    (
        "ReusableCredentialRequest",
        "crates/rustynet-control/src/lib.rs",
        "request descriptor",
    ),
    (
        "RelaySessionTokenRequest",
        "crates/rustynet-control/src/lib.rs",
        "request descriptor; tokens themselves are the listed RelaySessionToken",
    ),
    (
        "RelayTokenMintError",
        "crates/rustynet-control/src/lib.rs",
        "error enum carrying OS error text",
    ),
    (
        "CredentialRow",
        "crates/rustynet-control/src/persistence.rs",
        "DB projection row",
    ),
    (
        "NodeKeyPair",
        "crates/rustynet-crypto/src/lib.rs",
        "private half is the LISTED SecretKey, so Debug redacts transitively (decl lib.rs:71)",
    ),
    (
        "SigningProviderKind",
        "crates/rustynet-crypto/src/lib.rs",
        "kind enum",
    ),
    (
        "SigningProviderPolicy",
        "crates/rustynet-crypto/src/lib.rs",
        "policy descriptor",
    ),
    (
        "LinuxSecretToolProbe",
        "crates/rustynet-crypto/src/lib.rs",
        "payload-free classification enum (ProvedNoItems / Inconclusive) of a secret-tool search (AQ-45 step 2); name-only match, no secret bytes",
    ),
    (
        "LinuxSecretServicePresence",
        "crates/rustynet-crypto/src/lib.rs",
        "payload-free enum (Owned / Unavailable) for the org.freedesktop.secrets name-owner check (AQ-45 step 2); name-only match, no secret bytes",
    ),
    (
        "TokenBucket",
        "crates/rustynet-relay/src/rate_limit.rs",
        "rate limiter; 'token' is the rate-limit token bucket, false-positive vocabulary match",
    ),
    (
        "EnrollmentSecretLocation",
        "crates/rustynetd/src/enrollment_secret_custody.rs",
        "doc-declared diagnostic enum of custody LOCATIONS",
    ),
    (
        "EnrollmentTokenError",
        "crates/rustynetd/src/enrollment_token.rs",
        "error enum carrying status text",
    ),
    (
        "TokenInspection",
        "crates/rustynetd/src/enrollment_token.rs",
        "doc-declared never-carries-secrets inspection summary",
    ),
    (
        "CredentialPathOverride",
        "crates/rustynetd/src/key_material.rs",
        "test-module RAII guard over PathBuf",
    ),
    (
        "PreissuedRelaySessionTokenIssuer",
        "crates/rustynetd/src/relay_client.rs",
        "holds spool dir + PUBLIC VerifyingKey only",
    ),
    (
        "FailingRelaySessionTokenIssuer",
        "crates/rustynetd/src/relay_client.rs",
        "test double that always errors",
    ),
    (
        "StaticRelaySessionTokenIssuer",
        "crates/rustynetd/src/relay_client.rs",
        "test double; Debug transitive over redacting token",
    ),
    (
        "ControlPlaneNonceMintError",
        "crates/rustynet-control/src/lib.rs",
        "error struct for control-plane nonce minting failures (decl lib.rs:3683); carries only the OS source text, no nonce bytes (AQ-126 nonce-vocabulary widening)",
    ),
    (
        "NonceStore",
        "crates/rustynet-relay/src/transport.rs",
        "replay-window store of SEEN wire nonces (decl transport.rs:1150); derives Default only, carries no Debug/Display impl, tracks nonces already observed (AQ-126 nonce-vocabulary widening)",
    ),
    (
        "SessionTokenError",
        "crates/rustynet-llm-gateway/src/session.rs",
        "error enum (decl session.rs:29); Debug carries only static strings, a u64 clock reading, and a &'static str field name; Display prints static verdict text (AQ-141 workspace-scope classification)",
    ),
    (
        "NoRelayTokenSpool",
        "crates/rustynet-cli/src/vm_lab/mod.rs",
        "unit-struct no-op token-spool marker (HP-3 patch 3); holds no data and mints or stores nothing",
    ),
    (
        "RelayKeyPairing",
        "crates/rustynet-cli/src/vm_lab/mod.rs",
        "HP-3 preflight result: a PUBLIC verifier key in hex (read from the relay-verifier.pub / traversal verifier .pub files, never a signing secret) plus a summary naming only a 16-hex-char fingerprint",
    ),
    (
        "RelayTokenSpoolReport",
        "crates/rustynet-cli/src/vm_lab/orchestrator/adapter/node_adapter.rs",
        "HP-3 spool install observation: a clock reading and a spool FILE COUNT, no token bytes",
    ),
    (
        "E2eIssueRelaySessionTokensFromEnvConfig",
        "crates/rustynet-cli/src/ops_e2e.rs",
        "ops config of two PathBufs (env file, issue dir): paths only, never token bytes (sibling of the traversal and dns-zone issue configs)",
    ),
];

/// Returns true iff a scanner hit on `name` with reason `why` in file
/// `file_path_label` is a REVIEWED redacting impl. Derive-shaped reasons
/// (starting with `derive(`) are NEVER reviewable — a derive cannot redact.
/// Manual-impl hits are suppressed only when the type name AND the swept
/// file's path suffix both match a reviewed entry. Path matching normalizes
/// backslashes (Windows separators) exactly like the equality allowlist.
fn hit_is_reviewed_redacting_impl(
    name: &str,
    why: &str,
    file_path_label: &str,
    reviewed: &[(&str, &str, &str, &str)],
) -> bool {
    if why.starts_with("derive(") {
        return false;
    }
    let normalized_label = file_path_label.replace('\\', "/");
    reviewed.iter().any(|(entry_name, path, _why, _witness)| {
        *entry_name == name && normalized_label.ends_with(path)
    })
}

/// True iff the secret-vocabulary declaration `name` in `file_path_label` is
/// explicitly classified in one of the registries above. Used by the
/// coverage-backstop meta-test so a new secret-VOCABULARY type cannot ship
/// unclassified (AQ-126: vocabulary-scoped, not a completeness claim).
fn vocabulary_type_is_classified(name: &str, file_path_label: &str) -> bool {
    if FORBIDDEN_DEBUG_SECRET_TYPES.contains(&name)
        || FORBIDDEN_DISPLAY_SECRET_TYPES.contains(&name)
    {
        return true;
    }
    let normalized_label = file_path_label.replace('\\', "/");
    // Two registry shapes, so two closures. The impl registries carry a witness-test
    // name (4-tuple); the vocabulary exemptions do not (3-tuple, declared at the const
    // above). Passing the 3-tuple through a 4-tuple closure was E0308 and never compiled.
    let in_impl_registry = |registry: &[(&str, &str, &str, &str)]| {
        registry.iter().any(|(entry_name, path, _why, _witness)| {
            *entry_name == name && normalized_label.ends_with(path)
        })
    };
    let in_exemptions = |registry: &[(&str, &str, &str)]| {
        registry
            .iter()
            .any(|(entry_name, path, _why)| *entry_name == name && normalized_label.ends_with(path))
    };
    in_impl_registry(REVIEWED_REDACTING_DEBUG_IMPLS)
        || in_impl_registry(REVIEWED_REDACTING_DISPLAY_IMPLS)
        || in_exemptions(REVIEWED_SECRET_VOCABULARY_TYPE_EXEMPTIONS)
}

/// Identifier substrings (case-insensitive) that mark a type name as
/// secret-VOCABULARY for the coverage backstop below.
///
/// AQ-126 scope note: this list is a reviewed heuristic, NOT a claim that
/// every secret-bearing type name matches it. Deliberately excluded: bare
/// `"key"` (the 2026-09-22 enumeration adds 30 declarations to classify —
/// mostly public-key and custody-report naming: `PublicKey`,
/// `ExportKeysCommand`, the `*KeyCustody*` family — while the two REAL
/// exposures a bare `"key"` would surface are named below), and bearer-style
/// names carrying no vocabulary token at all. Known live escapes, left for a
/// follow-up AQ rather than misclassified as name-only here:
/// - `BlindCircuitKey` (crates/rustynet-relay/src/blind_relay_listener.rs)
///   derives `Debug` over a 32-byte `circuit_handle`;
/// - `EncryptedKeyBlob` (crates/rustynet-crypto/src/lib.rs) derives `Debug`
///   over `nonce: [u8; 24]` plus ciphertext.
/// - `AeadSealedBlob` (crates/rustynet-crypto/src/lib.rs) derives `Debug`
///   over `nonce: [u8; 24]` plus ciphertext — same sealed-blob shape, named
///   for no vocabulary token (AQ-140 sweep follow-up).
///
/// `seed` and `nonce` were ADDED by AQ-126 (reviewer finding: seed- and
/// nonce-bearing names escaped the original eight tokens).
const SECRET_VOCABULARY_NAME_TOKENS: &[&str] = &[
    "secret",
    "private",
    "passphrase",
    "signing",
    "token",
    "credential",
    "keyring",
    "keypair",
    "seed",
    "nonce",
];

/// Pure scan helper for the AQ-115/F3 coverage backstop: returns every
/// `struct`/`enum` DECLARATION in `body` whose type name carries the secret
/// vocabulary, as `(line_no, type_name)`. Grammar (kept identical to the
/// 2026-09-22 fleet sweep that enumerated the classification registries):
/// a trimmed, non-comment line matching
/// `^(pub (…)? )?(struct|enum) [A-Za-z0-9_]+` where the optional
/// `pub(…)` qualifier contains only lowercase ASCII letters/spaces, and
/// exactly one space separates each element. Comment-only lines are
/// skipped. AQ-201 R3: the grammar itself lives in
/// `strip_type_decl_prefix` — this scanner delegates to it rather than
/// keeping an inline copy.
pub(crate) fn scan_source_for_secret_vocabulary_type_declarations(
    body: &str,
) -> Vec<(usize, String)> {
    let mut hits: Vec<(usize, String)> = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("/*") {
            continue;
        }
        // AQ-201 R3: delegate to the ONE shared grammar instead of an
        // inline copy of it (the drift risk the review called out).
        let Some(after_keyword) = strip_type_decl_prefix(trimmed) else {
            continue;
        };
        let name = extract_decl_type_name(after_keyword);
        if name.is_empty() {
            continue;
        }
        let lowercase_name = name.to_ascii_lowercase();
        if SECRET_VOCABULARY_NAME_TOKENS
            .iter()
            .any(|token| lowercase_name.contains(token))
        {
            hits.push((idx + 1, name.to_owned()));
        }
    }
    hits
}

/// Sample type names used ONLY by the scanner-logic self-tests below, which
/// feed synthetic source bodies. Kept separate from the production
/// `FORBIDDEN_*_SECRET_TYPES` so the scanner logic is exercised independently
/// of what the production audit currently guards (RSA-0026 decoupling).
const SAMPLE_FORBIDDEN_SECRET_TYPES: &[&str] = &[
    "PassphraseMaterial",
    "SigningKeyMaterial",
    "RuntimePrivateKey",
    "WrappedKeyMaterial",
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
        // AQ-135: any attribute line that derives Display counts — not just a bare
        // `#[derive(...)]`, so `#[cfg_attr(..., derive(Display))]` is caught too.
        if trimmed.starts_with("#[") && trimmed.contains("derive(") && trimmed.contains("Display") {
            for next in body.lines().skip(idx + 1).take(4) {
                if let Some(rest) = strip_type_decl_prefix(next.trim_start()) {
                    let name = extract_decl_type_name(rest);
                    if secret_type_names.contains(&name) {
                        hits.push((
                            idx + 1,
                            name.to_owned(),
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
                if hit_is_reviewed_redacting_impl(
                    &name,
                    &why,
                    &rel.display().to_string(),
                    REVIEWED_REDACTING_DEBUG_IMPLS,
                ) {
                    continue;
                }
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

/// RSA-0026 anti-false-assurance meta-test. The forbidden-Debug/Display lists
/// previously named four types that are not defined anywhere in the workspace,
/// so the gate guarded zero real types while appearing to guard four. This test
/// fails closed if any production forbidden-type name is a phantom (has no
/// `struct`/`enum`/`type` definition under the audited roots), so a future edit
/// cannot re-introduce a guard that silently matches nothing.
#[test]
fn forbidden_secret_type_lists_contain_only_real_types() {
    let root = workspace_root();
    let mut sources = String::new();
    for src_root in audited_source_roots(&root) {
        let mut files: Vec<PathBuf> = Vec::new();
        collect_rs_files(&src_root, &mut files);
        for file in files {
            if let Ok(body) = fs::read_to_string(&file) {
                sources.push_str(&body);
                sources.push('\n');
            }
        }
    }
    let type_is_defined = |name: &str| {
        sources.contains(&format!("struct {name}"))
            || sources.contains(&format!("enum {name}"))
            || sources.contains(&format!("type {name}"))
    };
    let mut phantom: Vec<&str> = Vec::new();
    for name in FORBIDDEN_DEBUG_SECRET_TYPES
        .iter()
        .chain(FORBIDDEN_DISPLAY_SECRET_TYPES.iter())
    {
        if !type_is_defined(name) {
            phantom.push(name);
        }
    }
    assert!(
        phantom.is_empty(),
        "forbidden secret-type list contains phantom name(s) that resolve to no type \
         definition (false assurance — the gate would guard nothing): {phantom:?}"
    );
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
    let hits = scan_source_for_debug_on_secret_types(body, SAMPLE_FORBIDDEN_SECRET_TYPES);
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
    let hits = scan_source_for_debug_on_secret_types(body, SAMPLE_FORBIDDEN_SECRET_TYPES);
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
    let hits = scan_source_for_debug_on_secret_types(body, SAMPLE_FORBIDDEN_SECRET_TYPES);
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
    let hits = scan_source_for_debug_on_secret_types(body, SAMPLE_FORBIDDEN_SECRET_TYPES);
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
    let hits = scan_source_for_debug_on_secret_types(body, SAMPLE_FORBIDDEN_SECRET_TYPES);
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
    let hits = scan_source_for_display_on_secret_types(body, SAMPLE_FORBIDDEN_SECRET_TYPES);
    assert!(
        hits.is_empty(),
        "audit must not false-match `Display for SigningKeyMaterialError` against the `SigningKeyMaterial` allowlist entry: {hits:?}"
    );
}

#[test]
fn debug_scanner_flags_derive_debug_on_pub_crate_secret_type() {
    // AQ-135 escape 1: `pub(<path>)` declarations must be caught exactly
    // like plain `pub` declarations. The old scanner only knew
    // `pub struct `/`struct `/`pub enum `/`enum `, so this planted
    // `pub(crate)` secret type used to pass clean.
    let source =
        "\n#[derive(Debug)]\npub(crate) struct PassphraseMaterial {\n    bytes: Vec<u8>,\n}\n";
    let hits = scan_source_for_debug_on_secret_types(source, SAMPLE_FORBIDDEN_SECRET_TYPES);
    assert!(
        hits.iter().any(|(_, name, reason)| {
            name == "PassphraseMaterial" && reason.starts_with("derive(")
        }),
        "expected derive(Debug) hit for pub(crate) secret type, got {hits:?}"
    );
}

#[test]
fn debug_scanner_flags_derive_debug_on_pub_super_secret_type() {
    let source =
        "\n#[derive(Debug)]\npub(super) struct SigningKeyMaterial {\n    inner: Vec<u8>,\n}\n";
    let hits = scan_source_for_debug_on_secret_types(source, SAMPLE_FORBIDDEN_SECRET_TYPES);
    assert!(
        hits.iter().any(|(_, name, _)| name == "SigningKeyMaterial"),
        "expected derive(Debug) hit for pub(super) secret type, got {hits:?}"
    );
}

#[test]
fn debug_scanner_flags_cfg_attr_derive_debug_on_secret_type() {
    // AQ-135 decide-and-report fix: a derive hidden behind `cfg_attr`
    // used to evade the `#[derive(` prefix check entirely.
    let source = "\n#[cfg_attr(test, derive(Debug))]\npub struct PassphraseMaterial {\n    bytes: Vec<u8>,\n}\n";
    let hits = scan_source_for_debug_on_secret_types(source, SAMPLE_FORBIDDEN_SECRET_TYPES);
    assert!(
        hits.iter().any(|(_, name, reason)| {
            name == "PassphraseMaterial" && reason.starts_with("derive(")
        }),
        "expected cfg_attr derive(Debug) hit, got {hits:?}"
    );
}

#[test]
fn display_scanner_flags_derive_display_on_pub_crate_secret_type() {
    let source =
        "\n#[derive(Display)]\npub(crate) struct PassphraseMaterial {\n    bytes: Vec<u8>,\n}\n";
    let hits = scan_source_for_display_on_secret_types(source, SAMPLE_FORBIDDEN_SECRET_TYPES);
    assert!(
        hits.iter().any(|(_, name, reason)| {
            name == "PassphraseMaterial" && reason.starts_with("derive(")
        }),
        "expected derive(Display) hit for pub(crate) secret type, got {hits:?}"
    );
}

#[test]
fn display_scanner_flags_cfg_attr_derive_display_on_secret_type() {
    let source = "\n#[cfg_attr(test, derive(Display))]\npub struct SigningKeyMaterial {\n    inner: Vec<u8>,\n}\n";
    let hits = scan_source_for_display_on_secret_types(source, SAMPLE_FORBIDDEN_SECRET_TYPES);
    assert!(
        hits.iter().any(|(_, name, _)| name == "SigningKeyMaterial"),
        "expected cfg_attr derive(Display) hit, got {hits:?}"
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
                if hit_is_reviewed_redacting_impl(
                    &name,
                    &why,
                    &rel.display().to_string(),
                    REVIEWED_REDACTING_DISPLAY_IMPLS,
                ) {
                    continue;
                }
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
    let hits = scan_source_for_display_on_secret_types(body, SAMPLE_FORBIDDEN_SECRET_TYPES);
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
    let hits = scan_source_for_display_on_secret_types(body, SAMPLE_FORBIDDEN_SECRET_TYPES);
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
    let hits = scan_source_for_display_on_secret_types(body, SAMPLE_FORBIDDEN_SECRET_TYPES);
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
    let hits = scan_source_for_display_on_secret_types(body, SAMPLE_FORBIDDEN_SECRET_TYPES);
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
    let hits = scan_source_for_display_on_secret_types(body, SAMPLE_FORBIDDEN_SECRET_TYPES);
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

/// Reviewed allowlist of `(file_path_suffix, line_content_substring,
/// justification)` triples where an `==`/`!=` on a forbidden token is
/// intentionally not a security issue (e.g. integer counter zero-check,
/// all-zero sentinel rejection on a public field). Updating this list is a
/// deliberate act — every entry must carry a one-line justification.
///
/// The path is matched by suffix (`file_path_label.ends_with(path)`) so
/// workspace-prefix moves do not silently invalidate entries.
///
/// CRUCIALLY, each entry is anchored on the offending line's **content**
/// (a distinctive substring), NOT on an exact line number. The line-numbered
/// scheme this replaced drifted RED three times whenever an edit added/removed
/// lines above a reviewed site (`ccf0b4a`, `a4c0ddb`, and the 2026-06-25 +6
/// re-sync after `4c3d513` inserted 6 `cfg(unix)` lines into
/// `rustynet-control/src/lib.rs`). A content anchor survives those shifts and
/// only needs revisiting when the reviewed line's *text* actually changes —
/// which is exactly when a fresh review is warranted. Each substring is chosen
/// to be specific to the benign expression (e.g. a compare against a literal
/// `0` / zero-array, or a structural `iter().all(|v| *v == 0)` per-byte check),
/// so it cannot appear inside a genuine secret-vs-secret comparison
/// (`x == other_secret`) and therefore cannot accidentally suppress a real hit.
const REVIEWED_SECRET_EQUALITY_EXCEPTIONS: &[(&str, &str, &str)] = &[
    (
        "crates/rustynet-control/src/lib.rs",
        "nonce == 0",
        "nonce counter zero-check on relay fleet bundle/request u64 input (compare to the literal 0, never a secret-vs-secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        "relay_fleet_payload_u64(bundle.payload.as_str(), \"nonce\") != Some(bundle.nonce)",
        "canonical-payload u64 round-trip equality for the nonce field (structural re-encode check, not a secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        "nonce == [0u8; 16]",
        "all-zero sentinel rejection on relay session token nonce field (compare to a zero-array literal, not a secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        "token.canonical_payload() != payload",
        "canonical-payload structural equality on relay session token (canonicalisation check; the signature is verified separately via ct_eq)",
    ),
    (
        "crates/rustynet-control/src/blind_relay.rs",
        "token.canonical_payload() != payload",
        "canonical-payload structural equality on blind-relay leg token v2 (same reviewed canonicalisation check as the v1 site above; the signature is verified separately via ct_eq)",
    ),
    (
        "crates/rustynet-control/src/blind_relay.rs",
        "nonce == 0",
        "u64 nonce zero-check on blind-relay fleet descriptor v2 input (compare to the literal 0, never a secret-vs-secret compare; the byte-array secret fields go through reject_all_zero/ct_eq instead)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        "record.session_id.iter().all(|value| *value == 0)",
        "all-zero sentinel rejection on coordination session_id byte array (per-byte zero check, not a secret compare)",
    ),
    (
        "crates/rustynet-control/src/lib.rs",
        "record.nonce.iter().all(|value| *value == 0)",
        "all-zero sentinel rejection on coordination nonce byte array (per-byte zero check, not a secret compare)",
    ),
    (
        "crates/rustynet-relay/src/transport.rs",
        "session_token.scope != RELAY_TOKEN_SCOPE",
        "public-scope label string equality on relay hello (relay token scope is a public domain string, not secret material)",
    ),
    (
        "crates/rustynet-relay/src/transport.rs",
        "session_token.node_id == hello.session_token.peer_node_id",
        "self-paired-token structural check on relay hello (RLY-11): compares two NODE IDENTIFIERS carried in the same already-signature-verified token, not secret material. Both values are attacker-supplied and attacker-known, so there is no timing oracle to protect and ct_eq would be inappropriate",
    ),
    (
        "crates/rustynet-relay/src/transport.rs",
        "token is self-paired (node_id == peer_node_id)",
        "the rejection MESSAGE for the check above -- a string literal quoting the expression, not a compare site at all (scanner text match)",
    ),
];

/// Returns true iff the given `(file_path_label, line_content)` matches any
/// entry in `REVIEWED_SECRET_EQUALITY_EXCEPTIONS`. Suffix-match on the path and
/// substring-match on the line content keep entries stable across both
/// workspace-prefix changes and line-number drift.
fn equality_hit_is_allowlisted(file_path_label: &str, line_content: &str) -> bool {
    // Path match: the reviewed-exception suffixes use forward slashes, but the
    // swept path label mixes `/` (from the sweep-root literal) with the
    // OS-native separator from the directory walk — on Windows the filename
    // segment arrives as `…src\transport.rs`, so a raw `ends_with` against
    // `…src/transport.rs` would miss every reviewed exception and report the
    // justified sites as offenders. Normalize to forward slashes so the
    // allowlist applies identically on every host.
    //
    // Content match: anchor on the offending line's text (a distinctive
    // substring), NOT a line number, so edits that shift a reviewed site up or
    // down no longer silently re-break the gate. This does not weaken the
    // audit: each substring is specific to a benign expression (zero/sentinel/
    // structural check) and cannot occur inside a genuine secret-vs-secret
    // comparison, so equality on secret material outside the reviewed list
    // still fails on every platform.
    let normalized_label = file_path_label.replace('\\', "/");
    REVIEWED_SECRET_EQUALITY_EXCEPTIONS
        .iter()
        .any(|(path, snippet, _why)| {
            normalized_label.ends_with(path) && line_content.contains(snippet)
        })
}

/// Strips the contents of double-quoted string literals from one source
/// line, keeping the quote delimiters themselves so the line keeps its
/// shape for later substring searches.
///
/// The equality scanner is a substring matcher: it flags a line when a
/// forbidden identifier (`token`, `mac`, …) is followed by `==`/`!=`
/// further along the SAME line. That shape also occurs inside plain
/// string data — most commonly an assertion MESSAGE that quotes an
/// expression ("token node_id == cap must be inside the bound") — where
/// no comparison executes at all. Removing literal contents before the
/// token search stops those false positives without weakening the
/// audit: a genuine comparison site is code, not data, so its `==`/`!=`
/// never lives inside a string literal on the scanned line.
///
/// Scope and limits (deliberate):
/// - Per-line only. A literal left open at end-of-line swallows just the
///   remainder of THAT line, so detection state can never leak across a
///   line boundary and silence later findings — fail-closed by
///   construction. Multi-line literals therefore keep the scanner's
///   previous behaviour on their continuation lines.
/// - Char literals are recognised only in their tight forms `'x'` and
///   `'\x'`, so a `'"'` byte cannot open a phantom string; lifetime
///   ticks (`'a`) fall through as ordinary characters.
/// - Raw strings `r"…"`, `r#"…"#`, `br#"…"#` are honoured, but never
///   when the prefix character continues an identifier.
/// - Inline comments are blanked too (`// …` to end-of-line; `/* … */`
///   nesting-aware, unterminated → end-of-line), because executable
///   code may FOLLOW an inline block comment on the same line and a
///   stray quote inside that comment would otherwise open a phantom
///   string that swallows — and thereby hides — a genuine comparison
///   after it (over-stripping is fail-open). Whole-line comments are
///   skipped by the caller before this helper runs; this arm covers
///   the inline shapes. This also keeps comment-only mentions of
///   `ct_eq` from suppressing detection of a real compare on the line.
fn strip_string_literal_contents(line: &str) -> String {
    let chars: Vec<char> = line.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(line.len());
    let mut i = 0usize;
    while i < n {
        match chars[i] {
            '"' => {
                out.push('"');
                i += 1;
                while i < n {
                    if chars[i] == '\\' {
                        i = (i + 2).min(n);
                        continue;
                    }
                    let c = chars[i];
                    i += 1;
                    if c == '"' {
                        out.push('"');
                        break;
                    }
                }
            }
            '\'' => {
                let escape_form = i + 4 <= n && chars[i + 1] == '\\' && chars[i + 3] == '\'';
                let plain_form = i + 3 <= n && chars[i + 1] != '\\' && chars[i + 2] == '\'';
                if escape_form || plain_form {
                    let end = if escape_form { i + 4 } else { i + 3 };
                    while i < end {
                        out.push(chars[i]);
                        i += 1;
                    }
                } else {
                    // Lifetime tick or stray apostrophe: ordinary char.
                    out.push('\'');
                    i += 1;
                }
            }
            c @ ('r' | 'b') => {
                let prev_is_ident =
                    i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_');
                let mut j = i + 1;
                if c == 'b' && chars.get(j) != Some(&'r') {
                    // Plain `b"…"` byte string: its quote is handled by the
                    // normal-string arm on the next iteration.
                    out.push(c);
                    i += 1;
                    continue;
                }
                if c == 'b' {
                    j += 1;
                }
                let mut hashes = 0usize;
                while chars.get(j) == Some(&'#') {
                    hashes += 1;
                    j += 1;
                }
                if !prev_is_ident && chars.get(j) == Some(&'"') {
                    // Raw string opener r" / r#" / br##" (hashes may be 0):
                    // copy it verbatim, then skip to the closing sequence
                    // (`"` followed by the same number of `#`).
                    out.extend(&chars[i..=j]);
                    i = j + 1;
                    while i < n {
                        if chars[i] == '"'
                            && chars[i + 1..].len() >= hashes
                            && chars[i + 1..].iter().take(hashes).all(|&h| h == '#')
                        {
                            out.push('"');
                            i += 1 + hashes;
                            break;
                        }
                        i += 1;
                    }
                } else {
                    out.push(c);
                    i += 1;
                }
            }
            '/' => {
                match chars.get(i + 1) {
                    // `// …`: line comment — everything to end-of-line is
                    // comment; nothing executable can follow it, but
                    // blanking keeps a stray quote inside from opening a
                    // phantom string (and matches the caller's whole-line
                    // comment skip for inline placements).
                    Some('/') => break,
                    // `/* … */`: block comment — nesting-aware skip so
                    // executable code AFTER the closer stays visible.
                    // Unterminated → blank to end-of-line (the real
                    // literal/comment continues on later lines, which the
                    // caller's per-line reset already degrades safely).
                    Some('*') => {
                        let mut depth = 1usize;
                        i += 2;
                        while i < n && depth > 0 {
                            if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                                depth += 1;
                                i += 2;
                            } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                                depth -= 1;
                                i += 2;
                            } else {
                                i += 1;
                            }
                        }
                    }
                    _ => {
                        out.push('/');
                        i += 1;
                    }
                }
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    out
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
        // Equality that exists only INSIDE string data is not a compare
        // site: strip literal contents first so assertion messages quoting
        // an expression cannot be mistaken for one. The allowlist below is
        // still matched against the ORIGINAL line because some reviewed
        // anchors are themselves message-text snippets.
        let code_only = strip_string_literal_contents(line);
        // `ct_eq` is the canonical constant-time helper used through-
        // out the workspace; its presence on the line means the
        // developer already routed the compare correctly even if a
        // forbidden token also appears in the same expression.
        if code_only.contains("ct_eq") {
            continue;
        }
        for token in FORBIDDEN_SECRET_EQUALITY_TOKENS {
            // Find the token, then require a subsequent `==` or `!=`
            // anywhere later on the same line. Substring matching is
            // intentional — the allowlist absorbs the known false-
            // positives (integer counter zero-checks, etc.).
            let Some(pos) = code_only.find(token) else {
                continue;
            };
            let rest = &code_only[pos + token.len()..];
            if !(rest.contains("==") || rest.contains("!=")) {
                continue;
            }
            if equality_hit_is_allowlisted(file_path_label, line) {
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
    // Sanity: the reviewed `nonce == 0` zero-check must really be in the list,
    // anchored on its content (not a line number).
    assert!(
        REVIEWED_SECRET_EQUALITY_EXCEPTIONS
            .iter()
            .any(|(path, snippet, _)| {
                *path == "crates/rustynet-control/src/lib.rs" && *snippet == "nonce == 0"
            }),
        "the `nonce == 0` content-anchored allowlist entry must exist"
    );

    let body = "if nonce == 0 { return; }";

    // The same offending content under a NON-allowlisted path still fires (the
    // path suffix must also match — the anchor is not a global content exempt).
    let hits_other_path =
        scan_source_for_secret_material_equality(body, "crates/example/src/lib.rs");
    assert!(
        !hits_other_path.is_empty(),
        "sanity: nonce==0 under a non-allowlisted path must still fire: {hits_other_path:?}"
    );

    // Under the reviewed control/lib.rs path: suppressed regardless of the line.
    let path = "workspace/crates/rustynet-control/src/lib.rs";
    let hits_line1 = scan_source_for_secret_material_equality(body, path);
    assert!(
        hits_line1.is_empty(),
        "allowlisted nonce==0 must be suppressed under the reviewed path: {hits_line1:?}"
    );

    // The whole point of the redesign: a later edit that shifts the same content
    // far down the file must NOT re-break the gate. The old line-numbered scheme
    // failed here three times; the content anchor must survive it.
    let shifted = format!("{}{}", "\n".repeat(500), body);
    let hits_shifted = scan_source_for_secret_material_equality(&shifted, path);
    assert!(
        hits_shifted.is_empty(),
        "a line shift above an allowlisted site must NOT re-break the gate: {hits_shifted:?}"
    );

    // A DIFFERENT, genuinely secret-vs-secret comparison under the SAME reviewed
    // path is still flagged — the content anchor suppresses only its benign
    // expression, never the whole file.
    let real = "if computed_token == expected_token { accept(); }";
    let hits_real = scan_source_for_secret_material_equality(real, path);
    assert!(
        hits_real.iter().any(|(_, t)| t == "token"),
        "a real secret-vs-secret compare under the reviewed path must still fire: {hits_real:?}"
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
fn secret_equality_scanner_ignores_equality_inside_string_literals() {
    // Regression pin for the relay/src/main.rs false positives at :3240 and
    // :3249: an assert! MESSAGE quoting an expression ("token node_id == cap
    // …") contains no comparison at all — the `==` is string data. The
    // exact shape of those flagged lines must stay silent.
    let body = concat!(
        "            let err = parse_relay_hello(&hello_with_token_bytes(&token))\n",
        "                .expect_err(\"truncated token body still fails\");\n",
        "            assert!(\n",
        "                !err.contains(\"exceeds maximum\"),\n",
        "                \"token node_id == cap must be inside the bound; got: {err}\"\n",
        "            );\n",
        "            let err = parse_relay_hello(&hello_with_token_bytes(&token))\n",
        "                .expect_err(\"cap + 1 must be rejected\");\n",
        "            assert!(\n",
        "                err.contains(\"token node_id length\") && err.contains(\"exceeds maximum\"),\n",
        "                \"token node_id == cap + 1 must hit the bound; got: {err}\"\n",
        "            );\n"
    );
    let hits = scan_source_for_secret_material_equality(body, "crates/rustynet-relay/src/main.rs");
    assert!(
        hits.is_empty(),
        "equality quoted inside an assertion message must not be flagged: {hits:?}"
    );

    // Single-line form too: the whole compare living inside one string.
    let one_line = r#"log_info("token == expected is only prose here");"#;
    let hits_one_line =
        scan_source_for_secret_material_equality(one_line, "crates/example/src/lib.rs");
    assert!(
        hits_one_line.is_empty(),
        "an entire compare inside one string literal must not be flagged: {hits_one_line:?}"
    );
}

#[test]
fn secret_equality_scanner_still_flags_real_compare_beside_string_literal() {
    // The stripping must not blind the audit: a GENUINE secret-vs-secret
    // comparison on a line that ALSO carries string data is still caught,
    // even when the string itself contains a forbidden identifier.
    let body =
        r#"reject_enrollment(&format!("bad token length {n}"), supplied_mac == expected_mac);"#;
    let hits = scan_source_for_secret_material_equality(body, "crates/example/src/lib.rs");
    assert!(
        hits.iter().any(|(_, t)| t == "mac"),
        "a real mac compare sharing its line with string data must still fire: {hits:?}"
    );
}

#[test]
fn secret_equality_scanner_survives_char_literals_and_raw_strings() {
    // A `'"'` char literal must not open a phantom string that swallows the
    // rest of the line and hides a genuine compare behind it…
    let char_lit_line = r#"if chunk.first() == Some(&b'"') && supplied_nonce != expected_nonce {"#;
    let hits_char =
        scan_source_for_secret_material_equality(char_lit_line, "crates/example/src/lib.rs");
    assert!(
        hits_char.iter().any(|(_, t)| t == "nonce"),
        "a real nonce compare after a '\"' char literal must still fire: {hits_char:?}"
    );

    // …and raw-string data (`r#"…"#`) must be stripped like any other
    // literal while compares OUTSIDE it remain visible.
    let raw_pair = concat!(
        r##"const DOC: &str = r#"example: token == other_token is prose"#;"##,
        "\n",
        "if computed.signature != expected.signature { reject(); }",
    );
    let hits_raw = scan_source_for_secret_material_equality(raw_pair, "crates/example/src/lib.rs");
    assert!(
        hits_raw
            .iter()
            .any(|(line_no, t)| *line_no == 2 && t == "signature"),
        "signature compare after a raw-string line must fire on line 2: {hits_raw:?}"
    );
    assert!(
        !hits_raw.iter().any(|(line_no, _)| *line_no == 1),
        "raw-string contents on line 1 must not be flagged: {hits_raw:?}"
    );
}

// ---- TEMP ADVERSARIAL PROBES (zz_probe_*) --------------------------

#[test]
fn zz_pin_p7_compare_after_quoted_inline_block_comment_must_fire() {
    let with_quote = "f(x); /* say \"hi */ if supplied_token == expected_token {}";
    let hits = scan_source_for_secret_material_equality(with_quote, "crates/example/src/lib.rs");
    assert!(
        hits.iter().any(|(_, t)| t == "token"),
        "a real compare after an inline block comment containing a quote \
         must still fire (over-stripping is fail-open): {hits:?}"
    );
}

#[test]
fn zz_pin_p8_ct_eq_in_comment_must_not_suppress_real_compare() {
    let block = "if supplied_mac == expected_mac { /* TODO route via ct_eq */ }";
    let trailing = "if supplied_mac == expected_mac { process(); } // use ct_eq instead";
    for (name, body) in [("block", block), ("trailing", trailing)] {
        let hits = scan_source_for_secret_material_equality(body, "crates/example/src/lib.rs");
        assert!(
            hits.iter().any(|(_, t)| t == "mac"),
            "ct_eq mentioned only inside a {name} comment must not silence a real compare: {hits:?}"
        );
    }
}

#[test]
fn zz_pin_p6_unterminated_quote_does_not_leak_across_lines() {
    let body = "let s = \"oops
if supplied_mac == expected_mac {}";
    let hits = scan_source_for_secret_material_equality(body, "crates/example/src/lib.rs");
    assert!(
        hits.iter().any(|(line_no, t)| *line_no == 2 && t == "mac"),
        "fail-closed: a compare on the line AFTER an unterminated quote must still fire: {hits:?}"
    );
}

#[test]
fn zz_pin_escapes_escaped_quote_and_char_escape() {
    let dq = r#"let s = "a\"b"; if supplied_token != expected_token {}"#;
    let hits_dq = scan_source_for_secret_material_equality(dq, "crates/example/src/lib.rs");
    assert!(
        hits_dq.iter().any(|(_, t)| t == "token"),
        "escaped quote inside a literal must not hide a following real compare: {hits_dq:?}"
    );
    let sq = r#"let c = '\''; if supplied_mac == expected_mac {}"#;
    let hits_sq = scan_source_for_secret_material_equality(sq, "crates/example/src/lib.rs");
    assert!(
        hits_sq.iter().any(|(_, t)| t == "mac"),
        "escaped-quote char literal must not hide a following real compare: {hits_sq:?}"
    );
}

#[test]
fn reviewed_exception_list_entries_are_well_formed() {
    for (path, snippet, why) in REVIEWED_SECRET_EQUALITY_EXCEPTIONS {
        assert!(
            !path.is_empty(),
            "allowlist entry has empty path (snippet {snippet:?})"
        );
        // The content anchor must be specific enough not to over-match: a
        // distinctive substring of the reviewed line, not a bare token.
        assert!(
            snippet.len() >= 8,
            "allowlist content anchor for {path} too short to be specific: {snippet:?}"
        );
        // It must actually anchor an equality compare on a forbidden token —
        // otherwise it could never match a real scanner hit (a self-consistency
        // guard so an entry can't silently match nothing or, worse, anything).
        assert!(
            snippet.contains("==") || snippet.contains("!="),
            "allowlist content anchor {snippet:?} for {path} must contain an equality operator"
        );
        assert!(
            FORBIDDEN_SECRET_EQUALITY_TOKENS
                .iter()
                .any(|tok| snippet.contains(tok)),
            "allowlist content anchor {snippet:?} for {path} must contain a forbidden token it suppresses"
        );
        assert!(
            why.len() >= 16,
            "allowlist entry {path} ({snippet:?}) justification too short (need >= 16 chars): {why:?}"
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

// ---- AQ-115/F3: populated-lists liveness + vocabulary coverage backstop ---

#[test]
// clippy's `const_is_empty` correctly notes that the two emptiness asserts below are
// const-evaluable and true TODAY. That is the point of them, not a defect: they exist to
// fail on the day someone empties a list, which is exactly how this gate came to guard
// nothing before AQ-115. Rewriting them to satisfy the lint would delete the guard, so the
// lint is allowed here with the reason instead — the gate runs under `-D warnings`.
#[allow(clippy::const_is_empty)]
fn production_forbidden_lists_flag_planted_exposures() {
    // Anti-false-assurance complement to the phantom-name meta-test: every
    // production list entry must actually FIRE against a planted derive and
    // a planted manual impl of that exact type. An empty or stale list would
    // read green here (that is exactly how this gate guarded nothing).
    assert!(
        !FORBIDDEN_DEBUG_SECRET_TYPES.is_empty(),
        "FORBIDDEN_DEBUG_SECRET_TYPES must not be empty (AQ-115/F3: the gate must guard real types)"
    );
    assert!(
        !FORBIDDEN_DISPLAY_SECRET_TYPES.is_empty(),
        "FORBIDDEN_DISPLAY_SECRET_TYPES must not be empty (AQ-115/F3: the gate must guard real types)"
    );
    for name in FORBIDDEN_DEBUG_SECRET_TYPES {
        let derive_body = format!("#[derive(Debug)]\npub struct {name} {{ bytes: Vec<u8> }}\n");
        let derive_hits =
            scan_source_for_debug_on_secret_types(&derive_body, FORBIDDEN_DEBUG_SECRET_TYPES);
        assert!(
            derive_hits
                .iter()
                .any(|(_, n, why)| n == name && why.starts_with("derive(")),
            "planted derive(Debug) on {name} must fire with a derive-shaped reason: {derive_hits:?}"
        );
        let impl_body = format!(
            "impl std::fmt::Debug for {name} {{\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{\n        write!(f, \"{name}\")\n    }}\n}}\n"
        );
        let impl_hits =
            scan_source_for_debug_on_secret_types(&impl_body, FORBIDDEN_DEBUG_SECRET_TYPES);
        assert!(
            impl_hits.iter().any(|(_, n, _)| n == name),
            "planted manual impl Debug for {name} must fire: {impl_hits:?}"
        );
    }
    for name in FORBIDDEN_DISPLAY_SECRET_TYPES {
        let derive_body = format!("#[derive(Display)]\npub struct {name} {{ bytes: Vec<u8> }}\n");
        let derive_hits =
            scan_source_for_display_on_secret_types(&derive_body, FORBIDDEN_DISPLAY_SECRET_TYPES);
        assert!(
            derive_hits.iter().any(|(_, n, _)| n == name),
            "planted derive(Display) on {name} must fire: {derive_hits:?}"
        );
        let impl_body = format!(
            "impl std::fmt::Display for {name} {{\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{\n        write!(f, \"{name}\")\n    }}\n}}\n"
        );
        let impl_hits =
            scan_source_for_display_on_secret_types(&impl_body, FORBIDDEN_DISPLAY_SECRET_TYPES);
        assert!(
            impl_hits.iter().any(|(_, n, _)| n == name),
            "planted manual impl Display for {name} must fire: {impl_hits:?}"
        );
    }
}

// ---- AQ-141: scope liveness — the audit must cover the whole workspace ----

/// Pure helper: extract the `crates/<name>` member entries from the
/// root manifest text. Matches only array-element lines of the
/// `members` list shape (`"crates/…",`); the `exclude` line and any
/// other mention do not match because they do not start (after
/// trimming) with the quoted path followed by a comma. Split out pure
/// so the self-tests below can pin the parse without touching the
/// filesystem.
fn workspace_member_crate_dirs_from_manifest(manifest_text: &str) -> Vec<String> {
    let mut members = Vec::new();
    for line in manifest_text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("\"crates/")
            && let Some(dir) = rest.strip_suffix("\",")
        {
            members.push(format!("crates/{dir}"));
        }
    }
    members
}

#[test]
fn manifest_member_parser_extracts_member_lines() {
    let manifest = "members = [\n  \"crates/rustynetd\",\n  \"crates/rustynet-cli\",\n]\n";
    assert_eq!(
        workspace_member_crate_dirs_from_manifest(manifest),
        vec!["crates/rustynetd", "crates/rustynet-cli"]
    );
}

#[test]
fn manifest_member_parser_ignores_exclude_and_other_lines() {
    let manifest = "exclude = [\"gui\", \"crates/rustynet-lab-monitor\"]\nmembers = [\n  \"crates/rustynetd\",\n]\n# \"crates/commented-out\",\n";
    assert_eq!(
        workspace_member_crate_dirs_from_manifest(manifest),
        vec!["crates/rustynetd"]
    );
}

#[test]
fn audited_roots_cover_the_in_family_gap_crates() {
    // AQ-141 witness: the AQ-108 v2 display sweep found secret-bearing
    // Debug surfaces in these two workspace crates while the audit
    // walked neither — the gap was inside the audited crate family,
    // not across projects. Both must now be under the audit's roots.
    // This test fails against the pre-AQ-141 five-root list.
    let root = workspace_root();
    let roots = audited_source_roots(&root);
    for crate_dir in [
        "crates/rustynet-backend-wireguard",
        "crates/rustynet-llm-gateway",
    ] {
        let expected = root.join(crate_dir).join("src");
        assert!(
            roots.contains(&expected),
            "audited_source_roots must cover {crate_dir}/src — \
             a workspace crate holding secret-bearing types is outside the audit"
        );
    }
}

#[test]
fn audited_roots_track_workspace_membership() {
    // AQ-141 drift backstop: the walked roots must be EXACTLY the
    // workspace member set from the root Cargo.toml. A crate added to
    // the workspace without extending (or removing itself from) this
    // audit turns this test red — scope can no longer silently lag
    // the workspace.
    let root = workspace_root();
    let manifest_path = root.join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("must read root manifest {}: {e}", manifest_path.display()));
    let mut from_manifest = workspace_member_crate_dirs_from_manifest(&manifest);
    from_manifest.sort();
    let mut from_roots: Vec<String> = audited_source_roots(&root)
        .iter()
        .filter_map(|p| {
            p.strip_prefix(&root)
                .ok()?
                .to_str()
                .map(|s| s.trim_end_matches("/src").to_owned())
        })
        .collect();
    from_roots.sort();
    assert!(
        !from_manifest.is_empty(),
        "member parse found nothing — manifest shape drifted; update the parser, do not weaken the gate"
    );
    assert_eq!(
        from_roots, from_manifest,
        "audited_source_roots must exactly match the root Cargo.toml members — \
         every workspace crate is in the audit's scope (AQ-141)"
    );
}

#[test]
fn every_secret_vocabulary_type_is_classified() {
    // AQ-115/F3 coverage backstop: every secret-vocabulary struct/enum
    // declaration under the audited roots must be explicitly classified in
    // one of the registries above. AQ-126 scope: this enforces
    // classification of the DECLARED vocabulary
    // (`SECRET_VOCABULARY_NAME_TOKENS`); it is not proof that no
    // secret-bearing type exists outside that vocabulary.
    let root = workspace_root();
    let allowlist = audited_path_allowlist();
    let mut unclassified: Vec<String> = Vec::new();
    let mut vocabulary_hits = 0usize;
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
            let label = rel.display().to_string();
            for (line_no, name) in scan_source_for_secret_vocabulary_type_declarations(&body) {
                vocabulary_hits += 1;
                if vocabulary_type_is_classified(&name, &label) {
                    continue;
                }
                unclassified.push(format!("{label}:{line_no}: {name}"));
            }
        }
    }
    assert!(
        vocabulary_hits > 0,
        "vocabulary backstop found zero secret-vocabulary declarations — the scanner is blind; do not let this gate rot into a no-op"
    );
    if !unclassified.is_empty() {
        panic!(
            "secret-vocabulary coverage backstop found {} unclassified struct/enum declaration(s). \
             Classify each in secret_log_audit.rs: list it in FORBIDDEN_DEBUG/DISPLAY_SECRET_TYPES \
             (secret-bearing), REVIEWED_REDACTING_DEBUG/DISPLAY_IMPLS (reviewed redacting impl), or \
             REVIEWED_SECRET_VOCABULARY_TYPE_EXEMPTIONS (name-only / non-secret) with a justification:\n  {}",
            unclassified.len(),
            unclassified.join("\n  ")
        );
    }
}

// ---------------------------------------------------------------------------
// Compiled ground truth (AQ-201 aq201d, review r86 §4).
//
// The text scanner above reads NAMES in SOURCE and is therefore defeat-able
// by shapes rustc would not compile into a live test (r86 F1′: a
// `macro_rules` definition that retires tracking on its own opening line let
// an inert macro-body witness count as live). Ground truth is the COMPILER's
// own test binary: a registry witness counts as live only if the RUNNING
// test executable, asked `--list --format terse`, actually contains it —
// under the fully-qualified module path derived from the registry rel_path,
// and NOT in the `--ignored` listing (an `#[ignore]`d witness is not live
// evidence). This works identically under `cargo test` and `cargo nextest`:
// both spawn this same binary per test, and `current_exe()` + `--list` is a
// plain self-exec with no cargo involvement (no target-lock contention).
// The spawn FAILS CLOSED: any error, non-zero exit, unparseable line, or
// empty listing aborts the gate — including an empty `--ignored` listing:
// the parser refuses ANY empty listing, and the permanent `#[ignore]`d probe
// guarantees the `--ignored` listing is never legitimately empty (r92 N-2).
// ---------------------------------------------------------------------------

/// Fully-qualified name of this gate inside the rustynetd lib test binary.
/// Required to appear in the parsed `--list` output as a parse-sanity
/// sentinel before any registry entry is judged against it.
const COMPILED_GROUND_TRUTH_GATE_TEST: &str =
    "secret_log_audit::every_reviewed_redacting_impl_entry_has_a_live_witness_test";

/// A permanent `#[ignore]`d test pinning, end to end, the libtest semantics
/// the gate depends on: the probe IS in the all-tests listing, IS in the
/// `--ignored` listing, and is therefore excluded from the live set. If
/// libtest's `--ignored` semantics ever change, this probe's own assertions
/// go red BEFORE the registry gate could be fooled into counting an
/// `#[ignore]`d witness as live.
#[test]
#[ignore = "ground-truth probe: pinned as listed-but-not-live; never run by default"]
fn ground_truth_ignored_witness_probe() {}

#[test]
fn every_reviewed_redacting_impl_entry_has_a_live_witness_test() {
    // AQ-126 + AQ-201 aq201d (review r86 §4): a suppression that outlives
    // its evidence is a silent allowance. Ground truth is the COMPILER's:
    // every registry witness must appear in THIS test binary's own
    // `--list --format terse` output under the module path derived from the
    // registry rel_path, and must NOT be `#[ignore]`d (live = all-listing
    // minus `--ignored` listing). Both spawns fail closed; `cargo nextest`
    // runs this same binary per test, so the self-exec works there too.
    let all_tests = crate::witness_listing::libtest_listing(false)
        .unwrap_or_else(|err| panic!("compiled ground truth unavailable, failing closed: {err}"));
    let ignored_tests = crate::witness_listing::libtest_listing(true)
        .unwrap_or_else(|err| panic!("compiled ground truth unavailable, failing closed: {err}"));
    let live_tests: BTreeSet<String> = all_tests.difference(&ignored_tests).cloned().collect();
    assert!(
        live_tests.contains(COMPILED_GROUND_TRUTH_GATE_TEST),
        "parse sanity: this gate's own test \
         {COMPILED_GROUND_TRUTH_GATE_TEST:?} must appear in the compiled listing before \
         registry entries are judged against it"
    );
    assert!(
        !live_tests.contains("secret_log_audit::ground_truth_ignored_witness_probe"),
        "parse sanity: the #[ignore]d ground-truth probe must never be in the live set"
    );
    let mut failures: Vec<String> = Vec::new();
    let mut sibling_entries: Vec<(&str, &str, &str, &str)> = Vec::new();
    for (registry_name, registry) in [
        (
            "REVIEWED_REDACTING_DEBUG_IMPLS",
            REVIEWED_REDACTING_DEBUG_IMPLS,
        ),
        (
            "REVIEWED_REDACTING_DISPLAY_IMPLS",
            REVIEWED_REDACTING_DISPLAY_IMPLS,
        ),
    ] {
        assert!(
            !registry.is_empty() || registry_name == "REVIEWED_REDACTING_DISPLAY_IMPLS",
            "{registry_name} must not be silently emptied"
        );
        // `*registry` is an unsized `[T]` and is not IntoIterator — this was E0277.
        for (name, path, _why, witness) in registry.iter() {
            match crate::witness_listing::libtest_module_prefix(path) {
                // In-crate entry: COMPILED ground truth is the arbiter.
                Some((crate_name, module_prefix)) if crate_name == "rustynetd" => {
                    if let Some(reason) = crate::witness_listing::compiled_ground_truth_failure(
                        &all_tests,
                        &live_tests,
                        &module_prefix,
                        witness,
                    ) {
                        failures.push(format!("{registry_name}: {name}: {reason}"));
                    }
                }
                // AQ-213: sibling-crate entries are arbitrated by the owning
                // crate's own compiled gate (witness_listing, #[path]-shared
                // into each sibling), which this binary cannot run. What IS
                // pinned here: the one-to-one partition between the sibling
                // registry entries and the per-crate slice table, slice-table
                // integrity, and the canonical wiring anchor in every owning
                // crate's lib.rs.
                Some(_) => sibling_entries.push((registry_name, *name, *path, *witness)),
                // Unmappable path shape: refuse loudly rather than silently
                // weaken the contract (fail closed).
                None => {
                    failures.push(format!(
                        "{registry_name}: {name}: rel_path {path:?} does not map onto a lib \
                         target module; compiled ground truth cannot arbitrate it — fix the \
                         path shape (crates/<crate>/src/…)"
                    ));
                }
            }
        }
    }
    failures.extend(sibling_slice_failures(&sibling_entries));
    assert!(
        failures.is_empty(),
        "reviewed redacting-impl entries without a live witness test:\n  {}",
        failures.join("\n  ")
    );
}

/// AQ-213 partition + anchor checks over the SIBLING registry entries
/// (entries in crates other than rustynetd):
/// (1) every sibling entry appears exactly once in its owning crate's
///     slice-table rows;
/// (2) every sibling slice row corresponds to exactly one sibling
///     registry entry — in-crate rustynetd rows are exempt, being
///     arbitrated directly by the compiled arm above;
/// (3) slice integrity: every row's rel_path maps onto its owning crate
///     and its declared prefix stays under the rel_path-derived prefix;
/// (4) wiring anchor: every owning crate's lib.rs carries the canonical
///     test-only `witness_listing` declaration (`#[path]` + `mod` for
///     siblings, plain `mod` for rustynetd). Wiring presence is what is
///     checked here; each wired gate pins its own liveness at its own
///     runtime via the parse-sanity sentinel, so the combined chain
///     fails closed: removing the anchor removes the gate AND fails
///     this check, and a gate that stops seeing its witnesses fails the
///     crate's own suite.
fn sibling_slice_failures(entries: &[(&str, &str, &str, &str)]) -> Vec<String> {
    let mut failures: Vec<String> = Vec::new();
    let slices = crate::witness_listing::WITNESS_SLICES;
    for &(registry_name, name, path, witness) in entries {
        let Some((crate_name, _derived)) = crate::witness_listing::libtest_module_prefix(path)
        else {
            failures.push(format!(
                "{registry_name}: {name}: unmappable rel_path {path:?}"
            ));
            continue;
        };
        let Some((_, slice)) = slices
            .iter()
            .find(|(crate_in_table, _)| *crate_in_table == crate_name)
        else {
            failures.push(format!(
                "{registry_name}: {name}: crate {crate_name:?} owns registry entries but has \
                 no rows in the witness slice table"
            ));
            continue;
        };
        let hits = slice
            .iter()
            .filter(|(row_path, _, row_witness)| *row_path == path && *row_witness == witness)
            .count();
        if hits != 1 {
            failures.push(format!(
                "{registry_name}: {name}: slice table for {crate_name:?} lists \
                 (path={path:?}, witness={witness:?}) {hits} times, expected exactly 1"
            ));
        }
    }
    for &(crate_name, slice) in slices {
        if crate_name == "rustynetd" {
            continue;
        }
        for &(rel_path, _declared_prefix, witness) in slice {
            let hits = entries
                .iter()
                .filter(|(_, _, row_path, row_witness)| {
                    *row_path == rel_path && *row_witness == witness
                })
                .count();
            if hits != 1 {
                failures.push(format!(
                    "witness slice table: crate {crate_name:?} row (path={rel_path:?}, \
                     witness={witness:?}) matches {hits} sibling registry entries, expected \
                     exactly 1"
                ));
            }
        }
    }
    for &(crate_name, slice) in slices {
        if slice.is_empty() {
            failures.push(format!(
                "witness slice table: crate {crate_name:?} slice is empty"
            ));
            continue;
        }
        for &(rel_path, declared_prefix, witness) in slice {
            match crate::witness_listing::libtest_module_prefix(rel_path) {
                Some((mapped_crate, derived_prefix)) if mapped_crate == crate_name => {
                    if !crate::witness_listing::module_prefix_is_under_rel_path(
                        &derived_prefix,
                        declared_prefix,
                    ) {
                        failures.push(format!(
                            "witness slice table: crate {crate_name:?} row (path={rel_path:?}, \
                             witness={witness:?}) declares prefix {declared_prefix:?} that \
                             escapes the rel_path-derived prefix {derived_prefix:?}"
                        ));
                    }
                }
                other => failures.push(format!(
                    "witness slice table: crate {crate_name:?} row path {rel_path:?} maps to \
                     {other:?}, not the owning crate"
                )),
            }
        }
    }
    let root = workspace_root();
    for &(crate_name, _slice) in slices {
        let lib = root
            .join("crates")
            .join(crate_name)
            .join("src")
            .join("lib.rs");
        let Ok(body) = fs::read_to_string(&lib) else {
            failures.push(format!(
                "witness slice table: cannot read crates/{crate_name}/src/lib.rs to verify \
                 the witness_listing wiring anchor"
            ));
            continue;
        };
        let has_path_line = body
            .lines()
            .any(|line| line.trim() == "#[path = \"../../rustynetd/src/witness_listing.rs\"]");
        let has_mod_line = body
            .lines()
            .any(|line| line.trim() == "mod witness_listing;");
        if crate_name == "rustynetd" {
            if !has_mod_line {
                failures.push(
                    "witness slice table: rustynetd lib.rs must declare test-only \
                     `mod witness_listing;` — the in-crate slice rows would be unchecked"
                        .to_string(),
                );
            }
        } else if !has_path_line || !has_mod_line {
            failures.push(format!(
                "witness slice table: crates/{crate_name}/src/lib.rs must declare the \
                 canonical test-only pair `#[path = \
                 \"../../rustynetd/src/witness_listing.rs\"]` + `mod witness_listing;` — the \
                 crate's own compiled witness gate is not wired"
            ));
        }
    }
    failures
}

#[test]
fn ground_truth_ignored_probe_is_listed_but_never_live() {
    // Pins the libtest semantics the gate relies on (rustc 1.88.0, stable):
    // `--list` includes #[ignore]d tests indistinguishably,
    // `--list --ignored` lists ONLY ignored tests, so live = all − ignored,
    // and the permanent probe sits exactly in the excluded slice.
    let all_tests = crate::witness_listing::libtest_listing(false)
        .expect("self `--list` must succeed under the test harness");
    let ignored_tests = crate::witness_listing::libtest_listing(true)
        .expect("self `--list --ignored` must succeed");
    let probe = "secret_log_audit::ground_truth_ignored_witness_probe";
    assert!(
        all_tests.contains(probe),
        "probe must be in the all listing"
    );
    assert!(
        ignored_tests.contains(probe),
        "probe must be in the `--ignored` listing"
    );
    let live_tests: BTreeSet<String> = all_tests.difference(&ignored_tests).cloned().collect();
    assert!(
        !live_tests.contains(probe),
        "an #[ignore]d test must never be in the live set"
    );
}

#[test]
fn ground_truth_live_test_of_this_module_is_in_live_set() {
    // Positive control: a real, un-ignored existing test of this module is
    // in the live set, proving the two-spawn subtraction does not
    // over-exclude.
    let all_tests = crate::witness_listing::libtest_listing(false)
        .expect("self `--list` must succeed under the test harness");
    let ignored_tests = crate::witness_listing::libtest_listing(true)
        .expect("self `--list --ignored` must succeed");
    let live_tests: BTreeSet<String> = all_tests.difference(&ignored_tests).cloned().collect();
    assert!(
        live_tests.contains(COMPILED_GROUND_TRUTH_GATE_TEST),
        "a plain #[test] of this module must be in the live set"
    );
}

#[test]
fn derive_scanner_name_extraction_is_ascii() {
    // AQ-201 R3: the derive scanners extracted names with Unicode
    // `is_alphanumeric`, so `PrivateKey<uuml>` extracted as one name that
    // never matched the ASCII registry — the type escaped every scanner.
    // The shared ASCII extractor stops at the non-ASCII byte, so the
    // registry name still matches (over-catch is the safe direction for
    // an audit scanner).
    let debug_body = "#[derive(Debug)]\npub struct PrivateKey\u{fc} {}\n";
    let debug_hits = scan_source_for_debug_on_secret_types(debug_body, &["PrivateKey"]);
    assert!(
        debug_hits.iter().any(|(_, n, _)| n == "PrivateKey"),
        "Unicode-suffixed secret type must still surface (debug): {debug_hits:?}"
    );

    let display_body = "#[derive(Display)]\npub struct PrivateKey\u{fc} {}\n";
    let display_hits = scan_source_for_display_on_secret_types(display_body, &["PrivateKey"]);
    assert!(
        display_hits.iter().any(|(_, n, _)| n == "PrivateKey"),
        "Unicode-suffixed secret type must still surface (display): {display_hits:?}"
    );
}

#[test]
fn decl_scanners_documented_limit_double_space_after_visibility() {
    // AQ-201 R3, documented limit (review probe p8): a second space after
    // the visibility qualifier (`pub(crate)  struct`) matches no scanner —
    // the shared grammar requires exactly one separating space. Pinned
    // here so the limit stays a recorded decision, not an accident;
    // widening the grammar is an owner question (review §7.3), not taken.
    let vocab_body = "pub(crate)  struct FooPrivateKey {}\n";
    assert!(
        scan_source_for_secret_vocabulary_type_declarations(vocab_body).is_empty(),
        "double-space shape is a documented limit; if this fires the grammar widened"
    );

    let derive_body = "#[derive(Debug)]\npub(crate)  struct PrivateKey {}\n";
    assert!(
        scan_source_for_debug_on_secret_types(derive_body, &["PrivateKey"]).is_empty(),
        "double-space shape is a documented limit; if this fires the grammar widened"
    );
}

#[test]
fn decl_scanners_documented_limit_raw_identifier_name() {
    // AQ-201 R3, documented limit (review probe p6): a raw-identifier type
    // name (`r#…`) matches no scanner — the shared extractor reads only
    // `r` before the `#` stops it. Pinned as a recorded decision; raw-ident
    // awareness is an owner question (review §7.3), not taken.
    let vocab_body = "pub struct r#secret_key {}\n";
    assert!(
        scan_source_for_secret_vocabulary_type_declarations(vocab_body).is_empty(),
        "raw-ident shape is a documented limit; if this fires the extractor widened"
    );

    let derive_body = "#[derive(Debug)]\npub struct r#secret_key {}\n";
    assert!(
        scan_source_for_debug_on_secret_types(derive_body, &["secret_key"]).is_empty(),
        "raw-ident shape is a documented limit; if this fires the extractor widened"
    );
}

#[test]
fn vocabulary_scanner_flags_pub_crate_private_key_struct() {
    let body = "pub(crate) struct FooPrivateKey {\n    bytes: Vec<u8>,\n}\n";
    let hits = scan_source_for_secret_vocabulary_type_declarations(body);
    assert!(
        hits.iter().any(|(_, n)| n == "FooPrivateKey"),
        "pub(crate) secret-vocabulary declaration must surface: {hits:?}"
    );
}

#[test]
fn vocabulary_scanner_flags_enum_with_token_name() {
    let body = "pub enum BarToken {\n    Legacy,\n}\n";
    let hits = scan_source_for_secret_vocabulary_type_declarations(body);
    assert!(
        hits.iter().any(|(_, n)| n == "BarToken"),
        "token-named enum declaration must surface: {hits:?}"
    );
}

#[test]
fn vocabulary_scanner_silent_on_non_vocabulary_type() {
    let body = "pub struct AddressBook {\n    entries: Vec<String>,\n}\n";
    let hits = scan_source_for_secret_vocabulary_type_declarations(body);
    assert!(
        hits.is_empty(),
        "non-vocabulary declaration must not surface: {hits:?}"
    );
}

#[test]
fn vocabulary_scanner_silent_on_comment_only_mention() {
    let body = "// struct SecretThing would be flagged if it were code\n";
    let hits = scan_source_for_secret_vocabulary_type_declarations(body);
    assert!(
        hits.is_empty(),
        "comment-only mention must not surface: {hits:?}"
    );
}
