//! AQ-213: per-crate compiled ground-truth gate for the reviewed
//! redacting-`Debug`-impl witness registry
//! ([`crate::secret_log_audit::REVIEWED_REDACTING_DEBUG_IMPLS`] in the
//! rustynetd host).
//!
//! AQ-201 aq201d (review r86 §4) gave the IN-CRATE registry entries a
//! compiled-ground-truth gate but left SIBLING-crate entries on a
//! source-text scanner, which is defeat-able by shapes rustc never
//! compiles into a live test (the r86 F1′ class). This module closes
//! that gap by being COMPILED INTO EVERY CRATE that owns registry
//! entries: the file is included once by rustynetd
//! (`#[cfg(test)] mod witness_listing;`) and once per sibling via
//! `#[cfg(test)] #[path = "../../rustynetd/src/witness_listing.rs"]
//! mod witness_listing;`. Each host binary runs
//! [`every_reviewed_redacting_impl_entry_of_this_crate_has_a_live_witness_test`],
//! which judges exactly the rows [`WITNESS_SLICES`] assigns to
//! [`env!("CARGO_PKG_NAME")`] against the host crate's own test
//! binary listing.
//!
//! Ground truth is the COMPILER's: a slice row counts as live only if
//! the RUNNING test executable, asked `--list --format terse`, actually
//! contains the witness under its declared module prefix, and the
//! witness is NOT in the `--ignored` listing (an `#[ignore]`d witness
//! is not live evidence). This works identically under `cargo test`
//! and `cargo nextest`: both spawn this same binary per test, and
//! `current_exe()` + `--list` is a plain self-exec with no cargo
//! involvement. The spawn FAILS CLOSED: any error, non-zero exit,
//! unparseable line, or empty listing of EITHER kind aborts the gate.
//! The permanent `#[ignore]`d probe below guarantees the `--ignored`
//! listing is never empty, so an empty listing can only ever mean a
//! broken harness — never a vacuously-green subtraction.

use std::collections::BTreeSet;
use std::process::{Command, Stdio};

/// Fully-qualified name of the per-crate gate inside each host crate's
/// lib test binary. Required to appear in the parsed `--list` output as
/// a parse-sanity sentinel before any slice entry is judged against it.
const PER_CRATE_GATE_TEST: &str =
    "witness_listing::every_reviewed_redacting_impl_entry_of_this_crate_has_a_live_witness_test";

/// Fully-qualified name of the permanent `#[ignore]`d probe in each
/// host crate's lib test binary.
const PER_CRATE_IGNORED_PROBE: &str = "witness_listing::ground_truth_ignored_witness_probe";

/// One duty row of the per-crate slice table:
/// `(registry rel_path, declared module prefix, witness test name)`.
///
/// The declared prefix is the module path the witness COMPILES into
/// (usually `<derived>::tests` because the witness lives in the file's
/// `#[cfg(test)] mod tests`); the rel_path-derived prefix is the module
/// the FILE maps to. The two are tied together by
/// [`module_prefix_is_under_rel_path`] so a row cannot point a witness
/// at an unrelated module.
type WitnessSliceEntry = (&'static str, &'static str, &'static str);

/// The complete duty table: per crate, the reviewed-redacting-impl
/// witnesses that crate's own gate must find live in its own test
/// binary. Mirrors the sibling entries of
/// `secret_log_audit::REVIEWED_REDACTING_DEBUG_IMPLS` (plus the
/// in-crate rustynetd rows); the master gate in rustynetd enforces the
/// one-to-one partition between this table and the registry.
///
/// Declared prefixes reflect the observed compiled locations (AQ-213
/// `--list` survey): crypto/control `lib.rs` witnesses live under the
/// root `tests` module, the others under `<file module>::tests`.
pub const WITNESS_SLICES: &[(&str, &[WitnessSliceEntry])] = &[
    (
        "rustynetd",
        &[
            (
                "crates/rustynetd/src/enrollment_token.rs",
                "enrollment_token::tests",
                "enrollment_token_debug_output_redacts_tag_and_token_id",
            ),
            (
                "crates/rustynetd/src/enrollment_token.rs",
                "enrollment_token::tests",
                "consumed_token_ledger_debug_output_redacts_consumed_token_ids",
            ),
        ],
    ),
    (
        "rustynet-crypto",
        &[
            (
                "crates/rustynet-crypto/src/lib.rs",
                "tests",
                "secret_key_debug_redacts",
            ),
            (
                "crates/rustynet-crypto/src/lib.rs",
                "tests",
                "ed25519_signing_provider_debug_redacts_seed",
            ),
        ],
    ),
    (
        "rustynet-control",
        &[
            (
                "crates/rustynet-control/src/lib.rs",
                "tests",
                "token_claims_debug_redacts_sensitive_fields",
            ),
            (
                "crates/rustynet-control/src/lib.rs",
                "tests",
                "signed_token_claims_debug_redacts_signature_hex",
            ),
            (
                "crates/rustynet-control/src/lib.rs",
                "tests",
                "throwaway_credential_debug_redacts_sensitive_fields",
            ),
            (
                "crates/rustynet-control/src/lib.rs",
                "tests",
                "relay_session_token_debug_redacts_sensitive_fields",
            ),
            (
                "crates/rustynet-control/src/blind_relay.rs",
                "blind_relay::tests",
                "blind_relay_leg_token_v2_debug_redacts_secret_fields",
            ),
            (
                "crates/rustynet-control/src/blind_relay.rs",
                "blind_relay::tests",
                "blind_relay_pop_transcript_debug_redacts_secret_fields",
            ),
            (
                "crates/rustynet-control/src/blind_relay.rs",
                "blind_relay::tests",
                "blind_relay_hello_v2_debug_redacts_secret_fields",
            ),
        ],
    ),
    (
        "rustynet-relay",
        &[
            (
                "crates/rustynet-relay/src/blind_relay_listener.rs",
                "blind_relay_listener::tests",
                "address_validation_key_ring_debug_redacts_hmac_keys",
            ),
            (
                "crates/rustynet-relay/src/transport.rs",
                "transport::tests",
                "address_validation_artifact_debug_redacts_tag_bytes",
            ),
        ],
    ),
    (
        "rustynet-backend-wireguard",
        &[(
            "crates/rustynet-backend-wireguard/src/windows_command.rs",
            "windows_command::tests",
            "windows_backend_debug_redacts_runtime_private_key",
        )],
    ),
    (
        "rustynet-llm-gateway",
        &[(
            "crates/rustynet-llm-gateway/src/session.rs",
            "session::tests",
            "session_token_debug_redacts_signature",
        )],
    ),
];

/// The host crate's slice rows, or `None` when the table has no rows
/// for it (the per-crate gate treats that as a failure — a crate that
/// owns registry entries must have rows, and the master gate's
/// partition check keeps the table and the registry tied together).
fn slice_for_crate(crate_name: &str) -> Option<&'static [WitnessSliceEntry]> {
    WITNESS_SLICES
        .iter()
        .find(|(crate_in_table, _)| *crate_in_table == crate_name)
        .map(|(_, slice)| *slice)
}

/// Consistency rule tying a row's DECLARED module prefix to the prefix
/// derived from its rel_path: the declared prefix must be the derived
/// prefix itself or a strict descendant of it (the `mod tests` wrapper
/// shape). A lib.rs row derives the empty prefix and may declare any
/// non-empty prefix — the root `tests` module has no file of its own.
/// Anything else refuses: the row would let a witness satisfy the gate
/// from a module the registry path never named. Also used by the
/// rustynetd master gate's slice-integrity check.
pub fn module_prefix_is_under_rel_path(derived: &str, declared: &str) -> bool {
    if derived.is_empty() {
        return !declared.is_empty();
    }
    declared == derived
        || declared
            .strip_prefix(derived)
            .is_some_and(|rest| rest.starts_with("::"))
}

/// A permanent `#[ignore]`d test pinning, end to end, the libtest
/// semantics the gate depends on: the probe IS in the all-tests
/// listing, IS in the `--ignored` listing, and is therefore excluded
/// from the live set. It also guarantees the `--ignored` listing is
/// non-empty in every host crate, so the gate's fail-closed
/// empty-listing rule can never misread an empty ignored-listing as a
/// broken harness.
#[test]
#[ignore = "ground-truth probe: pinned as listed-but-not-live; never run by default"]
fn ground_truth_ignored_witness_probe() {}

/// Parse `--list --format terse` output into the set of fully-qualified
/// test names. Terse lines are `name: test`. Anything else (empty output,
/// an unknown kind, a malformed line, a suspicious name, a duplicate) is an
/// error so the gate fails closed on half-parsed listings.
pub fn parse_libtest_listing(stdout: &str) -> Result<BTreeSet<String>, String> {
    let mut names = BTreeSet::new();
    for line in stdout.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let Some((name, kind)) = line.rsplit_once(": ") else {
            return Err(format!("unparseable listing line {line:?}"));
        };
        if kind != "test" {
            return Err(format!("unexpected listing kind {kind:?} on line {line:?}"));
        }
        let ident_ok = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':');
        if !ident_ok {
            return Err(format!("suspicious test name on line {line:?}"));
        }
        if !names.insert(name.to_string()) {
            return Err(format!("duplicate test name {name:?} in listing"));
        }
    }
    if names.is_empty() {
        return Err("listing contained no `name: test` lines".to_string());
    }
    Ok(names)
}

/// One self-exec `--list` spawn of the RUNNING test binary.
/// `include_ignored` selects the `--ignored` listing (which contains ONLY
/// ignored tests, so live = all − ignored). Fails closed on spawn error,
/// non-zero exit, non-UTF-8 stdout, or unparseable/empty output.
pub fn libtest_listing(include_ignored: bool) -> Result<BTreeSet<String>, String> {
    let exe = std::env::current_exe().map_err(|err| format!("current_exe failed: {err}"))?;
    let mut command = Command::new(&exe);
    command.args(["--list", "--format", "terse"]);
    if include_ignored {
        command.arg("--ignored");
    }
    // Never inherit the harness's stdin: the child must be inert.
    command.stdin(Stdio::null());
    let output = command
        .output()
        .map_err(|err| format!("spawn of {exe:?} failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "self `--list` exited with {:?}",
            output.status.code()
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| "self `--list` stdout was not UTF-8".to_string())?;
    parse_libtest_listing(&stdout)
}

/// Map a registry `rel_path` onto `(crate_name, module_prefix)` for the lib
/// test target it compiles into: `crates/<crate>/src/lib.rs` →
/// `(crate, "")`, `…/src/a/b.rs` and `…/src/a/b/mod.rs` → `(crate, "a::b")`.
/// `None` = the path does not name a module of a lib target (a bin
/// `main.rs`, an integration `tests/` file, or a foreign shape the gate
/// does not guess at) — such an entry then fails closed rather than being
/// silently weakened.
pub fn libtest_module_prefix(rel_path: &str) -> Option<(String, String)> {
    let after_crates = rel_path.strip_prefix("crates/")?;
    let (crate_name, tail) = after_crates.split_once('/')?;
    let tail = tail.strip_prefix("src/")?;
    if tail == "lib.rs" {
        return Some((crate_name.to_string(), String::new()));
    }
    if tail == "main.rs" {
        return None;
    }
    let mut stem = tail.strip_suffix(".rs")?;
    if let Some(parent_stem) = stem.strip_suffix("/mod") {
        stem = parent_stem;
    }
    if stem.is_empty() {
        return None;
    }
    let prefix = stem
        .split('/')
        .map(|segment| segment.strip_prefix("r#").unwrap_or(segment))
        .collect::<Vec<_>>()
        .join("::");
    Some((crate_name.to_string(), prefix))
}

/// True when `full_name` from the compiled listing is the witness under the
/// declared module. A root entry (`prefix == ""`) demands an EXACT match —
/// the strictest form, so a same-named fn in any other module of the binary
/// never satisfies it. A non-empty prefix additionally admits
/// plain-identifier intermediate modules between the declared module and
/// the witness (e.g. a `mod tests` wrapper: `p::tests::<witness>` or
/// `p::tests::sub::<witness>`) and nothing looser. Stated residual: the
/// listing carries no file identity, so a witness in a real submodule FILE
/// of the declared module (`p::decoy`) also matches.
pub fn listing_name_matches_module(full_name: &str, module_prefix: &str, witness: &str) -> bool {
    let rest = if module_prefix.is_empty() {
        full_name
    } else {
        match full_name.strip_prefix(&format!("{module_prefix}::")) {
            Some(rest) => rest,
            None => return false,
        }
    };
    if rest == witness {
        return true;
    }
    if module_prefix.is_empty() {
        return false;
    }
    let Some(between) = rest.strip_suffix(witness) else {
        return false;
    };
    let Some(between) = between.strip_suffix("::") else {
        return false;
    };
    !between.is_empty()
        && between.split("::").all(|segment| {
            let mut chars = segment.chars();
            !segment.is_empty()
                && chars
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

/// Per-entry compiled-ground-truth verdict: `None` = a live witness is
/// present, `Some(reason)` = why it is NOT (absent from the binary, or
/// present but `#[ignore]`d — distinguished so an ignored witness is
/// never mistaken for a deleted one).
pub fn compiled_ground_truth_failure(
    all_tests: &BTreeSet<String>,
    live_tests: &BTreeSet<String>,
    module_prefix: &str,
    witness: &str,
) -> Option<String> {
    let matched: Vec<&String> = all_tests
        .iter()
        .filter(|name| listing_name_matches_module(name, module_prefix, witness))
        .collect();
    if matched.is_empty() {
        return Some(format!(
            "compiled ground truth: no fn `{witness}` under module {module_prefix:?} in this \
             test binary's `--list` — the redacting-impl suppression has no compiled evidence"
        ));
    }
    let live: Vec<&String> = matched
        .iter()
        .copied()
        .filter(|name| live_tests.contains(*name))
        .collect();
    if live.is_empty() {
        return Some(format!(
            "compiled ground truth: fn `{witness}` under module {module_prefix:?} is present \
             but #[ignore]d (excluded via the `--ignored` listing): {matched:?} — an ignored \
             witness is not live evidence"
        ));
    }
    None
}

/// AQ-213: the per-crate compiled ground-truth gate. Compiled into every
/// crate that owns reviewed-redacting-impl registry entries (via
/// `#[path]`), so it runs in each crate's OWN test binary and judges the
/// rows [`WITNESS_SLICES`] assigns to this host against the host's own
/// `--list` output. Fails closed on: unparseable/empty listings, a
/// missing parse-sanity sentinel, the probe leaking into the live set,
/// a slice table with no rows for the host, a row whose rel_path does
/// not map onto the host crate, a row whose declared prefix escapes its
/// rel_path, and — of course — any witness that is absent from the
/// compiled listing or `#[ignore]`d.
#[test]
fn every_reviewed_redacting_impl_entry_of_this_crate_has_a_live_witness_test() {
    let host = env!("CARGO_PKG_NAME");
    let slice = slice_for_crate(host)
        .unwrap_or_else(|| panic!("witness slice table has no rows for host crate {host:?}"));
    assert!(
        !slice.is_empty(),
        "witness slice table row set for {host:?} is empty"
    );
    let all_tests = libtest_listing(false)
        .unwrap_or_else(|err| panic!("compiled ground truth unavailable, failing closed: {err}"));
    let ignored_tests = libtest_listing(true)
        .unwrap_or_else(|err| panic!("compiled ground truth unavailable, failing closed: {err}"));
    let live_tests: BTreeSet<String> = all_tests.difference(&ignored_tests).cloned().collect();
    assert!(
        live_tests.contains(PER_CRATE_GATE_TEST),
        "parse sanity: this gate's own test {PER_CRATE_GATE_TEST:?} must appear in the \
         compiled listing before slice entries are judged against it"
    );
    assert!(
        !live_tests.contains(PER_CRATE_IGNORED_PROBE),
        "parse sanity: the #[ignore]d ground-truth probe must never be in the live set"
    );
    let mut failures: Vec<String> = Vec::new();
    for &(rel_path, declared_prefix, witness) in slice {
        match libtest_module_prefix(rel_path) {
            Some((crate_name, derived_prefix)) if crate_name == host => {
                if !module_prefix_is_under_rel_path(&derived_prefix, declared_prefix) {
                    failures.push(format!(
                        "{witness}: declared module prefix {declared_prefix:?} is not the \
                         rel_path-derived prefix {derived_prefix:?} or a descendant of it"
                    ));
                    continue;
                }
                if let Some(reason) =
                    compiled_ground_truth_failure(&all_tests, &live_tests, declared_prefix, witness)
                {
                    failures.push(format!("{witness}: {reason}"));
                }
            }
            other => failures.push(format!(
                "{witness}: slice row rel_path {rel_path:?} maps to {other:?}, not the host \
                 crate {host:?} — the row does not belong in this crate's slice"
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "reviewed redacting-impl entries owned by {host:?} without a live compiled witness:\n  {}",
        failures.join("\n  ")
    );
}

#[test]
fn ground_truth_listing_parser_accepts_terse_test_lines() {
    let parsed = parse_libtest_listing("a: test\nb::c: test\nspaced: test  \n")
        .expect("well-formed terse listing must parse");
    assert_eq!(
        parsed,
        BTreeSet::from(["a".to_string(), "b::c".to_string(), "spaced".to_string(),])
    );
}

#[test]
fn ground_truth_listing_parser_fails_closed_on_bad_output() {
    assert!(
        parse_libtest_listing("").is_err(),
        "empty listing must fail closed"
    );
    assert!(
        parse_libtest_listing("garbage without colon\n").is_err(),
        "unparseable line must fail closed"
    );
    assert!(
        parse_libtest_listing("a: benchmark\n").is_err(),
        "non-test kind must fail closed"
    );
    assert!(
        parse_libtest_listing("a b: test\n").is_err(),
        "name with whitespace must fail closed"
    );
    assert!(
        parse_libtest_listing("a: test\na: test\n").is_err(),
        "duplicate names must fail closed"
    );
}

#[test]
fn ground_truth_module_prefix_derivation_table() {
    assert_eq!(
        libtest_module_prefix("crates/rustynetd/src/lib.rs"),
        Some(("rustynetd".to_string(), String::new()))
    );
    assert_eq!(
        libtest_module_prefix("crates/rustynetd/src/enrollment_token.rs"),
        Some(("rustynetd".to_string(), "enrollment_token".to_string()))
    );
    assert_eq!(
        libtest_module_prefix("crates/rustynetd/src/a/b.rs"),
        Some(("rustynetd".to_string(), "a::b".to_string()))
    );
    assert_eq!(
        libtest_module_prefix("crates/rustynetd/src/a/b/mod.rs"),
        Some(("rustynetd".to_string(), "a::b".to_string()))
    );
    // Sibling crates map fine, but never claim the rustynetd binary.
    assert_eq!(
        libtest_module_prefix("crates/rustynet-crypto/src/lib.rs"),
        Some(("rustynet-crypto".to_string(), String::new()))
    );
    // Unmappable shapes fail closed.
    assert_eq!(libtest_module_prefix("crates/rustynetd/src/main.rs"), None);
    assert_eq!(libtest_module_prefix("crates/rustynetd/tests/it.rs"), None);
    assert_eq!(libtest_module_prefix("src/lib.rs"), None);
    assert_eq!(libtest_module_prefix("benches/x.rs"), None);
}

#[test]
fn ground_truth_declared_prefix_ancestor_rule_table() {
    // A lib.rs row derives the empty prefix; any non-empty declared
    // prefix (the root `tests` module shape) is consistent.
    assert!(module_prefix_is_under_rel_path("", "tests"));
    assert!(!module_prefix_is_under_rel_path("", ""));
    // The declared prefix may be the derived prefix itself…
    assert!(module_prefix_is_under_rel_path(
        "enrollment_token",
        "enrollment_token"
    ));
    // …or a strict descendant (the `mod tests` wrapper shape)…
    assert!(module_prefix_is_under_rel_path(
        "enrollment_token",
        "enrollment_token::tests"
    ));
    assert!(module_prefix_is_under_rel_path(
        "windows_command",
        "windows_command::tests"
    ));
    // …but never an unrelated module, a sibling by suffix, or a parent.
    assert!(!module_prefix_is_under_rel_path(
        "enrollment_token",
        "tests"
    ));
    assert!(!module_prefix_is_under_rel_path(
        "enrollment_token",
        "enrollment_token_extended::tests"
    ));
    assert!(!module_prefix_is_under_rel_path("enrollment_token", ""));
}

#[test]
fn ground_truth_match_rule_table() {
    // Root entries are exact-match only: a bare name satisfies the root
    // rule…
    assert!(listing_name_matches_module(
        "every_reviewed_redacting_impl_entry_of_this_crate_has_a_live_witness_test",
        "",
        "every_reviewed_redacting_impl_entry_of_this_crate_has_a_live_witness_test",
    ));
    // …while a different module and a same-named fn elsewhere must not.
    assert!(!listing_name_matches_module(
        PER_CRATE_GATE_TEST,
        "",
        "every_reviewed_redacting_impl_entry_of_this_crate_has_a_live_witness_test",
    ));
    assert!(!listing_name_matches_module(
        "tests::some_witness",
        "",
        "some_witness",
    ));
    // Non-root entries admit a plain-ident `mod tests` wrapper…
    assert!(listing_name_matches_module(
        "tests::secret_key_debug_redacts",
        "tests",
        "secret_key_debug_redacts",
    ));
    assert!(listing_name_matches_module(
        "enrollment_token::tests::some_witness",
        "enrollment_token",
        "some_witness",
    ));
    assert!(listing_name_matches_module(
        "enrollment_token::tests::sub::some_witness",
        "enrollment_token",
        "some_witness",
    ));
    assert!(listing_name_matches_module(
        "enrollment_token::some_witness",
        "enrollment_token",
        "some_witness",
    ));
    // …but not other modules of the crate, and never a non-boundary
    // prefix hit.
    assert!(!listing_name_matches_module(
        "secret_log_audit::tests::some_witness",
        "enrollment_token",
        "some_witness",
    ));
    assert!(!listing_name_matches_module(
        "enrollment_token_extended::tests::some_witness",
        "enrollment_token",
        "some_witness",
    ));
}

#[test]
fn ground_truth_per_entry_verdict_table() {
    let witness = "enrollment_token_debug_output_redacts_tag_and_token_id";
    let compiled = BTreeSet::from([format!("enrollment_token::tests::{witness}")]);
    assert_eq!(
        compiled_ground_truth_failure(&compiled, &compiled, "enrollment_token::tests", witness),
        None,
        "a live compiled witness passes"
    );

    // The r86 F1′ fail-open shape: an inert macro-body "witness" exists
    // only in source text, never in the compiled listing → absent, fail.
    let empty = BTreeSet::new();
    let absent = compiled_ground_truth_failure(&empty, &empty, "enrollment_token::tests", witness)
        .expect("absent witness must fail");
    assert!(absent.contains("no fn"), "absent reason: {absent}");

    // An #[ignore]d witness IS in the all-listing but NOT in the live set;
    // the failure must say so, not claim the witness is missing.
    let ignored_failure =
        compiled_ground_truth_failure(&compiled, &empty, "enrollment_token::tests", witness)
            .expect("ignored witness must fail");
    assert!(
        ignored_failure.contains("#[ignore]"),
        "ignored reason must mention ignore: {ignored_failure}"
    );

    // A same-named fn in the WRONG module does not satisfy the declared
    // prefix — even though the name exists somewhere in the binary.
    let wrong_module = BTreeSet::from(["secret_log_audit::some_witness".to_string()]);
    let wrong_module_failure =
        compiled_ground_truth_failure(&wrong_module, &wrong_module, "tests", "some_witness")
            .expect("wrong-module witness must fail");
    assert!(
        wrong_module_failure.contains("no fn"),
        "wrong-module reason: {wrong_module_failure}"
    );
}

#[test]
fn witness_slice_table_rows_are_non_empty_and_well_addressed() {
    assert!(
        WITNESS_SLICES
            .iter()
            .all(|(crate_name, slice)| !crate_name.is_empty() && !slice.is_empty()),
        "the slice table must not contain empty crates or empty slices"
    );
    for &(crate_name, slice) in WITNESS_SLICES {
        assert!(
            !slice.is_empty(),
            "slice for {crate_name:?} is empty; a listed crate must own at least one row"
        );
        for &(rel_path, declared_prefix, witness) in slice {
            let Some((mapped_crate, derived_prefix)) = libtest_module_prefix(rel_path) else {
                panic!("slice row for {crate_name:?} has an unmappable rel_path {rel_path:?}");
            };
            assert_eq!(
                mapped_crate, crate_name,
                "slice row {rel_path:?} does not map onto its owning crate {crate_name:?}"
            );
            assert!(
                module_prefix_is_under_rel_path(&derived_prefix, declared_prefix),
                "slice row ({rel_path:?}, {declared_prefix:?}) declares a prefix that escapes \
                 the rel_path-derived prefix {derived_prefix:?}"
            );
            assert!(
                !witness.is_empty(),
                "slice row for {crate_name:?} has an empty witness name"
            );
        }
    }
}

#[test]
fn witness_slice_table_rows_are_unique() {
    let mut seen: Vec<(&str, &str, &str)> = Vec::new();
    for &(crate_name, slice) in WITNESS_SLICES {
        for &(rel_path, declared_prefix, witness) in slice {
            let _ = declared_prefix;
            let key = (crate_name, rel_path, witness);
            assert!(!seen.contains(&key), "duplicate slice row {key:?}");
            seen.push(key);
        }
    }
}

#[test]
fn witness_slice_table_declares_rustynetd_and_its_five_siblings() {
    let crates: Vec<&str> = WITNESS_SLICES.iter().map(|(c, _)| *c).collect();
    for expected in [
        "rustynetd",
        "rustynet-crypto",
        "rustynet-control",
        "rustynet-relay",
        "rustynet-backend-wireguard",
        "rustynet-llm-gateway",
    ] {
        assert!(
            crates.contains(&expected),
            "slice table must cover {expected:?}"
        );
    }
}
