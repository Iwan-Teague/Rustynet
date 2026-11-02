// AQ-08 step 3 finish: test-only code is exempt from the crate-wide
// panic-family deny table (crates/rustynetd/Cargo.toml [lints.clippy]),
// the steps 1-2 pattern.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

//! Enrollment token audit trail and secret non-leakage tests.
//!
//! These tests pin three properties of the token pipeline:
//!
//! 1. A minted token's encoded form does not contain the raw enrollment
//!    secret or the raw signing key bytes — only HMAC-derived material.
//! 2. The Debug representation of `EnrollmentToken` redacts sensitive fields,
//!    so a stray log statement cannot leak the tag or token_id.
//! 3. `ConsumedTokenLedger` entries survive a spool round-trip (persist and
//!    reload) so the anti-replay defence works across daemon restarts.

#![forbid(unsafe_code)]

use rustynetd::enrollment_token::{
    ConsumedTokenLedger, ENROLLMENT_SECRET_LEN, EnrollmentTokenError, load_ledger,
    mint_token_with_clock, verify_and_consume_token_with_now, write_ledger,
};

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Length of the secret sub-windows searched for in the decoded token. Eight
/// bytes is long enough that a chance match against 64 bytes of HMAC output is
/// negligible (about 2^-40 per offset) and short enough that a partial leak is
/// still caught.
const LEAK_WINDOW_LEN: usize = 8;

/// Every encoding in which `secret` could plausibly be spelled out inside an
/// operator-visible token string: lowercase and uppercase hex, and the four
/// base64 spellings (standard and URL-safe, padded and unpadded).
fn secret_textual_encodings(secret: &[u8]) -> Vec<(&'static str, String)> {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    vec![
        ("hex lowercase", hex_lower(secret)),
        ("hex uppercase", hex_lower(secret).to_uppercase()),
        ("base64 standard", STANDARD.encode(secret)),
        ("base64 standard no pad", STANDARD_NO_PAD.encode(secret)),
        ("base64 url-safe", URL_SAFE.encode(secret)),
        ("base64 url-safe no pad", URL_SAFE_NO_PAD.encode(secret)),
    ]
}

/// Report how (if at all) `secret` leaks through the encoded token string.
///
/// Two independent checks, because the token is base64 of a binary struct and
/// either representation can betray the secret:
/// 1. the encoded text must not contain the secret in any textual encoding;
/// 2. the DECODED bytes must not contain the secret, or any
///    [`LEAK_WINDOW_LEN`]-byte window of it, verbatim. This is the check the
///    previous version of this test could not make: it looked for raw secret
///    bytes (including 0xef, which is not ASCII) inside a base64 ASCII string,
///    so it passed for any token whatsoever.
fn token_leak_report(encoded: &str, secret: &[u8]) -> Option<String> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    if let Some(report) = token_leak_report_for_text_only(encoded, secret) {
        return Some(report);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .expect("a minted token must be valid url-safe base64");
    for (offset, window) in secret.windows(LEAK_WINDOW_LEN).enumerate() {
        if decoded.windows(LEAK_WINDOW_LEN).any(|w| w == window) {
            return Some(format!(
                "decoded token contains raw secret bytes (window at secret offset {offset})"
            ));
        }
    }
    None
}

fn distinctive_secret() -> [u8; ENROLLMENT_SECRET_LEN] {
    // Non-repeating bytes: a constant-fill secret would make every window
    // identical and a single accidental match indistinguishable from a leak.
    let mut secret = [0u8; ENROLLMENT_SECRET_LEN];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(37).wrapping_add(0xa5);
    }
    secret
}

#[test]
fn minted_token_encoded_form_does_not_contain_raw_secret() {
    // The encoded token is base64url(token_id || issued_at || expires_at ||
    // tag). The HMAC tag is keyed by the secret but is NOT the secret itself.
    let secret = distinctive_secret();
    let (_token, encoded) =
        mint_token_with_clock(&secret, 600, 1_700_050_000).expect("mint must succeed");

    assert_eq!(
        token_leak_report(&encoded, &secret),
        None,
        "a minted token must not leak the enrollment secret"
    );
}

#[test]
fn token_leak_detector_flags_every_way_the_secret_can_appear() {
    // Positive control for the test above. A leak check that cannot fail is
    // worth nothing, so prove the detector fires on each representation it
    // claims to cover.
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let secret = distinctive_secret();
    let (_token, clean) =
        mint_token_with_clock(&secret, 600, 1_700_050_500).expect("mint must succeed");
    assert_eq!(token_leak_report(&clean, &secret), None, "clean token");

    // Textual leaks: the secret spelled out inside the encoded string.
    for (label, spelling) in secret_textual_encodings(&secret) {
        let leaky = format!("{clean}{spelling}");
        let report = token_leak_report_for_text_only(&leaky, &secret);
        assert!(
            report.is_some(),
            "detector must flag a token carrying the secret as {label}"
        );
    }

    // Binary leaks: the raw secret, and a partial window of it, placed in the
    // decoded bytes of an otherwise well-formed token.
    let mut decoded = URL_SAFE_NO_PAD
        .decode(clean.as_bytes())
        .expect("clean token decodes");
    let full_leak = {
        let mut bytes = decoded.clone();
        bytes.extend_from_slice(&secret);
        URL_SAFE_NO_PAD.encode(&bytes)
    };
    assert!(
        token_leak_report(&full_leak, &secret)
            .expect("full raw secret must be flagged")
            .contains("decoded token"),
    );
    decoded.extend_from_slice(&secret[10..10 + LEAK_WINDOW_LEN]);
    let partial_leak = URL_SAFE_NO_PAD.encode(&decoded);
    assert!(
        token_leak_report(&partial_leak, &secret)
            .expect("a partial raw window must be flagged")
            .contains("window at secret offset"),
    );
}

/// Textual half of [`token_leak_report`] only, for inputs that are not valid
/// base64 once a hex or padded spelling has been appended to them.
fn token_leak_report_for_text_only(encoded: &str, secret: &[u8]) -> Option<String> {
    secret_textual_encodings(secret)
        .into_iter()
        .find(|(_, needle)| encoded.contains(needle))
        .map(|(label, _)| format!("encoded token contains the secret as {label}"))
}

#[test]
fn enrollment_token_debug_redacts_sensitive_fields() {
    // A stray `log::debug!("{:?}", token)` must not reveal the tag or
    // token_id. The custom Debug impl should redact both.
    let secret = [0x55u8; ENROLLMENT_SECRET_LEN];
    let (token, _encoded) =
        mint_token_with_clock(&secret, 600, 1_700_051_000).expect("mint must succeed");
    let debug_repr = format!("{token:?}");

    assert!(
        debug_repr.contains("<redacted>"),
        "Debug output must redact sensitive fields, got: {debug_repr}"
    );
    // Ensure actual tag/token_id bytes do not appear.
    let tag_hex = hex_lower(&token.tag);
    let token_id_hex = hex_lower(&token.token_id);
    assert!(
        !debug_repr.contains(&tag_hex),
        "Debug output must not contain raw tag hex"
    );
    assert!(
        !debug_repr.contains(&token_id_hex),
        "Debug output must not contain raw token_id hex"
    );
}

#[test]
fn consumed_token_ledger_survives_spool_round_trip() {
    // After a daemon restart, the consumed-token ledger must reject tokens
    // that were already consumed before the restart. This pins that the
    // spool save/load path works correctly.
    let dir = tempfile::tempdir().expect("tempdir");
    let ledger_path = dir.path().join("consumed.bin");

    let secret = [0x77u8; ENROLLMENT_SECRET_LEN];
    let now_unix = 1_700_052_000u64;
    let mut ledger = ConsumedTokenLedger::new();

    let (_token, encoded) = mint_token_with_clock(&secret, 600, now_unix).expect("mint");
    let consumed = verify_and_consume_token_with_now(&encoded, &secret, &mut ledger, now_unix)
        .expect("consume");
    assert!(ledger.was_consumed(&consumed.token_id));

    // Persist.
    write_ledger(&ledger_path, &ledger).expect("write ledger");

    // Reload — simulates daemon restart.
    let restored = load_ledger(&ledger_path).expect("load ledger");
    assert!(
        restored.was_consumed(&consumed.token_id),
        "restored ledger must recognise the previously-consumed token"
    );

    // Attempt to re-consume the same token using the restored ledger.
    let err = verify_and_consume_token_with_now(&encoded, &secret, &mut { restored }, now_unix + 1)
        .expect_err("re-consume must fail after ledger restore");
    assert!(
        matches!(err, EnrollmentTokenError::AlreadyConsumed),
        "expected AlreadyConsumed, got {err:?}"
    );
}
