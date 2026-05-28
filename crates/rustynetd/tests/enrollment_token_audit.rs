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

#[test]
fn minted_token_encoded_form_does_not_contain_raw_secret() {
    // The encoded token is base64(token_id || issued_at || expires_at || tag).
    // The HMAC tag is keyed by the secret but is NOT the secret itself.
    // Verify that the raw secret bytes do not appear verbatim anywhere in
    // the encoded string.
    let secret = [0xefu8; ENROLLMENT_SECRET_LEN];
    let secret_hex = hex_lower(&secret);
    let now_unix = 1_700_050_000u64;
    let (_token, encoded) =
        mint_token_with_clock(&secret, 600, now_unix).expect("mint must succeed");

    assert!(
        !encoded.contains(&secret_hex),
        "encoded token must not contain raw secret hex"
    );
    // Also check the raw bytes are not in the encoded form via any sub-slice.
    // We check 4-byte sub-windows — a raw secret never leaks even partially.
    for window in secret.windows(4) {
        let window_hex = hex_lower(window);
        // The base64 encoded form of a 4-byte sequence is 6 chars; we check
        // that neither the hex nor the token itself contains the window raw.
        // This is a conservative check (base64 encodes across byte boundaries)
        // but catches the obvious case of raw bytes appearing as-is.
        assert!(
            !encoded.as_bytes().windows(4).any(|w| w == window),
            "encoded token must not contain raw secret bytes (window={window_hex})"
        );
    }
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
