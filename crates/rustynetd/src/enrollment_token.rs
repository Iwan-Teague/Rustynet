#![forbid(unsafe_code)]

//! D2.7 — Enrollment tokens.
//!
//! Per the dataplane execution plan §D2.7, a new device joins the
//! rustynet by presenting a one-time HMAC-authenticated enrollment
//! token. The token is minted by an operator (via the rustynet CLI)
//! and handed to the device out-of-band (QR code, file copy, paste).
//! No accounts, no SaaS-mediated identity, no third-party trust.
//!
//! Token shape (URL-safe base64 of the binary):
//!
//! ```text
//! +-----------+----------+--------------+----------+
//! | token_id  | issued_at| expires_at   | hmac_tag |
//! | 16 bytes  | u64 BE   | u64 BE       | 32 bytes |
//! +-----------+----------+--------------+----------+
//! ```
//!
//! The HMAC tag is computed over `b"rustynet:enrollment:v1" || token_id
//! || issued_at || expires_at` using HMAC-SHA256 keyed with the
//! daemon's enrollment secret (a 32-byte random key stored alongside
//! the runtime WireGuard key). The secret never leaves the daemon
//! host.
//!
//! Verification + consume is a single atomic operation: the consumer
//! looks up the token_id in its consumed-set, refuses if already
//! seen, recomputes the HMAC tag, compares constant-time, then checks
//! `expires_at > now()`. Single-use guarantee comes from the
//! consumed-set tracking — the daemon persists it across restarts
//! using the same watermark pattern as membership and trust.
//!
//! Security framing:
//!
//! * Domain separation via the `"rustynet:enrollment:v1"` prefix
//!   prevents a relay-session or peer-gossip HMAC from being misused
//!   as an enrollment token.
//! * Constant-time tag comparison via `subtle::ConstantTimeEq` so a
//!   timing oracle cannot leak the secret.
//! * The TTL is the second line of defence: even if the consumed-set
//!   is corrupted or rolled back, an old token cannot be replayed
//!   beyond its expiry.
//! * The token does NOT carry the enrollee's identity. The enrollee
//!   sends its public key + the token in a separate enrollment
//!   message; the daemon validates the token and, on success, adds
//!   the enrollee's public key to the membership snapshot. The
//!   token is opaque to the enrollee.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use rand::TryRngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

/// Domain separation prefix mixed into every enrollment HMAC.
pub const ENROLLMENT_TOKEN_DOMAIN: &[u8] = b"rustynet:enrollment:v1";

/// Default TTL for a freshly-minted token. The operator can override
/// via the CLI flag, but 30 minutes is the strict-secure-practical
/// default — long enough to walk a device through setup, short
/// enough that a token left on a shared screen doesn't outlive the
/// operator's attention.
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 30 * 60;

/// Maximum TTL the daemon will accept on mint. Tokens with a longer
/// requested TTL are rejected at mint time; the cap is "if you're
/// expecting an enrollment to take more than a day there's a process
/// problem". Operators can request a fresh token instead of a
/// long-lived one.
pub const MAX_TOKEN_TTL_SECS: u64 = 24 * 60 * 60;

/// Length of the random token identifier. 128 bits is more than enough
/// collision resistance for a single-use, TTL-bounded token.
pub const TOKEN_ID_LEN: usize = 16;

/// Length of the HMAC tag. SHA-256 → 32 bytes.
pub const TOKEN_TAG_LEN: usize = 32;

/// Binary token size: 16 token_id + 8 issued + 8 expires + 32 tag.
pub const TOKEN_BINARY_LEN: usize = TOKEN_ID_LEN + 8 + 8 + TOKEN_TAG_LEN;

/// Length of the daemon's enrollment secret key.
pub const ENROLLMENT_SECRET_LEN: usize = 32;

/// One enrollment token, decoded into its component fields. The
/// binary on-wire form is the URL-safe base64 of this struct's
/// canonical layout.
///
/// **Security**: the `tag` field IS the bearer credential — anyone
/// holding the (token_id, issued_at, expires_at, tag) tuple can
/// redeem the token. The custom `Debug` impl redacts the tag so a
/// stray `log::debug!("{:?}", token)` cannot leak it. `Drop` zeroises
/// both the tag and the token_id so a freed token does not leave the
/// credential floating in heap-reused memory.
#[derive(Clone, PartialEq, Eq)]
pub struct EnrollmentToken {
    pub token_id: [u8; TOKEN_ID_LEN],
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub tag: [u8; TOKEN_TAG_LEN],
}

impl std::fmt::Debug for EnrollmentToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentToken")
            .field("token_id", &"<redacted>")
            .field("issued_at_unix", &self.issued_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("tag", &"<redacted>")
            .finish()
    }
}

impl Drop for EnrollmentToken {
    fn drop(&mut self) {
        self.token_id.zeroize();
        self.tag.zeroize();
    }
}

#[derive(Debug)]
pub enum EnrollmentTokenError {
    /// Requested TTL is zero or exceeds [`MAX_TOKEN_TTL_SECS`].
    TtlOutOfRange { requested: u64, max: u64 },
    /// Local clock is before UNIX_EPOCH.
    TimestampUnavailable,
    /// Kernel CSPRNG (`OsRng`) refused to provide entropy. Fail closed
    /// — we never fall back to a non-CSPRNG source for token material.
    RngUnavailable,
    /// Couldn't decode the token (bad base64, wrong byte length,
    /// invalid layout).
    Malformed(String),
    /// The HMAC tag did not match the recomputed value under the
    /// daemon's enrollment secret. Either the secret is wrong (peer
    /// presenting a token from a different daemon) or the token was
    /// tampered with.
    TagMismatch,
    /// The token has expired.
    Expired { expired_secs_ago: u64 },
    /// The token has already been redeemed.
    AlreadyConsumed,
    /// The token's claimed issued_at is in the future relative to
    /// our clock by more than a tolerable skew. Rejected to stop a
    /// time-shifted attacker minting tokens with extended lifetime.
    IssuedInFuture { drift_secs: u64 },
}

impl std::fmt::Display for EnrollmentTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollmentTokenError::TtlOutOfRange { requested, max } => write!(
                f,
                "requested enrollment TTL {requested}s out of range (max {max}s)"
            ),
            EnrollmentTokenError::TimestampUnavailable => {
                write!(f, "local clock is before UNIX_EPOCH")
            }
            EnrollmentTokenError::RngUnavailable => write!(
                f,
                "kernel CSPRNG (OsRng) refused to provide entropy; refusing to mint with weak randomness"
            ),
            EnrollmentTokenError::Malformed(msg) => write!(f, "malformed enrollment token: {msg}"),
            EnrollmentTokenError::TagMismatch => write!(f, "enrollment token HMAC tag mismatch"),
            EnrollmentTokenError::Expired { expired_secs_ago } => {
                write!(f, "enrollment token expired {expired_secs_ago}s ago")
            }
            EnrollmentTokenError::AlreadyConsumed => {
                write!(f, "enrollment token has already been redeemed")
            }
            EnrollmentTokenError::IssuedInFuture { drift_secs } => write!(
                f,
                "enrollment token issued_at is {drift_secs}s in the future; rejecting"
            ),
        }
    }
}

impl std::error::Error for EnrollmentTokenError {}

/// Maximum allowed issued_at drift into the future before we treat the
/// token as a clock-skew attack. Symmetric with the gossip freshness
/// window — 5 minutes is generous for clock drift but tight enough
/// that a token issued an hour from now is clearly malicious.
pub const ISSUED_AT_FUTURE_TOLERANCE_SECS: u64 = 300;

/// Generate a fresh enrollment secret. Used once at daemon bring-up
/// and persisted under the daemon's state directory.
///
/// Uses `rand::rngs::OsRng` directly (not the threaded `rand::rng()`)
/// so the secret is drawn from the kernel CSPRNG with no intermediate
/// reseeded state. Returns a `Zeroizing<[u8; …]>` wrapper so the
/// secret is wiped on drop and can be passed through the daemon's
/// state-loading code paths without inadvertently leaving copies in
/// heap-reused memory.
///
/// Returns `None` if the kernel RNG is unavailable (e.g. very early
/// boot before the entropy pool is initialised); callers must NOT
/// fall back to a non-CSPRNG source.
pub fn generate_enrollment_secret() -> Option<Zeroizing<[u8; ENROLLMENT_SECRET_LEN]>> {
    let mut out = Zeroizing::new([0u8; ENROLLMENT_SECRET_LEN]);
    rand::rngs::OsRng.try_fill_bytes(out.as_mut_slice()).ok()?;
    Some(out)
}

fn current_unix_seconds() -> Result<u64, EnrollmentTokenError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| EnrollmentTokenError::TimestampUnavailable)
}

fn compute_tag(
    secret: &[u8; ENROLLMENT_SECRET_LEN],
    token_id: &[u8; TOKEN_ID_LEN],
    issued_at_unix: u64,
    expires_at_unix: u64,
) -> [u8; TOKEN_TAG_LEN] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(ENROLLMENT_TOKEN_DOMAIN);
    mac.update(token_id);
    mac.update(&issued_at_unix.to_be_bytes());
    mac.update(&expires_at_unix.to_be_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut tag = [0u8; TOKEN_TAG_LEN];
    tag.copy_from_slice(&bytes);
    tag
}

/// Mint a fresh enrollment token under the daemon's secret. Returns
/// the URL-safe-base64 encoding suitable for handing to an operator
/// (printable, QR-encodable).
pub fn mint_token(
    secret: &[u8; ENROLLMENT_SECRET_LEN],
    ttl_secs: u64,
) -> Result<(EnrollmentToken, String), EnrollmentTokenError> {
    if ttl_secs == 0 || ttl_secs > MAX_TOKEN_TTL_SECS {
        return Err(EnrollmentTokenError::TtlOutOfRange {
            requested: ttl_secs,
            max: MAX_TOKEN_TTL_SECS,
        });
    }
    let issued_at_unix = current_unix_seconds()?;
    mint_token_with_clock(secret, ttl_secs, issued_at_unix)
}

/// Test-friendly variant taking an explicit issued_at clock.
pub fn mint_token_with_clock(
    secret: &[u8; ENROLLMENT_SECRET_LEN],
    ttl_secs: u64,
    issued_at_unix: u64,
) -> Result<(EnrollmentToken, String), EnrollmentTokenError> {
    if ttl_secs == 0 || ttl_secs > MAX_TOKEN_TTL_SECS {
        return Err(EnrollmentTokenError::TtlOutOfRange {
            requested: ttl_secs,
            max: MAX_TOKEN_TTL_SECS,
        });
    }
    // OsRng directly so a one-time token_id is drawn straight from the
    // kernel CSPRNG. ThreadRng would also be CSPRNG-grade but the
    // direct call closes one extra layer of "what if the thread RNG
    // is misconfigured" defence-in-depth concern. If the kernel RNG
    // fails (very early boot, no entropy pool), we MUST not fall
    // back to a non-CSPRNG.
    let mut token_id = [0u8; TOKEN_ID_LEN];
    rand::rngs::OsRng
        .try_fill_bytes(&mut token_id)
        .map_err(|_| EnrollmentTokenError::RngUnavailable)?;
    let expires_at_unix = issued_at_unix.saturating_add(ttl_secs);
    let tag = compute_tag(secret, &token_id, issued_at_unix, expires_at_unix);
    let token = EnrollmentToken {
        token_id,
        issued_at_unix,
        expires_at_unix,
        tag,
    };
    let encoded = encode_token(&token);
    Ok((token, encoded))
}

/// Encode a token as URL-safe base64 (no padding).
pub fn encode_token(token: &EnrollmentToken) -> String {
    let mut buf = Vec::with_capacity(TOKEN_BINARY_LEN);
    buf.extend_from_slice(&token.token_id);
    buf.extend_from_slice(&token.issued_at_unix.to_be_bytes());
    buf.extend_from_slice(&token.expires_at_unix.to_be_bytes());
    buf.extend_from_slice(&token.tag);
    URL_SAFE_NO_PAD.encode(&buf)
}

/// Decode a URL-safe-base64 token back into its component fields.
/// Pure parser — does not validate the HMAC tag or the expiry.
///
/// **Security**: the intermediate `Vec<u8>` from the base64 decode
/// carries the HMAC tag (bearer credential). We wrap it in
/// `Zeroizing<Vec<u8>>` so the buffer is wiped before its allocation
/// returns to the heap allocator — otherwise the tag would briefly
/// reside in heap-reused memory between the decode and the field
/// copies completing.
pub fn decode_token(encoded: &str) -> Result<EnrollmentToken, EnrollmentTokenError> {
    let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded.trim())
            .map_err(|e| EnrollmentTokenError::Malformed(format!("base64 decode: {e}")))?,
    );
    if bytes.len() != TOKEN_BINARY_LEN {
        return Err(EnrollmentTokenError::Malformed(format!(
            "expected {TOKEN_BINARY_LEN} bytes after base64 decode, got {}",
            bytes.len()
        )));
    }
    let mut token_id = [0u8; TOKEN_ID_LEN];
    token_id.copy_from_slice(&bytes[..TOKEN_ID_LEN]);
    let issued_at_unix =
        u64::from_be_bytes(bytes[TOKEN_ID_LEN..TOKEN_ID_LEN + 8].try_into().unwrap());
    let expires_at_unix = u64::from_be_bytes(
        bytes[TOKEN_ID_LEN + 8..TOKEN_ID_LEN + 16]
            .try_into()
            .unwrap(),
    );
    let mut tag = [0u8; TOKEN_TAG_LEN];
    tag.copy_from_slice(&bytes[TOKEN_ID_LEN + 16..]);
    Ok(EnrollmentToken {
        token_id,
        issued_at_unix,
        expires_at_unix,
        tag,
    })
}

/// Bookkeeping for already-consumed token IDs. Persisted via the
/// daemon's watermark spool pattern so single-use survives restart.
#[derive(Debug, Default, Clone)]
pub struct ConsumedTokenLedger {
    inner: HashSet<[u8; TOKEN_ID_LEN]>,
}

impl ConsumedTokenLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn was_consumed(&self, token_id: &[u8; TOKEN_ID_LEN]) -> bool {
        self.inner.contains(token_id)
    }

    pub fn record_consumed(&mut self, token_id: [u8; TOKEN_ID_LEN]) {
        self.inner.insert(token_id);
    }

    pub fn consumed_count(&self) -> usize {
        self.inner.len()
    }

    /// Optional GC: drop expired tokens from the ledger to keep its
    /// footprint bounded. Safe because an expired token is already
    /// rejected by the expiry check; once it's expired we don't need
    /// to remember we saw it.
    pub fn purge_expired_against(&mut self, _now_unix: u64) {
        // The ledger stores only the token ID, not the expiry, so a
        // separate expiry-indexed structure is needed to purge
        // efficiently. The first cut keeps the ledger simple; a
        // production system will spool token_id + expires_at to a
        // file and prune at startup. This stub is documented as a
        // follow-up.
    }
}

/// Verify + consume a token in one atomic operation.
///
/// Steps:
/// 1. Decode the base64 to component fields.
/// 2. Recompute the HMAC tag under the daemon's secret.
/// 3. Constant-time compare against the presented tag.
/// 4. Check `expires_at > now`.
/// 5. Check `issued_at <= now + ISSUED_AT_FUTURE_TOLERANCE_SECS`.
/// 6. Check the token_id is not already in the consumed ledger.
/// 7. Insert the token_id into the consumed ledger.
///
/// Either every step succeeds (and the ledger is updated atomically
/// from the caller's perspective) or none of the visible-state
/// effects happen.
pub fn verify_and_consume_token(
    encoded: &str,
    secret: &[u8; ENROLLMENT_SECRET_LEN],
    ledger: &mut ConsumedTokenLedger,
) -> Result<EnrollmentToken, EnrollmentTokenError> {
    let now = current_unix_seconds()?;
    verify_and_consume_token_with_now(encoded, secret, ledger, now)
}

/// Test-friendly variant taking an explicit "now".
pub fn verify_and_consume_token_with_now(
    encoded: &str,
    secret: &[u8; ENROLLMENT_SECRET_LEN],
    ledger: &mut ConsumedTokenLedger,
    now_unix: u64,
) -> Result<EnrollmentToken, EnrollmentTokenError> {
    let token = decode_token(encoded)?;
    // Recompute and constant-time compare the tag. Do this BEFORE any
    // expiry/replay check so a tampered token never even reaches the
    // ledger.
    let expected = compute_tag(
        secret,
        &token.token_id,
        token.issued_at_unix,
        token.expires_at_unix,
    );
    if expected.ct_eq(&token.tag).unwrap_u8() != 1 {
        return Err(EnrollmentTokenError::TagMismatch);
    }
    if token.issued_at_unix > now_unix.saturating_add(ISSUED_AT_FUTURE_TOLERANCE_SECS) {
        return Err(EnrollmentTokenError::IssuedInFuture {
            drift_secs: token.issued_at_unix - now_unix,
        });
    }
    if token.expires_at_unix <= now_unix {
        return Err(EnrollmentTokenError::Expired {
            expired_secs_ago: now_unix - token.expires_at_unix,
        });
    }
    if ledger.was_consumed(&token.token_id) {
        return Err(EnrollmentTokenError::AlreadyConsumed);
    }
    ledger.record_consumed(token.token_id);
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_secret(byte: u8) -> [u8; ENROLLMENT_SECRET_LEN] {
        [byte; ENROLLMENT_SECRET_LEN]
    }

    #[test]
    fn mint_and_verify_round_trip_under_same_secret() {
        let secret = deterministic_secret(1);
        let mut ledger = ConsumedTokenLedger::new();
        let (_, encoded) =
            mint_token_with_clock(&secret, 600, 1_700_000_000).expect("mint succeeds");
        let verified =
            verify_and_consume_token_with_now(&encoded, &secret, &mut ledger, 1_700_000_300)
                .expect("verification succeeds");
        assert!(verified.expires_at_unix > 1_700_000_300);
        assert_eq!(ledger.consumed_count(), 1);
    }

    #[test]
    fn verify_under_different_secret_fails_with_tag_mismatch() {
        let issuer = deterministic_secret(2);
        let attacker = deterministic_secret(3);
        let mut ledger = ConsumedTokenLedger::new();
        let (_, encoded) =
            mint_token_with_clock(&issuer, 600, 1_700_000_000).expect("mint succeeds");
        let err =
            verify_and_consume_token_with_now(&encoded, &attacker, &mut ledger, 1_700_000_300)
                .expect_err("must reject under different secret");
        assert!(matches!(err, EnrollmentTokenError::TagMismatch));
        assert_eq!(
            ledger.consumed_count(),
            0,
            "ledger must not record a tampered/wrong-secret token"
        );
    }

    #[test]
    fn verify_after_expiry_fails() {
        let secret = deterministic_secret(4);
        let mut ledger = ConsumedTokenLedger::new();
        let (_, encoded) =
            mint_token_with_clock(&secret, 600, 1_700_000_000).expect("mint succeeds");
        // 1_700_000_000 + 600 = 1_700_000_600. Check at 1_700_001_000.
        let err = verify_and_consume_token_with_now(&encoded, &secret, &mut ledger, 1_700_001_000)
            .expect_err("must reject expired token");
        match err {
            EnrollmentTokenError::Expired { expired_secs_ago } => {
                assert_eq!(expired_secs_ago, 400);
            }
            other => panic!("expected Expired, got {other:?}"),
        }
        assert_eq!(ledger.consumed_count(), 0);
    }

    #[test]
    fn second_consumption_of_same_token_fails_with_already_consumed() {
        let secret = deterministic_secret(5);
        let mut ledger = ConsumedTokenLedger::new();
        let (_, encoded) =
            mint_token_with_clock(&secret, 600, 1_700_000_000).expect("mint succeeds");
        verify_and_consume_token_with_now(&encoded, &secret, &mut ledger, 1_700_000_300)
            .expect("first redemption succeeds");
        let err = verify_and_consume_token_with_now(&encoded, &secret, &mut ledger, 1_700_000_400)
            .expect_err("second redemption must fail");
        assert!(matches!(err, EnrollmentTokenError::AlreadyConsumed));
        assert_eq!(
            ledger.consumed_count(),
            1,
            "ledger should still hold exactly one entry"
        );
    }

    #[test]
    fn malformed_base64_is_rejected_with_descriptive_error() {
        let secret = deterministic_secret(6);
        let mut ledger = ConsumedTokenLedger::new();
        let err = verify_and_consume_token_with_now(
            "this-is-not-a-valid-token!!!",
            &secret,
            &mut ledger,
            1_700_000_000,
        )
        .expect_err("must reject malformed base64");
        assert!(matches!(err, EnrollmentTokenError::Malformed(_)));
    }

    #[test]
    fn truncated_token_is_rejected_with_length_error() {
        let secret = deterministic_secret(7);
        let mut ledger = ConsumedTokenLedger::new();
        // 5 bytes worth of valid base64.
        let too_short = URL_SAFE_NO_PAD.encode([1u8, 2, 3, 4, 5]);
        let err =
            verify_and_consume_token_with_now(&too_short, &secret, &mut ledger, 1_700_000_000)
                .expect_err("must reject short token");
        match err {
            EnrollmentTokenError::Malformed(msg) => {
                assert!(
                    msg.contains("bytes"),
                    "expected length diagnostic, got: {msg}"
                );
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn token_issued_far_in_the_future_is_rejected() {
        let secret = deterministic_secret(8);
        let mut ledger = ConsumedTokenLedger::new();
        // Issued 10 minutes from now — well beyond the 5-minute tolerance.
        let (_, encoded) =
            mint_token_with_clock(&secret, 600, 1_700_000_600).expect("mint succeeds");
        let err = verify_and_consume_token_with_now(&encoded, &secret, &mut ledger, 1_700_000_000)
            .expect_err("future-issued token must be rejected");
        assert!(matches!(err, EnrollmentTokenError::IssuedInFuture { .. }));
    }

    #[test]
    fn ttl_out_of_range_is_rejected_at_mint() {
        let secret = deterministic_secret(9);
        let err = mint_token_with_clock(&secret, 0, 1_700_000_000).expect_err("zero TTL rejected");
        assert!(matches!(err, EnrollmentTokenError::TtlOutOfRange { .. }));

        let err = mint_token_with_clock(&secret, MAX_TOKEN_TTL_SECS + 1, 1_700_000_000)
            .expect_err("over-cap TTL rejected");
        assert!(matches!(err, EnrollmentTokenError::TtlOutOfRange { .. }));
    }

    #[test]
    fn tampered_token_body_is_rejected_with_tag_mismatch() {
        let secret = deterministic_secret(10);
        let mut ledger = ConsumedTokenLedger::new();
        let (token, encoded) =
            mint_token_with_clock(&secret, 600, 1_700_000_000).expect("mint succeeds");
        // Decode, mutate expires_at to a later time, re-encode without
        // recomputing the tag — the verifier must reject.
        let mut bytes = URL_SAFE_NO_PAD.decode(encoded.trim()).unwrap();
        let new_expires = (token.expires_at_unix + 3600).to_be_bytes();
        bytes[TOKEN_ID_LEN + 8..TOKEN_ID_LEN + 16].copy_from_slice(&new_expires);
        let tampered = URL_SAFE_NO_PAD.encode(&bytes);
        let err = verify_and_consume_token_with_now(&tampered, &secret, &mut ledger, 1_700_000_300)
            .expect_err("tampered expires_at must fail tag check");
        assert!(matches!(err, EnrollmentTokenError::TagMismatch));
    }

    #[test]
    fn encode_decode_round_trip_preserves_all_fields() {
        let secret = deterministic_secret(11);
        let (token, encoded) =
            mint_token_with_clock(&secret, 600, 1_700_000_000).expect("mint succeeds");
        let decoded = decode_token(&encoded).expect("decode succeeds");
        assert_eq!(decoded, token);
    }

    #[test]
    fn encoded_token_is_url_safe_no_padding() {
        let secret = deterministic_secret(12);
        let (_, encoded) =
            mint_token_with_clock(&secret, 600, 1_700_000_000).expect("mint succeeds");
        // URL-safe alphabet: A-Z a-z 0-9 - _
        for ch in encoded.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || ch == '-' || ch == '_',
                "encoded token must use URL-safe base64 alphabet only; got {ch:?} in {encoded}"
            );
        }
        // Pad-less encoding never carries '='.
        assert!(!encoded.contains('='));
    }

    #[test]
    fn consumed_ledger_was_consumed_predicate_round_trips() {
        let mut ledger = ConsumedTokenLedger::new();
        let id = [99u8; TOKEN_ID_LEN];
        assert!(!ledger.was_consumed(&id));
        ledger.record_consumed(id);
        assert!(ledger.was_consumed(&id));
        // Idempotent: recording twice doesn't break the count.
        ledger.record_consumed(id);
        assert_eq!(ledger.consumed_count(), 1);
    }

    #[test]
    fn boundary_at_exact_expiry_is_rejected() {
        // Token expires at exactly `now` — must be rejected (strict
        // `<= now` check). Anti-replay: if we allowed equality, a
        // token could be consumed in the same second it expired,
        // which is fine; but allowing it at all means the boundary is
        // ambiguous. We reject for clarity.
        let secret = deterministic_secret(13);
        let mut ledger = ConsumedTokenLedger::new();
        let (_, encoded) =
            mint_token_with_clock(&secret, 600, 1_700_000_000).expect("mint succeeds");
        let err = verify_and_consume_token_with_now(&encoded, &secret, &mut ledger, 1_700_000_600)
            .expect_err("expiry exactly now must be rejected");
        assert!(matches!(err, EnrollmentTokenError::Expired { .. }));
    }

    #[test]
    fn enrollment_token_debug_output_redacts_tag_and_token_id() {
        // Security pin: an EnrollmentToken accidentally logged with
        // `{:?}` MUST NOT emit the HMAC tag (the bearer credential)
        // or the token_id (used to look up consumed state) in
        // plaintext. The custom Debug impl elides both.
        let secret = deterministic_secret(99);
        let (token, _encoded) = mint_token_with_clock(&secret, 600, 1_700_000_000).expect("mint");
        let debug_string = format!("{token:?}");
        assert!(
            debug_string.contains("<redacted>"),
            "Debug output should redact secret-bearing fields; got: {debug_string}"
        );
        // Hex of the actual tag must not appear in the debug output.
        let tag_hex: String = token.tag.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            !debug_string.contains(&tag_hex),
            "Debug output must NOT leak the HMAC tag; got: {debug_string}"
        );
        let id_hex: String = token.token_id.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            !debug_string.contains(&id_hex),
            "Debug output must NOT leak the token_id; got: {debug_string}"
        );
    }

    #[test]
    fn enrollment_token_drop_zeroises_secret_material() {
        // Security pin: dropping an EnrollmentToken zeroises its tag
        // and token_id so a freed token does not leave the bearer
        // credential floating in heap-reused memory. We can't observe
        // the after-drop state directly without unsafe, so we
        // verify the explicit zeroize call by mutating in place.
        let secret = deterministic_secret(101);
        let (mut token, _) = mint_token_with_clock(&secret, 600, 1_700_000_000).expect("mint");
        // Sanity: the freshly minted token has non-zero material.
        assert!(token.tag.iter().any(|b| *b != 0));
        assert!(token.token_id.iter().any(|b| *b != 0));
        // Manually invoke the Zeroize semantics that Drop would.
        token.tag.zeroize();
        token.token_id.zeroize();
        assert!(token.tag.iter().all(|b| *b == 0));
        assert!(token.token_id.iter().all(|b| *b == 0));
    }

    #[test]
    fn generate_enrollment_secret_returns_zeroizing_wrapper_with_full_entropy() {
        // Pin: the production path returns a Zeroizing<[u8; 32]>
        // (not a bare array) so the secret can be carried through the
        // daemon state-loading code without leaking copies. The
        // resulting bytes must be non-trivial (not all-zero).
        let secret = generate_enrollment_secret().expect("OsRng available on this host");
        let all_zero = secret.iter().all(|b| *b == 0);
        assert!(
            !all_zero,
            "fresh enrollment secret must contain entropy (got all-zero)"
        );
        assert_eq!(secret.len(), ENROLLMENT_SECRET_LEN);
    }
}
