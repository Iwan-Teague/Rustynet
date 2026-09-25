//! Value-level at-rest sealing for `control.db` (AQ-45).
//!
//! Implements §8 step 1 of `charter/design/rustynet-control-db-atrest-v0.2.md`
//! only: the sealing primitives, with no schema change and no product callers
//! yet. The envelope and its binding follow design §3:
//!
//! ```text
//! byte 0      format version (0x01)
//! bytes 1-24  XChaCha nonce (24 random bytes)
//! bytes 25-   ciphertext || 16-byte Poly1305 tag
//! ```
//!
//! Every seal draws a fresh nonce from the kernel CSPRNG and fails closed if
//! entropy is unavailable — the tree's existing discipline
//! (`rustynet-crypto/src/lib.rs:94-98`); `ThreadRng` is never used as a
//! fallback. Every seal/open binds a [`ValueAad`] (database id, table, column,
//! row key, format version), so a ciphertext moved to another row, column,
//! table or database fails the Poly1305 tag there.
//!
//! The sealing layer stays private to `rustynet-control`, designed for
//! extraction when a second consumer needs it (provisional on OI-46 Q5).
//!
//! Residual accepted by v1 (design §7(a), provisional on OI-46 Q6): the AAD
//! does not bind a per-row value version, so a same-cell same-epoch rollback
//! to an older sealed value is not detected here; envelope format 0x02 adds a
//! `ver: u64` field to the AAD when a second ENCRYPT column joins.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::TryRngCore;
use zeroize::Zeroizing;

/// Envelope format version byte (design §3). The only version this module
/// writes or accepts; 0x02 is reserved for the priced OI-46 Q6 upgrade that
/// adds a per-row value version to the AAD.
pub const VALUE_ENVELOPE_FORMAT_VERSION: u8 = 0x01;

/// XChaCha20-Poly1305 nonce length in bytes (envelope bytes 1-24).
const NONCE_LEN: usize = 24;

/// Poly1305 tag length in bytes, carried at the end of the ciphertext.
const TAG_LEN: usize = 16;

/// The coordinates a sealed value is bound to (design §3).
///
/// Sealing under one `ValueAad` and opening under any other fails: the AAD is
/// mixed into the Poly1305 tag, so a ciphertext cut from row A and pasted into
/// row B — or into another column, table or control.db — is refused.
///
/// `db_id` is the random per-database identifier stored in `atrest_meta`;
/// `row_key` is the row's PRIMARY KEY; `fmt` must be
/// [`VALUE_ENVELOPE_FORMAT_VERSION`] for this envelope version (seal refuses
/// any other value; a mismatch on open fails the tag like any AAD mismatch).
pub struct ValueAad<'a> {
    pub db_id: [u8; 16],
    pub table: &'a str,
    pub column: &'a str,
    pub row_key: &'a str,
    pub fmt: u8,
}

impl ValueAad<'_> {
    /// Deterministic AAD byte encoding: format byte, database id, then each
    /// string as a u32 little-endian length prefix plus raw UTF-8 bytes.
    /// Length-prefixing makes the encoding injective, so no two distinct
    /// `ValueAad`s can produce the same bytes; a field of 2^32 bytes or more
    /// (impossible for these columns) is refused fail-closed rather than
    /// silently mis-encoded by a truncating cast, which would have broken
    /// injectivity for such inputs.
    fn encode(&self) -> Result<Vec<u8>, ValueEnvelopeError> {
        let mut out = Vec::with_capacity(
            1 + 16 + 12 + self.table.len() + self.column.len() + self.row_key.len(),
        );
        out.push(self.fmt);
        out.extend_from_slice(&self.db_id);
        for part in [self.table, self.column, self.row_key] {
            let len = u32::try_from(part.len()).map_err(|_| ValueEnvelopeError)?;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(part.as_bytes());
        }
        Ok(out)
    }
}

/// Opaque failure of a seal or open operation.
///
/// Single unit variant by design: callers and logs learn only that the
/// operation was refused, never which check failed (wrong version byte, AAD
/// mismatch and tag failure are indistinguishable), so the error surface is
/// not a decryption oracle. It carries no key or plaintext bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValueEnvelopeError;

impl std::fmt::Display for ValueEnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "value envelope rejected")
    }
}

impl std::error::Error for ValueEnvelopeError {}

/// Sealer/opener for `control.db` values (design §3, §4).
///
/// Holds exactly one 32-byte XChaCha20-Poly1305 key, wrapped in
/// `Zeroizing` so the key bytes are wiped on drop. The key is never exposed
/// by the API, and `Debug` is implemented by hand to print
/// `ValueCipher(REDACTED)` so no formatted output can carry key material.
pub struct ValueCipher {
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for ValueCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ValueCipher(REDACTED)")
    }
}

impl ValueCipher {
    /// Build a cipher over a 32-byte key handed over already wrapped in
    /// `Zeroizing`. The wrapped key is stored as-is and wiped on drop, and a
    /// custody source that returns `Zeroizing<[u8; 32]>` (the §8 step 2
    /// `ControlDbKeySource::load` shape) transfers the key without ever
    /// unwrapping it into an intermediate that no `Drop` wipes. Custody
    /// itself (OS keystore item `rustynet/control-db/dek/value/v1`) is
    /// §8 step 2 and does not exist yet.
    pub fn from_key(key: Zeroizing<[u8; 32]>) -> Self {
        Self { key }
    }

    /// Seal `plaintext` into the §3 envelope: version byte, fresh nonce,
    /// ciphertext || tag. Every call draws a new nonce from the OS CSPRNG and
    /// fails closed if it cannot.
    pub fn seal(&self, aad: &ValueAad, plaintext: &[u8]) -> Result<Vec<u8>, ValueEnvelopeError> {
        if aad.fmt != VALUE_ENVELOPE_FORMAT_VERSION {
            return Err(ValueEnvelopeError);
        }
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| ValueEnvelopeError)?;
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        let body = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad.encode()?,
                },
            )
            .map_err(|_| ValueEnvelopeError)?;
        let mut envelope = Vec::with_capacity(1 + NONCE_LEN + body.len());
        envelope.push(VALUE_ENVELOPE_FORMAT_VERSION);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&body);
        Ok(envelope)
    }

    /// Open a §3 envelope, returning the plaintext wrapped in `Zeroizing`
    /// so the heap copy is wiped on drop — these values are sensitive
    /// column data and this mirrors the tree's own habit for unwrapped
    /// secrets (`credential_unwrap.rs`, same crate). Refuses with the single
    /// opaque [`ValueEnvelopeError`] when the version byte is wrong, the AAD
    /// does not match the sealing one, or the Poly1305 tag fails.
    pub fn open(
        &self,
        aad: &ValueAad,
        envelope: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ValueEnvelopeError> {
        let (version, rest) = envelope.split_first().ok_or(ValueEnvelopeError)?;
        if *version != VALUE_ENVELOPE_FORMAT_VERSION {
            return Err(ValueEnvelopeError);
        }
        let (nonce, body) = rest.split_at_checked(NONCE_LEN).ok_or(ValueEnvelopeError)?;
        if body.len() < TAG_LEN {
            return Err(ValueEnvelopeError);
        }
        let cipher = XChaCha20Poly1305::new((&*self.key).into());
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: body,
                    aad: &aad.encode()?,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| ValueEnvelopeError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn witness_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        let pattern = b"AQ45KEY!";
        for (i, slot) in key.iter_mut().enumerate() {
            *slot = pattern[i % pattern.len()];
        }
        key
    }

    fn cipher() -> ValueCipher {
        ValueCipher::from_key(Zeroizing::new(witness_key()))
    }

    fn aad<'a>(table: &'a str, column: &'a str, row_key: &'a str) -> ValueAad<'a> {
        ValueAad {
            db_id: [0x11; 16],
            table,
            column,
            row_key,
            fmt: VALUE_ENVELOPE_FORMAT_VERSION,
        }
    }

    fn nonce_of(envelope: &[u8]) -> Vec<u8> {
        envelope
            .get(1..=NONCE_LEN)
            .expect("envelope shorter than version byte + nonce")
            .to_vec()
    }

    fn pseudo_random_bytes(len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        for _ in 0..len {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            out.push((state >> 33) as u8);
        }
        out
    }

    #[test]
    fn round_trip_property_across_lengths() {
        let c = cipher();
        let a = aad("users", "user_id", "user-1");
        for len in [
            0usize, 1, 2, 15, 16, 17, 24, 25, 31, 255, 4096, 65_536, 1_048_576,
        ] {
            let plaintext = pseudo_random_bytes(len);
            let sealed = c.seal(&a, &plaintext).expect("seal must succeed");
            assert_eq!(sealed.len(), 1 + NONCE_LEN + len + TAG_LEN);
            assert_eq!(sealed[0], VALUE_ENVELOPE_FORMAT_VERSION);
            let opened = c.open(&a, &sealed).expect("open must succeed");
            assert_eq!(*opened, plaintext, "round trip failed at len {len}");
        }
    }

    #[test]
    fn nonce_uniqueness_over_many_seals() {
        let c = cipher();
        let a = aad("users", "user_id", "user-1");
        let plaintext = b"alice";
        let mut nonces = std::collections::HashSet::new();
        let mut first: Option<Vec<u8>> = None;
        for _ in 0..512 {
            let sealed = c.seal(&a, plaintext).expect("seal must succeed");
            if let Some(previous) = &first {
                assert_ne!(&sealed, previous, "two seals produced identical envelopes");
            }
            first = Some(sealed.clone());
            assert!(
                nonces.insert(nonce_of(&sealed)),
                "nonce reused across seals"
            );
        }
        assert_eq!(nonces.len(), 512);
    }

    #[test]
    fn aad_mismatch_refuses_open() {
        let c = cipher();
        let plaintext = b"alice";
        let sealed = c
            .seal(&aad("users", "user_id", "user-1"), plaintext)
            .expect("seal must succeed");
        assert!(
            c.open(&aad("users", "user_id", "user-1"), &sealed).is_ok(),
            "identical AAD must open"
        );
        // Different row, column, table, database id, and format version each
        // refuse with the same single error.
        let aad_mismatches = [
            ("users", "user_id", "user-2"),
            ("users", "display_name", "user-1"),
            ("auth_events", "user_id", "user-1"),
            ("users", "user_id", "user-1x"),
        ];
        for (table, column, row_key) in aad_mismatches {
            let err = c
                .open(&aad(table, column, row_key), &sealed)
                .expect_err("cross-context open must be refused");
            assert_eq!(err, ValueEnvelopeError);
        }
        let mut other_db = aad("users", "user_id", "user-1");
        other_db.db_id = [0x22; 16];
        assert_eq!(
            c.open(&other_db, &sealed)
                .expect_err("cross-db open must be refused"),
            ValueEnvelopeError
        );
        let mut other_fmt = aad("users", "user_id", "user-1");
        other_fmt.fmt = 0x02;
        assert_eq!(
            c.open(&other_fmt, &sealed)
                .expect_err("cross-fmt open must be refused"),
            ValueEnvelopeError
        );
    }

    #[test]
    fn envelope_corruption_and_wrong_version_refuse() {
        let c = cipher();
        let plaintext = b"alice";
        let sealed = c
            .seal(&aad("users", "user_id", "user-1"), plaintext)
            .expect("seal must succeed");
        // Wrong version byte.
        let mut wrong_version = sealed.clone();
        wrong_version[0] = 0x02;
        assert_eq!(
            c.open(&aad("users", "user_id", "user-1"), &wrong_version)
                .expect_err("wrong version byte must be refused"),
            ValueEnvelopeError
        );
        // Truncated envelopes: version-only, nonce-only, missing tag bytes.
        for cut in [1usize, 1 + NONCE_LEN, sealed.len() - 1] {
            let truncated = sealed.get(..cut).expect("cut within envelope").to_vec();
            assert_eq!(
                c.open(&aad("users", "user_id", "user-1"), &truncated)
                    .expect_err("truncated envelope must be refused"),
                ValueEnvelopeError
            );
        }
        // Flipped ciphertext byte (tag failure).
        let mut flipped = sealed.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;
        assert_eq!(
            c.open(&aad("users", "user_id", "user-1"), &flipped)
                .expect_err("tampered envelope must be refused"),
            ValueEnvelopeError
        );
        // Empty envelope.
        assert_eq!(
            c.open(&aad("users", "user_id", "user-1"), &[])
                .expect_err("empty envelope must be refused"),
            ValueEnvelopeError
        );
    }

    #[test]
    fn seal_refuses_aad_with_foreign_format_version() {
        let c = cipher();
        let mut a = aad("users", "user_id", "user-1");
        a.fmt = 0x02;
        assert_eq!(
            c.seal(&a, b"alice")
                .expect_err("seal must refuse a non-0x01 AAD format"),
            ValueEnvelopeError
        );
    }

    #[test]
    fn different_keys_do_not_interchange() {
        let c1 = ValueCipher::from_key(Zeroizing::new([0x01; 32]));
        let c2 = ValueCipher::from_key(Zeroizing::new([0x02; 32]));
        let a = aad("users", "user_id", "user-1");
        let sealed = c1.seal(&a, b"alice").expect("seal must succeed");
        assert_eq!(
            c2.open(&a, &sealed)
                .expect_err("open under the wrong key must be refused"),
            ValueEnvelopeError
        );
    }

    #[test]
    fn debug_redacts_key_material() {
        let c = cipher();
        assert_eq!(format!("{c:?}"), "ValueCipher(REDACTED)");
    }

    #[test]
    fn key_never_appears_in_formatted_output() {
        let c = cipher();
        let key = witness_key();
        let a = aad("users", "user_id", "user-1");
        let sealed = c.seal(&a, b"alice").expect("seal must succeed");
        let err = c
            .open(&aad("users", "user_id", "user-2"), &sealed)
            .expect_err("open must fail for a different row");
        let surfaces: [Vec<u8>; 5] = [
            format!("{c:?}").into_bytes(),
            format!("{err}").into_bytes(),
            format!("{err:?}").into_bytes(),
            sealed,
            a.encode().expect("witness AAD is short"),
        ];
        for surface in &surfaces {
            for (label, needle) in key_encodings(&key) {
                assert!(
                    !contains(surface, &needle),
                    "key ({label}) leaked into output: {:?}",
                    String::from_utf8_lossy(surface)
                );
            }
        }
    }

    /// The witness key in the encodings a formatter might emit: raw bytes,
    /// lowercase and uppercase hex, and the comma-separated decimal array
    /// text that a derived `Debug` on `[u8; 32]` produces.
    fn key_encodings(key: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
        let mut out = vec![("raw", key.to_vec())];
        let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
        out.push(("hex", hex.clone().into_bytes()));
        out.push(("HEX", hex.to_uppercase().into_bytes()));
        let decimal: String = key
            .iter()
            .map(|byte| byte.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        out.push(("decimal", decimal.into_bytes()));
        out
    }

    /// Envelope boundary lengths are all refused with the single opaque
    /// error and never panic: empty, version-only, nonce cut short,
    /// nonce-only, one byte short of a full tag, and a tag-only body.
    #[test]
    fn envelope_boundary_lengths_reject() {
        let c = cipher();
        let a = aad("users", "user_id", "user-1");
        for len in [0usize, 1, 24, 25, 40, 41] {
            let mut env = vec![0xA5u8; len];
            if len > 0 {
                env[0] = VALUE_ENVELOPE_FORMAT_VERSION;
            }
            assert!(
                c.open(&a, &env).is_err(),
                "envelope of {len} bytes must be refused"
            );
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.len() >= needle.len()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }
}
