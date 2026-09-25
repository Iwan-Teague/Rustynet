//! Keyed blind index for `users.email` (AQ-45 step 3).
//!
//! Implements §8 step 3 of `charter/design/rustynet-control-db-atrest-v0.2.md`
//! only: email normalisation plus the HMAC construction. No schema, no
//! callers, no key custody — the key arrives as [`BlindIndexKey`] over
//! `zeroize::Zeroizing<[u8; 32]>`, so the §4 key source (the OS-keystore item
//! for the blind-index DEK, `rustynet/control-db/dek/bix/v1`) can feed it
//! unchanged when it lands.
//!
//! PROVISIONAL on OI-46 Q2: the keyed blind-index column (`users.email_bix`
//! BLOB carrying its own UNIQUE index, design §3) is the adopted default for
//! preserving `UNIQUE(email)` semantics once the email value itself is sealed
//! under random nonces, but the owner question is open. If Q2 is answered
//! against the blind index, this module is unused by product code and
//! removable without migration.
//!
//! # Construction
//!
//! The index is HMAC-SHA256 (RFC 2104) under an independent 32-byte key —
//! deliberately not a derivation of the value-encryption DEK (design §3, §4:
//! one keystore item per purpose, no subkey derivation) — over a
//! domain-separated input:
//!
//! ```text
//! "rustynet/control-db/bix/users.email/v1" || 0x00 || normalised email bytes
//! ```
//!
//! The fixed ASCII label names the column and the construction version, so a
//! future blind index for another column (design §3 names `auth_events.*` as
//! the expected second ENCRYPT target) cannot be confused with this one: its
//! label produces a different HMAC input under the same key. The single 0x00
//! separator removes label/email boundary ambiguity — the label never
//! contains 0x00 and email bytes are appended raw after it, so the split
//! point is unambiguous even for emails containing bytes that look like the
//! label.
//!
//! Without the key the output is unlinkable: it equals no keyless hash of the
//! email, so a leaked database reveals no email-equality information beyond
//! the bix column's own UNIQUE collisions — which is exactly the equality
//! information today's cleartext `UNIQUE(email)` index already reveals.
//!
//! # Normalisation is identity — byte-exact, on purpose
//!
//! Today's uniqueness is byte-exact, and this module must preserve it
//! exactly: reject the pairs today's `UNIQUE` rejects, accept the pairs it
//! accepts. Evidence pinned at this tree (AQ-45 step-3 report):
//!
//! - `migrations/0001_init.sql:9` declares `email TEXT NOT NULL UNIQUE` with
//!   no `COLLATE`, so SQLite's default BINARY collation applies (byte-exact
//!   comparison; no `COLLATE` clause exists anywhere under `migrations/`).
//! - The only write into `users.email` in the workspace is the upsert at
//!   `src/persistence.rs:183-191`, which binds `user.email` verbatim
//!   (`?2` ← `user.email`, `persistence.rs:191`).
//! - Nothing in `src/persistence.rs` or `src/enrollment.rs` folds case or
//!   Unicode on email: `enrollment.rs` contains zero occurrences of `email`,
//!   and the crate's only `to_lowercase` / `to_ascii_lowercase` uses are in
//!   `blind_relay.rs` render checks, `ga.rs` DNSSEC algorithm names and
//!   `membership.rs` node-pubkey-hex normalisation — none touch email.
//!
//! [`normalize_email_for_bix`] is therefore the single place where email
//! normalisation lives, and its body is identity. ANY future change here —
//! ASCII case-folding, full Unicode case-folding, NFC/NFKC — is a SEMANTIC
//! CHANGE to enrollment uniqueness: it merges addresses today's `UNIQUE`
//! treats as distinct (two rows today may hold `Alice@` and `alice@`) and
//! makes a stored duplicate fail the migrated UNIQUE index on migration day.
//! Such a change needs its own owner decision with a stated migration plan,
//! not a drive-by edit of this function.
//!
//! The chosen semantics are pinned by
//! `bix_pins_binary_collation_semantics` in this module's tests.

use hmac::digest::generic_array::{GenericArray, typenum::U64};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Domain-separation label for the `users.email` blind index (v1).
///
/// ASCII only, no 0x00 bytes, names crate / database / purpose / column /
/// version. Changing it changes every derived index value, so it is versioned
/// for life: a v2 construction for this column gets `.../v2`, never an edit
/// of this string.
pub const EMAIL_BIX_DOMAIN_LABEL: &str = "rustynet/control-db/bix/users.email/v1";

/// Blind-index output width: a full, untruncated HMAC-SHA256.
type HmacSha256 = Hmac<Sha256>;

/// The independent blind-index key (design §3, §4).
///
/// Held in `Zeroizing` so the key bytes are wiped on drop. Custody is §8
/// step 2's concern: this type only wraps what a key source hands over, and
/// exposes no accessor for the raw bytes.
pub struct BlindIndexKey {
    key: Zeroizing<[u8; 32]>,
}

impl BlindIndexKey {
    /// Wrap a 32-byte blind-index key.
    ///
    /// Takes `Zeroizing<[u8; 32]>` only — never a plain array — so the type
    /// system forces callers through a wiping key source. Distinct-purpose
    /// keys stay distinct: the value DEK and this key are separate keystore
    /// items, never derivations of one another.
    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self { key }
    }
}

impl std::fmt::Debug for BlindIndexKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlindIndexKey(REDACTED)")
    }
}

/// Normalise an email for blind-index derivation: return it byte-exact.
///
/// Identity, on purpose — see the module documentation for why byte-exactness
/// is the only semantics that preserves today's `UNIQUE(email)` behaviour.
/// This is the single place where email normalisation lives; every bix
/// derivation must go through it.
pub fn normalize_email_for_bix(email: &str) -> &str {
    email
}

/// Derive the blind index for `email` under `key`.
///
/// `HMAC-SHA256(key, EMAIL_BIX_DOMAIN_LABEL || 0x00 ||
/// normalize_email_for_bix(email))`, returned as raw 32 bytes for storage in
/// the `users.email_bix` BLOB column (step 4's schema). Deterministic by
/// design: equal normalised emails under one key give equal indexes, which is
/// what lets SQL-level UNIQUE keep enforcing email uniqueness across
/// different `user_id`s once the email value itself is sealed under random
/// nonces (design §3).
pub fn email_bix(key: &BlindIndexKey, email: &str) -> [u8; 32] {
    bix_under_label(key, EMAIL_BIX_DOMAIN_LABEL, email)
}

/// Derive a blind index under an explicit label.
///
/// Private: exists so the domain-separation witness can derive under a
/// second label with the same key and bytes. Product code always goes through
/// [`email_bix`] and its fixed label.
fn bix_under_label(key: &BlindIndexKey, label: &str, email: &str) -> [u8; 32] {
    // `KeyInit::new` takes the BLOCK-sized key buffer (64 bytes for SHA-256)
    // and is infallible — no `Err` value exists, so no `clippy::panic` allow
    // is needed. HMAC zero-pads keys shorter than the block (RFC 2104), so
    // `K || 0x00 * 32` here derives exactly the same MAC as
    // `new_from_slice(K)` with the 32-byte key; the witness
    // `bix_matches_documented_construction` pins that equality against the
    // independent `new_from_slice` path.
    let mut padded = GenericArray::<u8, U64>::default();
    for (slot, byte) in padded.iter_mut().zip(key.key.iter()) {
        *slot = *byte;
    }
    let mut mac = HmacSha256::new(&padded);
    mac.update(label.as_bytes());
    mac.update(&[0x00]);
    mac.update(normalize_email_for_bix(email).as_bytes());
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Witness key: nonzero, repeating ASCII pattern, in the style of the
    /// step-1 sealing primitives' witness key.
    fn witness_key_bytes() -> [u8; 32] {
        let mut key = [0u8; 32];
        let pattern = b"AQ45BIX!";
        for (i, slot) in key.iter_mut().enumerate() {
            *slot = pattern[i % pattern.len()];
        }
        key
    }

    fn witness_key() -> BlindIndexKey {
        BlindIndexKey::new(Zeroizing::new(witness_key_bytes()))
    }

    fn other_key() -> BlindIndexKey {
        let mut bytes = witness_key_bytes();
        bytes[0] ^= 0x01;
        BlindIndexKey::new(Zeroizing::new(bytes))
    }

    fn bix_hex(bix: &[u8; 32]) -> String {
        bix.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Minimal standard base64 (test-only, no new dependencies): the encoding
    /// a formatter might emit for raw key bytes.
    fn base64(data: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
            let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[(n >> 18) as usize & 63] as char);
            out.push(ALPHABET[(n >> 12) as usize & 63] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[(n >> 6) as usize & 63] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[n as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    /// Every encoding of the witness key a formatter might emit: raw bytes,
    /// lowercase and uppercase hex, standard base64, and the comma-separated
    /// decimal array text that a derived `Debug` on `[u8; 32]` produces.
    fn key_encodings(key: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
        let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
        let decimal: String = key
            .iter()
            .map(|byte| byte.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        vec![
            ("raw", key.to_vec()),
            ("hex", hex.clone().into_bytes()),
            ("HEX", hex.to_uppercase().into_bytes()),
            ("base64", base64(key).into_bytes()),
            ("decimal", decimal.into_bytes()),
        ]
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return false;
        }
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn hmac_under(label: &str, email: &str, key: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(key).expect("32-byte HMAC key is always valid");
        mac.update(label.as_bytes());
        mac.update(&[0x00]);
        mac.update(email.as_bytes());
        mac.finalize().into_bytes().into()
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    #[test]
    fn bix_is_deterministic() {
        let key = witness_key();
        for email in [
            "alice@example.local",
            "Alice@Example.LOCAL",
            "",
            "a",
            "ünïcode@例子.example",
        ] {
            assert_eq!(
                email_bix(&key, email),
                hmac_under(EMAIL_BIX_DOMAIN_LABEL, email, &witness_key_bytes()),
                "same key and email must derive the same index: {email:?}"
            );
        }
    }

    #[test]
    fn bix_is_key_bound() {
        let k1 = witness_key();
        let k2 = other_key();
        let k3 = BlindIndexKey::new(Zeroizing::new([0x5Au8; 32]));
        for email in ["alice@example.local", "Alice@example.com", ""] {
            let i1 = email_bix(&k1, email);
            assert_ne!(
                i1,
                email_bix(&k2, email),
                "one-bit key change must change the index for {email:?}"
            );
            assert_ne!(
                i1,
                email_bix(&k3, email),
                "unrelated key must change the index for {email:?}"
            );
            assert_ne!(email_bix(&k2, email), email_bix(&k3, email));
        }
    }

    #[test]
    fn bix_matches_documented_construction() {
        // Pins the documented input exactly — label literal, 0x00 separator,
        // then the byte-exact email — so any change to the construction (or
        // to the label constant) fails here rather than silently re-indexing
        // every stored row.
        let key = witness_key();
        let email = "alice@example.local";
        assert_eq!(
            email_bix(&key, email),
            hmac_under(
                "rustynet/control-db/bix/users.email/v1",
                email,
                &witness_key_bytes()
            ),
        );
        // The public label constant is that same literal.
        assert_eq!(
            EMAIL_BIX_DOMAIN_LABEL,
            "rustynet/control-db/bix/users.email/v1"
        );
        // Normalisation is where it must be: identity.
        assert_eq!(normalize_email_for_bix(email), email);
    }

    #[test]
    fn bix_unlinkable_without_key() {
        let key = witness_key();
        for email in ["alice@example.local", "bob@example.com"] {
            let bix = email_bix(&key, email);
            // Not a keyless hash of the email...
            assert_ne!(
                bix,
                sha256(email.as_bytes()),
                "bix leaked SHA-256(email) for {email:?}"
            );
            // ...nor a keyless hash of the domain-separated input...
            let domain_input: Vec<u8> = EMAIL_BIX_DOMAIN_LABEL
                .as_bytes()
                .iter()
                .copied()
                .chain(std::iter::once(0x00))
                .chain(email.as_bytes().iter().copied())
                .collect();
            assert_ne!(
                bix,
                sha256(&domain_input),
                "bix leaked an unkeyed hash of the domain-separated input for {email:?}"
            );
            // ...nor the keyed construction under the all-zero key (a
            // constant, publicly computable substitute).
            assert_ne!(
                bix,
                hmac_under(EMAIL_BIX_DOMAIN_LABEL, email, &[0u8; 32]),
                "bix equals the all-zero-key HMAC for {email:?}"
            );
        }
    }

    #[test]
    fn bix_domain_separates_by_label() {
        let key = witness_key();
        for email in ["alice@example.local", ""] {
            let bix = email_bix(&key, email);
            assert_ne!(
                bix,
                bix_under_label(&key, "rustynet/control-db/bix/other.column/v2", email),
                "same key and bytes under another label must not match users.email's index"
            );
            assert_ne!(
                bix,
                bix_under_label(&key, "", email),
                "empty label must not match the real construction"
            );
        }
        // Equal bytes under the equal label stay equal (label participates,
        // but deterministically).
        assert_eq!(
            bix_under_label(
                &key,
                "rustynet/control-db/bix/other.column/v2",
                "alice@example.local"
            ),
            bix_under_label(
                &key,
                "rustynet/control-db/bix/other.column/v2",
                "alice@example.local"
            ),
        );
    }

    #[test]
    fn bix_pins_binary_collation_semantics() {
        let key = witness_key();
        // Case differs → the bytes differ → today's BINARY-collation UNIQUE
        // treats these as distinct, so their indexes must differ too.
        assert_ne!(
            email_bix(&key, "Alice@example.com"),
            email_bix(&key, "alice@example.com"),
            "case-differing emails must not collide (BINARY collation pin)"
        );
        // Identical bytes → equal indexes (the accept direction).
        assert_eq!(
            email_bix(&key, "alice@example.com"),
            email_bix(&key, "alice@example.com"),
        );
        // Byte-exact means no Unicode folding either: NFC and NFD spellings
        // of the same visible address are different byte strings and must
        // index differently, exactly as today's UNIQUE treats them.
        assert_ne!(
            email_bix(&key, "caf\u{e9}@example.local"),
            email_bix(&key, "cafe\u{301}@example.local"),
            "Unicode-equivalent but byte-differing emails must not collide"
        );
        // Byte-exact means no trimming either: surrounding whitespace is part
        // of the address today.
        assert_ne!(
            email_bix(&key, "alice@example.com"),
            email_bix(&key, " alice@example.com"),
        );
    }

    #[test]
    fn debug_redacts_key_material() {
        assert_eq!(format!("{:?}", witness_key()), "BlindIndexKey(REDACTED)");
    }

    #[test]
    fn key_never_appears_in_formatted_output() {
        let key = witness_key();
        let key_bytes = witness_key_bytes();
        let bix = email_bix(&key, "alice@example.local");
        // Every formatted surface this module can produce: the key's own
        // Debug (already redacted), the derived index raw and in its Debug
        // form (the decimal array text a derived impl would print), and the
        // index hex.
        let surfaces: [Vec<u8>; 4] = [
            format!("{key:?}").into_bytes(),
            bix.to_vec(),
            format!("{bix:?}").into_bytes(),
            format!("{:?}", bix_hex(&bix)).into_bytes(),
        ];
        for surface in &surfaces {
            for (label, needle) in key_encodings(&key_bytes) {
                assert!(
                    !contains(surface, &needle),
                    "key ({label}) leaked into formatted output: {:?}",
                    String::from_utf8_lossy(surface)
                );
            }
        }
    }
}
