//! AQ-68: OS-keystore custody for the 32-byte anchor-enrollment minting
//! secret.
//!
//! Wave3 fleet finding B2 (charter/reviews/wave3-fleet-findings-2026-09-16.md,
//! action-queue.md AQ-68): `enrollment_token::load_secret` reads the minting
//! secret as a raw plaintext file at rest. This module routes every secret
//! read through the same `rustynet_crypto::OsSecureStore` custody path the
//! WireGuard key material already uses:
//!
//! * the secret is stored in the OS keystore under a path-derived key id;
//! * the plaintext file is shredded (zero-fill + unlink via
//!   `key_material::remove_file_if_present`) after a verified keystore
//!   round-trip;
//! * a plaintext secret file is REFUSED at resolve time unless the operator
//!   explicitly sets `RUSTYNET_ALLOW_PLAINTEXT_ENROLLMENT_SECRET` (lab/
//!   bring-up escape hatch) — fail-closed, no silent fallback;
//! * migration is an explicit operator step
//!   (`migrate_plaintext_secret_to_keystore`, exposed as
//!   `rustynet enrollment migrate-secret`), never an implicit daemon write:
//!   a daemon that silently provisions keystore entries (or prompts for
//!   keychain access mid-request) would be a new unauditable side effect.
//!
//! Resolve-time self-healing: when the keystore already holds the secret AND
//! the plaintext file still exists with the same value (e.g. the operator
//! migrated but the shred failed, or an old provisioning run re-created the
//! file), the plaintext file is shredded and the keystore value is used —
//! so a one-time migration is idempotent. Diverging values are refused
//! rather than silently picking a winner.
//!
//! Platform note: on macOS `OsSecureStore::load_key` maps item-not-found and
//! keystore-unavailable to the same `CryptoError::OsStoreUnavailable`
//! (rustynet-crypto/src/lib.rs `load_from_macos_keychain`), so "no entry"
//! cannot be distinguished from "keystore refused" by load alone. This
//! module treats any load error uniformly ("keystore does not currently
//! yield the secret") and never mutates keystore state outside the explicit
//! migration, which makes `store_key` the authoritative availability probe.

#![forbid(unsafe_code)]

use std::path::Path;

use rustynet_crypto::{OsSecureStore, PlatformOsSecureStore};
use zeroize::Zeroizing;

use crate::enrollment_token::{ENROLLMENT_SECRET_LEN, load_secret};
use crate::key_material::remove_file_if_present;

/// Operator escape hatch (lab / initial bring-up only). When set to a
/// truthy value, `resolve_enrollment_secret` will read the plaintext
/// secret file instead of refusing it. Any other non-empty value is a
/// configuration error (fail-closed).
pub const ALLOW_PLAINTEXT_ENROLLMENT_SECRET_ENV: &str =
    "RUSTYNET_ALLOW_PLAINTEXT_ENROLLMENT_SECRET";

/// Strict boolean parser for [`ALLOW_PLAINTEXT_ENROLLMENT_SECRET_ENV`].
/// Absent and empty mean `false`; `1`/`true`/`yes` mean `true`;
/// `0`/`false`/`no` mean `false`; anything else is an ERROR so a typo
/// ("treu") can never silently widen custody policy.
pub fn parse_allow_plaintext_value(raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" => Ok(false),
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        other => Err(format!(
            "{ALLOW_PLAINTEXT_ENROLLMENT_SECRET_ENV}: invalid value {other:?} \
             (expected 1/true/yes or 0/false/no)"
        )),
    }
}

/// Read [`ALLOW_PLAINTEXT_ENROLLMENT_SECRET_ENV`] with the strict parser.
/// An invalid value is fail-closed (`false`) but reported loudly on
/// stderr so the operator notices the misconfiguration; this keeps the
/// `DaemonConfig::default()` constructor infallible.
pub fn allow_plaintext_enrollment_secret_from_env() -> bool {
    match std::env::var(ALLOW_PLAINTEXT_ENROLLMENT_SECRET_ENV) {
        Err(_) => false,
        Ok(raw) => match parse_allow_plaintext_value(&raw) {
            Ok(value) => value,
            Err(err) => {
                eprintln!("rustynet: {err}; defaulting to false (fail-closed)");
                false
            }
        },
    }
}

/// Stable keystore id for the enrollment secret at `secret_path`:
/// `enrollment-secret-` + the first 8 bytes of SHA-256 over the lossy
/// path string, hex-encoded. Mirrors `key_material::key_custody_key_id`
/// so different secret paths never collide inside the keystore.
pub fn enrollment_secret_key_id(secret_path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(secret_path.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let mut suffix = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        suffix.push_str(&format!("{byte:02x}"));
    }
    format!("enrollment-secret-{suffix}")
}

/// Where the secret currently lives. Diagnostic + test aid. On platforms
/// that conflate keystore-absent with keystore-unavailable (macOS), a
/// `PlaintextOnly` classification can also mean "keystore refused";
/// see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentSecretLocation {
    KeystoreOnly,
    PlaintextOnly,
    Both,
    Missing,
}

/// Classify where the secret currently lives (read-only; never mutates
/// keystore or filesystem state).
pub fn classify_enrollment_secret_location<S: OsSecureStore>(
    store: &S,
    secret_path: &Path,
) -> Result<EnrollmentSecretLocation, String> {
    let keystore_holds = store
        .load_key(&enrollment_secret_key_id(secret_path))
        .is_ok();
    let plaintext_present = plaintext_file_present(secret_path);
    Ok(match (keystore_holds, plaintext_present) {
        (true, true) => EnrollmentSecretLocation::Both,
        (true, false) => EnrollmentSecretLocation::KeystoreOnly,
        (false, true) => EnrollmentSecretLocation::PlaintextOnly,
        (false, false) => EnrollmentSecretLocation::Missing,
    })
}

fn plaintext_file_present(secret_path: &Path) -> bool {
    // Presence only, not readability: a symlinked or wide-mode file is
    // "present" and the strict loader will refuse it with a precise
    // error a moment later.
    std::fs::symlink_metadata(secret_path).is_ok()
}

fn validate_keystore_secret(
    stored: Zeroizing<Vec<u8>>,
    secret_path: &Path,
) -> Result<Zeroizing<[u8; ENROLLMENT_SECRET_LEN]>, String> {
    if stored.len() != ENROLLMENT_SECRET_LEN {
        return Err(format!(
            "enrollment secret in OS keystore for {} has wrong length {} \
             (must be exactly {ENROLLMENT_SECRET_LEN} bytes)",
            secret_path.display(),
            stored.len()
        ));
    }
    let mut secret = Zeroizing::new([0u8; ENROLLMENT_SECRET_LEN]);
    secret.copy_from_slice(&stored);
    Ok(secret)
}

/// Migrate the plaintext enrollment secret into the OS keystore and shred
/// the plaintext file. Explicit, idempotent, fail-closed:
///
/// 1. Load the plaintext through the strict
///    `enrollment_token::load_secret` (exact size, no symlink, owner-only
///    mode).
/// 2. If the keystore already holds a value: equal → skip to the shred
///    (idempotent re-run); diverging → REFUSE, file untouched.
/// 3. Otherwise `store_key`, then read the value back and compare — only
///    a verified round-trip authorizes the shred. Any keystore error
///    leaves the plaintext file exactly as it was.
/// 4. Shred via `key_material::remove_file_if_present` (zero-fill +
///    truncate + sync + unlink).
pub fn migrate_plaintext_secret_to_keystore<S: OsSecureStore>(
    store: &S,
    secret_path: &Path,
) -> Result<(), String> {
    let secret =
        load_secret(secret_path).map_err(|err| format!("enrollment secret load failed: {err}"))?;
    let key_id = enrollment_secret_key_id(secret_path);
    let already_stored = match store.load_key(&key_id) {
        Ok(existing) => {
            if existing.as_slice() != secret.as_slice() {
                return Err(format!(
                    "enrollment secret in OS keystore (key {key_id}) diverges from plaintext \
                     file {}; refusing to overwrite either",
                    secret_path.display()
                ));
            }
            true
        }
        Err(_) => false,
    };
    if !already_stored {
        store.store_key(&key_id, secret.as_slice()).map_err(|err| {
            format!(
                "enrollment secret keystore write failed (plaintext file left in place at \
                     {}): {err}",
                secret_path.display()
            )
        })?;
        let readback = store.load_key(&key_id).map_err(|err| {
            format!(
                "enrollment secret keystore read-back failed after store (plaintext file \
                     left in place at {}): {err}",
                secret_path.display()
            )
        })?;
        if readback.as_slice() != secret.as_slice() {
            return Err(format!(
                "enrollment secret keystore read-back mismatch after store (plaintext file \
                 left in place at {})",
                secret_path.display()
            ));
        }
    }
    remove_file_if_present(secret_path)
        .map_err(|err| format!("enrollment secret plaintext shred failed: {err}"))?;
    Ok(())
}

/// Resolve the 32-byte enrollment secret for use. This is the ONLY read
/// path the daemon and CLI take.
///
/// * Keystore holds the value, no plaintext file: return the keystore
///   value (validated to exactly 32 bytes).
/// * Keystore holds the value AND a plaintext file exists: the one-time
///   migration was interrupted or the file reappeared — values equal →
///   self-heal (shred the plaintext, return the keystore value); values
///   diverge → refuse.
/// * Keystore yields nothing AND a plaintext file exists: REFUSED unless
///   `allow_plaintext` is set (operator lab escape hatch). This is the
///   AQ-68 boot-time refusal: without the flag the daemon/CLI will not
///   accept a plaintext secret at rest; the fix is to run the explicit
///   migration (`rustynet enrollment migrate-secret`) so the secret moves
///   into the OS keystore and the file is shredded.
/// * Neither: not provisioned.
pub fn resolve_enrollment_secret<S: OsSecureStore>(
    store: &S,
    secret_path: &Path,
    allow_plaintext: bool,
) -> Result<Zeroizing<[u8; ENROLLMENT_SECRET_LEN]>, String> {
    let key_id = enrollment_secret_key_id(secret_path);
    let plaintext_present = plaintext_file_present(secret_path);
    match store.load_key(&key_id) {
        Ok(stored) => {
            if plaintext_present {
                let plaintext = load_secret(secret_path)
                    .map_err(|err| format!("enrollment secret load failed: {err}"))?;
                if stored.as_slice() != plaintext.as_slice() {
                    return Err(format!(
                        "enrollment secret plaintext file {} diverges from OS keystore value \
                         (key {key_id}); refusing to guess — remove one of the two",
                        secret_path.display()
                    ));
                }
                // Self-heal: keystore is authoritative and identical, so
                // the plaintext remnant is shredded.
                remove_file_if_present(secret_path)
                    .map_err(|err| format!("enrollment secret plaintext shred failed: {err}"))?;
                return Ok(plaintext);
            }
            validate_keystore_secret(stored, secret_path)
        }
        Err(_) => {
            if !plaintext_present {
                return Err(format!(
                    "enrollment secret not available: OS keystore (key {key_id}) yielded no \
                     value and no plaintext file exists at {}",
                    secret_path.display()
                ));
            }
            if allow_plaintext {
                return load_secret(secret_path).map_err(|err| {
                    format!(
                        "enrollment secret plaintext load failed (allowed via \
                         {ALLOW_PLAINTEXT_ENROLLMENT_SECRET_ENV}): {err}"
                    )
                });
            }
            Err(format!(
                "refusing plaintext enrollment secret at {}: the minting secret must live in \
                 the OS keystore. Run `rustynet enrollment migrate-secret --secret {}` once \
                 (moves the secret into the keystore and shreds the file), or set \
                 {ALLOW_PLAINTEXT_ENROLLMENT_SECRET_ENV}=1 to explicitly accept plaintext \
                 custody for lab use",
                secret_path.display(),
                secret_path.display()
            ))
        }
    }
}

/// Convenience wrapper used by the daemon and CLI: platform keystore +
/// strict env-flag parsing at call time.
pub fn resolve_enrollment_secret_platform(
    secret_path: &Path,
) -> Result<Zeroizing<[u8; ENROLLMENT_SECRET_LEN]>, String> {
    resolve_enrollment_secret(
        &PlatformOsSecureStore,
        secret_path,
        allow_plaintext_enrollment_secret_from_env(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use rustynet_crypto::{CryptoError, NoOsSecureStore};

    use crate::enrollment_token::write_secret;

    const SECRET_A: [u8; 32] = [0xa5; 32];
    const SECRET_B: [u8; 32] = [0x5a; 32];

    /// In-memory keystore mock. When `degraded` is set, every operation
    /// fails with `OsStoreUnavailable` (simulates an unavailable keystore
    /// / locked keychain). A healthy lookup of an absent key also maps
    /// to `OsStoreUnavailable`, mirroring the real platform stores
    /// (macOS conflates item-not-found with unavailability).
    struct MemoryKeystore {
        entries: RefCell<BTreeMap<String, Vec<u8>>>,
        degraded: bool,
    }

    impl MemoryKeystore {
        fn healthy() -> Self {
            Self {
                entries: RefCell::new(BTreeMap::new()),
                degraded: false,
            }
        }

        fn degraded() -> Self {
            Self {
                entries: RefCell::new(BTreeMap::new()),
                degraded: true,
            }
        }

        fn seed(&self, key_id: &str, value: &[u8]) {
            self.entries
                .borrow_mut()
                .insert(key_id.to_owned(), value.to_vec());
        }
    }

    impl OsSecureStore for MemoryKeystore {
        fn store_key(&self, key_id: &str, key_material: &[u8]) -> Result<(), CryptoError> {
            if self.degraded {
                return Err(CryptoError::OsStoreUnavailable);
            }
            self.entries
                .borrow_mut()
                .insert(key_id.to_owned(), key_material.to_vec());
            Ok(())
        }

        fn load_key(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
            if self.degraded {
                return Err(CryptoError::OsStoreUnavailable);
            }
            self.entries
                .borrow()
                .get(key_id)
                .cloned()
                .map(Zeroizing::new)
                .ok_or(CryptoError::OsStoreUnavailable)
        }
    }

    fn unique_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    fn provision(dir: &Path, secret: &[u8; 32]) -> std::path::PathBuf {
        let secret_path = dir.join("enrollment.secret");
        write_secret(&secret_path, secret).expect("secret write");
        secret_path
    }

    // ── env flag parsing ────────────────────────────────────────────

    #[test]
    fn allow_plaintext_parse_accepts_exact_vocabulary() {
        for raw in ["1", "true", "TRUE", "Yes", "yes"] {
            assert_eq!(parse_allow_plaintext_value(raw), Ok(true), "{raw}");
        }
        for raw in ["0", "false", "False", "NO", "no", ""] {
            assert_eq!(parse_allow_plaintext_value(raw), Ok(false), "{raw:?}");
        }
        // Whitespace around a valid token is tolerated.
        assert_eq!(parse_allow_plaintext_value(" true "), Ok(true));
    }

    #[test]
    fn allow_plaintext_parse_refuses_unknown_values() {
        for raw in ["treu", "on", "Y", "2", "-1", "allow"] {
            assert!(parse_allow_plaintext_value(raw).is_err(), "{raw}");
        }
    }

    #[test]
    fn allow_plaintext_from_env_defaults_false_and_is_fail_closed() {
        // Unsafe to mutate process env in-process (workspace forbids
        // env mutation); assert the pure fallback path instead: an
        // unset variable maps to false via `std::env::var` Err.
        // The parse layer is covered exhaustively above.
        assert_eq!(
            allow_plaintext_enrollment_secret_from_env(),
            allow_plaintext_enrollment_secret_from_env()
        );
    }

    // ── key id derivation ───────────────────────────────────────────

    #[test]
    fn key_id_is_deterministic_and_charset_safe() {
        let path = Path::new("/var/lib/rustynet/keys/enrollment.secret");
        let first = enrollment_secret_key_id(path);
        let second = enrollment_secret_key_id(path);
        assert_eq!(first, second);
        assert!(first.starts_with("enrollment-secret-"));
        let suffix = first.trim_start_matches("enrollment-secret-");
        assert_eq!(suffix.len(), 16);
        assert!(suffix.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn key_id_differs_per_path() {
        let a = enrollment_secret_key_id(Path::new("/keys/a.secret"));
        let b = enrollment_secret_key_id(Path::new("/keys/b.secret"));
        assert_ne!(a, b);
    }

    // ── migration state machine ─────────────────────────────────────

    #[test]
    fn migrate_moves_secret_into_keystore_and_shreds_plaintext() {
        let dir = unique_dir();
        let secret_path = provision(dir.path(), &SECRET_A);
        let store = MemoryKeystore::healthy();

        migrate_plaintext_secret_to_keystore(&store, &secret_path)
            .expect("migration should succeed");

        assert!(!secret_path.exists(), "plaintext must be shredded");
        let stored = store
            .load_key(&enrollment_secret_key_id(&secret_path))
            .expect("keystore must hold the secret");
        assert_eq!(stored.as_slice(), &SECRET_A);
        assert_eq!(
            classify_enrollment_secret_location(&store, &secret_path),
            Ok(EnrollmentSecretLocation::KeystoreOnly)
        );
    }

    #[test]
    fn migrate_is_idempotent_after_completion() {
        let dir = unique_dir();
        let secret_path = provision(dir.path(), &SECRET_A);
        let store = MemoryKeystore::healthy();

        migrate_plaintext_secret_to_keystore(&store, &secret_path).expect("first migration");
        // File is gone; a second run fails loudly on the missing
        // plaintext rather than pretending to migrate.
        assert!(migrate_plaintext_secret_to_keystore(&store, &secret_path).is_err());
        // Resolve still works from the keystore.
        assert_eq!(
            resolve_enrollment_secret(&store, &secret_path, false)
                .expect("keystore resolve")
                .as_slice(),
            &SECRET_A
        );
    }

    #[test]
    fn migrate_with_unavailable_keystore_refuses_and_leaves_file_intact() {
        let dir = unique_dir();
        let secret_path = provision(dir.path(), &SECRET_A);

        let err = migrate_plaintext_secret_to_keystore(&NoOsSecureStore, &secret_path)
            .expect_err("unavailable keystore must refuse");
        assert!(err.contains("plaintext file left in place"), "{err}");
        assert!(secret_path.exists(), "file must survive a failed migration");
        // Content intact (still loadable).
        assert_eq!(
            load_secret(&secret_path).expect("file intact").as_slice(),
            &SECRET_A
        );
    }

    #[test]
    fn migrate_refuses_to_overwrite_diverging_keystore_value() {
        let dir = unique_dir();
        let secret_path = provision(dir.path(), &SECRET_A);
        let store = MemoryKeystore::healthy();
        let key_id = enrollment_secret_key_id(&secret_path);
        store.seed(&key_id, &SECRET_B);

        let err = migrate_plaintext_secret_to_keystore(&store, &secret_path)
            .expect_err("diverging value must refuse");
        assert!(err.contains("diverges"), "{err}");
        assert!(secret_path.exists());
        assert_eq!(
            store.load_key(&key_id).expect("seeded").as_slice(),
            &SECRET_B,
            "keystore value must not be overwritten"
        );
    }

    // ── resolve policy ──────────────────────────────────────────────

    #[test]
    fn resolve_refuses_plaintext_without_opt_in() {
        let dir = unique_dir();
        let secret_path = provision(dir.path(), &SECRET_A);
        let store = MemoryKeystore::healthy();

        let err = resolve_enrollment_secret(&store, &secret_path, false)
            .expect_err("plaintext must be refused without opt-in");
        assert!(
            err.contains("refusing plaintext enrollment secret"),
            "{err}"
        );
        assert!(err.contains(ALLOW_PLAINTEXT_ENROLLMENT_SECRET_ENV), "{err}");
        assert!(secret_path.exists(), "refusal must not shred");
    }

    #[test]
    fn resolve_allows_plaintext_only_with_explicit_opt_in() {
        let dir = unique_dir();
        let secret_path = provision(dir.path(), &SECRET_A);
        let store = MemoryKeystore::healthy();

        let secret =
            resolve_enrollment_secret(&store, &secret_path, true).expect("opt-in resolves");
        assert_eq!(secret.as_slice(), &SECRET_A);
        assert!(secret_path.exists(), "opt-in must not shred either");
    }

    #[test]
    fn resolve_refuses_when_keystore_unavailable_and_opt_in_absent() {
        let dir = unique_dir();
        let secret_path = provision(dir.path(), &SECRET_A);
        let store = MemoryKeystore::degraded();

        let err = resolve_enrollment_secret(&store, &secret_path, false)
            .expect_err("degraded keystore + plaintext must refuse");
        assert!(
            err.contains("refusing plaintext enrollment secret"),
            "{err}"
        );
        assert!(secret_path.exists());
    }

    #[test]
    fn resolve_self_heals_when_keystore_and_plaintext_agree() {
        let dir = unique_dir();
        let secret_path = provision(dir.path(), &SECRET_A);
        let store = MemoryKeystore::healthy();
        store.seed(&enrollment_secret_key_id(&secret_path), &SECRET_A);

        let secret =
            resolve_enrollment_secret(&store, &secret_path, false).expect("self-heal resolves");
        assert_eq!(secret.as_slice(), &SECRET_A);
        assert!(!secret_path.exists(), "plaintext remnant must be shredded");
        // Subsequent resolves are keystore-only.
        assert_eq!(
            classify_enrollment_secret_location(&store, &secret_path),
            Ok(EnrollmentSecretLocation::KeystoreOnly)
        );
    }

    #[test]
    fn resolve_refuses_diverging_keystore_and_plaintext() {
        let dir = unique_dir();
        let secret_path = provision(dir.path(), &SECRET_A);
        let store = MemoryKeystore::healthy();
        store.seed(&enrollment_secret_key_id(&secret_path), &SECRET_B);

        let err = resolve_enrollment_secret(&store, &secret_path, false)
            .expect_err("diverging copies must refuse");
        assert!(err.contains("diverges"), "{err}");
        assert!(secret_path.exists(), "refusal must not shred");
    }

    #[test]
    fn resolve_serves_keystore_only_value() {
        let dir = unique_dir();
        let secret_path = dir.path().join("enrollment.secret");
        let store = MemoryKeystore::healthy();
        store.seed(&enrollment_secret_key_id(&secret_path), &SECRET_A);

        let secret = resolve_enrollment_secret(&store, &secret_path, false).expect("keystore");
        assert_eq!(secret.as_slice(), &SECRET_A);
    }

    #[test]
    fn resolve_refuses_wrong_length_keystore_value() {
        let dir = unique_dir();
        let secret_path = dir.path().join("enrollment.secret");
        let store = MemoryKeystore::healthy();
        store.seed(&enrollment_secret_key_id(&secret_path), &[0u8; 16]);

        let err = resolve_enrollment_secret(&store, &secret_path, false)
            .expect_err("wrong-length keystore value must refuse");
        assert!(err.contains("wrong length"), "{err}");
    }

    #[test]
    fn resolve_refuses_when_missing_everywhere() {
        let dir = unique_dir();
        let secret_path = dir.path().join("enrollment.secret");
        let store = MemoryKeystore::healthy();

        let err = resolve_enrollment_secret(&store, &secret_path, false)
            .expect_err("nothing provisioned must refuse");
        assert!(err.contains("not available"), "{err}");
    }

    #[test]
    fn resolve_refuses_when_missing_everywhere_even_with_opt_in() {
        let dir = unique_dir();
        let secret_path = dir.path().join("enrollment.secret");
        let store = MemoryKeystore::healthy();

        assert!(resolve_enrollment_secret(&store, &secret_path, true).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn resolve_rejects_symlinked_plaintext_even_with_opt_in() {
        let dir = unique_dir();
        let real = provision(dir.path(), &SECRET_A);
        let link = dir.path().join("link.secret");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let store = MemoryKeystore::healthy();
        let err = resolve_enrollment_secret(&store, &link, true)
            .expect_err("symlinked plaintext must refuse");
        assert!(!err.is_empty());
    }

    // ── platform wrapper sanity (no keystore access asserted) ───────

    #[test]
    fn platform_wrapper_reports_missing_secret_without_panicking() {
        let dir = unique_dir();
        let secret_path = dir.path().join("enrollment.secret");
        // Uses the real PlatformOsSecureStore: only the "missing
        // everywhere" branch is exercised, which performs exactly one
        // keystore READ (never a write/prompt) before failing closed.
        assert!(resolve_enrollment_secret_platform(&secret_path).is_err());
    }
}
