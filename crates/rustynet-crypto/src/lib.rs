#![forbid(unsafe_code)]
// AQ-08 step 1: test code is exempt from the panic-family lints (deny via [lints]
// in Cargo.toml); non-test code must propagate errors instead.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

pub mod mlkem;

use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
#[cfg(target_os = "windows")]
use rustynet_windows_native::{
    apply_protected_dacl_to_path, create_new_file_with_sddl, dpapi_protect, dpapi_unprotect,
    inspect_file_sddl, WindowsDpapiScope,
};
#[cfg(target_os = "macos")]
use security_framework::os::macos::keychain::SecKeychain;
#[cfg(target_os = "macos")]
use security_framework::passwords::{get_generic_password, set_generic_password};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
// Unconditional: SecretKey::Drop and the key-envelope helpers zeroize derived
// key material on every platform, so the trait must always be in scope.
use zeroize::Zeroize;
use zeroize::Zeroizing;

#[cfg(target_os = "windows")]
const WINDOWS_DPAPI_KEY_CUSTODY_ROOT: &str = r"C:\ProgramData\RustyNet\secrets\key-custody";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn ct_eq(&self, other: &SecretKey) -> subtle::Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(REDACTED)")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // zeroize() guarantees the write is not elided by the optimizer (unlike
        // a plain fill(0), which a dead-store pass may remove since the buffer
        // is never read afterward).
        self.0.zeroize();
    }
}

#[derive(Debug)]
pub struct NodeKeyPair {
    pub public_key: PublicKey,
    pub private_key: SecretKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    InvalidLength,
    WeakMaterial,
    DeniedAlgorithm,
    PermissionDenied,
    PermissionValidationUnavailable,
    OsStoreUnavailable,
    TimeUnavailable,
    InvalidClock,
    UnsupportedProviderPolicy,
    AttestationVerificationFailed,
    Io,
    KdfFailed,
    EncryptionFailed,
    DecryptionFailed,
    /// Kernel CSPRNG (`OsRng`) was unavailable for fresh key-custody salt
    /// and nonce material. We refuse to fall back to any non-CSPRNG source
    /// (including the seeded `ThreadRng`, which on first use seeds from
    /// `OsRng` and could carry forward stale entropy): the XChaCha20-Poly1305
    /// nonce MUST be unique, and an Argon2 salt that is predictable defeats
    /// the per-blob KDF stretching invariant.
    RandomnessUnavailable,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidLength => f.write_str("invalid key length"),
            CryptoError::WeakMaterial => f.write_str("weak key material"),
            CryptoError::DeniedAlgorithm => f.write_str("algorithm denied by policy"),
            CryptoError::PermissionDenied => f.write_str("key custody permission check failed"),
            CryptoError::PermissionValidationUnavailable => {
                f.write_str("permission validation unavailable on this platform")
            }
            CryptoError::OsStoreUnavailable => f.write_str("os secure store unavailable"),
            CryptoError::TimeUnavailable => f.write_str("time source unavailable"),
            CryptoError::InvalidClock => f.write_str("invalid system clock"),
            CryptoError::UnsupportedProviderPolicy => {
                f.write_str("unsupported key custody provider policy")
            }
            CryptoError::AttestationVerificationFailed => {
                f.write_str("attestation verification failed")
            }
            CryptoError::Io => f.write_str("i/o error"),
            CryptoError::KdfFailed => f.write_str("key derivation failed"),
            CryptoError::EncryptionFailed => f.write_str("encryption failed"),
            CryptoError::DecryptionFailed => f.write_str("decryption failed"),
            CryptoError::RandomnessUnavailable => {
                f.write_str("kernel CSPRNG unavailable for key-custody material")
            }
        }
    }
}

impl Error for CryptoError {}

impl NodeKeyPair {
    /// Build a keypair from raw bytes, rejecting material that is degenerate or
    /// internally inconsistent.
    ///
    /// CRY-06: this previously validated only that neither half was all-zeros,
    /// which is close to security theatre — it rejects exactly one degenerate
    /// encoding while every other mismatch passes. Nothing checked that
    /// `public_key` is actually the key belonging to `private_key`, so the struct
    /// could hold an inconsistent pair. The crate's own test proved it: a pair of
    /// `([7; 32], [9; 32])` was accepted. Publishing such a `public_key` while
    /// signing with `private_key` yields signatures nobody can verify, or binds an
    /// identity to a key the holder does not control.
    ///
    /// The private half is an ed25519 seed (the same interpretation
    /// `Ed25519SigningProvider::from_seed` uses), so the correct public key is
    /// derivable and the pair can simply be checked.
    ///
    /// The all-zeros check is kept as a cheap early reject. It returns the same
    /// `WeakMaterial` error as the correspondence check — an earlier version of
    /// this comment wrongly claimed a distinct error. It is not redundant: an
    /// all-zero seed has a real corresponding public key, so a genuinely
    /// consistent all-zero pair is refused only by that branch. That single
    /// decisive case has no test, which is worth stating rather than implying the
    /// branch is fully covered.
    pub fn from_raw(public_key: [u8; 32], private_key: [u8; 32]) -> Result<Self, CryptoError> {
        if is_all_zeros(&public_key) || is_all_zeros(&private_key) {
            return Err(CryptoError::WeakMaterial);
        }

        // Derived from the private half; comparison is on public material, so a
        // constant-time compare buys nothing here.
        let derived = SigningKey::from_bytes(&private_key)
            .verifying_key()
            .to_bytes();
        if derived != public_key {
            return Err(CryptoError::WeakMaterial);
        }

        Ok(Self {
            public_key: PublicKey(public_key),
            private_key: SecretKey(private_key),
        })
    }
}

fn is_all_zeros(key: &[u8; 32]) -> bool {
    key.iter().all(|value| *value == 0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAlgorithm {
    Tls13,
    TunnelTransportAead,
    Ed25519,
    Sha256,
    Sha512,
    Blake2s,
    Blake2b,
    HkdfSha256,
    Argon2id,
    Aes256Gcm,
    XChaCha20Poly1305,
    Md5,
    Sha1,
    Rc4,
    Des,
    TripleDes,
    BlowfishCbc,
    WeakDh,
}

/// RSA-0003 (closed 2026-09-26): the crypto-layer compatibility-exception
/// facility was deleted (the audit's option (a)). Nothing consumed it, and
/// repairing its inverted guard would have opened an ungoverned route for
/// denylisted algorithms. `AlgorithmPolicy` is pure default-deny: allowlisted
/// algorithms pass, everything else - including every denylisted algorithm -
/// is refused with [`CryptoError::DeniedAlgorithm`]. Time-bounded
/// compatibility exceptions remain governed by rustynet-control's
/// `InsecureCompatibilityException` (`ga.rs`), which acceptance row P1-AT-12
/// exercises.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AlgorithmPolicy {}

impl AlgorithmPolicy {
    pub fn validate(
        &self,
        algorithm: CryptoAlgorithm,
        _now_unix_seconds: u64,
    ) -> Result<(), CryptoError> {
        if is_allowlisted(algorithm) {
            return Ok(());
        }

        Err(CryptoError::DeniedAlgorithm)
    }

    pub fn validate_now(&self, algorithm: CryptoAlgorithm) -> Result<(), CryptoError> {
        let now = unix_now()?;
        self.validate(algorithm, now)
    }
}

fn is_allowlisted(algorithm: CryptoAlgorithm) -> bool {
    matches!(
        algorithm,
        CryptoAlgorithm::Tls13
            | CryptoAlgorithm::TunnelTransportAead
            | CryptoAlgorithm::Ed25519
            | CryptoAlgorithm::Sha256
            | CryptoAlgorithm::Sha512
            | CryptoAlgorithm::Blake2s
            | CryptoAlgorithm::Blake2b
            | CryptoAlgorithm::HkdfSha256
            | CryptoAlgorithm::Argon2id
            | CryptoAlgorithm::Aes256Gcm
            | CryptoAlgorithm::XChaCha20Poly1305
    )
}

pub fn unix_now() -> Result<u64, CryptoError> {
    let now = SystemTime::now();
    let duration = now
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CryptoError::InvalidClock)?;
    Ok(duration.as_secs())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedKeyBlob {
    pub version: u8,
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// The result of asking a secure store *whether an item exists* without
/// treating "cannot answer" as "absent" (AQ-45 step 2, design
/// `charter/design/rustynet-control-db-atrest-v0.2.md` §4).
///
/// [`OsSecureStore::load_key`] collapses three different answers into one
/// `Err`: the item is absent, the store is broken, and the platform backend
/// cannot distinguish the two. A caller that must decide whether to mint a
/// fresh key — and must never overwrite an existing one — needs the
/// distinction, so the lookup surface reports all three:
///
/// - [`OsStoreLookup::Found`] — the item exists; the payload is the same
///   byte sequence [`OsSecureStore::load_key`] would return.
/// - [`OsStoreLookup::ProvedAbsent`] — every platform mechanism the load
///   path consults answered, and all of them positively reported "no such
///   item". Only this variant may trigger key minting.
/// - [`OsStoreLookup::Unavailable`] — the store could not answer (backend
///   failure, missing OS facility, transport error, or a load-path mechanism
///   that failed for a reason other than item-not-found). A caller must
///   treat this as "unknown", never as "absent".
#[derive(Clone, PartialEq, Eq)]
pub enum OsStoreLookup {
    Found(Zeroizing<Vec<u8>>),
    ProvedAbsent,
    Unavailable,
}

impl fmt::Debug for OsStoreLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Found payloads are key material; the Debug must never carry the
        // bytes (same discipline as `SecretKey` / `ValueCipher`).
        match self {
            OsStoreLookup::Found(_) => f.write_str("Found(REDACTED)"),
            OsStoreLookup::ProvedAbsent => f.write_str("ProvedAbsent"),
            OsStoreLookup::Unavailable => f.write_str("Unavailable"),
        }
    }
}

/// Platform-independent classification of the macOS Security framework's
/// numeric status codes (AQ-45 step 2). Kept out of the `cfg(macos)` block so
/// its unit tests — and the failure-mode contract they pin — compile and run
/// on every platform.
// The classifiers are compiled (and unit-tested) on every platform so the
// absence-proof contract is pinned everywhere; their non-test call sites are
// inside per-platform lookup paths, so on the other platforms they are
// deliberately unreferenced outside tests.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MacKeychainProbe {
    /// The framework/CLI positively reported that no matching item exists.
    ItemNotFound,
    /// Any other outcome: the keychain could not be consulted.
    Unavailable,
}

/// `errSecItemNotFound` (Security.framework `SecBase.h`; verified at
/// MacOSX.sdk `Security.framework/Headers/SecBase.h:353`).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const MACOS_ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

/// Exit code `/usr/bin/security find-generic-password` returns for a missing
/// item ("The specified item could not be found in the keychain."), verified
/// empirically on the macOS host; `security(1)` documents no exit-status
/// table, so this constant is pinned by test rather than by manpage.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const MACOS_SECURITY_CLI_EXIT_ITEM_NOT_FOUND: i32 = 44;

/// Classify a Security.framework status code: only `errSecItemNotFound`
/// counts as a positive "absent" answer; every other code (including
/// `errSecNoDefaultKeychain`) means the keychain could not be consulted.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn classify_macos_framework_status(code: i32) -> MacKeychainProbe {
    if code == MACOS_ERR_SEC_ITEM_NOT_FOUND {
        MacKeychainProbe::ItemNotFound
    } else {
        MacKeychainProbe::Unavailable
    }
}

/// Classify a `/usr/bin/security` exit status. `None` (terminated by signal)
/// and any unrecognized code are inconclusive.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn classify_macos_cli_exit(exit: Option<i32>) -> MacKeychainProbe {
    match exit {
        Some(code) if code == MACOS_SECURITY_CLI_EXIT_ITEM_NOT_FOUND => {
            MacKeychainProbe::ItemNotFound
        }
        _ => MacKeychainProbe::Unavailable,
    }
}

/// `errSecNoDefaultKeychain` (Security.framework `SecBase.h`): the process
/// has no default keychain, which is the normal state for a headless
/// launchd daemon (AQ-45 step-2 review finding F6; owner decision OI-21
/// blesses daemons on the file-based System keychain).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const MACOS_ERR_SEC_NO_DEFAULT_KEYCHAIN: i32 = -25307;

/// Outcome of macOS lookup probe 1 (framework read of the session's DEFAULT
/// keychain) for absence-conjunction purposes (AQ-45 review finding F6).
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MacosDefaultKeychainProbe {
    /// The default keychain was consulted and does not hold the item.
    ItemNotFound,
    /// The process has NO default keychain (`errSecNoDefaultKeychain`,
    /// -25307): the probe did not consult any keychain, and on the OI-21(a)
    /// daemon deployment shape that is expected, not a store failure. This
    /// outcome is NOT APPLICABLE and must not poison the absence
    /// conjunction; the System-keychain probes (2 and 3) still have to prove
    /// absence positively on their own.
    NotApplicableNoDefaultKeychain,
    /// Any other failure: a keychain was there but could not be consulted.
    Unavailable,
}

/// Classify macOS probe 1's framework status code. ONLY
/// [`MACOS_ERR_SEC_NO_DEFAULT_KEYCHAIN`] is not-applicable; any other error
/// (including [`MACOS_ERR_SEC_ITEM_NOT_FOUND`], handled here for
/// completeness) keeps its existing meaning, and every other code stays
/// `Unavailable`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn classify_macos_default_keychain_probe(code: i32) -> MacosDefaultKeychainProbe {
    if code == MACOS_ERR_SEC_NO_DEFAULT_KEYCHAIN {
        MacosDefaultKeychainProbe::NotApplicableNoDefaultKeychain
    } else {
        match classify_macos_framework_status(code) {
            MacKeychainProbe::ItemNotFound => MacosDefaultKeychainProbe::ItemNotFound,
            MacKeychainProbe::Unavailable => MacosDefaultKeychainProbe::Unavailable,
        }
    }
}

/// The absence conjunction across macOS lookup probes 1/2/3 (AQ-45 review
/// finding F6): `true` (candidate for `ProvedAbsent`) only when every
/// APPLICABLE probe positively answered item-not-found. A probe-1
/// not-applicable (`errSecNoDefaultKeychain`, headless daemon) does not
/// poison the conjunction, but BOTH System-keychain probes (2 and 3) must
/// still prove absence positively; any other probe-1 error — and any
/// probe-2/3 failure — makes the conjunction false (`Unavailable`).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn combine_macos_absence_probes(
    probe1_default_keychain: MacosDefaultKeychainProbe,
    probe2_system_owned: MacKeychainProbe,
    probe3_system_cli: MacKeychainProbe,
) -> bool {
    let probe1_ok = matches!(
        probe1_default_keychain,
        MacosDefaultKeychainProbe::ItemNotFound
            | MacosDefaultKeychainProbe::NotApplicableNoDefaultKeychain
    );
    probe1_ok
        && probe2_system_owned == MacKeychainProbe::ItemNotFound
        && probe3_system_cli == MacKeychainProbe::ItemNotFound
}

/// Platform-independent classification of a `secret-tool search --all`
/// invocation (AQ-45 step 2), compiled on every platform for the same reason
/// as [`classify_macos_framework_status`].
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxSecretToolProbe {
    /// `search --all` succeeded and printed nothing: no item carries the
    /// attribute among the items VISIBLE to the session's secret service.
    /// On a host with no reachable secret service the same outcome occurs
    /// vacuously (verified live: exit 0, empty stdout), so this alone is NOT
    /// an absence proof — [`lookup_linux_secret_service`] additionally
    /// requires [`classify_linux_secrets_name_has_owner`] to confirm that
    /// `org.freedesktop.secrets` actually has an owner on the session bus.
    ProvedNoItems,
    /// Success with output (item exists — inconclusive for absence) or any
    /// failure (no reachable secret service, transport error).
    Inconclusive,
}

/// Classify `secret-tool search --all <attr> <value>`: an empty result is
/// only the search half of the absence proof. `secret-tool lookup` cannot
/// play any role here: it exits non-zero both for absent items and for
/// "could not connect" (verified live), so its failure is ambiguous.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn classify_linux_secret_tool_search(
    success: bool,
    stdout_empty: bool,
) -> LinuxSecretToolProbe {
    if success && stdout_empty {
        LinuxSecretToolProbe::ProvedNoItems
    } else {
        LinuxSecretToolProbe::Inconclusive
    }
}

/// Outcome of the `org.freedesktop.secrets` name-owner check that turns a
/// `LinuxSecretToolProbe::ProvedNoItems` search result into an absence
/// proof (AQ-45 review finding F2).
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxSecretServicePresence {
    /// `org.freedesktop.secrets` has an owner on the session bus: a secret
    /// service is actually running and the empty search result is meaningful.
    Owned,
    /// The name has no owner, `dbus-send` is not installed, or the check
    /// failed for any reason (no session bus, non-zero exit, malformed
    /// reply). The empty search result is vacuous; the lookup is
    /// `Unavailable`.
    Unavailable,
}

/// Classify a `dbus-send --session --print-reply --dest=org.freedesktop.DBus
/// /org/freedesktop/DBus org.freedesktop.DBus.NameHasOwner
/// string:org.freedesktop.secrets` outcome. `reply_says_owned` is
/// `Some(true)`/`Some(false)` when the daemon answered with a D-Bus boolean,
/// and `None` for every failure shape: `dbus-send` missing (spawn error),
/// no session bus, non-zero exit, or an unparseable reply. ONLY an owned
/// name completes the absence proof; every other outcome is `Unavailable`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn classify_linux_secrets_name_has_owner(
    reply_says_owned: Option<bool>,
) -> LinuxSecretServicePresence {
    match reply_says_owned {
        Some(true) => LinuxSecretServicePresence::Owned,
        Some(false) | None => LinuxSecretServicePresence::Unavailable,
    }
}

/// Platform-independent classification of a Windows file-stat failure
/// (AQ-45 step 2).
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsDpapiProbe {
    /// The DPAPI blob file does not exist.
    ItemNotFound,
    /// Any other stat failure (permission, I/O).
    Unavailable,
}

/// Classify a `symlink_metadata` error kind for a DPAPI blob path.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn classify_windows_dpapi_item_missing(kind: std::io::ErrorKind) -> WindowsDpapiProbe {
    if kind == std::io::ErrorKind::NotFound {
        WindowsDpapiProbe::ItemNotFound
    } else {
        WindowsDpapiProbe::Unavailable
    }
}

pub trait OsSecureStore {
    fn store_key(&self, key_id: &str, key_material: &[u8]) -> Result<(), CryptoError>;
    fn load_key(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError>;

    /// Ask the store whether `key_id` exists, preserving the "cannot answer"
    /// case ([`OsStoreLookup`]).
    ///
    /// The provided default is deliberately conservative: it can report
    /// `Found` or `Unavailable` but never `ProvedAbsent`, because a
    /// `load_key` error cannot distinguish "absent" from "broken". Only
    /// backends whose platform mechanisms can *prove* absence override this;
    /// every existing implementor therefore keeps its exact previous
    /// behavior and can never cause a caller to mint replacement keys.
    fn lookup_key(&self, key_id: &str) -> OsStoreLookup {
        match self.load_key(key_id) {
            Ok(value) => OsStoreLookup::Found(value),
            Err(_) => OsStoreLookup::Unavailable,
        }
    }

    /// Store `key_material` under `key_id` refusing to overwrite an existing
    /// item ("create-only").
    ///
    /// The provided default refuses unconditionally: a backend that cannot
    /// prove create-only semantics must not silently degrade to the upsert
    /// behavior of [`OsSecureStore::store_key`]. An `Err` here means "did not
    /// store"; the item, if any, is untouched.
    fn store_key_create_only(
        &self,
        _key_id: &str,
        _key_material: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::OsStoreUnavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCustodyBackend {
    OsSecureStore,
    EncryptedFileFallback,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NoOsSecureStore;

impl OsSecureStore for NoOsSecureStore {
    fn store_key(&self, _key_id: &str, _key_material: &[u8]) -> Result<(), CryptoError> {
        Err(CryptoError::OsStoreUnavailable)
    }

    fn load_key(&self, _key_id: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        Err(CryptoError::OsStoreUnavailable)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PlatformOsSecureStore;

impl OsSecureStore for PlatformOsSecureStore {
    fn store_key(&self, key_id: &str, key_material: &[u8]) -> Result<(), CryptoError> {
        #[cfg(target_os = "macos")]
        {
            store_in_macos_keychain(key_id, key_material)
        }
        #[cfg(target_os = "linux")]
        {
            store_in_linux_secret_service(key_id, key_material)
        }
        #[cfg(target_os = "windows")]
        {
            store_in_windows_dpapi(key_id, key_material)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            let _ = (key_id, key_material);
            Err(CryptoError::OsStoreUnavailable)
        }
    }

    fn load_key(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        #[cfg(target_os = "macos")]
        {
            load_from_macos_keychain(key_id)
        }
        #[cfg(target_os = "linux")]
        {
            load_from_linux_secret_service(key_id)
        }
        #[cfg(target_os = "windows")]
        {
            load_from_windows_dpapi(key_id)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            let _ = key_id;
            Err(CryptoError::OsStoreUnavailable)
        }
    }

    fn lookup_key(&self, key_id: &str) -> OsStoreLookup {
        #[cfg(target_os = "macos")]
        {
            lookup_macos_keychain(key_id)
        }
        #[cfg(target_os = "linux")]
        {
            lookup_linux_secret_service(key_id)
        }
        #[cfg(target_os = "windows")]
        {
            lookup_windows_dpapi(key_id)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            let _ = key_id;
            OsStoreLookup::Unavailable
        }
    }

    fn store_key_create_only(&self, key_id: &str, key_material: &[u8]) -> Result<(), CryptoError> {
        #[cfg(target_os = "macos")]
        {
            store_in_macos_keychain_create_only(key_id, key_material)
        }
        #[cfg(target_os = "linux")]
        {
            store_in_linux_secret_service_create_only(key_id, key_material)
        }
        #[cfg(target_os = "windows")]
        {
            store_in_windows_dpapi_create_only(key_id, key_material)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            let _ = (key_id, key_material);
            Err(CryptoError::OsStoreUnavailable)
        }
    }
}

pub struct KeyCustodyManager<S: OsSecureStore> {
    os_store: S,
    fallback_directory: PathBuf,
    fallback_passphrase: Zeroizing<String>,
    permission_policy: KeyCustodyPermissionPolicy,
    fallback_policy: OsStoreFallbackPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OsStoreFallbackPolicy {
    #[default]
    AllowEncryptedFileFallback,
    RequireOsSecureStore,
}

impl<S: OsSecureStore> KeyCustodyManager<S> {
    pub fn new(
        os_store: S,
        fallback_directory: PathBuf,
        fallback_passphrase: String,
        permission_policy: KeyCustodyPermissionPolicy,
    ) -> Self {
        Self::new_zeroizing(
            os_store,
            fallback_directory,
            Zeroizing::new(fallback_passphrase),
            permission_policy,
        )
    }

    pub fn new_zeroizing(
        os_store: S,
        fallback_directory: PathBuf,
        fallback_passphrase: Zeroizing<String>,
        permission_policy: KeyCustodyPermissionPolicy,
    ) -> Self {
        Self {
            os_store,
            fallback_directory,
            fallback_passphrase,
            permission_policy,
            fallback_policy: OsStoreFallbackPolicy::default(),
        }
    }

    pub fn with_fallback_policy(mut self, policy: OsStoreFallbackPolicy) -> Self {
        self.fallback_policy = policy;
        self
    }

    pub fn store_private_key(
        &self,
        key_id: &str,
        key_material: &[u8],
    ) -> Result<KeyCustodyBackend, CryptoError> {
        match self.os_store.store_key(key_id, key_material) {
            Ok(()) => Ok(KeyCustodyBackend::OsSecureStore),
            Err(CryptoError::OsStoreUnavailable) => {
                if matches!(
                    self.fallback_policy,
                    OsStoreFallbackPolicy::RequireOsSecureStore
                ) {
                    return Err(CryptoError::OsStoreUnavailable);
                }
                let file_path = self.fallback_file_path(key_id)?;
                write_encrypted_key_file(
                    &self.fallback_directory,
                    &file_path,
                    key_material,
                    self.fallback_passphrase.as_str(),
                    self.permission_policy,
                )?;
                Ok(KeyCustodyBackend::EncryptedFileFallback)
            }
            Err(other) => Err(other),
        }
    }

    pub fn load_private_key(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        match self.os_store.load_key(key_id) {
            Ok(key) => Ok(key),
            Err(CryptoError::OsStoreUnavailable) => {
                if matches!(
                    self.fallback_policy,
                    OsStoreFallbackPolicy::RequireOsSecureStore
                ) {
                    return Err(CryptoError::OsStoreUnavailable);
                }
                let file_path = self.fallback_file_path(key_id)?;
                read_encrypted_key_file(
                    &self.fallback_directory,
                    &file_path,
                    self.fallback_passphrase.as_str(),
                    self.permission_policy,
                )
            }
            Err(other) => Err(other),
        }
    }

    fn fallback_file_path(&self, key_id: &str) -> Result<PathBuf, CryptoError> {
        if !is_valid_key_identifier(key_id) {
            return Err(CryptoError::InvalidLength);
        }
        Ok(self.fallback_directory.join(format!("{key_id}.enc")))
    }
}

fn is_valid_key_identifier(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

#[cfg(target_os = "macos")]
fn store_in_macos_keychain(key_id: &str, key_material: &[u8]) -> Result<(), CryptoError> {
    // Validate the identifier before it is interpolated into the keychain
    // service name, mirroring the file-fallback and Windows custody paths.
    // The CLI invocation is already argv-only (no shell), so this is
    // defense-in-depth against keychain-namespace confusion, not injection.
    if !is_valid_key_identifier(key_id) {
        return Err(CryptoError::InvalidLength);
    }
    store_macos_generic_password(
        format!("rustynet.{key_id}").as_str(),
        "rustynet",
        key_material,
    )
}

#[cfg(target_os = "macos")]
fn load_from_macos_keychain(key_id: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if !is_valid_key_identifier(key_id) {
        return Err(CryptoError::InvalidLength);
    }
    let mut value = load_macos_generic_password(format!("rustynet.{key_id}").as_str(), "rustynet")
        .map_err(|_| CryptoError::OsStoreUnavailable)?;

    if let Ok(text) = std::str::from_utf8(&value) {
        let trimmed = text.trim();
        let maybe_hex_decoded = (!trimmed.is_empty()
            && (trimmed.len() & 1) == 0
            && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| hex_decode(trimmed))
        .and_then(Result::ok);
        if let Some(decoded) = maybe_hex_decoded {
            value.zeroize();
            return Ok(Zeroizing::new(decoded));
        }
    }

    Ok(Zeroizing::new(value))
}

/// Absolute path to the macOS System keychain.
///
/// Service-account / launchd-managed callers (`rustynetd`) have no
/// user-session default keychain, so any `SecItem`/`set_generic_password`
/// call that targets the default keychain fails with
/// `errSecNoDefaultKeychain` (-25307). The System keychain is the
/// hardened fallback the daemon reads from at startup; the load-side
/// already targets it via the `security` CLI. Mirroring that target
/// here closes Gap H surfaced in Phase 24 live validation.
#[cfg(target_os = "macos")]
pub const MACOS_SYSTEM_KEYCHAIN_PATH: &str = "/Library/Keychains/System.keychain";

/// Strict allow-list for the keychain `service` and `account` labels we
/// hand to `SecKeychain::set_generic_password`. The safe Rust API does
/// not interpolate shell metacharacters, but defense-in-depth still
/// rejects whitespace, control bytes, NUL, and over-long values that
/// could confuse Keychain Services. CWE-20 / SecurityMinimumBar §3.7.
#[cfg(target_os = "macos")]
pub(crate) fn validate_macos_keychain_label(field: &str, value: &str) -> Result<(), CryptoError> {
    let _ = field;
    if value.is_empty() {
        return Err(CryptoError::OsStoreUnavailable);
    }
    if value.len() > 128 {
        return Err(CryptoError::OsStoreUnavailable);
    }
    if !value.chars().all(|ch| {
        ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '/' | '+' | '@')
    }) {
        return Err(CryptoError::OsStoreUnavailable);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn store_macos_generic_password(
    service: &str,
    account: &str,
    secret: &[u8],
) -> Result<(), CryptoError> {
    validate_macos_keychain_label("service", service)?;
    validate_macos_keychain_label("account", account)?;
    // A root writer (bootstrap / installer provisioning key custody for the
    // launchd daemon) always targets the System keychain, never the default
    // one. `sudo` from a console user's session leaves THAT user's login
    // keychain as root's default, so the default-first path below silently
    // stored the gossip signing key in the operator's login keychain, where
    // the daemon (uid rustynetd, no login session) can never read it: the
    // daemon then died at start with "gossip signing secret load failed: os
    // secure store unavailable" (live macOS lab runs 27-29). The daemon only
    // ever reads the System keychain, and the owned store deletes any prior
    // item and re-binds it to this binary, so re-minting also works.
    if nix::unistd::Uid::effective().is_root() {
        return store_macos_generic_password_system_keychain_owned(service, account, secret);
    }
    // Default keychain first. Works for an interactive operator/CLI run from
    // a login shell — the user-session keychain is the canonical place for
    // per-user secrets.
    if set_generic_password(service, account, secret).is_ok() {
        return Ok(());
    }
    // Fallback: target the System keychain explicitly. Required for the
    // launchd-managed daemon and for any other context that lacks a
    // reachable default keychain (e.g. `sudo -u rustynetd ... key init`).
    // Mirrors the load-side fallback in `load_macos_generic_password`.
    store_macos_generic_password_system_keychain(service, account, secret)
}

/// Store a System-keychain generic password with an allow-any-application
/// ACL (`security add-generic-password -A`).
///
/// Use this for secrets that must be read back by a *different* binary than
/// the one that stored them — e.g. the trust signing-key passphrase, stored by
/// `rustynetd` at bootstrap and read by `rustynet ops refresh-signed-trust` via
/// `/usr/bin/security -w`. The default [`store_macos_generic_password`] path
/// prefers the `SecKeychain` framework, which binds read access to the storing
/// binary's code-signing identity and would deny the cross-binary reader. This
/// entry point goes straight to the `-A` CLI path so any local application can
/// read the item (single-tenant service-account install layout; see the
/// rationale on `store_macos_generic_password_system_keychain_via_security_cli`).
#[cfg(target_os = "macos")]
pub fn store_macos_generic_password_allow_any_app(
    service: &str,
    account: &str,
    secret: &[u8],
) -> Result<(), CryptoError> {
    validate_macos_keychain_label("service", service)?;
    validate_macos_keychain_label("account", account)?;
    store_macos_generic_password_system_keychain_via_security_cli(service, account, secret)
}

/// Targets the macOS System keychain. First attempts the legacy `SecKeychain`
/// framework API; falls back to `/usr/bin/security add-generic-password`
/// when the framework path fails. macOS 26 has progressively deprecated
/// the `SecKeychain*` family for headless / service-account contexts — on
/// the Phase 24 lab VM (macOS 26.5) `SecKeychainAddGenericPassword` fails
/// with an opaque error even when (a) the calling uid is root, (b) the
/// System.keychain is verifiably unlocked at the shell level via
/// `security unlock-keychain`, and (c) the same write succeeds when issued
/// through `security add-generic-password ... /Library/Keychains/System.keychain`.
/// Mirrors `load_macos_generic_password`'s shell-CLI fallback so the
/// store / load surfaces converge on the same enforcement point.
///
/// **Argv exposure**: `security add-generic-password` accepts the password
/// only via `-w <password>` (argv) or interactive TTY prompt. There is no
/// stdin / file-descriptor / file-path option (verified against the macOS
/// `security(1)` manpage). The bootstrap-time call runs as root in a
/// single-shot context with no other same-uid processes; the argv window
/// is the lifetime of the `security` exec (~50 ms) and is observable only
/// to other root processes, which already have full system access. We
/// accept that trade-off here to unblock the bootstrap on macOS where the
/// framework path is unreliable.
#[cfg(target_os = "macos")]
fn store_macos_generic_password_system_keychain(
    service: &str,
    account: &str,
    secret: &[u8],
) -> Result<(), CryptoError> {
    validate_macos_keychain_label("service", service)?;
    validate_macos_keychain_label("account", account)?;
    if let Ok(mut keychain) = SecKeychain::open(MACOS_SYSTEM_KEYCHAIN_PATH) {
        let _ = keychain.unlock(Some(""));
        if keychain
            .set_generic_password(service, account, secret)
            .is_ok()
        {
            return Ok(());
        }
    }
    store_macos_generic_password_system_keychain_via_security_cli(service, account, secret)
}

/// `/usr/bin/security`-backed write path for the macOS System keychain.
/// Mirrors `load_macos_generic_password`'s CLI fallback. Service / account
/// were validated upstream by `validate_macos_keychain_label` (caller
/// `store_macos_generic_password_system_keychain` runs the label check
/// before delegating here); the password argv exposure trade-off is
/// documented at the caller — validated upstream.
#[cfg(target_os = "macos")]
fn store_macos_generic_password_system_keychain_via_security_cli(
    service: &str,
    account: &str,
    secret: &[u8],
) -> Result<(), CryptoError> {
    // service / account labels validated upstream by the dispatcher
    // (store_macos_generic_password_system_keychain calls
    // validate_macos_keychain_label before delegating here).
    // Reject embedded NULs so the password cannot be truncated by C-string
    // handling inside the `security` CLI's argv parser.
    if secret.contains(&0) {
        return Err(CryptoError::OsStoreUnavailable);
    }
    let secret_str = std::str::from_utf8(secret).map_err(|_| CryptoError::OsStoreUnavailable)?;
    // `-A` allows any application on the same host to read the item without
    // an additional ACL prompt. Required because the daemon
    // (`/usr/local/bin/rustynetd`, uid 500) reads the item via a *different*
    // process from the one that stored it (`/usr/bin/security`, here run as
    // root by the bootstrap), and the default System.keychain ACL would
    // bind read access to the storing app's code-signing identity. The
    // alternative `-T <app>` flag is per-app — not appropriate here because
    // load_macos_generic_password's CLI fallback also goes through
    // `/usr/bin/security`, so a one-app ACL would block our own loader.
    // For the single-tenant lab / service-account install layout this is
    // the canonical pattern; revisit if/when the host hosts multiple
    // tenants that must not share keychain item access.
    //
    // Delete-then-add (rather than `-U` update): `add-generic-password -U`
    // updates the password slot but keeps the existing ACL. If a previous
    // bootstrap stored the item with a more restrictive ACL (e.g. before
    // this -A flag landed, or via a different code-signing identity), -U
    // alone leaves that ACL intact and the daemon's load path still fails
    // with errSecAuthFailed. Delete-first forces a fresh ACL on every store.
    let _ = std::process::Command::new("/usr/bin/security")
        .args([
            "delete-generic-password",
            "-a",
            account,
            "-s",
            service,
            "/Library/Keychains/System.keychain",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let status = std::process::Command::new("/usr/bin/security")
        .args([
            "add-generic-password",
            "-A",
            "-a",
            account,
            "-s",
            service,
            "-w",
            secret_str,
            "/Library/Keychains/System.keychain",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|_| CryptoError::OsStoreUnavailable)?;
    if !status.success() {
        return Err(CryptoError::OsStoreUnavailable);
    }
    // Read-back verification, fail-closed. On macOS 26 `add-generic-password`
    // can exit 0 without leaving a *readable* System.keychain item — the daemon
    // (launchd, no user session) then fails its tunnel-key decrypt at startup with
    // `os secure store unavailable` and crash-loops, with no signal at
    // provisioning time. Confirm the secret reads back through the SAME CLI path
    // the daemon's loader uses (`security find-generic-password -w … System.keychain`)
    // so a silent custody-store failure is caught here, not hours later as an
    // opaque daemon exit. `-w` exercises the read ACL (a write-but-unreadable
    // item fails this), which a bare attribute lookup would not.
    let verified = std::process::Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-a",
            account,
            "-s",
            service,
            "-w",
            "/Library/Keychains/System.keychain",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if verified {
        Ok(())
    } else {
        Err(CryptoError::OsStoreUnavailable)
    }
}

#[cfg(target_os = "macos")]
pub fn load_macos_generic_password(service: &str, account: &str) -> Result<Vec<u8>, CryptoError> {
    if service.trim().is_empty() || account.trim().is_empty() {
        return Err(CryptoError::OsStoreUnavailable);
    }
    // Try the framework API first (works in GUI/user sessions with default keychain).
    if let Ok(pw) = get_generic_password(service, account) {
        return Ok(pw);
    }
    // Next: the System keychain, scoped and read via `SecItemCopyMatching` as
    // the calling binary's own code-signing identity. This is where
    // `store_macos_generic_password_system_keychain_owned` places items (e.g.
    // the WG key passphrase). Required for the launchd daemon, whose default
    // search list does not reliably include the System keychain and which cannot
    // read legacy `-A` items cross-session.
    if let Ok(pw) = load_macos_generic_password_system_keychain_owned(service, account) {
        return Ok(pw);
    }
    // Fallback: query the System keychain explicitly via the security CLI.
    // Required for legacy `-A` items stored by `store_macos_generic_password_allow_any_app`
    // (e.g. the trust signing-key passphrase, read by the `rustynet` CLI).
    // service/account are validated upstream (normalize_macos_keychain_account).
    let output = std::process::Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-a",
            account,
            "-s",
            service,
            "-w",
            "/Library/Keychains/System.keychain",
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|_| CryptoError::OsStoreUnavailable)?;
    if output.status.success() {
        let mut bytes = output.stdout;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        return Ok(bytes);
    }
    Err(CryptoError::OsStoreUnavailable)
}

/// Store a generic password into the macOS **System** keychain via the modern
/// `SecItemAdd` API ([`security_framework::item::ItemAddOptions`]), owned by the
/// *calling binary's* code-signing identity. The same signed binary reads it
/// back cross-session via [`load_macos_generic_password_system_keychain_owned`];
/// no other binary — not even `/usr/bin/security` — can read it.
///
/// This is the correct, tightest custody for a secret that is both written and
/// read by `rustynetd`: the tunnel key passphrase is stored at bootstrap by
/// `rustynetd key store-passphrase` (running as root) and read at daemon startup
/// by the same `rustynetd` binary (running as the uid-500 service account).
/// Rust binaries are ad-hoc linker-signed on macOS arm64, giving `rustynetd` a
/// stable code identity across both invocations.
///
/// **Why not the other write paths** (all verified live on macOS 26.5):
/// - The deprecated `SecKeychainAddGenericPassword` family (used by
///   [`store_macos_generic_password_system_keychain`]) fails opaquely for the
///   System keychain even as root with the keychain unlocked.
/// - The `-A` `security`-CLI path
///   ([`store_macos_generic_password_allow_any_app`]) writes an item whose
///   secret is **not** readable across a login-session boundary — the launchd
///   daemon (and even root in a fresh session) gets `errSecAuthFailed`, because
///   macOS gates generic-password secret reads by a partition list keyed on
///   code-signing identity and `-A` does not place a usable entry on it.
/// - This `SecItemAdd` path makes the storing binary's stable-cdhash identity
///   the partition owner; the same binary reads it back in any later session and
///   as any uid (proven: cross-session read succeeds for root *and* the uid-500
///   daemon, while the `security` CLI is correctly denied).
#[cfg(target_os = "macos")]
pub fn store_macos_generic_password_system_keychain_owned(
    service: &str,
    account: &str,
    secret: &[u8],
) -> Result<(), CryptoError> {
    use core_foundation::data::CFData;
    use security_framework::item::{ItemAddOptions, ItemAddValue, ItemClass, Location};
    validate_macos_keychain_label("service", service)?;
    validate_macos_keychain_label("account", account)?;
    // Reject embedded NULs: the delete helper below passes account/service as
    // argv to `security`, where C-string handling would truncate at a NUL.
    if secret.contains(&0) || service.as_bytes().contains(&0) || account.as_bytes().contains(&0) {
        return Err(CryptoError::OsStoreUnavailable);
    }
    let mut keychain = SecKeychain::open(MACOS_SYSTEM_KEYCHAIN_PATH)
        .map_err(|_| CryptoError::OsStoreUnavailable)?;
    // The System keychain is auto-unlocked via /var/db/SystemKey; this is a
    // best-effort no-op when it is already unlocked.
    let _ = keychain.unlock(Some(""));
    // Remove any prior item so the fresh `SecItemAdd` re-establishes ownership
    // by *this* binary's identity. A previous bootstrap may have stored the item
    // via the legacy `-A` CLI path (partition owned by `apple-tool:`) or under a
    // different identity; without the delete, `SecItemAdd` returns
    // `errSecDuplicateItem` and the stale ACL/partition survives. The delete
    // carries no secret in argv (only the validated service/account attributes),
    // so it does not share the `-A` add path's argv-exposure trade-off, and root
    // can delete an item regardless of its read partition.
    delete_macos_system_keychain_generic_password_via_cli(service, account);
    let mut opts = ItemAddOptions::new(ItemAddValue::Data {
        class: ItemClass::generic_password(),
        data: CFData::from_buffer(secret),
    });
    opts.set_service(service)
        .set_account_name(account)
        .set_location(Location::FileKeychain(keychain));
    opts.add().map_err(|_| CryptoError::OsStoreUnavailable)?;
    // Fail-closed read-back through the *same* `SecItemCopyMatching` path the
    // daemon's loader uses, so a silent store failure surfaces here at
    // provisioning time rather than as an opaque daemon crash-loop hours later.
    match load_macos_generic_password_system_keychain_owned(service, account) {
        Ok(got) if got.as_slice() == secret => Ok(()),
        _ => Err(CryptoError::OsStoreUnavailable),
    }
}

/// Read a generic password owned by the calling binary from the macOS System
/// keychain via `SecItemCopyMatching`
/// ([`security_framework::item::ItemSearchOptions`]) scoped explicitly to
/// `/Library/Keychains/System.keychain`. Counterpart to
/// [`store_macos_generic_password_system_keychain_owned`]; see that function for
/// the macOS-26 rationale.
#[cfg(target_os = "macos")]
pub fn load_macos_generic_password_system_keychain_owned(
    service: &str,
    account: &str,
) -> Result<Vec<u8>, CryptoError> {
    use security_framework::item::{ItemClass, ItemSearchOptions, SearchResult};
    if service.trim().is_empty() || account.trim().is_empty() {
        return Err(CryptoError::OsStoreUnavailable);
    }
    let keychain = SecKeychain::open(MACOS_SYSTEM_KEYCHAIN_PATH)
        .map_err(|_| CryptoError::OsStoreUnavailable)?;
    let keychains = [keychain];
    let results = ItemSearchOptions::new()
        .keychains(&keychains)
        .class(ItemClass::generic_password())
        .service(service)
        .account(account)
        .load_data(true)
        .limit(1i64)
        .search()
        .map_err(|_| CryptoError::OsStoreUnavailable)?;
    for result in results {
        if let SearchResult::Data(data) = result {
            return Ok(data);
        }
    }
    Err(CryptoError::OsStoreUnavailable)
}

/// Does a generic-password item for `service`/`account` exist in the macOS
/// **System** keychain? Attribute-only `SecItemCopyMatching` scoped to
/// `/Library/Keychains/System.keychain` — the secret is never loaded, so a
/// custody PROBE can run as any uid without touching the passphrase. Returns
/// `Ok(false)` when no item matches, and `Err` when the keychain cannot be
/// opened or searched (fail closed at the caller: "unknown" is not "present").
///
/// This deliberately does NOT prove the daemon identity can read the secret
/// (that is `load_macos_generic_password_system_keychain_owned`, which the
/// daemon exercises at startup); it proves the item is where the reviewed
/// custody contract says the passphrase lives, which is what a key-custody
/// report is allowed to assert without handling key material.
#[cfg(target_os = "macos")]
pub fn macos_system_keychain_generic_password_present(
    service: &str,
    account: &str,
) -> Result<bool, CryptoError> {
    use security_framework::item::{ItemClass, ItemSearchOptions};
    if service.trim().is_empty() || account.trim().is_empty() {
        return Err(CryptoError::OsStoreUnavailable);
    }
    let keychain = SecKeychain::open(MACOS_SYSTEM_KEYCHAIN_PATH)
        .map_err(|_| CryptoError::OsStoreUnavailable)?;
    let keychains = [keychain];
    match ItemSearchOptions::new()
        .keychains(&keychains)
        .class(ItemClass::generic_password())
        .service(service)
        .account(account)
        .load_attributes(true)
        .limit(1i64)
        .search()
    {
        Ok(results) => Ok(!results.is_empty()),
        // errSecItemNotFound is the framework's "no match" answer; every other
        // error is a keychain problem the caller must treat as unknown.
        Err(err) if err.code() == -25300 => Ok(false),
        Err(_) => Err(CryptoError::OsStoreUnavailable),
    }
}

/// `/usr/bin/security delete-generic-password` against the System keychain.
/// Used to clear a prior item before an owned `SecItemAdd` re-store. Carries no
/// secret in argv; service/account are validated by the caller.
#[cfg(target_os = "macos")]
fn delete_macos_system_keychain_generic_password_via_cli(service: &str, account: &str) {
    let _ = std::process::Command::new("/usr/bin/security")
        .args([
            "delete-generic-password",
            "-a",
            account,
            "-s",
            service,
            "/Library/Keychains/System.keychain",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Normalize a macOS keychain payload the same way
/// [`load_from_macos_keychain`] does (hex-decode-if-hex, legacy compat), so a
/// [`OsStoreLookup::Found`] payload is byte-identical to what
/// [`OsSecureStore::load_key`] would have returned for the same item.
#[cfg(target_os = "macos")]
fn normalize_macos_keychain_payload(mut value: Vec<u8>) -> Vec<u8> {
    if let Ok(text) = std::str::from_utf8(&value) {
        let trimmed = text.trim();
        let maybe_hex_decoded = (!trimmed.is_empty()
            && (trimmed.len() & 1) == 0
            && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| hex_decode(trimmed))
        .and_then(Result::ok);
        if let Some(decoded) = maybe_hex_decoded {
            value.zeroize();
            return decoded;
        }
    }
    value
}

/// Classifying lookup across the same three mechanisms
/// [`load_macos_generic_password`] consults, in the same order, preserving
/// the load path's fallback semantics: the first mechanism that *finds* the
/// item wins. `ProvedAbsent` is returned only when every APPLICABLE
/// mechanism positively answered "no such item" (see
/// [`combine_macos_absence_probes`]): probe 1's `errSecNoDefaultKeychain`
/// (-25307, the headless-launchd state; OI-21(a) daemons use the file-based
/// System keychain) is NOT APPLICABLE and does not poison the conjunction,
/// but the System-keychain probes 2 and 3 must both still prove absence
/// positively. If any probe fails for any other reason (keychain locked,
/// spawn failure, signal), the answer is `Unavailable` — a control-plane key
/// must never be re-minted because one probe could not run.
#[cfg(target_os = "macos")]
fn lookup_macos_keychain(key_id: &str) -> OsStoreLookup {
    if !is_valid_key_identifier(key_id) {
        return OsStoreLookup::Unavailable;
    }
    let service = format!("rustynet.{key_id}");
    let account = "rustynet";

    // 1. Framework query against the session default keychain search list —
    //    same call `load_macos_generic_password` makes first.
    let probe1_default_keychain = match get_generic_password(service.as_str(), account) {
        Ok(payload) => {
            return OsStoreLookup::Found(Zeroizing::new(normalize_macos_keychain_payload(payload)));
        }
        Err(err) => classify_macos_default_keychain_probe(err.code()),
    };

    // 2. Owned `SecItemCopyMatching` scoped to the System keychain.
    let probe2_system_owned =
        match probe_macos_system_keychain_owned_payload(service.as_str(), account) {
            Ok(payload) => {
                return OsStoreLookup::Found(Zeroizing::new(normalize_macos_keychain_payload(
                    payload,
                )));
            }
            Err(probe) => probe,
        };

    // 3. `/usr/bin/security find-generic-password` against the System
    //    keychain (legacy `-A` items).
    let probe3_system_cli = match load_macos_security_cli_payload(service.as_str(), account) {
        Ok(payload) => {
            return OsStoreLookup::Found(Zeroizing::new(normalize_macos_keychain_payload(payload)));
        }
        Err(probe) => probe,
    };

    if combine_macos_absence_probes(
        probe1_default_keychain,
        probe2_system_owned,
        probe3_system_cli,
    ) {
        OsStoreLookup::ProvedAbsent
    } else {
        OsStoreLookup::Unavailable
    }
}

/// Data-carrying counterpart of [`macos_system_keychain_generic_password_present`]:
/// the owned System-keychain search [`load_macos_generic_password_system_keychain_owned`]
/// performs, with the framework error code preserved so item-not-found is
/// distinguishable from "keychain could not be opened/searched".
#[cfg(target_os = "macos")]
fn probe_macos_system_keychain_owned_payload(
    service: &str,
    account: &str,
) -> Result<Vec<u8>, MacKeychainProbe> {
    use security_framework::item::{ItemClass, ItemSearchOptions, SearchResult};
    if service.trim().is_empty() || account.trim().is_empty() {
        return Err(MacKeychainProbe::Unavailable);
    }
    let keychain =
        SecKeychain::open(MACOS_SYSTEM_KEYCHAIN_PATH).map_err(|_| MacKeychainProbe::Unavailable)?;
    let keychains = [keychain];
    match ItemSearchOptions::new()
        .keychains(&keychains)
        .class(ItemClass::generic_password())
        .service(service)
        .account(account)
        .load_data(true)
        .limit(1i64)
        .search()
    {
        Ok(results) => {
            for result in results {
                if let SearchResult::Data(data) = result {
                    return Ok(data);
                }
            }
            // With load_data(true) a hit always carries data; an empty hit
            // list is not an "absent" proof, so it stays inconclusive
            // (mirrors load_macos_generic_password_system_keychain_owned).
            Err(MacKeychainProbe::Unavailable)
        }
        Err(err) if err.code() == MACOS_ERR_SEC_ITEM_NOT_FOUND => {
            Err(MacKeychainProbe::ItemNotFound)
        }
        Err(_) => Err(MacKeychainProbe::Unavailable),
    }
}

/// `/usr/bin/security find-generic-password -w` payload read with the exit
/// code preserved: exit 44 is the CLI's item-not-found answer (verified
/// empirically; see [`MACOS_SECURITY_CLI_EXIT_ITEM_NOT_FOUND`]).
#[cfg(target_os = "macos")]
fn load_macos_security_cli_payload(
    service: &str,
    account: &str,
) -> Result<Vec<u8>, MacKeychainProbe> {
    let output = std::process::Command::new("/usr/bin/security")
        .args([
            "find-generic-password",
            "-a",
            account,
            "-s",
            service,
            "-w",
            "/Library/Keychains/System.keychain",
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|_| MacKeychainProbe::Unavailable)?;
    if output.status.success() {
        let mut bytes = output.stdout;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
        }
        return Ok(bytes);
    }
    Err(match classify_macos_cli_exit(output.status.code()) {
        MacKeychainProbe::ItemNotFound => MacKeychainProbe::ItemNotFound,
        MacKeychainProbe::Unavailable => MacKeychainProbe::Unavailable,
    })
}

/// Create-only store into the macOS **System** keychain via `SecItemAdd`:
/// [`store_macos_generic_password_system_keychain_owned`] minus the
/// delete-then-add. A pre-existing item is never removed or replaced —
/// `SecItemAdd` fails (typically `errSecDuplicateItem`, -25299) and that
/// failure — like every other add failure — is a refusal. AQ-45 step 2 uses
/// this for control-database DEKs, which must never be silently re-keyed.
#[cfg(target_os = "macos")]
pub fn store_macos_generic_password_create_only(
    service: &str,
    account: &str,
    secret: &[u8],
) -> Result<(), CryptoError> {
    use core_foundation::data::CFData;
    use security_framework::item::{ItemAddOptions, ItemAddValue, ItemClass, Location};
    validate_macos_keychain_label("service", service)?;
    validate_macos_keychain_label("account", account)?;
    if secret.contains(&0) || service.as_bytes().contains(&0) || account.as_bytes().contains(&0) {
        return Err(CryptoError::OsStoreUnavailable);
    }
    let mut keychain = SecKeychain::open(MACOS_SYSTEM_KEYCHAIN_PATH)
        .map_err(|_| CryptoError::OsStoreUnavailable)?;
    // Best-effort no-op when already unlocked (see the owned store path).
    let _ = keychain.unlock(Some(""));
    let mut opts = ItemAddOptions::new(ItemAddValue::Data {
        class: ItemClass::generic_password(),
        data: CFData::from_buffer(secret),
    });
    opts.set_service(service)
        .set_account_name(account)
        .set_location(Location::FileKeychain(keychain));
    // No pre-delete here — that is the entire point. ANY add failure,
    // including errSecDuplicateItem, is a refusal, not an overwrite.
    opts.add().map_err(|_| CryptoError::OsStoreUnavailable)?;
    // Fail-closed read-back through the same SecItemCopyMatching path the
    // daemon's loader uses (same discipline as the owned store path). The
    // compare is constant-time for uniformity with `load_or_provision`'s
    // authoritative adopt-or-refuse compare (AQ-45 review finding F4).
    match load_macos_generic_password_system_keychain_owned(service, account) {
        Ok(got) if bool::from(got.as_slice().ct_eq(secret)) => Ok(()),
        _ => Err(CryptoError::OsStoreUnavailable),
    }
}

#[cfg(target_os = "macos")]
fn store_in_macos_keychain_create_only(
    key_id: &str,
    key_material: &[u8],
) -> Result<(), CryptoError> {
    if !is_valid_key_identifier(key_id) {
        return Err(CryptoError::InvalidLength);
    }
    store_macos_generic_password_create_only(
        format!("rustynet.{key_id}").as_str(),
        "rustynet",
        key_material,
    )
}

#[cfg(target_os = "linux")]
fn store_in_linux_secret_service(key_id: &str, key_material: &[u8]) -> Result<(), CryptoError> {
    let tool = resolve_trusted_system_binary("secret-tool")?;
    let mut child = Command::new(tool)
        .arg("store")
        .arg("--label=Rustynet Key")
        .arg("rustynet-key-id")
        .arg(key_id)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| CryptoError::OsStoreUnavailable)?;
    let mut stdin = child.stdin.take().ok_or(CryptoError::OsStoreUnavailable)?;
    use std::io::Write;
    let encoded = Zeroizing::new(hex_bytes(key_material));
    stdin
        .write_all(encoded.as_bytes())
        .map_err(|_| CryptoError::OsStoreUnavailable)?;
    drop(stdin);
    let status = child.wait().map_err(|_| CryptoError::OsStoreUnavailable)?;
    if status.success() {
        return Ok(());
    }
    Err(CryptoError::OsStoreUnavailable)
}

#[cfg(target_os = "linux")]
fn load_from_linux_secret_service(key_id: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let tool = resolve_trusted_system_binary("secret-tool")?;
    let output = Command::new(tool)
        .arg("lookup")
        .arg("rustynet-key-id")
        .arg(key_id)
        .output()
        .map_err(|_| CryptoError::OsStoreUnavailable)?;
    if !output.status.success() {
        return Err(CryptoError::OsStoreUnavailable);
    }
    let mut value =
        String::from_utf8(output.stdout).map_err(|_| CryptoError::OsStoreUnavailable)?;
    let decoded = {
        let trimmed = value.trim();
        hex_decode(trimmed)
    };
    value.zeroize();
    decoded.map(Zeroizing::new)
}

/// Classifying lookup for the secret service. `secret-tool lookup` exits
/// non-zero both for absent items and for transport failures (verified live:
/// without a running secret service the same exit 1 and stderr appear), so a
/// failed lookup falls through to `secret-tool search --all`. An empty
/// search result alone is NOT an absence proof — on a host with no secret
/// service it is vacuously empty — so `ProvedAbsent` additionally requires a
/// `dbus-send NameHasOwner` check confirming that `org.freedesktop.secrets`
/// has an owner on the session bus. The owner check runs AFTER the search so
/// that D-Bus activation triggered by the search itself counts. Anything
/// else stays `Unavailable` (fail-closed; containment for a phantom absence
/// would otherwise be only the later create failure).
#[cfg(target_os = "linux")]
fn lookup_linux_secret_service(key_id: &str) -> OsStoreLookup {
    match load_from_linux_secret_service(key_id) {
        Ok(value) => OsStoreLookup::Found(value),
        Err(_) => {
            let probe = resolve_trusted_system_binary("secret-tool")
                .ok()
                .and_then(|tool| {
                    Command::new(tool)
                        .args(["search", "--all", "rustynet-key-id", key_id])
                        .stdin(Stdio::null())
                        .output()
                        .ok()
                })
                .map_or(LinuxSecretToolProbe::Inconclusive, |output| {
                    classify_linux_secret_tool_search(
                        output.status.success(),
                        output.stdout.is_empty(),
                    )
                });
            match probe {
                // Empty search: only meaningful when a secret service is
                // actually there to have searched (F2). Checked after the
                // search so activation-by-search counts.
                LinuxSecretToolProbe::ProvedNoItems => {
                    match classify_linux_secrets_name_has_owner(linux_secrets_name_has_owner()) {
                        LinuxSecretServicePresence::Owned => OsStoreLookup::ProvedAbsent,
                        LinuxSecretServicePresence::Unavailable => OsStoreLookup::Unavailable,
                    }
                }
                LinuxSecretToolProbe::Inconclusive => OsStoreLookup::Unavailable,
            }
        }
    }
}

/// `dbus-send NameHasOwner(org.freedesktop.secrets)` against the session
/// bus. `Some(true)`/`Some(false)` — the bus answered with a boolean; `None`
/// — `dbus-send` missing, no session bus, non-zero exit, or a malformed
/// reply (all `Unavailable` downstream).
#[cfg(target_os = "linux")]
fn linux_secrets_name_has_owner() -> Option<bool> {
    let output = Command::new(resolve_trusted_system_binary("dbus-send").ok()?)
        .args([
            "--session",
            "--print-reply",
            "--dest=org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.NameHasOwner",
            "string:org.freedesktop.secrets",
        ])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let reply = String::from_utf8(output.stdout).ok()?;
    if reply.contains("boolean true") {
        Some(true)
    } else if reply.contains("boolean false") {
        Some(false)
    } else {
        None
    }
}

/// Fixed search path for the custody helper binaries (KM-1). `PATH` is never
/// consulted: a caller-controlled or attacker-seeded directory must not be
/// able to shadow `secret-tool`/`dbus-send`, which receive hex-encoded
/// private key material or drive the absence proof.
#[cfg(target_os = "linux")]
const TRUSTED_SYSTEM_BINARY_DIRECTORIES: [&str; 3] = ["/usr/bin", "/bin", "/usr/local/bin"];

/// Resolve a custody helper binary from [`TRUSTED_SYSTEM_BINARY_DIRECTORIES`]
/// in order, accepting the first candidate that passes
/// [`validate_trusted_binary`] for `trusted_uid` 0 (root). Any failure —
/// missing everywhere, or present but untrusted — collapses to
/// [`CryptoError::OsStoreUnavailable`], the same outcome as the previous
/// on-`PATH` spawn failure, so downstream classification is unchanged.
#[cfg(target_os = "linux")]
fn resolve_trusted_system_binary(name: &str) -> Result<PathBuf, CryptoError> {
    for directory in TRUSTED_SYSTEM_BINARY_DIRECTORIES {
        let candidate = PathBuf::from(directory).join(name);
        match validate_trusted_binary(&candidate, 0) {
            Ok(resolved) => return Ok(resolved),
            Err(_) => continue,
        }
    }
    Err(CryptoError::OsStoreUnavailable)
}

/// Pure validator for a candidate trusted system binary: canonicalise the
/// path, require a regular executable file owned by `trusted_uid` that is
/// not group/other-writable, and require EVERY directory on the canonical
/// path (up to and including the root) to be owned by `trusted_uid` and not
/// group/other-writable — no sticky-bit exception, since a writable ancestor
/// lets any local user race a binary swap between validation and spawn.
/// Returns the canonical path on success. The error is a plain diagnostic
/// string; callers map every failure to a single domain error.
#[cfg(unix)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn validate_trusted_binary(candidate: &Path, trusted_uid: u32) -> Result<PathBuf, String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let resolved = candidate
        .canonicalize()
        .map_err(|err| format!("cannot canonicalize {}: {err}", candidate.display()))?;
    let metadata = std::fs::metadata(&resolved)
        .map_err(|err| format!("cannot stat {}: {err}", resolved.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", resolved.display()));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o111 == 0 {
        return Err(format!(
            "{} is not executable (mode {:o})",
            resolved.display(),
            mode & 0o7777
        ));
    }
    if metadata.uid() != trusted_uid {
        return Err(format!(
            "{} is owned by uid {}, expected trusted uid {}",
            resolved.display(),
            metadata.uid(),
            trusted_uid
        ));
    }
    if mode & 0o022 != 0 {
        return Err(format!(
            "{} is group/other writable (mode {:o})",
            resolved.display(),
            mode & 0o7777
        ));
    }
    let ancestors: Vec<&Path> = resolved.ancestors().skip(1).collect();
    validate_trusted_directory_chain(&ancestors, trusted_uid)?;
    Ok(resolved)
}

/// Validate a chain of directories on a trusted-binary path: each must be a
/// directory owned by `trusted_uid` and not group/other-writable (mode bits
/// `0o022` clear). List-taking so tests can exercise the chain rule on
/// directories they actually create — a full to-root walk cannot be satisfied
/// over tempdirs, whose fixed ancestors are root-owned (and `/tmp` sticky on
/// Linux).
#[cfg(unix)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn validate_trusted_directory_chain(dirs: &[&Path], trusted_uid: u32) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    for dir in dirs {
        let metadata = std::fs::metadata(dir)
            .map_err(|err| format!("cannot stat {}: {err}", dir.display()))?;
        if !metadata.is_dir() {
            return Err(format!("{} is not a directory", dir.display()));
        }
        if metadata.uid() != trusted_uid {
            return Err(format!(
                "ancestor directory {} is owned by uid {}, expected trusted uid {}",
                dir.display(),
                metadata.uid(),
                trusted_uid
            ));
        }
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 {
            return Err(format!(
                "ancestor directory {} is group/other writable (mode {:o})",
                dir.display(),
                mode & 0o7777
            ));
        }
    }
    Ok(())
}

/// `secret-tool` has no create-only verb — its `store` subcommand upserts.
/// The read-back compare in `load_or_provision` does NOT close this race:
/// two processes can each adopt a DIFFERENT key. A and B both probe Absent;
/// A stores KA and reads back KA (match — A adopts KA and may seal columns
/// with it); B then stores KB, overwriting, and reads back KB (match — B
/// adopts KB). Both succeed, the store ends holding KB, and A's sealed
/// writes are orphaned; the divergence is caught at the NEXT open (fail-
/// closed mismatch), but the columns sealed under KA are lost. The store is
/// therefore only safe when first provisioning is serialized:
/// `load_or_provision` documents that REQUIREMENT, and the step 5/6 open
/// path must satisfy it by provisioning only while holding the control.db
/// write lock (`BEGIN IMMEDIATE`) — not implemented in this step.
#[cfg(target_os = "linux")]
fn store_in_linux_secret_service_create_only(
    key_id: &str,
    key_material: &[u8],
) -> Result<(), CryptoError> {
    store_in_linux_secret_service(key_id, key_material)
}

#[cfg(target_os = "windows")]
fn store_in_windows_dpapi(key_id: &str, key_material: &[u8]) -> Result<(), CryptoError> {
    let root = windows_dpapi_root()?;
    validate_windows_dpapi_root(root.as_path())?;
    let path = windows_dpapi_file_path(root.as_path(), key_id)?;
    if path.exists() {
        validate_windows_dpapi_file(path.as_path())?;
    }
    let mut protected = dpapi_protect(
        key_material,
        // LocalMachine scope is required so the daemon service (running as
        // NT AUTHORITY\SYSTEM / LocalSystem) can decrypt key material that
        // was stored by the bootstrap/install helper (running as the SSH
        // user or an interactive admin). CurrentUser scope ties the blob
        // to the encrypting user's master key, which is inaccessible to
        // LocalSystem and causes CryptoError::DecryptionFailed at service
        // startup (the daemon's runtime tunnel-key material preparation). NTFS ACLs on
        // the key-custody directory (set by windows-runtime-acls-check and
        // validated by validate_windows_dpapi_root/file) are the access
        // boundary; DPAPI LocalMachine encryption provides at-rest
        // protection against off-machine extraction.
        WindowsDpapiScope::LocalMachine,
        &format!("RustyNet key {key_id}"),
    )
    .map_err(|_| CryptoError::EncryptionFailed)?;
    let write_result = write_windows_dpapi_blob(path.as_path(), &protected);
    protected.zeroize();
    write_result
}

#[cfg(target_os = "windows")]
fn load_from_windows_dpapi(key_id: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let root = windows_dpapi_root()?;
    validate_windows_dpapi_root(root.as_path())?;
    let path = windows_dpapi_file_path(root.as_path(), key_id)?;
    validate_windows_dpapi_file(path.as_path())?;
    let protected_len = std::fs::metadata(path.as_path())
        .map_err(|_| CryptoError::Io)?
        .len();
    if protected_len > MAX_ENCRYPTED_KEY_FILE_BYTES {
        return Err(CryptoError::Io);
    }
    let mut protected = std::fs::read(path.as_path()).map_err(|_| CryptoError::Io)?;
    let result = dpapi_unprotect(&protected)
        .map_err(|_| CryptoError::DecryptionFailed)
        .map(Zeroizing::new);
    protected.zeroize();
    result
}

/// Classifying lookup for the DPAPI blob store: a missing blob *file* (with
/// the custody root already validated) is a positive "absent" answer; any
/// other stat failure or decrypt failure is `Unavailable`.
#[cfg(target_os = "windows")]
fn lookup_windows_dpapi(key_id: &str) -> OsStoreLookup {
    let root = match windows_dpapi_root() {
        Ok(root) => root,
        Err(_) => return OsStoreLookup::Unavailable,
    };
    if validate_windows_dpapi_root(root.as_path()).is_err() {
        return OsStoreLookup::Unavailable;
    }
    let path = match windows_dpapi_file_path(root.as_path(), key_id) {
        Ok(path) => path,
        Err(_) => return OsStoreLookup::Unavailable,
    };
    match std::fs::symlink_metadata(path.as_path()) {
        Err(err) => match classify_windows_dpapi_item_missing(err.kind()) {
            WindowsDpapiProbe::ItemNotFound => OsStoreLookup::ProvedAbsent,
            WindowsDpapiProbe::Unavailable => OsStoreLookup::Unavailable,
        },
        Ok(_) => match load_from_windows_dpapi(key_id) {
            Ok(value) => OsStoreLookup::Found(value),
            Err(_) => OsStoreLookup::Unavailable,
        },
    }
}

/// Create-only DPAPI store: refuses when a blob already exists instead of the
/// remove-and-rename used by [`store_in_windows_dpapi`]. The final write uses
/// `create_new(true)`, which fails atomically if a concurrent writer created
/// the file after our probe — the check-then-create race fails closed.
#[cfg(target_os = "windows")]
fn store_in_windows_dpapi_create_only(
    key_id: &str,
    key_material: &[u8],
) -> Result<(), CryptoError> {
    use std::io::Write;
    let root = windows_dpapi_root()?;
    validate_windows_dpapi_root(root.as_path())?;
    let path = windows_dpapi_file_path(root.as_path(), key_id)?;
    match std::fs::symlink_metadata(path.as_path()) {
        Ok(_) => return Err(CryptoError::OsStoreUnavailable),
        Err(err) => {
            if classify_windows_dpapi_item_missing(err.kind()) != WindowsDpapiProbe::ItemNotFound {
                return Err(CryptoError::OsStoreUnavailable);
            }
        }
    }
    let mut protected = dpapi_protect(
        key_material,
        // Same LocalMachine-scope rationale as store_in_windows_dpapi.
        WindowsDpapiScope::LocalMachine,
        &format!("RustyNet key {key_id}"),
    )
    .map_err(|_| CryptoError::EncryptionFailed)?;
    let write_result = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.as_path())
        .and_then(|mut file| file.write_all(&protected))
        .map_err(|_| CryptoError::Io);
    protected.zeroize();
    write_result
}

#[cfg(target_os = "windows")]
fn windows_dpapi_root() -> Result<PathBuf, CryptoError> {
    let root = PathBuf::from(WINDOWS_DPAPI_KEY_CUSTODY_ROOT);
    if !root.exists() {
        return Err(CryptoError::OsStoreUnavailable);
    }
    Ok(root)
}

#[cfg(target_os = "windows")]
fn windows_dpapi_file_path(root: &Path, key_id: &str) -> Result<PathBuf, CryptoError> {
    if !is_valid_key_identifier(key_id) {
        return Err(CryptoError::InvalidLength);
    }
    Ok(root.join(format!("{key_id}.dpapi")))
}

#[cfg(target_os = "windows")]
fn validate_windows_dpapi_root(root: &Path) -> Result<(), CryptoError> {
    let metadata = std::fs::symlink_metadata(root).map_err(|_| CryptoError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CryptoError::PermissionDenied);
    }
    let sddl = inspect_file_sddl(root).map_err(|_| CryptoError::PermissionValidationUnavailable)?;
    if !sddl.contains("D:P")
        || sddl.contains(";;;WD)")
        || sddl.contains(";;;AU)")
        || sddl.contains(";;;BU)")
    {
        return Err(CryptoError::PermissionDenied);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn validate_windows_dpapi_file(path: &Path) -> Result<(), CryptoError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| CryptoError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CryptoError::PermissionDenied);
    }
    let sddl = inspect_file_sddl(path).map_err(|_| CryptoError::PermissionValidationUnavailable)?;
    if !sddl.contains("D:")
        || sddl.contains(";;;WD)")
        || sddl.contains(";;;AU)")
        || sddl.contains(";;;BU)")
    {
        return Err(CryptoError::PermissionDenied);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn write_windows_dpapi_blob(path: &Path, bytes: &[u8]) -> Result<(), CryptoError> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let parent = path.parent().ok_or(CryptoError::Io)?;
    validate_windows_dpapi_root(parent)?;
    let candidate = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("key"),
        std::process::id()
    ));
    if candidate.exists() {
        let metadata =
            std::fs::symlink_metadata(candidate.as_path()).map_err(|_| CryptoError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CryptoError::PermissionDenied);
        }
        std::fs::remove_file(candidate.as_path()).map_err(|_| CryptoError::Io)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(candidate.as_path())
        .map_err(|_| CryptoError::Io)?;
    file.write_all(bytes).map_err(|_| CryptoError::Io)?;
    file.flush().map_err(|_| CryptoError::Io)?;
    if path.exists() {
        validate_windows_dpapi_file(path)?;
        std::fs::remove_file(path).map_err(|_| CryptoError::Io)?;
    }
    std::fs::rename(candidate.as_path(), path).map_err(|_| CryptoError::Io)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningProviderKind {
    LocalEncryptedFile,
    Kms,
    Hsm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningProviderPolicy {
    pub require_hardware_backed_primary: bool,
    pub allow_local_fallback: bool,
}

impl Default for SigningProviderPolicy {
    fn default() -> Self {
        Self {
            require_hardware_backed_primary: true,
            allow_local_fallback: false,
        }
    }
}

pub trait SigningProvider {
    fn kind(&self) -> SigningProviderKind;
    fn key_identifier(&self) -> &str;
    fn sign_attestation(&self, payload: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn verify_attestation(&self, payload: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}

#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519SigningProvider {
    provider_kind: SigningProviderKind,
    key_id: String,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl fmt::Debug for Ed25519SigningProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519SigningProvider")
            .field("provider_kind", &self.provider_kind)
            .field("key_id", &self.key_id)
            .field("signing_key", &"REDACTED")
            .field("verifying_key", &hex_bytes(self.verifying_key.as_bytes()))
            .finish()
    }
}

impl Ed25519SigningProvider {
    /// Fallible constructor for PRODUCTION paths: rejects the degenerate
    /// all-zero seed (the publicly-known Ed25519 identity a blank key file
    /// would mint) with `WeakMaterial`, mirroring `NodeKeyPair::from_raw`.
    /// The by-value seed copy is wiped on both success and rejection.
    pub fn try_from_seed(
        provider_kind: SigningProviderKind,
        key_id: impl Into<String>,
        mut seed: [u8; 32],
    ) -> Result<Self, CryptoError> {
        if is_all_zeros(&seed) {
            seed.zeroize();
            return Err(CryptoError::WeakMaterial);
        }
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        // CRY-11: wipe our by-value copy of the seed. `SigningKey` zeroizes its
        // own copy on drop (ed25519-dalek's `ZeroizeOnDrop`), but this parameter
        // is a separate stack copy that otherwise outlives the call.
        seed.zeroize();
        Ok(Self {
            provider_kind,
            key_id: key_id.into(),
            signing_key,
            verifying_key,
        })
    }

    /// Infallible TEST-only helper: derives the provider from any seed,
    /// including degenerate all-zero material. Compiled out of production
    /// builds — every non-test caller MUST use [`Self::try_from_seed`],
    /// which fails closed on a zero seed.
    #[cfg(test)]
    pub fn from_seed(
        provider_kind: SigningProviderKind,
        key_id: impl Into<String>,
        mut seed: [u8; 32],
    ) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        // CRY-11: wipe our by-value copy of the seed. `SigningKey` zeroizes its
        // own copy on drop (ed25519-dalek's `ZeroizeOnDrop`), but this parameter
        // is a separate stack copy that otherwise outlives the call.
        seed.zeroize();
        Self {
            provider_kind,
            key_id: key_id.into(),
            signing_key,
            verifying_key,
        }
    }

    pub fn verifying_key_hex(&self) -> String {
        hex_bytes(self.verifying_key.as_bytes())
    }
}

impl SigningProvider for Ed25519SigningProvider {
    fn kind(&self) -> SigningProviderKind {
        self.provider_kind
    }

    fn key_identifier(&self) -> &str {
        &self.key_id
    }

    fn sign_attestation(&self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signature = self.signing_key.sign(payload);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify_attestation(&self, payload: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        if signature.len() != 64 {
            return Err(CryptoError::AttestationVerificationFailed);
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(signature);
        let signature = Signature::from_bytes(&bytes);
        // verify_strict rejects non-canonical S and small-order/torsion points
        // (RFC 8032 strict / ZIP-215), eliminating ed25519 malleability so a
        // valid signature cannot be mauled into a distinct accepted encoding.
        self.verifying_key
            .verify_strict(payload, &signature)
            .map_err(|_| CryptoError::AttestationVerificationFailed)
    }
}

pub fn validate_signing_provider_policy(
    primary: SigningProviderKind,
    fallback: Option<SigningProviderKind>,
    policy: SigningProviderPolicy,
) -> Result<(), CryptoError> {
    if policy.require_hardware_backed_primary && primary == SigningProviderKind::LocalEncryptedFile
    {
        return Err(CryptoError::UnsupportedProviderPolicy);
    }
    if !policy.allow_local_fallback && fallback == Some(SigningProviderKind::LocalEncryptedFile) {
        return Err(CryptoError::UnsupportedProviderPolicy);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAttestation {
    pub provider_kind: SigningProviderKind,
    pub key_identifier: String,
    pub payload_digest_hex: String,
    pub signature_hex: String,
}

pub fn create_provider_attestation(
    provider: &dyn SigningProvider,
    payload: &[u8],
) -> Result<ProviderAttestation, CryptoError> {
    let payload_digest = hex_bytes(&Sha256::digest(payload));
    let signature = provider.sign_attestation(payload)?;
    Ok(ProviderAttestation {
        provider_kind: provider.kind(),
        key_identifier: provider.key_identifier().to_owned(),
        payload_digest_hex: payload_digest,
        signature_hex: hex_bytes(&signature),
    })
}

pub fn verify_provider_attestation(
    provider: &dyn SigningProvider,
    payload: &[u8],
    attestation: &ProviderAttestation,
) -> Result<(), CryptoError> {
    if attestation.provider_kind != provider.kind() {
        return Err(CryptoError::AttestationVerificationFailed);
    }
    if attestation.key_identifier != provider.key_identifier() {
        return Err(CryptoError::AttestationVerificationFailed);
    }

    let expected_payload = hex_bytes(&Sha256::digest(payload));
    if expected_payload != attestation.payload_digest_hex {
        return Err(CryptoError::AttestationVerificationFailed);
    }

    let signature = hex_decode(attestation.signature_hex.as_str())?;
    provider.verify_attestation(payload, &signature)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_decode(value: &str) -> Result<Vec<u8>, CryptoError> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || (bytes.len() & 1) != 0 {
        return Err(CryptoError::AttestationVerificationFailed);
    }

    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        // AQ-08: `chunks_exact(2)` yields exactly two bytes per pair, so the
        // `ok_or` arms below are unreachable; `first`/`get(1)` replace direct
        // indexing to keep the indexing_slicing lint denied.
        let hi = (pair
            .first()
            .copied()
            .ok_or(CryptoError::AttestationVerificationFailed)? as char)
            .to_digit(16)
            .ok_or(CryptoError::AttestationVerificationFailed)?;
        let lo = (pair
            .get(1)
            .copied()
            .ok_or(CryptoError::AttestationVerificationFailed)? as char)
            .to_digit(16)
            .ok_or(CryptoError::AttestationVerificationFailed)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

// AQ-08: this legacy entry point has no production callers — it is retained
// only for test fixtures (see the doc comment), so it is compiled solely
// under `cfg(test)` where the panic-family lints are exempted. Production
// callers must use `try_generate_key_custody_material`.
#[cfg(test)]
pub fn generate_key_custody_material() -> ([u8; 16], [u8; 24]) {
    // Legacy infallible entry point retained for existing test fixtures and
    // dev-tool wiring. Production code paths MUST use
    // `try_generate_key_custody_material` so a CSPRNG failure surfaces as a
    // structured `CryptoError::RandomnessUnavailable` instead of either
    // panicking or silently degrading to a non-CSPRNG source.
    match try_generate_key_custody_material() {
        Ok(material) => material,
        Err(err) => panic!("kernel CSPRNG unavailable for key-custody material: {err}"),
    }
}

/// Fallible analogue of the test-only `generate_key_custody_material`
/// wrapper (that wrapper is `#[cfg(test)]`-gated because only this crate's
/// unit tests call it, so linking it here would dangle outside test
/// rustdoc).
///
/// `salt` is consumed by Argon2 for per-blob KDF stretching; if a salt
/// repeats across blobs, an attacker that compromises one passphrase can
/// pre-compute keys against any other blob with the same salt — the
/// stretching invariant collapses. `nonce` is consumed by XChaCha20-Poly1305;
/// any nonce reuse with the same key catastrophically breaks
/// confidentiality + integrity (Poly1305 forgery becomes trivial). Both
/// MUST come from the kernel CSPRNG. We refuse to silently fall back to
/// `ThreadRng` because `ThreadRng` itself reseeds from `OsRng` and would
/// inherit any stale entropy if `OsRng` later fails — fail-closed is the
/// only safe behavior.
pub fn try_generate_key_custody_material() -> Result<([u8; 16], [u8; 24]), CryptoError> {
    use rand::TryRngCore;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| CryptoError::RandomnessUnavailable)?;
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::RandomnessUnavailable)?;
    Ok((salt, nonce))
}

/// AAD construction for the key envelope: the constant magic `b"RNET"` plus
/// the envelope version byte. Shared by the encrypt path and the v1 decrypt
/// arm so the two sides of the AEAD context binding cannot drift.
const KEY_ENVELOPE_AAD_MAGIC: &[u8; 4] = b"RNET";
const KEY_ENVELOPE_VERSION_V1: u8 = 1;

fn key_envelope_aad(version: u8) -> [u8; 5] {
    [
        KEY_ENVELOPE_AAD_MAGIC[0],
        KEY_ENVELOPE_AAD_MAGIC[1],
        KEY_ENVELOPE_AAD_MAGIC[2],
        KEY_ENVELOPE_AAD_MAGIC[3],
        version,
    ]
}

/// Encrypt `plaintext` under `passphrase` with Argon2id + XChaCha20-Poly1305.
///
/// Generates a v1 envelope with AAD binding: the AAD is the constant
/// magic `b"RNET"` plus the version byte. This binds the ciphertext to
/// the Rustynet key-envelope format so a blob cannot be replayed into a
/// different context (different project, different key-envelope version,
/// raw AEAD unwrap without the envelope framing).
pub fn encrypt_private_key_envelope(
    plaintext: &[u8],
    passphrase: &str,
    salt: [u8; 16],
    nonce: [u8; 24],
) -> Result<EncryptedKeyBlob, CryptoError> {
    let aad = key_envelope_aad(KEY_ENVELOPE_VERSION_V1);
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|_| CryptoError::KdfFailed)?;

    let cipher = XChaCha20Poly1305::new((&key).into());
    let ciphertext = match cipher.encrypt(
        XNonce::from_slice(&nonce),
        chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad: &aad,
        },
    ) {
        Ok(value) => value,
        Err(_) => {
            key.zeroize();
            return Err(CryptoError::EncryptionFailed);
        }
    };

    key.zeroize();

    Ok(EncryptedKeyBlob {
        version: KEY_ENVELOPE_VERSION_V1,
        salt,
        nonce,
        ciphertext,
    })
}

/// Decrypt a key envelope, supporting both v0 (legacy, no AAD) and
/// v1 (AAD-bound) blobs. v0 decryption uses empty AAD; v1 uses the
/// constant magic `b"RNET"` + version byte.
///
/// OI-13 (owner decision, 2026-09-24): the v0 empty-AAD decrypt branch is
/// RETIRED via a re-encrypt-on-read window — [`read_encrypted_key_file`]
/// re-seals every v0 blob it sees as v1 and persists the upgrade atomically,
/// so each v0 blob is read as v0 at most once. THIS BRANCH IS REMOVED IN THE
/// NEXT RELEASE: once the fleet's `v0_envelope_reads_total()` counter has
/// settled at zero, the `0` arm below must be deleted and v0 must fail
/// closed (`CryptoError::DeniedAlgorithm`). Until that cutover, the only
/// sanctioned reader of the v0 arm is the migration window.
pub fn decrypt_private_key_envelope(
    blob: &EncryptedKeyBlob,
    passphrase: &str,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &blob.salt, &mut key)
        .map_err(|_| CryptoError::KdfFailed)?;

    let cipher = XChaCha20Poly1305::new((&key).into());
    let decrypt_result = match blob.version {
        0 => cipher.decrypt(
            XNonce::from_slice(&blob.nonce),
            chacha20poly1305::aead::Payload {
                msg: blob.ciphertext.as_ref(),
                // DEPRECATED (OI-13, owner decision 2026-09-24): the legacy v0
                // envelope predates AAD binding, so its ciphertext carries
                // none. This arm exists ONLY for the re-encrypt-on-read
                // migration window in `read_encrypted_key_file` and is
                // REMOVED IN THE NEXT RELEASE: after the cutover this match
                // arm must be deleted and version 0 must fail closed with
                // `CryptoError::DeniedAlgorithm`, never decrypt. Kept
                // byte-for-byte identical to the pre-window behaviour until
                // then.
                aad: b"",
            },
        ),
        1 => {
            let aad = key_envelope_aad(blob.version);
            cipher.decrypt(
                XNonce::from_slice(&blob.nonce),
                chacha20poly1305::aead::Payload {
                    msg: blob.ciphertext.as_ref(),
                    aad: &aad,
                },
            )
        }
        _ => {
            key.zeroize();
            return Err(CryptoError::DeniedAlgorithm);
        }
    };
    let plaintext = match decrypt_result {
        Ok(value) => value,
        Err(_) => {
            key.zeroize();
            return Err(CryptoError::DecryptionFailed);
        }
    };

    key.zeroize();

    Ok(Zeroizing::new(plaintext))
}

/// Raw-key XChaCha20-Poly1305 sealed blob for at-rest service data
/// (D13 NAS backup objects, snapshot manifests, quota records).
/// Same reviewed primitive as the key envelopes — no new crypto.
/// The 32-byte key is supplied by the caller and is NOT derived from a
/// passphrase KDF. CRY-10: an earlier version of this comment claimed the key
/// "comes from OS-secure custody (keychain / DPAPI / `LoadCredentialEncrypted`)".
/// That overstates the production path — `rustynet-nas` loads it from
/// `--at-rest-key-file` (a plain 0600 file holding exactly 32 raw bytes) or from
/// `--at-rest-key-credential`; only the latter plausibly involves a systemd
/// credential, and no keychain or DPAPI is involved on any platform. Callers are
/// responsible for the key's custody.
///
/// The associated data binds the blob to its logical location (peer namespace +
/// content address) so a ciphertext cannot be replayed into another peer's
/// namespace or under another name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AeadSealedBlob {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Seal `plaintext` under `key` with `aad` as associated data.
/// Nonce is drawn from the OS CSPRNG; fails closed when the CSPRNG
/// is unavailable (nonce reuse under one key breaks the AEAD).
///
/// Fails closed on a degenerate all-zero key (`WeakMaterial`). The
/// production key source for these helpers is a raw 32-byte file
/// (`rustynet-nas --at-rest-key-file`), whose loader checks length and
/// permissions but not content — a zero-filled or truncated-then-grown
/// file yields the one key whose "ciphertext" anyone can decrypt. This
/// mirrors the all-zero rejection in `NodeKeyPair::from_raw` and
/// `Ed25519SigningProvider::try_from_seed`; an XChaCha20-Poly1305 key
/// that is publicly known provides no confidentiality, so refusing it
/// is strictly fail-closed.
pub fn aead_seal(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<AeadSealedBlob, CryptoError> {
    if is_all_zeros(key) {
        return Err(CryptoError::WeakMaterial);
    }
    use rand::TryRngCore;
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::RandomnessUnavailable)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(AeadSealedBlob { nonce, ciphertext })
}

/// Open a sealed blob. Any tamper of nonce, ciphertext, or location
/// binding (`aad`) fails the tag check and is rejected.
///
/// Fails closed on a degenerate all-zero key (`WeakMaterial`) for the
/// same reason as [`aead_seal`]: the open path must refuse to "decrypt"
/// at-rest data under the one publicly-known key, so a mis-provisioned
/// key source surfaces as an error instead of silent zero-value
/// plaintext.
pub fn aead_open(
    key: &[u8; 32],
    aad: &[u8],
    blob: &AeadSealedBlob,
) -> Result<Vec<u8>, CryptoError> {
    if is_all_zeros(key) {
        return Err(CryptoError::WeakMaterial);
    }
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(&blob.nonce),
            chacha20poly1305::aead::Payload {
                msg: blob.ciphertext.as_ref(),
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

pub fn write_encrypted_key_file(
    directory: &Path,
    file: &Path,
    plaintext: &[u8],
    passphrase: &str,
    policy: KeyCustodyPermissionPolicy,
) -> Result<(), CryptoError> {
    // Fail-closed on CSPRNG unavailability: see the rationale comment on
    // `try_generate_key_custody_material`. We refuse to write a key file
    // sealed with a non-CSPRNG-derived salt or nonce because that would
    // break Argon2's per-blob KDF uniqueness and could enable nonce reuse
    // against the AEAD.
    let (salt, nonce) = try_generate_key_custody_material()?;
    let blob = encrypt_private_key_envelope(plaintext, passphrase, salt, nonce)?;
    let encoded = encode_encrypted_blob(&blob)?;

    if directory.exists() {
        let directory_link_metadata =
            std::fs::symlink_metadata(directory).map_err(|_| CryptoError::Io)?;
        if directory_link_metadata.file_type().is_symlink() || !directory_link_metadata.is_dir() {
            return Err(CryptoError::PermissionDenied);
        }
    }

    // RSA-0025 (lander): only a directory THIS call creates gets its DACL
    // rewritten. An existing directory is never rewritten (on Windows the
    // protected SY+BA DACL would lock a non-elevated owner out of a shared
    // or personal folder, unlike the owner-preserving Unix chmod below); it
    // is only validated after the write, and fails closed if too broad.
    #[cfg(target_os = "windows")]
    let directory_preexisted = directory.exists();
    std::fs::create_dir_all(directory).map_err(|_| CryptoError::Io)?;
    if file.parent() != Some(directory) {
        return Err(CryptoError::Io);
    }
    #[cfg(target_os = "windows")]
    {
        // RSA-0025: harden the custody directory with an explicit PROTECTED
        // DACL BEFORE any key material is written into it, so a host whose
        // default/inherited ACL is too broad produces a hardened directory
        // instead of failing the post-write SDDL validation. The rewrite is
        // idempotent, pins exactly the reviewed principal set the daemon's
        // Windows runtime-ACL startup gate enforces (grant SY + BA, protected
        // DACL, no WD/AU/BU grant), and fails closed on any error.
        if !windows_key_custody_sddl_is_hardened(WINDOWS_KEY_CUSTODY_FILE_SDDL) {
            return Err(CryptoError::PermissionValidationUnavailable);
        }
        if !directory_preexisted {
            apply_protected_dacl_to_path(directory, WINDOWS_KEY_CUSTODY_FILE_SDDL)
                .map_err(|_| CryptoError::PermissionDenied)?;
        }
    }
    write_atomic_encrypted_key_file(file, &encoded, policy.required_file_mode)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            directory,
            std::fs::Permissions::from_mode(policy.required_directory_mode),
        )
        .map_err(|_| CryptoError::Io)?;
        std::fs::set_permissions(
            file,
            std::fs::Permissions::from_mode(policy.required_file_mode),
        )
        .map_err(|_| CryptoError::Io)?
    };
    validate_key_custody_permissions(directory, file, policy)?;
    Ok(())
}

fn write_atomic_encrypted_key_file(
    path: &Path,
    bytes: &[u8],
    _mode: u32,
) -> Result<(), CryptoError> {
    use std::io::Write;

    // Bound to `_parent` because the parent directory handle is only fsynced on
    // unix (see the `#[cfg(unix)]` block below); the path-has-a-parent check is a
    // fail-closed validation that runs on every platform regardless.
    let _parent = path.parent().ok_or(CryptoError::Io)?;
    let temp = temp_path_for(path);

    // RSA-0025 (Windows): the temp file is created WITH the protected DACL in
    // the very CreateFileW call that creates it (security attributes on
    // create), so the ciphertext never exists on disk under an inherited or
    // host-default broad ACL, and the later rename carries that descriptor
    // onto the final path. CREATE_NEW keeps the create-only race posture and
    // the exclusive share mode (0) blocks concurrent openers.
    #[cfg(target_os = "windows")]
    let mut file = {
        if !windows_key_custody_sddl_is_hardened(WINDOWS_KEY_CUSTODY_FILE_SDDL) {
            return Err(CryptoError::PermissionValidationUnavailable);
        }
        create_new_file_with_sddl(&temp, WINDOWS_KEY_CUSTODY_FILE_SDDL)
            .map_err(|_| CryptoError::Io)?
    };

    // RSA-0025 (non-Windows): unchanged std path; the unix mode bits are
    // still applied at create time via OpenOptionsExt::mode.
    #[cfg(not(target_os = "windows"))]
    let mut file = {
        use std::fs::OpenOptions;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(_mode);
        }
        options.open(&temp).map_err(|_| CryptoError::Io)?
    };

    if file.write_all(bytes).is_err() {
        let _ = std::fs::remove_file(&temp);
        return Err(CryptoError::Io);
    }
    if file.sync_all().is_err() {
        let _ = std::fs::remove_file(&temp);
        return Err(CryptoError::Io);
    }
    if std::fs::rename(&temp, path).is_err() {
        let _ = std::fs::remove_file(&temp);
        return Err(CryptoError::Io);
    }

    // Directory fsync is a no-op on Windows: FlushFileBuffers on a directory
    // handle requires special access flags not provided by File::open, and the
    // durability guarantee is enforced by the rename above.
    #[cfg(unix)]
    {
        let parent_dir = std::fs::File::open(_parent).map_err(|_| CryptoError::Io)?;
        parent_dir.sync_all().map_err(|_| CryptoError::Io)?
    };
    Ok(())
}

fn temp_path_for(path: &Path) -> PathBuf {
    let mut out = path.as_os_str().to_os_string();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    out.push(format!(".tmp.{}.{}", std::process::id(), stamp));
    PathBuf::from(out)
}

/// On-disk bound for encrypted key material files (and DPAPI-protected
/// blobs). Checked BEFORE the file is read so tampered or oversized disk
/// state cannot drive allocation proportional to file size.
const MAX_ENCRYPTED_KEY_FILE_BYTES: u64 = 64 * 1024;

/// OI-13 migration telemetry: how many v0 (legacy, empty-AAD) key-envelope
/// blobs have been observed ON DISK by `read_encrypted_key_file` during the
/// re-encrypt-on-read window. Every v0 blob seen counts exactly once, even
/// when the read is then rejected (tampered blob, wrong passphrase) — those
/// show up here but never upgrade, so a counter that stalls above zero means
/// an operator should audit that node's key files. No secret material is
/// counted or logged: this is a single unsigned integer.
static V0_ENVELOPE_READS_TOTAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// OI-13 migration telemetry: v0 reads whose v1 re-seal could NOT be made
/// durable (the persist call failed). The key is still returned to the caller
/// and the v0 file is left untouched, so the same blob is re-counted and the
/// upgrade re-attempted on the next read. A value stuck above zero means the
/// migration is wedged for at least one blob.
static V0_ENVELOPE_UPGRADE_FAILURES_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// OI-13: v0 envelopes observed on disk so far (see
/// [`V0_ENVELOPE_READS_TOTAL`]). Operators watch this settle at zero — with
/// [`v0_envelope_upgrade_failures_total`] also at zero — to confirm the
/// migration finished before the v0 decrypt branch is removed in the next
/// release.
pub fn v0_envelope_reads_total() -> u64 {
    V0_ENVELOPE_READS_TOTAL.load(std::sync::atomic::Ordering::Relaxed)
}

/// OI-13: v0 reads whose v1 re-seal failed to persist (see
/// [`V0_ENVELOPE_UPGRADE_FAILURES_TOTAL`]).
pub fn v0_envelope_upgrade_failures_total() -> u64 {
    V0_ENVELOPE_UPGRADE_FAILURES_TOTAL.load(std::sync::atomic::Ordering::Relaxed)
}

/// RSA-0001 repair telemetry: reads where the ambiguous v0/v1 frame
/// detection repair fired, i.e. a blob reached the v0 path even though its
/// first byte is non-zero (a legacy v0 salt byte that the old
/// length+first-byte heuristic misrouted to the v1 decoder, where it failed
/// to load). This counts repair FIRINGS at the reader — regardless of the
/// eventual authentication outcome — so it should climb once as upgraded
/// fleets drain their remaining v0 blobs and then settle at zero; activity
/// afterwards would mean v0-shaped files are still appearing on disk, which
/// the v1-only encoder refuses to write. No secret material is counted or
/// logged: this is a single unsigned integer.
static V0_ENVELOPE_FALLBACK_DECODES_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// RSA-0001: reads repaired by the ambiguous-frame detection fallback (see
/// [`V0_ENVELOPE_FALLBACK_DECODES_TOTAL`]).
pub fn v0_envelope_fallback_decodes_total() -> u64 {
    V0_ENVELOPE_FALLBACK_DECODES_TOTAL.load(std::sync::atomic::Ordering::Relaxed)
}

/// OI-13: the only production persist path for the re-encrypt-on-read
/// upgrade — the same `write_encrypted_key_file` used for every other key
/// write (fresh CSPRNG salt+nonce, v1 AAD-bound seal, temp + fsync + rename,
/// custody modes re-applied and re-validated). Injected as a function value
/// so tests can simulate persist failure without touching the filesystem.
fn persist_v1_upgrade(
    directory: &Path,
    file: &Path,
    plaintext: &[u8],
    passphrase: &str,
    policy: KeyCustodyPermissionPolicy,
) -> Result<(), CryptoError> {
    write_encrypted_key_file(directory, file, plaintext, passphrase, policy)
}

/// The persist side of [`persist_v1_upgrade`], abstracted for the
/// persist-failure test.
type PersistKeyFileFn =
    dyn Fn(&Path, &Path, &[u8], &str, KeyCustodyPermissionPolicy) -> Result<(), CryptoError>;

pub fn read_encrypted_key_file(
    directory: &Path,
    file: &Path,
    passphrase: &str,
    policy: KeyCustodyPermissionPolicy,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    read_encrypted_key_file_inner(directory, file, passphrase, policy, &persist_v1_upgrade)
}

fn read_encrypted_key_file_inner(
    directory: &Path,
    file: &Path,
    passphrase: &str,
    policy: KeyCustodyPermissionPolicy,
    persist_upgrade: &PersistKeyFileFn,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    validate_key_custody_permissions(directory, file, policy)?;
    let encoded_len = std::fs::metadata(file).map_err(|_| CryptoError::Io)?.len();
    if encoded_len > MAX_ENCRYPTED_KEY_FILE_BYTES {
        return Err(CryptoError::Io);
    }
    let encoded = std::fs::read(file).map_err(|_| CryptoError::Io)?;
    decrypt_key_file_blob(
        &encoded,
        directory,
        file,
        passphrase,
        policy,
        persist_upgrade,
    )
}

/// RSA-0001 decode-and-decrypt decision over already-read envelope bytes.
/// Split from [`read_encrypted_key_file_inner`] so the fallback rules are
/// decidable (and testable) on raw bytes, independent of the on-disk size
/// cap. The exact rule:
///
/// 1. `decode_encrypted_blob` structurally routes the frame (v0-only for a
///    leading zero byte or a sub-45-byte frame; otherwise v1 parse first,
///    falling back to a v0 parse only when the v1 frame parse fails). A v1
///    blob is therefore never downgraded at the structural layer.
/// 2. A structurally-v0 blob takes the OI-13 migration path: v0 decrypt
///    (which must authenticate), then re-seal as v1. Any v0 blob recovered
///    despite a non-zero first byte is counted by
///    [`v0_envelope_fallback_decodes_total`] as an RSA-0001 repair.
/// 3. A structurally non-v0 blob (any non-zero version byte decodes as the
///    v1-family framing) decrypts under the AAD-bound scheme for its
///    version and that is its only chance: if authentication fails the
///    reader fails closed with that error (or `DeniedAlgorithm` outright
///    for an unknown version). There is NO retry under the v0 scheme after
///    a failure — such a retry would be a runtime fallback/downgrade/
///    legacy branch in a production path (forbidden by AGENTS.md §3) — and
///    no legacy v0 envelope ever needs one: for any frame under the 64KB
///    reader cap a genuine v0 blob can never also parse as a non-v0 frame
///    (a double-parse requires a >16MB envelope; see
///    `decode_encrypted_blob`), so the structural routing alone loads
///    every legacy v0 key file, and a hypothetical oversized double-parse
///    blob is refused rather than decrypted under the weaker empty-AAD
///    scheme.
fn decrypt_key_file_blob(
    encoded: &[u8],
    directory: &Path,
    file: &Path,
    passphrase: &str,
    policy: KeyCustodyPermissionPolicy,
    persist_upgrade: &PersistKeyFileFn,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let blob = decode_encrypted_blob(encoded)?;
    if blob.version == 0 {
        // RSA-0001: a v0 blob here whose first byte is non-zero arrived via
        // the detection repair in `decode_encrypted_blob` — the old
        // length+first-byte heuristic misrouted exactly this shape to the
        // v1 decoder, where it failed to load and never reached the OI-13
        // re-seal path below.
        if encoded.first() != Some(&0) {
            V0_ENVELOPE_FALLBACK_DECODES_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        // OI-13 re-encrypt-on-read window: a v0 blob on disk is decrypted via
        // the (deprecated) empty-AAD branch and immediately re-sealed as v1
        // with fresh CSPRNG salt+nonce, persisted through the atomic
        // temp+fsync+rename writer. The v0 bytes stay on disk untouched until
        // the rename, so a failed persist never loses the key — the caller
        // still gets the plaintext and the next read retries the upgrade.
        V0_ENVELOPE_READS_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let plaintext = decrypt_private_key_envelope(&blob, passphrase)?;
        if persist_upgrade(directory, file, plaintext.as_slice(), passphrase, policy).is_err() {
            V0_ENVELOPE_UPGRADE_FAILURES_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        return Ok(plaintext);
    }
    // Fail closed: a structurally non-v0 blob authenticates under the
    // AAD-bound scheme for its routed version, exactly once, and an
    // unknown version is refused outright. No v0 retry exists after a
    // failure — see the function docs for why no legacy v0 envelope ever
    // needs one under the reader's 64KB cap.
    decrypt_private_key_envelope(&blob, passphrase)
}

/// OI-13: the encoder emits v1 (AAD-bound) blobs ONLY. Anything that is not
/// exactly version 1 is refused (`DeniedAlgorithm`) instead of encoded, so no
/// caller — current or future — can persist a v0 envelope: during the
/// migration window the v0 population on disk can only shrink. (Proof that
/// every writer reaches the disk through here: `write_encrypted_key_file` is
/// the crate's single key-file writer, and its blob comes from
/// `encrypt_private_key_envelope`, which is v1-only by construction — pinned
/// by `encrypted_envelope_is_v1_aad_bound_and_fails_closed_on_version_tamper`.)
/// `decode_encrypted_blob` still READS v0 until the OI-13 cutover in the next
/// release, when the v0 decoder is deleted and v0 fails closed at decode.
fn encode_encrypted_blob(blob: &EncryptedKeyBlob) -> Result<Vec<u8>, CryptoError> {
    if blob.version != KEY_ENVELOPE_VERSION_V1 {
        return Err(CryptoError::DeniedAlgorithm);
    }
    let mut out = Vec::with_capacity(1 + 16 + 24 + 4 + blob.ciphertext.len());
    out.push(blob.version);
    out.extend_from_slice(&blob.salt);
    out.extend_from_slice(&blob.nonce);
    out.extend_from_slice(&(blob.ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&blob.ciphertext);
    Ok(out)
}

fn decode_encrypted_blob(bytes: &[u8]) -> Result<EncryptedKeyBlob, CryptoError> {
    // RSA-0001: v1 ([version:1][salt:16][nonce:24][len:4][ct], min 45 bytes,
    // version != 0) and v0 ([salt:16][nonce:24][len:4][ct], min 44 bytes,
    // version implicitly 0) framings are near-identical, so a single
    // length+first-byte guess misroutes legacy v0 blobs — whose first byte
    // is just salt[0], non-zero for 255/256 of real blobs — to the v1
    // decoder, where they fail to load and never reach the OI-13 re-seal
    // path. The structural rule is now:
    //   1. `bytes[0] == 0` or `len < 45`: v0 parse only. v1 requires a
    //      non-zero version byte, so a leading zero can only be v0 salt.
    //   2. otherwise the v1 frame is tried FIRST and a well-formed v1 blob
    //      is always returned as v1: this layer can never downgrade v1.
    //   3. if the v1 frame parse fails, the bytes may still be a legacy v0
    //      frame; the v0 parse decides. Two failures fail closed with
    //      `InvalidLength` (unchanged error surface).
    // This layer parses only — authentication stays in
    // `decrypt_private_key_envelope`. A shape that parses as BOTH frames
    // leaves here as a non-v0 frame and that verdict is final:
    // `decrypt_key_file_blob` never retries under v0 after a non-v0
    // failure, so a genuine double-parse legacy envelope (>16MB —
    // unreachable through the 64KB reader cap) would be refused, never
    // decrypted under the weaker empty-AAD scheme. Every legacy v0
    // envelope under the cap parses as v0-only and takes the OI-13 path
    // above.
    // AQ-08: `get(..)` + `ok_or` replaces direct slicing. Every range in the
    // decoders below is inside the `len >= 44` bound each checks first, so
    // the `ok_or` arms are unreachable for any input that reaches them.
    if bytes.len() >= 45 && bytes.first() != Some(&0) {
        if let Ok(blob) = decode_encrypted_blob_v1(bytes) {
            return Ok(blob);
        }
    }
    decode_encrypted_blob_v0(bytes)
}

fn decode_encrypted_blob_v0(bytes: &[u8]) -> Result<EncryptedKeyBlob, CryptoError> {
    if bytes.len() < 44 {
        return Err(CryptoError::InvalidLength);
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(bytes.get(0..16).ok_or(CryptoError::InvalidLength)?);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(bytes.get(16..40).ok_or(CryptoError::InvalidLength)?);

    let mut length_bytes = [0u8; 4];
    length_bytes.copy_from_slice(bytes.get(40..44).ok_or(CryptoError::InvalidLength)?);
    let ciphertext_len = u32::from_be_bytes(length_bytes) as usize;
    // CRY-12: checked add. The declared length is attacker-controlled up to
    // u32::MAX; on a 32-bit target (armv7 relay/exit nodes are a documented
    // roadmap item) `44 + ciphertext_len` overflows `usize`, which panics in a
    // debug build while merely parsing a malformed key file.
    let expected_len = ciphertext_len
        .checked_add(44)
        .ok_or(CryptoError::InvalidLength)?;
    if bytes.len() != expected_len {
        return Err(CryptoError::InvalidLength);
    }

    Ok(EncryptedKeyBlob {
        version: 0,
        salt,
        nonce,
        ciphertext: bytes.get(44..).ok_or(CryptoError::InvalidLength)?.to_vec(),
    })
}

fn decode_encrypted_blob_v1(bytes: &[u8]) -> Result<EncryptedKeyBlob, CryptoError> {
    if bytes.len() < 45 {
        return Err(CryptoError::InvalidLength);
    }
    // AQ-08: same `get` + `ok_or` pattern as the v0 decoder; the length gate
    // above makes the error arms unreachable.
    let version = bytes.first().copied().ok_or(CryptoError::InvalidLength)?;
    if version == 0 {
        return Err(CryptoError::InvalidLength);
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(bytes.get(1..17).ok_or(CryptoError::InvalidLength)?);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(bytes.get(17..41).ok_or(CryptoError::InvalidLength)?);

    let mut length_bytes = [0u8; 4];
    length_bytes.copy_from_slice(bytes.get(41..45).ok_or(CryptoError::InvalidLength)?);
    let ciphertext_len = u32::from_be_bytes(length_bytes) as usize;
    // CRY-12: see the v0 decoder — checked add for the same reason.
    let expected_len = ciphertext_len
        .checked_add(45)
        .ok_or(CryptoError::InvalidLength)?;
    if bytes.len() != expected_len {
        return Err(CryptoError::InvalidLength);
    }

    Ok(EncryptedKeyBlob {
        version,
        salt,
        nonce,
        ciphertext: bytes.get(45..).ok_or(CryptoError::InvalidLength)?.to_vec(),
    })
}

/// RSA-0025: the SDDL pinned at write time onto Windows encrypted
/// key-material files and their custody directory. `D:P` is a PROTECTED
/// DACL (inheritance disabled, so a host-default broad ACL cannot
/// reappear), granting full file access (`FA`) ONLY to LocalSystem
/// (`SY`) and Builtin Administrators (`BA`): the daemon service runs as
/// LocalSystem (the same reason DPAPI custody uses LocalMachine scope,
/// see `store_in_windows_dpapi`), and BA is retained so operators keep
/// remediation access — the same reviewed principal set the daemon's
/// Windows runtime-ACL evaluator enforces at startup
/// (`crates/rustynetd/src/windows_paths.rs`
/// `evaluate_windows_runtime_acl_sddl`). This string passes both
/// `validate_windows_dpapi_root` and `validate_windows_dpapi_file`, so
/// the post-write custody validation stays a true post-condition.
///
/// REVIEW FIX (RSA-0025 follow-up): no `O:`/`G:` owner/group fields. The
/// reviewed string pinned owner AND group to LocalSystem (`O:SYG:SY`),
/// but a caller may only assign an owner other than itself when it holds
/// `SeRestorePrivilege` ENABLED — a privilege present but disabled by
/// default in operator tokens — so every non-SYSTEM writer (the operator
/// CLI paths: `persist_encrypted_secret_material` and
/// `rustynet-windows-trust-cli`) would have failed at `CreateFileW` with
/// `ERROR_INVALID_OWNER`, turning the custody write itself into a
/// denial of the legitimate operator flow. With owner/group left
/// unspecified, Windows defaults them to the creator's token: LocalSystem
/// for the daemon services (still the `SY` owner the daemon's runtime-ACL
/// evaluator accepts) and Administrators or the invoking user for
/// operator runs — neither reads as a broad principal, and the DACL (the
/// actual enforcement this fix is about) is unchanged.
pub const WINDOWS_KEY_CUSTODY_FILE_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";

/// Pure, every-platform check that an SDDL string is the hardened shape
/// RSA-0025 requires: a protected DACL (`D:P`) that grants no broad
/// well-known principal (`WD` Everyone, `AU` Authenticated Users, `BU`
/// Builtin Users) and does grant both `SY` and `BA`. Only allow ACEs
/// count as grants — a deny ACE for a principal is not a grant (and a
/// deny for SY/BA is separately rejected by the daemon's evaluator).
/// An SDDL that carries an owner field (`O:` — owner is the first SDDL
/// field, so a leading `O:` is how any owner assignment announces itself)
/// is also rejected: assigning an owner requires a privilege most callers
/// lack, so such a string would fail closed at create time on Windows.
/// The Windows write path re-runs this on
/// [`WINDOWS_KEY_CUSTODY_FILE_SDDL`] before every use, so a fat-fingered
/// edit of the constant fails closed instead of applying a weak ACL.
pub fn windows_key_custody_sddl_is_hardened(sddl: &str) -> bool {
    const FORBIDDEN_GRANTS: [&str; 3] = ["WD", "AU", "BU"];
    if sddl.starts_with("O:") || sddl.starts_with("G:") {
        return false;
    }
    if !sddl.contains("D:P") {
        return false;
    }
    if FORBIDDEN_GRANTS
        .iter()
        .any(|principal| sddl_grants_well_known_principal(sddl, principal))
    {
        return false;
    }
    sddl_grants_well_known_principal(sddl, "SY") && sddl_grants_well_known_principal(sddl, "BA")
}

/// ACE-level principal extraction for
/// [`windows_key_custody_sddl_is_hardened`]: returns the account
/// principals of every ACE in `sddl` whose ACE type is `wanted_type`
/// (`A` allow, `D` deny). Parses the SDDL ACE shape
/// `(type;flags;rights;object_guid;inherit_object_guid;account_sid)`
/// with exact principal matching — `WD` never matches `WDX` or a string
/// SID, and a malformed ACE grants nothing.
fn sddl_ace_principals<'a>(sddl: &'a str, wanted_type: &str) -> Vec<&'a str> {
    sddl.split('(')
        .skip(1)
        .filter_map(|ace| {
            let body = ace.strip_suffix(')')?;
            let fields: Vec<&str> = body.split(';').collect();
            if fields.len() != 6 || fields.first() != Some(&wanted_type) {
                return None;
            }
            fields.last().copied()
        })
        .collect()
}

fn sddl_grants_well_known_principal(sddl: &str, principal: &str) -> bool {
    sddl_ace_principals(sddl, "A").contains(&principal)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyCustodyPermissionPolicy {
    pub required_directory_mode: u32,
    pub required_file_mode: u32,
}

impl Default for KeyCustodyPermissionPolicy {
    fn default() -> Self {
        Self {
            required_directory_mode: 0o700,
            required_file_mode: 0o600,
        }
    }
}

/// The ownership and mode facts about a key-custody directory and file.
///
/// Split out from the syscalls so the decision below is testable. The
/// attacker-owned case is the one that matters most and an unprivileged test
/// cannot create it -- `chown` to another uid needs root -- so a test that only
/// drove the real filesystem could verify the modes and never the ownership
/// check, which is precisely the half that was missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnixCustodyMetadata {
    pub directory_uid: u32,
    pub directory_mode: u32,
    pub file_uid: u32,
    pub file_mode: u32,
}

/// Decide whether a key-custody directory and file are safely held.
///
/// # CRY-07
///
/// This used to check modes only. An ATTACKER-owned directory and file with
/// perfectly correct `0700`/`0600` modes passed: the owner of a file may rewrite
/// it however restrictively it is moded, so "only the owner may read this" says
/// nothing useful until you also assert WHO the owner is.
///
/// It was the weaker of two sibling implementations -- the peer store's
/// `ensure_unix_owner` is audited PASS specifically for pairing a uid check with
/// `0700`/`0600`. The two now agree, and use the same `Uid::effective()`
/// primitive.
///
/// Modes are checked before ownership so the error a misconfigured (rather than
/// hostile) deployment sees still points at the more likely cause.
pub fn evaluate_unix_custody_metadata(
    metadata: UnixCustodyMetadata,
    policy: KeyCustodyPermissionPolicy,
    effective_uid: u32,
) -> Result<(), CryptoError> {
    if metadata.directory_mode != policy.required_directory_mode {
        return Err(CryptoError::PermissionDenied);
    }
    if metadata.file_mode != policy.required_file_mode {
        return Err(CryptoError::PermissionDenied);
    }
    if metadata.directory_uid != effective_uid || metadata.file_uid != effective_uid {
        return Err(CryptoError::PermissionDenied);
    }
    Ok(())
}

pub fn validate_key_custody_permissions(
    directory: &Path,
    file: &Path,
    policy: KeyCustodyPermissionPolicy,
) -> Result<(), CryptoError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        let directory_link_metadata =
            std::fs::symlink_metadata(directory).map_err(|_| CryptoError::Io)?;
        if directory_link_metadata.file_type().is_symlink() || !directory_link_metadata.is_dir() {
            return Err(CryptoError::PermissionDenied);
        }
        let file_link_metadata = std::fs::symlink_metadata(file).map_err(|_| CryptoError::Io)?;
        if file_link_metadata.file_type().is_symlink() || !file_link_metadata.is_file() {
            return Err(CryptoError::PermissionDenied);
        }

        let directory_metadata = std::fs::metadata(directory).map_err(|_| CryptoError::Io)?;
        let file_metadata = std::fs::metadata(file).map_err(|_| CryptoError::Io)?;

        // Effective rather than real uid, because that is the identity the
        // subsequent `read` will be authorized against.
        evaluate_unix_custody_metadata(
            UnixCustodyMetadata {
                directory_uid: directory_metadata.uid(),
                directory_mode: directory_metadata.permissions().mode() & 0o777,
                file_uid: file_metadata.uid(),
                file_mode: file_metadata.permissions().mode() & 0o777,
            },
            policy,
            nix::unistd::Uid::effective().as_raw(),
        )
    }

    #[cfg(windows)]
    {
        // CRY-05 / AUDIT-027 (Windows implementation). Map the owner-only
        // key-custody policy onto an SDDL assertion, reusing the same audited
        // checks Windows DPAPI custody uses. `validate_windows_dpapi_root`
        // requires the directory to carry a PROTECTED DACL (`D:P`) that grants
        // no broad principal — Everyone (`WD`), Authenticated Users (`AU`) or
        // Builtin Users (`BU`); `validate_windows_dpapi_file` requires the
        // file's DACL to grant none of those either. That is at least as strict
        // as the unix owner-only mode this policy expresses — every caller uses
        // the 0o700/0o600 default — because access is confined to SYSTEM,
        // Administrators and specific user SIDs, never a broad group. Any SDDL
        // read failure or broad ACE fails closed
        // (`PermissionValidationUnavailable` / `PermissionDenied`), so an
        // unimplemented or misconfigured ACL can never read as a pass — the
        // fail-open shape CRY-05 exists to prevent.
        //
        // The unix mode bits do not translate to Windows; the SDDL assertion is
        // the enforcement, so `policy` is intentionally unused here.
        let _ = policy;
        validate_windows_dpapi_root(directory)?;
        validate_windows_dpapi_file(file)?;
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    {
        // FAIL CLOSED. This used to return `Ok(())` with the note "Windows ACL
        // validation not yet implemented; defer to OS enforcement" — but the
        // caller cannot tell that answer apart from a real pass, so an
        // unimplemented check silently became a passing one.
        //
        // That matters because of where this sits: it gates
        // `read_encrypted_key_file`, i.e. the encrypted-at-rest FALLBACK used
        // when the OS secure store is unavailable. The SecurityMinimumBar
        // requires that fallback to carry "strict permissions and startup
        // permission checks"; on a target with no permission model we can
        // assert, it carries neither, so the one control standing between a
        // world-readable key file and the process is absent. "Defer to OS
        // enforcement" is not enforcement — nothing had asked the OS anything.
        //
        // `PermissionValidationUnavailable` is the honest answer. Windows now
        // has a real SDDL arm above (the same validators DPAPI custody uses);
        // this stub bites only on platforms that are neither unix nor Windows,
        // where no permission mapping exists. CRY-05 / AUDIT-027.
        let _ = (directory, file, policy);
        Err(CryptoError::PermissionValidationUnavailable)
    }
}

#[cfg(all(test, unix))]
mod unix_custody_tests {
    use super::{
        evaluate_unix_custody_metadata, CryptoError, KeyCustodyPermissionPolicy,
        UnixCustodyMetadata,
    };

    const ME: u32 = 501;
    const ATTACKER: u32 = 502;

    fn safe() -> UnixCustodyMetadata {
        UnixCustodyMetadata {
            directory_uid: ME,
            directory_mode: 0o700,
            file_uid: ME,
            file_mode: 0o600,
        }
    }

    #[test]
    fn correctly_owned_and_moded_custody_is_accepted() {
        evaluate_unix_custody_metadata(safe(), KeyCustodyPermissionPolicy::default(), ME)
            .expect("0700/0600 owned by the effective user must pass");
    }

    /// CRY-07: the case the mode-only validator accepted.
    ///
    /// Every mode is exactly right; only the owner is wrong. The owner of a file
    /// can rewrite it regardless of its mode, so this must be refused.
    #[test]
    fn attacker_owned_custody_with_perfect_modes_is_refused() {
        for (label, metadata) in [
            (
                "attacker owns both",
                UnixCustodyMetadata {
                    directory_uid: ATTACKER,
                    file_uid: ATTACKER,
                    ..safe()
                },
            ),
            (
                "attacker owns the directory",
                UnixCustodyMetadata {
                    directory_uid: ATTACKER,
                    ..safe()
                },
            ),
            (
                // The subtler half: the directory is ours but the KEY FILE is
                // not. Checking only the directory would pass this.
                "attacker owns the key file",
                UnixCustodyMetadata {
                    file_uid: ATTACKER,
                    ..safe()
                },
            ),
            (
                // root is not a safe owner either when we are not root: the
                // check is equality with the effective uid, not a trust ranking.
                "root owns the key file",
                UnixCustodyMetadata {
                    file_uid: 0,
                    ..safe()
                },
            ),
        ] {
            assert_eq!(
                evaluate_unix_custody_metadata(metadata, KeyCustodyPermissionPolicy::default(), ME),
                Err(CryptoError::PermissionDenied),
                "{label}: correct modes must not substitute for correct ownership"
            );
        }
    }

    /// The pre-existing mode checks must survive the restructure.
    #[test]
    fn wrong_modes_are_still_refused_regardless_of_ownership() {
        for (label, metadata) in [
            (
                "group-readable directory",
                UnixCustodyMetadata {
                    directory_mode: 0o750,
                    ..safe()
                },
            ),
            (
                "world-readable key file",
                UnixCustodyMetadata {
                    file_mode: 0o644,
                    ..safe()
                },
            ),
            (
                "group-readable key file",
                UnixCustodyMetadata {
                    file_mode: 0o640,
                    ..safe()
                },
            ),
        ] {
            assert_eq!(
                evaluate_unix_custody_metadata(metadata, KeyCustodyPermissionPolicy::default(), ME),
                Err(CryptoError::PermissionDenied),
                "{label} must be refused"
            );
        }
    }

    /// root running as root is the ordinary daemon case and must still work --
    /// the check is uid EQUALITY, so it must not special-case uid 0 in either
    /// direction.
    #[test]
    fn root_owned_custody_passes_when_the_effective_user_is_root() {
        evaluate_unix_custody_metadata(
            UnixCustodyMetadata {
                directory_uid: 0,
                file_uid: 0,
                ..safe()
            },
            KeyCustodyPermissionPolicy::default(),
            0,
        )
        .expect("a root-owned key store must validate for a root-running daemon");
    }
}

#[cfg(test)]
mod tests {
    /// Round-trip of the at-rest AEAD primitive used by the NAS store.
    #[test]
    fn aead_seal_then_open_round_trips() {
        let key = [7u8; 32];
        let blob = super::aead_seal(&key, b"peer-a/snap-1", b"payload").expect("seal");
        assert_ne!(blob.nonce, [0u8; 24]);
        let plaintext = super::aead_open(&key, b"peer-a/snap-1", &blob).expect("open must succeed");
        assert_eq!(plaintext, b"payload");
    }

    /// CRY/D13: the AAD binds a blob to its logical location, so a ciphertext
    /// captured under one namespace must NOT open under another.
    #[test]
    fn aead_open_rejects_wrong_aad() {
        let key = [7u8; 32];
        let blob = super::aead_seal(&key, b"peer-a/snap-1", b"payload").expect("seal");
        let err = super::aead_open(&key, b"peer-b/snap-1", &blob)
            .expect_err("replay into another namespace must fail");
        assert!(matches!(err, super::CryptoError::DecryptionFailed));

        // The sharper half of the binding: a blob sealed with NO associated
        // data must not be opened under a CLAIMED namespace either, otherwise
        // an attacker strips the AAD at rest and replays across namespaces.
        let unbound = super::aead_seal(&key, b"", b"payload").expect("seal");
        assert!(matches!(
            super::aead_open(&key, b"peer-b/snap-1", &unbound),
            Err(super::CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn aead_open_rejects_tampered_ciphertext_and_wrong_key() {
        let key = [7u8; 32];
        let mut blob = super::aead_seal(&key, b"aad", b"payload").expect("seal");
        blob.ciphertext[0] ^= 0x01;
        assert!(matches!(
            super::aead_open(&key, b"aad", &blob),
            Err(super::CryptoError::DecryptionFailed)
        ));

        let intact = super::aead_seal(&key, b"aad", b"payload").expect("seal");
        assert!(matches!(
            super::aead_open(&[8u8; 32], b"aad", &intact),
            Err(super::CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn aead_seal_draws_fresh_nonces() {
        let key = [7u8; 32];
        let first = super::aead_seal(&key, b"aad", b"x").expect("seal");
        let second = super::aead_seal(&key, b"aad", b"x").expect("seal");
        assert_ne!(first.nonce, second.nonce);
    }

    /// The AEAD helpers must refuse the one key that provides no
    /// confidentiality. The production key source is a raw 32-byte file whose
    /// loader checks length and permissions but not content, so an all-zero
    /// key is a realistic mis-provisioning (`truncate -s 32`, `dd if=/dev/zero`).
    /// Sealing under it would silently publish data; the failure must surface
    /// as `WeakMaterial`, mirroring `NodeKeyPair::from_raw`.
    #[test]
    fn aead_seal_rejects_all_zero_key_fail_closed() {
        let result = super::aead_seal(&[0u8; 32], b"peer-a/snap-1", b"payload");
        assert_eq!(result.err(), Some(super::CryptoError::WeakMaterial));
    }

    /// Symmetric control: the open path must also refuse the all-zero key so
    /// data at rest sealed under a mis-provisioned key cannot be "decrypted"
    /// into silent zero-value plaintext — the store fails closed instead.
    #[test]
    fn aead_open_rejects_all_zero_key_fail_closed() {
        let key = [0x2b_u8; 32];
        let blob = super::aead_seal(&key, b"aad", b"payload").expect("seal under a real key");
        let result = super::aead_open(&[0u8; 32], b"aad", &blob);
        assert_eq!(result.err(), Some(super::CryptoError::WeakMaterial));
    }

    /// A single zero byte does not make the key degenerate; the check targets
    /// exactly the all-zero material and must not reject legitimate keys whose
    /// bytes merely include zeros.
    #[test]
    fn aead_seal_accepts_key_containing_zero_bytes() {
        let mut key = [0u8; 32];
        key[31] = 1;
        super::aead_seal(&key, b"aad", b"payload").expect("near-zero key is still a real key");
    }

    /// The unimplemented-platform arm must FAIL, not pass.
    ///
    /// Runs only on a platform that still hits the refuse stub — neither unix
    /// (real mode/uid check) nor windows (real SDDL check, added for CRY-05 in
    /// commit 77262024). On unix and windows the stub is compiled out and this
    /// test cannot execute at all; the source pin below is what protects the
    /// stub there.
    #[cfg(not(any(unix, windows)))]
    #[test]
    fn key_custody_permission_check_fails_closed_when_unimplemented() {
        let dir = std::env::temp_dir();
        let file = dir.join("rustynet-cry05-probe.key");
        let err = super::validate_key_custody_permissions(
            dir.as_path(),
            file.as_path(),
            super::KeyCustodyPermissionPolicy::default(),
        )
        .expect_err("an unimplemented permission check must not report success");
        assert!(matches!(
            err,
            super::CryptoError::PermissionValidationUnavailable
        ));
    }

    /// Source pin for CRY-05 / AUDIT-027, because the arm it guards is
    /// compiled out on every host that runs this suite by default.
    ///
    /// The regression is a one-word edit — `Err(...)` back to `Ok(())` — and it
    /// would restore a silent fail-open on the encrypted-at-rest fallback path,
    /// where this is the only permission control. A reviewer on unix cannot see
    /// it compile, so pin the text.
    /// Reduce Rust source to code-shaped text: drop line comments and
    /// nesting-aware block comments, empty the contents of normal and raw
    /// string literals, and consume character literals wholesale. The
    /// key-custody pins below must judge only real code — adversarial
    /// re-review of these very tests found bypasses where a comment, string
    /// literal, nested block comment (`/* /* */ x */`), or raw string
    /// (`r#"a"b"#`) carried the pinned text verbatim while the guarded path
    /// was broken.
    ///
    /// The scanner recognizes `r"…"`, `br"…"`, `cr"…"`, and their `#`-delimited
    /// forms so a raw-string interior cannot leak into the code stream, tracks
    /// block-comment nesting so an inner `*/` cannot close the comment early,
    /// and consumes `'…'` character literals (including `'"'`) so their quotes
    /// cannot flip string state. Lifetime elisions (`'a`) are emitted
    /// untouched. An unclosed construct consumes to EOF, which only occurs in
    /// source that does not compile.
    fn strip_non_code(input: &str) -> String {
        let chars: Vec<char> = input.chars().collect();
        let n = chars.len();
        let mut out = String::with_capacity(input.len());
        let mut i = 0usize;
        while i < n {
            let c = chars[i];
            // Line comment.
            if c == '/' && i + 1 < n && chars[i + 1] == '/' {
                i += 2;
                while i < n && chars[i] != '\n' {
                    i += 1;
                }
                out.push(' ');
                continue;
            }
            // Nesting-aware block comment.
            if c == '/' && i + 1 < n && chars[i + 1] == '*' {
                let mut depth = 1usize;
                i += 2;
                while i < n && depth > 0 {
                    if chars[i] == '/' && i + 1 < n && chars[i + 1] == '*' {
                        depth += 1;
                        i += 2;
                    } else if chars[i] == '*' && i + 1 < n && chars[i + 1] == '/' {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                out.push(' ');
                continue;
            }
            // Raw string literals: r"…", r#"…"#, br"…", br#"…"#, cr"…",
            // cr#"…"#. A prefix only counts when it does not continue an
            // identifier.
            let prefix_raw =
                (c == 'r') || ((c == 'b' || c == 'c') && i + 1 < n && chars[i + 1] == 'r');
            let prefix_clean = i == 0 || !(chars[i - 1].is_alphanumeric() || chars[i - 1] == '_');
            if prefix_raw && prefix_clean {
                let mut k = if c == 'r' { i + 1 } else { i + 2 };
                let mut hashes = 0usize;
                while k < n && chars[k] == '#' {
                    hashes += 1;
                    k += 1;
                }
                if k < n && chars[k] == '"' {
                    k += 1;
                    loop {
                        if k >= n {
                            break;
                        }
                        if chars[k] == '"' {
                            let mut end = k + 1;
                            let mut seen = 0usize;
                            while seen < hashes && end < n && chars[end] == '#' {
                                seen += 1;
                                end += 1;
                            }
                            if seen == hashes {
                                k = end;
                                break;
                            }
                        }
                        k += 1;
                    }
                    out.push(' ');
                    i = k;
                    continue;
                }
            }
            // Character literals: consume wholesale so their quotes cannot
            // toggle string state. A `'` that is not a char literal (lifetime
            // elision, loop labels) is emitted untouched.
            if c == '\'' {
                if i + 1 < n && chars[i + 1] == '\\' {
                    let mut k = i + 2;
                    while k < n && chars[k] != '\'' {
                        k += 1;
                    }
                    i = (k + 1).min(n);
                    out.push(' ');
                    continue;
                }
                if i + 2 < n && chars[i + 2] == '\'' {
                    i += 3;
                    out.push(' ');
                    continue;
                }
                out.push(c);
                i += 1;
                continue;
            }
            // Normal string literal: delimiters kept, contents emptied,
            // escapes honored.
            if c == '"' {
                out.push('"');
                i += 1;
                let mut escaped = false;
                while i < n {
                    let ch = chars[i];
                    i += 1;
                    if escaped {
                        escaped = false;
                    } else if ch == '\\' {
                        escaped = true;
                    } else if ch == '"' {
                        break;
                    }
                }
                continue;
            }
            out.push(c);
            i += 1;
        }
        out
    }

    #[test]
    fn non_unix_key_custody_arm_does_not_return_ok() {
        // Scan COMMENT-STRIPPED source: a comment carrying the pinned Err text
        // verbatim satisfied the old raw-text pins while the arm returned
        // `Ok(())` outright.
        let source = strip_non_code(include_str!("lib.rs"));
        let marker = "let _ = (directory, file, policy);";
        let at = source
            .find(marker)
            .expect("the non-unix key-custody arm must still discard its arguments");
        let fn_start = source
            .find("pub fn validate_key_custody_permissions(")
            .expect("validate_key_custody_permissions must remain present");
        // Whitespace-normalized needles: `return\n    Ok(())`, `return  Ok(())`,
        // and any other spacing defeated the old contiguous-substring check.
        // The rationale comments are stripped above, so prose can never form
        // this needle either.
        let fail_open_return = ["return", "Ok(("].concat();
        let normalize =
            |text: &str| -> String { text.chars().filter(|c| !c.is_whitespace()).collect() };
        // (1) Between the function's entry and the discard marker.
        let prelude_norm = normalize(&source[fn_start..at]);
        assert!(
            !prelude_norm.contains(fail_open_return.as_str()),
            "the non-unix key-custody arm must not gain an early escape that \
             returns Ok — that is the CRY-05/AUDIT-027 fail-open, reached \
             through a different spelling"
        );
        // (2) Between the discard marker and the required refusal expression:
        // a compact guard such as `if true { return Ok(()); }` once fit inside
        // the old fixed next-statement window and passed every pin.
        let err_needle = "Err(CryptoError::PermissionValidationUnavailable)";
        let err_at = source[at..].find(err_needle).map(|rel| at + rel).expect(
            "the non-unix key-custody arm must still refuse via PermissionValidationUnavailable",
        );
        let between_norm = normalize(&source[at + marker.len()..err_at]);
        assert!(
            !between_norm.contains(fail_open_return.as_str()),
            "nothing between the discard marker and the permission refusal may \
             return Ok — a guarded early escape there is the same CRY-05/ \
             AUDIT-027 fail-open behind a conditional"
        );
        let tail = &source[at + marker.len()..];
        let next_stmt: String = tail.chars().take(120).collect();
        assert!(
            next_stmt.contains(err_needle),
            "the non-unix key-custody arm must fail closed; found: {next_stmt:?}"
        );
        assert!(
            !next_stmt.trim_start().starts_with("Ok(())"),
            "the non-unix key-custody arm must never return Ok(()) -- that is the \
             fail-open CRY-05/AUDIT-027 records"
        );
    }

    use super::{
        create_provider_attestation, decode_encrypted_blob_v0, decode_encrypted_blob_v1,
        decrypt_private_key_envelope, encrypt_private_key_envelope, generate_key_custody_material,
        sddl_ace_principals, try_generate_key_custody_material, validate_signing_provider_policy,
        verify_provider_attestation, windows_key_custody_sddl_is_hardened, AlgorithmPolicy,
        CryptoAlgorithm, CryptoError, Ed25519SigningProvider, KeyCustodyManager,
        KeyCustodyPermissionPolicy, NoOsSecureStore, NodeKeyPair, SigningProvider,
        SigningProviderKind, SigningProviderPolicy, WINDOWS_KEY_CUSTODY_FILE_SDDL,
    };
    use ed25519_dalek::SigningKey;
    // The encrypted-key-file custody helpers and the OS-store fallback policy are
    // only exercised by `#[cfg(unix)]` tests below (they rely on unix permission
    // bits / symlink semantics); gate the imports to match so Windows does not see
    // them as unused.
    #[cfg(unix)]
    use super::{
        read_encrypted_key_file, read_encrypted_key_file_inner, v0_envelope_fallback_decodes_total,
        v0_envelope_reads_total, v0_envelope_upgrade_failures_total,
        validate_key_custody_permissions, write_encrypted_key_file, OsStoreFallbackPolicy,
    };

    #[test]
    fn hex_decode_accepts_valid_and_rejects_malformed() {
        use super::hex_decode;
        assert_eq!(hex_decode("00ff").unwrap(), vec![0x00, 0xff]);
        assert_eq!(
            hex_decode("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        // Digit decoding is case-insensitive.
        assert_eq!(
            hex_decode("DeAdBeEf").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        // Empty and odd-length inputs are rejected.
        assert!(matches!(
            hex_decode(""),
            Err(CryptoError::AttestationVerificationFailed)
        ));
        assert!(matches!(
            hex_decode("abc"),
            Err(CryptoError::AttestationVerificationFailed)
        ));
        // Even-length inputs containing a non-hex byte are rejected.
        assert!(matches!(
            hex_decode("zz"),
            Err(CryptoError::AttestationVerificationFailed)
        ));
        assert!(matches!(
            hex_decode("0x"),
            Err(CryptoError::AttestationVerificationFailed)
        ));
    }

    #[test]
    fn valid_key_identifier_allowlist_blocks_path_and_namespace_confusion() {
        use super::is_valid_key_identifier;
        // Accepted: ASCII alphanumerics plus '-' and '_'.
        assert!(is_valid_key_identifier("node-1"));
        assert!(is_valid_key_identifier("Abc_123-XYZ"));
        // Rejected: empty.
        assert!(!is_valid_key_identifier(""));
        // Rejected: separators / traversal that would escape the key namespace
        // or fallback directory when interpolated into a path or keychain name.
        assert!(!is_valid_key_identifier("../etc/shadow"));
        assert!(!is_valid_key_identifier("key.enc"));
        assert!(!is_valid_key_identifier("a/b"));
        assert!(!is_valid_key_identifier("a\\b"));
        // Rejected: whitespace, shell/format metacharacters, NUL, and non-ASCII.
        assert!(!is_valid_key_identifier("a b"));
        assert!(!is_valid_key_identifier("key$(rm)"));
        assert!(!is_valid_key_identifier("k\0y"));
        assert!(!is_valid_key_identifier("kéy"));
    }

    /// Regression: `try_generate_key_custody_material` must (1) succeed on a
    /// healthy host, (2) yield distinct salts and nonces under repeated calls
    /// (catches a buggy fallback that returned a zeroed buffer), and (3) keep
    /// the strict `Result<_, CryptoError::RandomnessUnavailable>` shape that
    /// production callers rely on.
    #[test]
    fn try_generate_key_custody_material_returns_distinct_csprng_output() {
        let (salt_a, nonce_a) =
            try_generate_key_custody_material().expect("OsRng available in test env");
        let (salt_b, nonce_b) =
            try_generate_key_custody_material().expect("OsRng available in test env");
        assert_ne!(
            salt_a, salt_b,
            "duplicate Argon2 salt would collapse per-blob KDF uniqueness"
        );
        assert_ne!(
            nonce_a, nonce_b,
            "duplicate XChaCha20-Poly1305 nonce would enable Poly1305 forgery"
        );
        assert!(
            !salt_a.iter().all(|b| *b == 0),
            "zeroed salt indicates fallback was triggered"
        );
        assert!(
            !nonce_a.iter().all(|b| *b == 0),
            "zeroed nonce indicates fallback was triggered"
        );
    }

    /// CRY-11: `Ed25519SigningProvider::from_seed` must wipe its by-value copy of
    /// the seed.
    ///
    /// Pinned by source-grep because a stack wipe is not observable from a unit
    /// test — the same reason this crate already pins the fallible-CSPRNG call
    /// below that way. `SigningKey` zeroizes its own copy on drop, but the
    /// parameter is a separate copy that would otherwise outlive the call.
    #[test]
    fn from_seed_zeroizes_its_seed_parameter() {
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let body =
            std::fs::read_to_string(crate_root.join("src/lib.rs")).expect("crypto source readable");
        let start = body
            .find("pub fn from_seed(")
            .expect("from_seed must remain present");
        let window_end = (start + 1_200).min(body.len());
        let window = &body[start..window_end];
        assert!(
            window.contains("mut seed: [u8; 32]"),
            "from_seed must take the seed as `mut` so it can be wiped"
        );
        assert!(
            window.contains("seed.zeroize()"),
            "from_seed must zeroize its by-value seed copy before returning"
        );
    }

    // ---- RSA-0025: Windows write-time protected DACL (pure SDDL logic) ----

    /// The pinned constant must itself read as hardened, and its exact text
    /// is pinned so a careless edit cannot silently weaken the ACL granted
    /// at write time. It must also stay owner-free: an `O:` field asks
    /// Windows to assign an owner the caller may not have the privilege
    /// for, which fails the create itself (REVIEW FIX follow-up).
    #[test]
    fn rsa0025_pinned_sddl_is_the_hardened_shape() {
        assert_eq!(WINDOWS_KEY_CUSTODY_FILE_SDDL, "D:P(A;;FA;;;SY)(A;;FA;;;BA)");
        assert!(!WINDOWS_KEY_CUSTODY_FILE_SDDL.starts_with("O:"));
        assert!(!WINDOWS_KEY_CUSTODY_FILE_SDDL.starts_with("G:"));
        assert!(windows_key_custody_sddl_is_hardened(
            WINDOWS_KEY_CUSTODY_FILE_SDDL
        ));
    }

    /// REVIEW FIX follow-up: an SDDL that assigns an owner (or group) must
    /// never read as hardened, even with a perfect protected DACL — the
    /// create call that would apply it fails closed for non-SYSTEM
    /// callers without an enabled owner-assignment privilege.
    #[test]
    fn rsa0025_hardened_check_rejects_owner_assignment() {
        assert!(!windows_key_custody_sddl_is_hardened(
            "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)"
        ));
        assert!(!windows_key_custody_sddl_is_hardened(
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
        ));
    }

    /// A grant to Everyone (`WD`), Authenticated Users (`AU`) or Builtin
    /// Users (`BU`) must never read as hardened — this is exactly what the
    /// post-write validators reject, so the pre-write check must agree.
    #[test]
    fn rsa0025_hardened_check_rejects_broad_principal_grants() {
        for broad in ["WD", "AU", "BU"] {
            let sddl = format!("O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{broad})");
            assert!(
                !windows_key_custody_sddl_is_hardened(&sddl),
                "grant to {broad} must not read as hardened"
            );
        }
    }

    /// Without the PROTECTED-DACL flag (`D:P`) inherited host-default ACEs
    /// reappear, so the check must reject it; an SDDL without a DACL at all
    /// likewise.
    #[test]
    fn rsa0025_hardened_check_requires_protected_dacl() {
        assert!(!windows_key_custody_sddl_is_hardened(
            "D:(A;;FA;;;SY)(A;;FA;;;BA)"
        ));
        assert!(!windows_key_custody_sddl_is_hardened(""));
    }

    /// Only ALLOW ACEs are grants: a deny ACE for a broad principal is not a
    /// grant, and principal matching is exact (never a substring of `WDX` or
    /// of a string SID).
    #[test]
    fn rsa0025_hardened_check_counts_allow_aces_not_deny_aces() {
        let deny_wd = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(D;;FA;;;WD)";
        assert!(windows_key_custody_sddl_is_hardened(deny_wd));
        let prefix_trap = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WDX)";
        assert!(windows_key_custody_sddl_is_hardened(prefix_trap));
    }

    /// Both reviewed principals must be granted — dropping either breaks the
    /// daemon's runtime-ACL startup gate (`evaluate_windows_runtime_acl_sddl`
    /// requires SY and BA grants).
    #[test]
    fn rsa0025_hardened_check_requires_sy_and_ba_grants() {
        assert!(!windows_key_custody_sddl_is_hardened("D:P(A;;FA;;;SY)"));
        assert!(!windows_key_custody_sddl_is_hardened("D:P(A;;FA;;;BA)"));
    }

    /// Malformed ACEs grant nothing and never panic: unterminated ACE, wrong
    /// field count, and deny-typed ACEs are all filtered by
    /// [`sddl_ace_principals`].
    #[test]
    fn rsa0025_malformed_aces_are_not_grants() {
        assert!(sddl_ace_principals("(A;;FA;;;SY", "A").is_empty());
        assert!(sddl_ace_principals("(A;;FA;;;SY;extra)", "A").is_empty());
        assert_eq!(sddl_ace_principals("(A;;FA;;;SY)", "A"), vec!["SY"]);
        assert!(sddl_ace_principals("(A;;FA;;;SY)", "D").is_empty());
    }

    /// Witness: on Windows the temp file must be created WITH the protected
    /// DACL (security attributes on create), not created bare and patched
    /// afterwards. Source-pinned with the repo's comment-stripped window
    /// scan, because the flow itself only runs on a Windows host.
    #[test]
    fn rsa0025_windows_temp_file_create_uses_sddl_security_attributes() {
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let body =
            std::fs::read_to_string(crate_root.join("src/lib.rs")).expect("crypto source readable");
        let start = body
            .find("fn write_atomic_encrypted_key_file(")
            .expect("write_atomic_encrypted_key_file must remain present");
        let after_start = start + 8;
        let window_end = body[after_start..]
            .find("\nfn ")
            .map(|at| after_start + at)
            .unwrap_or(body.len());
        let window = strip_non_code(&body[start..window_end]);
        assert!(
            window.contains("create_new_file_with_sddl(&temp, WINDOWS_KEY_CUSTODY_FILE_SDDL)"),
            "Windows key-file write must create the temp file with the pinned protected DACL"
        );
    }

    /// Witness: on Windows the custody directory must be hardened BEFORE the
    /// write, not merely validated afterwards (the RSA-0025 partial-fix gap).
    #[test]
    fn rsa0025_windows_directory_dacl_applied_before_write() {
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let body =
            std::fs::read_to_string(crate_root.join("src/lib.rs")).expect("crypto source readable");
        let start = body
            .find("pub fn write_encrypted_key_file(")
            .expect("write_encrypted_key_file must remain present");
        let after_start = start + 8;
        let window_end = body[after_start..]
            .find("\nfn ")
            .map(|at| after_start + at)
            .unwrap_or(body.len());
        let window = strip_non_code(&body[start..window_end]);
        let dacl_apply = window
            .find("apply_protected_dacl_to_path(directory, WINDOWS_KEY_CUSTODY_FILE_SDDL)")
            .expect("directory protected-DACL application must remain in the write path");
        let atomic_write = window
            .find("write_atomic_encrypted_key_file(file, &encoded")
            .expect("atomic write call must remain in the write path");
        assert!(
            dacl_apply < atomic_write,
            "the directory DACL must be applied BEFORE key material is written"
        );
    }

    /// Witness (RSA-0025 lander): the Windows directory DACL rewrite applies
    /// only to a directory this call created; an existing directory is only
    /// validated, never rewritten.
    #[test]
    fn rsa0025_windows_directory_rewrite_only_for_new_directories() {
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let body =
            std::fs::read_to_string(crate_root.join("src/lib.rs")).expect("crypto source readable");
        let start = body
            .find("pub fn write_encrypted_key_file(")
            .expect("write_encrypted_key_file must remain present");
        let after_start = start + 8;
        let window_end = body[after_start..]
            .find("\nfn ")
            .map(|at| after_start + at)
            .unwrap_or(body.len());
        let window = strip_non_code(&body[start..window_end]);
        let preexisted = window
            .find("let directory_preexisted = directory.exists();")
            .expect("the pre-existence check must remain in the write path");
        let create = window
            .find("create_dir_all(directory)")
            .expect("create_dir_all must remain in the write path");
        assert!(
            preexisted < create,
            "pre-existence must be recorded BEFORE create_dir_all can create the directory"
        );
        let guard = window
            .find("if !directory_preexisted {")
            .expect("the directory DACL rewrite must be conditional on a new directory");
        let dacl_apply = window
            .find("apply_protected_dacl_to_path(directory, WINDOWS_KEY_CUSTODY_FILE_SDDL)")
            .expect("directory protected-DACL application must remain in the write path");
        assert!(
            guard < dacl_apply,
            "the DACL rewrite must sit inside the new-directory guard"
        );
    }

    /// Regression: `write_encrypted_key_file` must use the fallible nonce/salt
    /// generator. A future refactor that called the panicking
    /// `generate_key_custody_material` would re-introduce the same DoS-on-
    /// CSPRNG-fault shape we are trying to remove. We pin via source-grep.
    #[test]
    fn write_encrypted_key_file_calls_fallible_csprng() {
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let body =
            std::fs::read_to_string(crate_root.join("src/lib.rs")).expect("crypto source readable");
        let start = body
            .find("pub fn write_encrypted_key_file(")
            .expect("write_encrypted_key_file must remain present");
        // Bound the window at the NEXT top-level item (col-0 `fn ` / `pub fn `)
        // so a sibling function's own mint statement can never satisfy these
        // pins for THIS function.
        let after_start = start + 8;
        let next_plain = body[after_start..].find("\nfn ").map(|at| after_start + at);
        let next_pub = body[after_start..]
            .find("\npub fn ")
            .map(|at| after_start + at);
        let next_fn = match (next_plain, next_pub) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
        .unwrap_or(body.len());
        let window_end = next_fn.min(body.len());
        // Scan the COMMENT- AND STRING-STRIPPED window: a canonical mint text
        // embedded in a comment or string literal satisfied every textual pin
        // below while the hot path routed through a panicking wrapper.
        let window = strip_non_code(&body[start..window_end]);
        // A bare presence pin is too weak: a wrapper fn whose body mentions
        // the allowed name (or an added cold-branch call) satisfies it while
        // the hot path routes through any other spelling. Pin the canonical
        // mint statement itself...
        let canonical = [
            "let (salt, nonce) = ",
            "try_generate_key_custody_material()?;",
        ]
        .concat();
        assert!(
            window.contains(canonical.as_str()),
            "write_encrypted_key_file must mint its salt+nonce from the canonical \
             fallible expression; routing the hot path through any other spelling \
             (a wrapped/panicking minter included) re-introduces the DoS-on- \
             CSPRNG-fault shape"
        );
        // ...and make the negative half non-vacuous. `generate_key_custody_material()`
        // is a SUBSTRING of the allowed `try_generate_key_custody_material()`, so
        // the old `!contains || contains` disjunction passed whenever the allowed
        // name appeared anywhere in the window. Every occurrence must instead be
        // spelled with the `try_` prefix.
        let minter = ["generate_key_", "custody_material()"].concat();
        let mut at = 0usize;
        let mut occurrences = 0usize;
        while let Some(rel) = window[at..].find(minter.as_str()) {
            let idx = at + rel;
            occurrences += 1;
            assert!(
                idx >= 4 && &window[idx - 4..idx] == "try_",
                "write_encrypted_key_file must reach the minter ONLY as \
                 try_generate_key_custody_material — an occurrence under any other \
                 receiver/path/import alias is the removed panicking minter"
            );
            at = idx + minter.len();
        }
        assert!(occurrences > 0, "the mint call must remain present");
    }

    /// Sign-then-verify round-trip over the degenerate zero-length payload:
    /// the strict (RFC 8032 / ZIP-215) `verify_strict` verifier must accept a
    /// genuine signature even on an empty message.
    #[test]
    fn sign_verify_round_trip_on_empty_message() {
        let provider = Ed25519SigningProvider::from_seed(
            SigningProviderKind::LocalEncryptedFile,
            "round-trip-empty-message",
            [7u8; 32],
        );
        let signature = provider.sign_attestation(b"").expect("signing succeeds");
        provider
            .verify_attestation(b"", &signature)
            .expect("genuine empty-message signature verifies");
    }

    /// Negative half of the empty-message pin: a verifier that fails OPEN
    /// (accepting tampered, truncated, or cross-payload signatures) must be
    /// caught by this test, not only by the broader attestation suite.
    #[test]
    fn empty_message_verification_fails_closed_on_bad_signatures() {
        let provider = Ed25519SigningProvider::from_seed(
            SigningProviderKind::LocalEncryptedFile,
            "empty-message-fail-closed",
            [7u8; 32],
        );
        let signature = provider.sign_attestation(b"").expect("signing succeeds");

        // Tampered: flip one byte of the S component.
        let mut tampered = signature.clone();
        tampered[63] ^= 0x01;
        assert_eq!(
            provider.verify_attestation(b"", &tampered),
            Err(CryptoError::AttestationVerificationFailed),
            "tampered empty-message signature must be rejected"
        );

        // Truncated: 63-byte encoding is structurally invalid.
        assert_eq!(
            provider.verify_attestation(b"", &signature[..63]),
            Err(CryptoError::AttestationVerificationFailed),
            "truncated signature must be rejected"
        );

        // Oversized: 65 bytes must hit the same length guard, not panic or
        // silently truncate into some other accepted encoding.
        let mut oversized = signature.clone();
        oversized.push(0u8);
        assert_eq!(
            provider.verify_attestation(b"", &oversized),
            Err(CryptoError::AttestationVerificationFailed),
            "oversized signature must be rejected"
        );

        // Cross-payload: a signature over b"" is not valid for other data.
        assert_eq!(
            provider.verify_attestation(b"x", &signature),
            Err(CryptoError::AttestationVerificationFailed),
            "empty-message signature must not verify over a different payload"
        );
    }

    /// `try_from_seed` fails closed on the degenerate all-zero seed and
    /// accepts any other 32-byte seed, yielding the same keys as the
    /// infallible test helper.
    #[test]
    fn try_from_seed_rejects_zero_seed_and_matches_from_seed_otherwise() {
        assert_eq!(
            Ed25519SigningProvider::try_from_seed(
                SigningProviderKind::LocalEncryptedFile,
                "zero",
                [0u8; 32],
            )
            .err(),
            Some(CryptoError::WeakMaterial),
            "all-zero seed must be rejected, not minted into a known key"
        );

        let seed = [9u8; 32];
        let fallible = Ed25519SigningProvider::try_from_seed(SigningProviderKind::Kms, "ok", seed)
            .expect("non-zero seed is accepted");
        let infallible = Ed25519SigningProvider::from_seed(SigningProviderKind::Kms, "ok", seed);
        assert_eq!(
            fallible.verifying_key_hex(),
            infallible.verifying_key_hex(),
            "try_from_seed derives the same identity as from_seed"
        );
    }

    /// CRY-11, `try_from_seed` variant: the rejection path must wipe the
    /// by-value seed copy BEFORE returning `WeakMaterial`. A stack wipe is
    /// not observable from a behavioral unit test, so — like the sibling
    /// pins in this module — it is pinned by source-grep.
    #[test]
    fn try_from_seed_wipes_the_seed_before_rejecting() {
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let body =
            std::fs::read_to_string(crate_root.join("src/lib.rs")).expect("crypto source readable");
        let start = body
            .find("pub fn try_from_seed(")
            .expect("try_from_seed must remain present");
        let window_end = (start + 1_500).min(body.len());
        let window = &body[start..window_end];
        let guard = window
            .find("if is_all_zeros(&seed)")
            .expect("try_from_seed must gate on the all-zero seed");
        let err_return = window[guard..]
            .find("return Err(CryptoError::WeakMaterial)")
            .expect("rejection path must return WeakMaterial");
        let prefix = &window[..guard + err_return];
        assert!(
            prefix.contains("seed.zeroize()"),
            "try_from_seed must zeroize its by-value seed copy before rejecting"
        );
    }

    /// Cross-key rejection: a signature made under key A must never
    /// verify under an unrelated key B — a verifier that accepted it
    /// would break identity binding entirely.
    #[test]
    fn verification_rejects_signature_from_wrong_key() {
        let signer = Ed25519SigningProvider::from_seed(
            SigningProviderKind::LocalEncryptedFile,
            "cross-key-signer",
            [11u8; 32],
        );
        let other = Ed25519SigningProvider::from_seed(
            SigningProviderKind::LocalEncryptedFile,
            "cross-key-other",
            [22u8; 32],
        );
        let signature = signer
            .sign_attestation(b"payload")
            .expect("signing succeeds");
        assert_ne!(
            signer.verifying_key_hex(),
            other.verifying_key_hex(),
            "test keys must be distinct for this pin to mean anything"
        );
        assert_eq!(
            other.verify_attestation(b"payload", &signature),
            Err(CryptoError::AttestationVerificationFailed),
            "signature from a different key must be rejected"
        );
    }

    #[test]
    fn rejects_zero_key_material() {
        let result = NodeKeyPair::from_raw([0; 32], [0; 32]);
        assert_eq!(result.err(), Some(CryptoError::WeakMaterial));
    }

    #[test]
    fn accepts_nonzero_key_material() {
        // CRY-06: this fixture used to be `from_raw([7; 32], [9; 32])`, which is
        // NOT a corresponding pair — it passed only because nothing checked that
        // the public half belongs to the private half, and the finding cited this
        // test as the demonstration of that gap. The test's intent (valid nonzero
        // material is accepted) is preserved by deriving the public key.
        let private_key = [9u8; 32];
        let public_key = SigningKey::from_bytes(&private_key)
            .verifying_key()
            .to_bytes();
        let result = NodeKeyPair::from_raw(public_key, private_key);
        assert!(result.is_ok(), "a corresponding pair must be accepted");
    }

    /// CRY-06: a public key that does not belong to the private key must be
    /// refused. Pre-fix `from_raw([7; 32], [9; 32])` was accepted, so the struct
    /// could hold an inconsistent pair — publishing that public key while signing
    /// with that private key produces signatures nobody can verify, or binds an
    /// identity to a key the holder does not control.
    #[test]
    fn rejects_mismatched_public_and_private_key() {
        let result = NodeKeyPair::from_raw([7u8; 32], [9u8; 32]);
        assert_eq!(
            result.err(),
            Some(CryptoError::WeakMaterial),
            "a non-corresponding keypair must be rejected"
        );

        // A pair correct except for a single flipped bit — flipped in the LAST
        // byte deliberately. Flipping byte 0 would also be caught by a
        // first-byte-only comparison, so it would not distinguish a full compare
        // from a weakened one; a mutation to `derived[0] != public_key[0]`
        // survived an earlier version of this test for exactly that reason.
        let private_key = [9u8; 32];
        let mut public_key = SigningKey::from_bytes(&private_key)
            .verifying_key()
            .to_bytes();
        public_key[31] ^= 0x01;
        assert_eq!(
            NodeKeyPair::from_raw(public_key, private_key).err(),
            Some(CryptoError::WeakMaterial),
            "a one-bit mismatch in the final byte must be rejected — the whole key \
             must be compared, not a prefix"
        );
    }

    /// CRY-06: an all-zero seed has a real corresponding public key, so a
    /// genuinely *consistent* all-zero pair is refused only by the all-zeros
    /// branch. The review noted that branch had no discriminating test; this is it.
    #[test]
    fn rejects_consistent_but_all_zero_keypair() {
        let seed = [0u8; 32];
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        assert_eq!(
            NodeKeyPair::from_raw(public_key, seed).err(),
            Some(CryptoError::WeakMaterial),
            "an all-zero seed must be refused even though its public key corresponds"
        );
    }

    /// CRY-12: a declared ciphertext length near `u32::MAX` must be refused.
    ///
    /// **This test does not discriminate the fix on a 64-bit host, and saying so
    /// matters.** `ciphertext_len` comes from a `u32`, so `44 + ciphertext_len`
    /// cannot overflow a 64-bit `usize` — the malformed blob is rejected either
    /// way, and reverting `checked_add` to a wrapping add leaves this test green.
    /// The overflow is only reachable where `usize` is 32-bit (armv7 relay/exit
    /// nodes are a documented roadmap item), where the pre-fix code panics in a
    /// debug build while merely parsing a malformed key file. What this test does
    /// pin is that such a blob is refused at all; the overflow safety itself is
    /// carried by `checked_add` being present, not by this assertion.
    #[test]
    fn blob_decode_rejects_overflowing_declared_length() {
        // v0 frame: [salt:16][nonce:24][len:4][ct] with len = u32::MAX.
        let mut v0 = vec![7u8; 40];
        v0.extend_from_slice(&u32::MAX.to_be_bytes());
        v0.push(0);
        assert_eq!(
            decode_encrypted_blob_v0(&v0).err(),
            Some(CryptoError::InvalidLength)
        );

        // v1 frame: [version:1][salt:16][nonce:24][len:4][ct].
        let mut v1 = vec![1u8];
        v1.extend_from_slice(&[7u8; 40]);
        v1.extend_from_slice(&u32::MAX.to_be_bytes());
        v1.push(0);
        assert_eq!(
            decode_encrypted_blob_v1(&v1).err(),
            Some(CryptoError::InvalidLength)
        );
    }

    #[test]
    fn allowlisted_algorithm_is_accepted() {
        let policy = AlgorithmPolicy::default();
        let result = policy.validate(CryptoAlgorithm::Tls13, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn denylisted_algorithm_is_rejected_without_exception() {
        let policy = AlgorithmPolicy::default();
        let result = policy.validate(CryptoAlgorithm::Sha1, 100);
        assert_eq!(result.err(), Some(CryptoError::DeniedAlgorithm));
    }

    #[test]
    fn default_policy_denies_every_denylisted_and_accepts_every_allowlisted_algorithm() {
        // P1-AT-11 pin: the default policy refuses EVERY denylisted variant
        // with DeniedAlgorithm and accepts EVERY allowlisted variant.
        // RSA-0003 (2026-09-26): there is no exception route left to exercise.
        let policy = AlgorithmPolicy::default();

        for algorithm in [
            CryptoAlgorithm::Md5,
            CryptoAlgorithm::Sha1,
            CryptoAlgorithm::Rc4,
            CryptoAlgorithm::Des,
            CryptoAlgorithm::TripleDes,
            CryptoAlgorithm::BlowfishCbc,
            CryptoAlgorithm::WeakDh,
        ] {
            assert_eq!(
                policy.validate(algorithm, 0).err(),
                Some(CryptoError::DeniedAlgorithm),
                "denylisted {algorithm:?} must be refused with DeniedAlgorithm"
            );
        }

        for algorithm in [
            CryptoAlgorithm::Tls13,
            CryptoAlgorithm::TunnelTransportAead,
            CryptoAlgorithm::Ed25519,
            CryptoAlgorithm::Sha256,
            CryptoAlgorithm::Sha512,
            CryptoAlgorithm::Blake2s,
            CryptoAlgorithm::Blake2b,
            CryptoAlgorithm::HkdfSha256,
            CryptoAlgorithm::Argon2id,
            CryptoAlgorithm::Aes256Gcm,
            CryptoAlgorithm::XChaCha20Poly1305,
        ] {
            assert!(
                policy.validate(algorithm, 0).is_ok(),
                "allowlisted {algorithm:?} must be accepted"
            );
        }
    }

    #[test]
    fn encrypted_envelope_roundtrip_succeeds() {
        let (salt, nonce) = generate_key_custody_material();
        let blob =
            encrypt_private_key_envelope(b"private-material", "phase2-passphrase", salt, nonce)
                .expect("encryption should succeed");

        let plaintext = decrypt_private_key_envelope(&blob, "phase2-passphrase")
            .expect("decryption should succeed");
        assert_eq!(plaintext.as_slice(), b"private-material".as_slice());
    }

    #[test]
    fn encrypted_envelope_rejects_wrong_passphrase() {
        let (salt, nonce) = generate_key_custody_material();
        let blob =
            encrypt_private_key_envelope(b"private-material", "phase2-passphrase", salt, nonce)
                .expect("encryption should succeed");

        let result = decrypt_private_key_envelope(&blob, "wrong-passphrase");
        assert_eq!(result.err(), Some(CryptoError::DecryptionFailed));
    }

    #[test]
    fn encrypted_envelope_is_v1_aad_bound_and_fails_closed_on_version_tamper() {
        // RN-08 (AAD binding): `encrypt_private_key_envelope` always emits a v1
        // envelope whose AEAD AAD binds magic b"RNET" + the version byte. This
        // verification confirms the control end-to-end: (1) v1 is emitted, (2) it
        // round-trips through the on-disk encode/decode router, (3) tampering the
        // version byte fails closed (denied, never decrypted), and (4) the v1
        // ciphertext does not decrypt under the legacy v0 empty-AAD path — i.e.
        // the AAD genuinely binds the envelope context rather than being inert.
        let (salt, nonce) = generate_key_custody_material();
        let blob = encrypt_private_key_envelope(b"private-material", "pw", salt, nonce)
            .expect("encryption should succeed");
        assert_eq!(blob.version, 1, "encrypt must emit a v1 AAD-bound envelope");

        // (2) Round-trip through the real on-disk encoding + decode router.
        let encoded = super::encode_encrypted_blob(&blob)
            .expect("a v1 blob must encode (OI-13: v1 is the only encodable version)");
        assert_eq!(
            encoded[0], 1,
            "v1 encoding carries an explicit version byte"
        );
        let decoded = super::decode_encrypted_blob(&encoded).expect("v1 blob should decode");
        assert_eq!(
            decrypt_private_key_envelope(&decoded, "pw")
                .expect("v1 round-trip should decrypt")
                .as_slice(),
            b"private-material".as_slice()
        );

        // (3) Tamper the version byte to an unknown version: the blob still
        // parses structurally, but decrypt must deny it, never return plaintext.
        let mut tampered = encoded.clone();
        tampered[0] = 2;
        let tampered_blob =
            super::decode_encrypted_blob(&tampered).expect("tampered blob parses structurally");
        assert_eq!(
            decrypt_private_key_envelope(&tampered_blob, "pw").err(),
            Some(CryptoError::DeniedAlgorithm),
            "unknown envelope version must be denied, not decrypted"
        );

        // (4) Re-label the v1 ciphertext as v0 (empty AAD). The tag was computed
        // over the v1 AAD, so the empty-AAD path must fail the tag check.
        let as_v0 = super::EncryptedKeyBlob {
            version: 0,
            salt: blob.salt,
            nonce: blob.nonce,
            ciphertext: blob.ciphertext.clone(),
        };
        assert_eq!(
            decrypt_private_key_envelope(&as_v0, "pw").err(),
            Some(CryptoError::DecryptionFailed),
            "v1 ciphertext must not decrypt under the v0 empty-AAD path"
        );
    }

    #[test]
    fn legacy_v0_envelope_still_decrypts_and_reencrypts_as_v1() {
        // AQ-67 F2 behaviour pin, PRE-cutover: a genuine v0 envelope (empty
        // AAD, as written by legacy writers) still decrypts while the v0
        // empty-AAD decrypt branch is retained (owner cutover decision
        // pending). The positive test also pins the documented migration
        // semantics: any re-encryption emits a v1 AAD-bound envelope, so the
        // next write cycle upgrades a v0 secret in place.
        use super::{Argon2, XChaCha20Poly1305, XNonce};
        use chacha20poly1305::aead::{Aead, KeyInit};
        use zeroize::Zeroize;

        let (salt, nonce) = generate_key_custody_material();
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(b"v0-passphrase", &salt, &mut key)
            .expect("kdf should succeed");
        let cipher = XChaCha20Poly1305::new((&key).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: b"v0-secret",
                    aad: b"",
                },
            )
            .expect("legacy v0 seal should succeed");
        key.zeroize();
        let legacy_blob = super::EncryptedKeyBlob {
            version: 0,
            salt,
            nonce,
            ciphertext,
        };

        let plaintext = decrypt_private_key_envelope(&legacy_blob, "v0-passphrase")
            .expect("legacy v0 envelope must still decrypt pre-cutover");
        assert_eq!(plaintext.as_slice(), b"v0-secret".as_slice());

        // The v0 path still authenticates the passphrase (AEAD tag), it only
        // lacks context binding — a wrong passphrase must fail closed.
        assert_eq!(
            decrypt_private_key_envelope(&legacy_blob, "wrong-passphrase").err(),
            Some(CryptoError::DecryptionFailed),
            "v0 decryption must still verify the passphrase tag"
        );

        // Re-encrypting the recovered secret today always emits v1 (AAD-bound).
        let (salt, nonce) = generate_key_custody_material();
        let upgraded = encrypt_private_key_envelope(&plaintext, "v0-passphrase", salt, nonce)
            .expect("re-encryption should succeed");
        assert_eq!(
            upgraded.version, 1,
            "new writes must always be v1 AAD-bound envelopes"
        );
    }

    // ---- OI-13: re-encrypt-on-read migration window -------------------------
    //
    // The v0-read counters are process-global atomics and libtest runs test
    // threads in parallel, so every test below that performs a v0 disk read
    // takes this mutex: without it, concurrent tests bump the counter while a
    // delta assertion is in flight and the exact-once check flakes.
    // Every v0 disk-read test below is #[cfg(unix)], so the lock must be too
    // or the Windows-target lib-test build fails with dead-code.
    #[cfg(unix)]
    static OI13_V0_DISK_READ_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // Fixture builders and disk-level tests for the v0 -> v1 key-envelope
    // migration. The v0 framing is `[salt:16][nonce:24][len:4][ct]` with no
    // version byte and empty AEAD AAD; the fixture seals with the same empty
    // AAD the legacy v0 decrypt branch expects.

    #[cfg(unix)]
    fn oi13_v0_fixture(passphrase: &str, plaintext: &[u8]) -> Vec<u8> {
        use super::{Argon2, XChaCha20Poly1305, XNonce};
        use chacha20poly1305::aead::{Aead, KeyInit};
        use zeroize::Zeroize;

        // This fixture keeps the first salt byte zero so the OI-13 tests
        // exercise the leading-zero route through `decode_encrypted_blob`;
        // the RSA-0001 tests below cover the colliding non-zero salt[0]
        // shapes the old heuristic misrouted.
        let mut salt = [0u8; 16];
        salt[1] = 0x0d;
        salt[15] = 0xf0;
        let nonce = [0x42u8; 24];

        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
            .expect("kdf should succeed");
        let cipher = XChaCha20Poly1305::new((&key).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: b"",
                },
            )
            .expect("legacy v0 seal should succeed");
        key.zeroize();

        let mut out = Vec::with_capacity(44 + ciphertext.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&ciphertext);
        out
    }

    #[cfg(unix)]
    fn oi13_write_custody_file(directory: &std::path::Path, file: &std::path::Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt;

        std::fs::create_dir_all(directory).expect("custody directory should be created");
        std::fs::write(file, bytes).expect("key file should be written");
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .expect("directory mode should be set");
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))
            .expect("file mode should be set");
    }

    #[cfg(unix)]
    fn oi13_temp_custody_dir(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let unique = format!(
            "rustynet-oi13-{}-{}",
            tag,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(unique);
        let file = directory.join("node-key.enc");
        (directory, file)
    }

    #[cfg(unix)]
    #[test]
    fn v0_key_file_is_upgraded_to_v1_on_disk_by_read() {
        let (directory, file) = oi13_temp_custody_dir("upgrade");
        let _oi13_guard = OI13_V0_DISK_READ_LOCK.lock().expect("OI13 lock poisoned");
        let v0_bytes = oi13_v0_fixture("oi13-pass", b"oi13-disk-secret");
        oi13_write_custody_file(&directory, &file, &v0_bytes);

        let plaintext = read_encrypted_key_file(
            &directory,
            &file,
            "oi13-pass",
            KeyCustodyPermissionPolicy::default(),
        )
        .expect("v0 envelope must still decrypt during the OI-13 window");
        assert_eq!(plaintext.as_slice(), b"oi13-disk-secret".as_slice());

        let on_disk = std::fs::read(&file).expect("upgraded file should be readable");
        let blob =
            super::decode_encrypted_blob(&on_disk).expect("the re-sealed blob must decode cleanly");
        assert_eq!(
            blob.version, 1,
            "OI-13: reading a v0 key file must re-seal it as v1 on disk"
        );
        let again = decrypt_private_key_envelope(&blob, "oi13-pass")
            .expect("the v1 re-seal must decrypt under the same passphrase");
        assert_eq!(again.as_slice(), b"oi13-disk-secret".as_slice());

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&directory);
    }

    #[cfg(unix)]
    #[test]
    fn second_read_of_upgraded_file_takes_the_v1_path() {
        let (directory, file) = oi13_temp_custody_dir("second-read");
        let _oi13_guard = OI13_V0_DISK_READ_LOCK.lock().expect("OI13 lock poisoned");
        let v0_bytes = oi13_v0_fixture("oi13-pass", b"oi13-second-secret");
        oi13_write_custody_file(&directory, &file, &v0_bytes);

        let policy = KeyCustodyPermissionPolicy::default();
        let first = read_encrypted_key_file(&directory, &file, "oi13-pass", policy)
            .expect("first (v0) read should succeed");
        assert_eq!(first.as_slice(), b"oi13-second-secret".as_slice());

        let after_first = std::fs::read(&file).expect("file should be readable");
        let first_blob = super::decode_encrypted_blob(&after_first)
            .expect("blob after the first read must decode");
        assert_eq!(
            first_blob.version, 1,
            "first read must have upgraded the file"
        );

        let second = read_encrypted_key_file(&directory, &file, "oi13-pass", policy)
            .expect("second read should take the v1 path");
        assert_eq!(second.as_slice(), b"oi13-second-secret".as_slice());

        let after_second = std::fs::read(&file).expect("file should be readable");
        assert_eq!(
            after_second, after_first,
            "the v1 file must be byte-stable across a second read"
        );

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&directory);
    }

    // BEFORE-RUN SHELF (OI-13): encoder test restored with the fix.
    #[test]
    fn encoder_never_emits_v0_blobs() {
        // OI-13: the on-disk writer must be physically unable to persist a v0
        // envelope, so the migration window can only shrink the v0 fleet.
        let v0_blob = super::EncryptedKeyBlob {
            version: 0,
            salt: [7u8; 16],
            nonce: [9u8; 24],
            ciphertext: vec![1, 2, 3],
        };
        assert_eq!(
            super::encode_encrypted_blob(&v0_blob).err(),
            Some(CryptoError::DeniedAlgorithm),
            "OI-13: no code path may encode a v0 envelope for persistence"
        );
    }
    #[cfg(unix)]
    #[test]
    fn tampered_v0_key_file_is_rejected_and_left_unmodified() {
        let (directory, file) = oi13_temp_custody_dir("tamper-v0");
        let _oi13_guard = OI13_V0_DISK_READ_LOCK.lock().expect("OI13 lock poisoned");
        let mut v0_bytes = oi13_v0_fixture("oi13-pass", b"oi13-tamper-secret");
        let last = v0_bytes.len() - 1;
        v0_bytes[last] ^= 0x01;
        oi13_write_custody_file(&directory, &file, &v0_bytes);

        let result = read_encrypted_key_file(
            &directory,
            &file,
            "oi13-pass",
            KeyCustodyPermissionPolicy::default(),
        );
        assert_eq!(
            result.err(),
            Some(CryptoError::DecryptionFailed),
            "a tampered v0 envelope must fail the AEAD tag check"
        );
        assert_eq!(
            std::fs::read(&file).expect("file should survive a rejected read"),
            v0_bytes,
            "a rejected v0 read must not rewrite the file"
        );

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&directory);
    }

    #[cfg(unix)]
    #[test]
    fn tampered_v1_key_file_is_rejected() {
        let (directory, file) = oi13_temp_custody_dir("tamper-v1");
        let policy = KeyCustodyPermissionPolicy::default();
        write_encrypted_key_file(&directory, &file, b"oi13-v1-secret", "oi13-pass", policy)
            .expect("v1 write should succeed");

        let mut on_disk = std::fs::read(&file).expect("v1 file should be readable");
        let last = on_disk.len() - 1;
        on_disk[last] ^= 0x01;
        std::fs::write(&file, &on_disk).expect("tampered file should be written");

        let result = read_encrypted_key_file(&directory, &file, "oi13-pass", policy);
        assert_eq!(
            result.err(),
            Some(CryptoError::DecryptionFailed),
            "a tampered v1 envelope must fail the AEAD tag check"
        );

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&directory);
    }

    #[cfg(unix)]
    #[test]
    fn v0_reads_are_counted_and_v1_reads_are_not() {
        let (directory, file) = oi13_temp_custody_dir("counter");
        let _oi13_guard = OI13_V0_DISK_READ_LOCK.lock().expect("OI13 lock poisoned");
        let v0_bytes = oi13_v0_fixture("oi13-pass", b"oi13-counter-secret");
        oi13_write_custody_file(&directory, &file, &v0_bytes);
        let policy = KeyCustodyPermissionPolicy::default();

        let before = v0_envelope_reads_total();
        read_encrypted_key_file(&directory, &file, "oi13-pass", policy)
            .expect("v0 read should succeed during the OI-13 window");
        assert_eq!(
            v0_envelope_reads_total(),
            before + 1,
            "exactly one v0 disk read must be counted"
        );

        let mid = v0_envelope_reads_total();
        read_encrypted_key_file(&directory, &file, "oi13-pass", policy)
            .expect("second (v1) read should succeed");
        assert_eq!(
            v0_envelope_reads_total(),
            mid,
            "the v1 path must not advance the v0 counter"
        );

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&directory);
    }

    #[cfg(unix)]
    #[test]
    fn failed_v1_persist_keeps_v0_file_and_still_returns_key() {
        let (directory, file) = oi13_temp_custody_dir("persist-failure");
        let _oi13_guard = OI13_V0_DISK_READ_LOCK.lock().expect("OI13 lock poisoned");
        let v0_bytes = oi13_v0_fixture("oi13-pass", b"oi13-durable-secret");
        oi13_write_custody_file(&directory, &file, &v0_bytes);
        let policy = KeyCustodyPermissionPolicy::default();

        let before_failures = v0_envelope_upgrade_failures_total();
        let refusing_persist: &super::PersistKeyFileFn = &|_, _, _, _, _| Err(CryptoError::Io);

        let result =
            read_encrypted_key_file_inner(&directory, &file, "oi13-pass", policy, refusing_persist);
        let plaintext =
            result.expect("a failed v1 persist must NOT lose the already-authenticated key");
        assert_eq!(plaintext.as_slice(), b"oi13-durable-secret".as_slice());

        assert_eq!(
            std::fs::read(&file).expect("v0 file should survive the failed persist"),
            v0_bytes,
            "OI-13: the v0 file must stay on disk until the v1 write is durable"
        );
        assert_eq!(
            v0_envelope_upgrade_failures_total(),
            before_failures + 1,
            "the failed upgrade must be visible to operators"
        );

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&directory);
    }

    #[cfg(unix)]
    #[test]
    fn validates_strict_key_custody_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let unique = format!(
            "rustynet-crypto-permission-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let temp_dir = std::env::temp_dir().join(unique);
        let key_file = temp_dir.join("node-key.enc");

        std::fs::create_dir_all(&temp_dir).expect("temp directory should be created");
        std::fs::write(&key_file, b"ciphertext").expect("key file should be written");

        std::fs::set_permissions(&temp_dir, std::fs::Permissions::from_mode(0o700))
            .expect("directory mode should be set");
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600))
            .expect("file mode should be set");

        let validation = validate_key_custody_permissions(
            &temp_dir,
            &key_file,
            KeyCustodyPermissionPolicy::default(),
        );

        assert!(validation.is_ok());
        let _ = std::fs::remove_file(&key_file);
        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_weak_key_custody_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let unique = format!(
            "rustynet-crypto-permission-test-weak-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let temp_dir = std::env::temp_dir().join(unique);
        let key_file = temp_dir.join("node-key.enc");

        std::fs::create_dir_all(&temp_dir).expect("temp directory should be created");
        std::fs::write(&key_file, b"ciphertext").expect("key file should be written");

        std::fs::set_permissions(&temp_dir, std::fs::Permissions::from_mode(0o755))
            .expect("directory mode should be set");
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o644))
            .expect("file mode should be set");

        let validation = validate_key_custody_permissions(
            &temp_dir,
            &key_file,
            KeyCustodyPermissionPolicy::default(),
        );

        assert_eq!(validation.err(), Some(CryptoError::PermissionDenied));
        let _ = std::fs::remove_file(&key_file);
        let _ = std::fs::remove_dir(&temp_dir);
    }

    #[cfg(unix)]
    #[test]
    fn encrypted_key_file_roundtrip_with_permission_checks() {
        let unique = format!(
            "rustynet-encrypted-key-file-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(unique);
        let file = directory.join("node-key.enc");

        write_encrypted_key_file(
            &directory,
            &file,
            b"very-secret-private-key",
            "phase2-passphrase",
            KeyCustodyPermissionPolicy::default(),
        )
        .expect("write should succeed");

        let plaintext = read_encrypted_key_file(
            &directory,
            &file,
            "phase2-passphrase",
            KeyCustodyPermissionPolicy::default(),
        )
        .expect("read should succeed");

        assert_eq!(plaintext.as_slice(), b"very-secret-private-key".as_slice());

        let wrong = read_encrypted_key_file(
            &directory,
            &file,
            "wrong-passphrase",
            KeyCustodyPermissionPolicy::default(),
        );
        assert_eq!(wrong.err(), Some(CryptoError::DecryptionFailed));

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&directory);
    }

    #[cfg(unix)]
    #[test]
    fn read_encrypted_key_file_refuses_oversized_file_before_reading() {
        use std::os::unix::fs::PermissionsExt;

        let unique = format!(
            "rustynet-oversized-key-file-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&directory).expect("directory should be created");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("directory mode should be set");
        let file = directory.join("node-key.enc");
        // Valid custody modes so the permission gate passes and ONLY the
        // size bound can reject the read.
        std::fs::write(&file, vec![b'x'; 64 * 1024 + 1]).expect("oversize file written");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))
            .expect("file mode should be set");

        let result = read_encrypted_key_file(
            &directory,
            &file,
            "phase2-passphrase",
            KeyCustodyPermissionPolicy::default(),
        );

        assert_eq!(result.err(), Some(CryptoError::Io));

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&directory);
    }

    #[cfg(unix)]
    #[test]
    fn key_custody_manager_falls_back_when_os_store_unavailable() {
        let unique = format!(
            "rustynet-key-custody-manager-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let fallback_directory = std::env::temp_dir().join(unique);
        let manager = KeyCustodyManager::new(
            NoOsSecureStore,
            fallback_directory.clone(),
            "phase2-passphrase".to_owned(),
            KeyCustodyPermissionPolicy::default(),
        );

        let backend = manager
            .store_private_key("node_identity", b"node-private-key")
            .expect("fallback storage should succeed");
        assert_eq!(backend, super::KeyCustodyBackend::EncryptedFileFallback);

        let loaded = manager
            .load_private_key("node_identity")
            .expect("fallback read should succeed");
        assert_eq!(loaded.as_slice(), b"node-private-key".as_slice());

        let key_file = fallback_directory.join("node_identity.enc");
        let _ = std::fs::remove_file(key_file);
        let _ = std::fs::remove_dir(fallback_directory);
    }

    #[cfg(unix)]
    #[test]
    fn load_private_key_returns_zeroizing_key_bytes() {
        // AQ-67 F1: decrypted key bytes must leave this crate as
        // zeroize-on-drop memory, not a bare `Vec<u8>`. The type annotation is
        // the enforcement point: reverting the return type to
        // `Result<Vec<u8>, _>` fails compilation, not merely review.
        use zeroize::Zeroizing;

        let unique = format!(
            "rustynet-crypto-zeroizing-load-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let fallback_directory = std::env::temp_dir().join(unique);
        let manager = KeyCustodyManager::new(
            NoOsSecureStore,
            fallback_directory.clone(),
            "phase2-passphrase".to_owned(),
            KeyCustodyPermissionPolicy::default(),
        );

        manager
            .store_private_key("node_identity", b"node-private-key")
            .expect("fallback storage should succeed");

        let loaded: Zeroizing<Vec<u8>> = manager
            .load_private_key("node_identity")
            .expect("fallback read should succeed");
        assert_eq!(loaded.as_slice(), b"node-private-key".as_slice());

        let key_file = fallback_directory.join("node_identity.enc");
        let _ = std::fs::remove_file(key_file);
        let _ = std::fs::remove_dir(fallback_directory);
    }

    #[cfg(unix)]
    #[test]
    fn key_custody_manager_strict_mode_rejects_encrypted_file_fallback() {
        let unique = format!(
            "rustynet-key-custody-manager-strict-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let fallback_directory = std::env::temp_dir().join(unique);
        let manager = KeyCustodyManager::new(
            NoOsSecureStore,
            fallback_directory.clone(),
            "phase2-passphrase".to_owned(),
            KeyCustodyPermissionPolicy::default(),
        )
        .with_fallback_policy(OsStoreFallbackPolicy::RequireOsSecureStore);

        let store_result = manager.store_private_key("node_identity", b"node-private-key");
        assert_eq!(store_result.err(), Some(CryptoError::OsStoreUnavailable));
        assert!(!fallback_directory.join("node_identity.enc").exists());

        let load_result = manager.load_private_key("node_identity");
        assert_eq!(load_result.err(), Some(CryptoError::OsStoreUnavailable));

        let _ = std::fs::remove_dir(fallback_directory);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_key_file_permissions() {
        use std::os::unix::fs::symlink;

        let unique = format!(
            "rustynet-key-custody-symlink-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(unique);
        let target = directory.join("node-key.target");
        let file = directory.join("node-key.enc");

        std::fs::create_dir_all(&directory).expect("directory should be created");
        std::fs::write(&target, b"ciphertext").expect("target should be written");
        symlink(&target, &file).expect("symlink should be created");

        let result = validate_key_custody_permissions(
            &directory,
            &file,
            KeyCustodyPermissionPolicy::default(),
        );
        assert_eq!(result.err(), Some(CryptoError::PermissionDenied));

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_dir(&directory);
    }

    #[test]
    fn signing_provider_policy_matrix_accepts_and_rejects_each_arm() {
        // Arm coverage for validate_signing_provider_policy: the
        // hardware-primary rejection was pinned; here the ACCEPT path
        // and the LOCAL-FALLBACK-DISALLOWED rejection arm get pinned.
        let kms = SigningProviderKind::Kms;
        let local = SigningProviderKind::LocalEncryptedFile;

        // 1. Hardware-backed primary, no fallback: always acceptable.
        let no_fallback = SigningProviderPolicy {
            require_hardware_backed_primary: true,
            allow_local_fallback: true,
        };
        assert_eq!(
            validate_signing_provider_policy(kms, None, no_fallback),
            Ok(())
        );

        // 2. Software primary permitted when the policy does not
        //    demand a hardware-backed primary.
        let software_ok = SigningProviderPolicy {
            require_hardware_backed_primary: false,
            allow_local_fallback: false,
        };
        assert_eq!(
            validate_signing_provider_policy(local, None, software_ok),
            Ok(())
        );

        // 3. A local fallback is refused when the policy forbids it.
        let no_local = SigningProviderPolicy {
            require_hardware_backed_primary: false,
            allow_local_fallback: false,
        };
        assert_eq!(
            validate_signing_provider_policy(kms, Some(local), no_local),
            Err(CryptoError::UnsupportedProviderPolicy)
        );
        let _ = software_ok;
    }

    #[test]
    fn key_custody_manager_rejects_invalid_key_identifier() {
        let manager = KeyCustodyManager::new(
            NoOsSecureStore,
            std::env::temp_dir().join("rustynet-key-custody-invalid-id"),
            "phase2-passphrase".to_owned(),
            KeyCustodyPermissionPolicy::default(),
        );

        let result = manager.store_private_key("bad/key", b"node-private-key");
        assert_eq!(result.err(), Some(CryptoError::InvalidLength));
    }

    #[test]
    fn signing_provider_policy_requires_hardware_primary() {
        let result = validate_signing_provider_policy(
            SigningProviderKind::LocalEncryptedFile,
            Some(SigningProviderKind::Kms),
            SigningProviderPolicy {
                require_hardware_backed_primary: true,
                allow_local_fallback: true,
            },
        );
        assert_eq!(result.err(), Some(CryptoError::UnsupportedProviderPolicy));
    }

    #[test]
    fn provider_attestation_roundtrip_verifies() {
        let provider = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/signing-key",
            [7; 32],
        );
        let payload = b"release-artifact-digest";
        let attestation =
            create_provider_attestation(&provider, payload).expect("attestation should be created");

        verify_provider_attestation(&provider, payload, &attestation)
            .expect("attestation should verify");

        let bad_result = verify_provider_attestation(&provider, b"tampered", &attestation);
        assert_eq!(
            bad_result.err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn provider_attestation_rejects_wrong_signing_key() {
        let source = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/signing-key",
            [7; 32],
        );
        let payload = b"release-artifact-digest";
        let attestation =
            create_provider_attestation(&source, payload).expect("attestation should be created");

        let wrong_provider = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/signing-key",
            [9; 32],
        );
        let verification = verify_provider_attestation(&wrong_provider, payload, &attestation);
        assert_eq!(
            verification.err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    /// The envelope's provider_kind and key_identifier bindings must each
    /// reject INDEPENDENTLY of the signature math: existing negative tests
    /// vary the seed, so a deleted kind or id guard would have survived the
    /// suite behind the signature check.
    #[test]
    fn verify_provider_attestation_rejects_kind_and_key_id_mismatches() {
        let payload = b"release-artifact-digest";
        let source = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/signing-key",
            [7; 32],
        );
        let attestation =
            create_provider_attestation(&source, payload).expect("attestation should be created");

        // Same identifier, same key material, WRONG provider kind.
        let other_kind = Ed25519SigningProvider::from_seed(
            SigningProviderKind::LocalEncryptedFile,
            "kms://rustynet/signing-key",
            [7; 32],
        );
        assert_eq!(
            verify_provider_attestation(&other_kind, payload, &attestation).err(),
            Some(CryptoError::AttestationVerificationFailed),
            "provider_kind mismatch must reject before any signature work"
        );

        // Same kind, same key material, WRONG key identifier.
        let other_id = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://other/signing-key",
            [7; 32],
        );
        assert_eq!(
            verify_provider_attestation(&other_id, payload, &attestation).err(),
            Some(CryptoError::AttestationVerificationFailed),
            "key_identifier mismatch must reject before any signature work"
        );
    }

    #[test]
    fn fresh_keypair_sign_then_verify_accepts_valid_signature() {
        // Happy path, raw trait level: a FRESH keypair signs a
        // message and its own verify() accepts the signature.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/happy-path-fresh",
            [21; 32],
        );
        let message = b"happy-path-canary";
        let signature = keypair.sign_attestation(message).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(message, &signature)
            .expect("a valid signature from the same fresh key must be accepted");
    }

    #[test]
    fn fresh_ed25519_keypairs_are_distinct() {
        // No key reuse: two independently generated keypairs must
        // have different public keys and produce different signatures
        // over the same bytes. (The CSPRNG salt/nonce distinctness pin
        // covers custody material; this covers the signing identity.)
        let a = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/distinct-a",
            [31; 32],
        );
        let b = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/distinct-b",
            [32; 32],
        );

        let vk_a = a.verifying_key_hex();
        let vk_b = b.verifying_key_hex();
        assert!(!vk_a.is_empty());
        assert_ne!(vk_a, vk_b, "distinct seeds must yield distinct public keys");
        // Deterministic derivation: the same provider reports the
        // same public key on every call.
        assert_eq!(vk_a, a.verifying_key_hex());

        let message = b"key-distinctness-canary";
        let sig_a = a.sign_attestation(message).expect("sign a");
        let sig_b = b.sign_attestation(message).expect("sign b");
        assert_ne!(
            sig_a, sig_b,
            "distinct keys must not emit identical signatures over the same message"
        );
    }

    #[test]
    fn verify_attestation_rejects_all_zero_and_empty_signatures() {
        // Bytes of zero are not a signature: an all-zero 64-byte
        // blob has degenerate (identity/small-order) R and S points
        // and must be refused by strict verification, not accepted
        // because its LENGTH happens to be right. An empty slice is
        // refused even earlier, by the length guard.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/zero-signature",
            [41; 32],
        );
        let payload = b"zero-signature-canary";

        let all_zero = vec![0u8; 64];
        assert_eq!(
            keypair.verify_attestation(payload, &all_zero).err(),
            Some(CryptoError::AttestationVerificationFailed),
            "an all-zero 64-byte blob must not verify"
        );

        assert_eq!(
            keypair.verify_attestation(payload, &[]).err(),
            Some(CryptoError::AttestationVerificationFailed),
            "an empty signature must be refused by the length guard"
        );

        // Control: a real signature over the same payload verifies.
        let genuine = keypair.sign_attestation(payload).expect("sign");
        assert!(genuine != all_zero);
        keypair
            .verify_attestation(payload, &genuine)
            .expect("control signature must verify");
    }

    #[test]
    fn signing_is_deterministic_same_message_same_signature() {
        // RFC 8032 ed25519 is deterministic: the same key over the
        // same bytes must yield byte-identical signatures on every
        // call. Randomized signing would break signature-derived
        // dedup/replay bookkeeping downstream.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/determinism",
            [51; 32],
        );
        let message = b"determinism-canary";
        let first = keypair.sign_attestation(message).expect("sign once");
        let second = keypair.sign_attestation(message).expect("sign twice");
        assert_eq!(first.len(), 64);
        assert_eq!(
            first, second,
            "the same key over the same message must produce identical signature bytes"
        );

        // Control: a different message still signs differently.
        let other = keypair
            .sign_attestation(b"other-canary")
            .expect("sign other");
        assert_ne!(first, other);
    }

    #[test]
    fn verify_attestation_rejects_signature_with_flipped_last_byte() {
        // Flipping ANY byte of a valid signature — including the last
        // byte of S — must break verification.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/flip-last-byte",
            [61; 32],
        );
        let payload = b"flip-last-byte-canary";
        let mut signature = keypair.sign_attestation(payload).expect("sign");
        keypair
            .verify_attestation(payload, &signature)
            .expect("control signature must verify");

        let last = signature[63];
        signature[63] = if last == u8::MAX { 0 } else { last + 1 };
        assert_eq!(
            keypair.verify_attestation(payload, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed),
            "a signature with a flipped final byte must be rejected"
        );
    }

    #[test]
    fn verify_attestation_rejects_signature_presented_for_different_message() {
        // A signature over message A binds to A's bytes only: verify()
        // against a DIFFERENT message B must return Err even though
        // the signature itself is genuine.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/cross-message",
            [71; 32],
        );
        let message_a = b"message-a-canary";
        let message_b = b"an entirely different message B";
        let signature_a = keypair.sign_attestation(message_a).expect("sign a");
        keypair
            .verify_attestation(message_a, &signature_a)
            .expect("control: signature verifies for its own message");

        assert_eq!(
            keypair.verify_attestation(message_b, &signature_a).err(),
            Some(CryptoError::AttestationVerificationFailed),
            "a signature over A must not verify against B"
        );
    }

    #[test]
    fn two_keypairs_signing_same_message_yield_different_signatures() {
        // Signatures bind to the signer's key: the SAME message
        // signed by two different keypairs must produce different
        // signature bytes.
        let keypair_a = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/sig-diff-a",
            [81; 32],
        );
        let keypair_b = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/sig-diff-b",
            [82; 32],
        );
        let message = b"same-message-two-signers";
        let sig_a = keypair_a.sign_attestation(message).expect("sign a");
        let sig_b = keypair_b.sign_attestation(message).expect("sign b");
        assert_eq!(sig_a.len(), 64);
        assert_eq!(sig_b.len(), 64);
        assert_ne!(
            sig_a, sig_b,
            "two different keys must not produce identical signatures"
        );
    }

    #[test]
    fn empty_message_sign_and_verify_round_trips() {
        // Empty-input edge case: ed25519 signs the SHA-512 of the
        // message, so b"" is a valid input — sign must succeed and
        // verify of that signature over b"" must ACCEPT.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/empty-message",
            [91; 32],
        );
        let empty: &[u8] = b"";
        let signature = keypair
            .sign_attestation(empty)
            .expect("empty payload signs");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(empty, &signature)
            .expect("signature over the empty message must verify");

        // Control: it is bound to the empty string, not to everything.
        let err = keypair.verify_attestation(b"x", &signature).err();
        assert_eq!(err, Some(CryptoError::AttestationVerificationFailed));
    }

    #[test]
    fn verify_attestation_rejects_truncated_signatures_without_panicking() {
        // Any non-64-byte signature — truncated or over-long — must
        // come back as a typed error, never panic and never verify.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/truncation",
            [101; 32],
        );
        let payload = b"truncation-canary";
        let signature = keypair.sign_attestation(payload).expect("sign");

        for len in [0usize, 1, 32, 63] {
            let truncated = &signature[..len];
            assert_eq!(
                keypair.verify_attestation(payload, truncated).err(),
                Some(CryptoError::AttestationVerificationFailed),
                "truncated-to-{len}-byte signature must be rejected"
            );
        }
        for len in [65usize, 128] {
            let mut overlong = signature.clone();
            overlong.resize(len, 0);
            assert_eq!(
                keypair.verify_attestation(payload, &overlong).err(),
                Some(CryptoError::AttestationVerificationFailed),
                "over-long-{len}-byte signature must be rejected"
            );
        }

        // Control: the untouched signature still verifies.
        keypair
            .verify_attestation(payload, &signature)
            .expect("control signature must verify");
    }

    #[test]
    fn signature_from_keypair_a_is_rejected_by_keypair_b() {
        // Wrong-key rejection: a signature made by keypair A must be
        // REJECTED when verified against keypair B's public key.
        let a = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/wrong-key-a",
            [111; 32],
        );
        let b = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/wrong-key-b",
            [112; 32],
        );
        assert_ne!(a.verifying_key_hex(), b.verifying_key_hex());

        let message = b"wrong-key-canary";
        let sig_a = a.sign_attestation(message).expect("sign with A");

        // Control: B's own signature verifies under B.
        let sig_b = b.sign_attestation(message).expect("sign with B");
        b.verify_attestation(message, &sig_b)
            .expect("control: B verifies its own signature");

        assert_eq!(
            b.verify_attestation(message, &sig_a).err(),
            Some(CryptoError::AttestationVerificationFailed),
            "B must reject the signature produced by A"
        );
        assert_eq!(
            a.verify_attestation(message, &sig_b).err(),
            Some(CryptoError::AttestationVerificationFailed),
            "A must reject the signature produced by B"
        );
    }

    #[test]
    fn ed25519_verifying_key_is_exactly_32_bytes() {
        // An ed25519 public key is exactly 32 bytes; the hex form is
        // 64 characters and decodes to 32 bytes. A shorter or longer
        // key would break every downstream fixed-size key check.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/vk-length",
            [121; 32],
        );
        let vk_hex = keypair.verifying_key_hex();
        assert_eq!(
            vk_hex.len(),
            64,
            "hex encoding of a 32-byte key is 64 chars"
        );
        let decoded = super::hex_decode(&vk_hex).expect("hex must decode");
        assert_eq!(decoded.len(), 32, "ed25519 public keys are 32 bytes");
        // Deterministic: same provider, same key material.
        assert_eq!(vk_hex, keypair.verifying_key_hex());
    }

    #[test]
    fn ed25519_secret_key_is_exactly_32_bytes() {
        // The signing key material is exactly 32 bytes: the SecretKey
        // newtype wraps [u8; 32] (compile-time enforced), as_bytes()
        // exposes exactly 32 bytes, and size_of confirms no padding
        // or extra storage leaks into the wire representation.
        let secret = super::SecretKey([7u8; 32]);
        assert_eq!(secret.as_bytes().len(), 32);
        assert_eq!(std::mem::size_of::<super::SecretKey>(), 32);

        // from_seed accepts ONLY a [u8; 32] seed — pin that the
        // provider derives from full-width key material by signing
        // with a known seed and verifying determinism of the derived
        // identity (indirect but observable without exposing bytes).
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/sk-length",
            [131; 32],
        );
        let sig = keypair.sign_attestation(b"sk-length-canary").expect("sign");
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn verify_attestation_rejects_bitwise_not_of_valid_signature() {
        // The full bitwise complement of a genuine signature inverts
        // BOTH the R point encoding and the S scalar: neither can
        // still satisfy the verification equation. Strict
        // verification must reject it outright.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/bitflip-all",
            [141; 32],
        );
        let payload = b"all-bits-flipped-canary";
        let signature = keypair.sign_attestation(payload).expect("sign");
        keypair
            .verify_attestation(payload, &signature)
            .expect("control signature must verify");

        let inverted: Vec<u8> = signature.iter().map(|b| !b).collect();
        assert_eq!(inverted.len(), 64);
        assert_ne!(inverted, signature);
        assert_eq!(
            keypair.verify_attestation(payload, &inverted).err(),
            Some(CryptoError::AttestationVerificationFailed),
            "the bitwise complement of a valid signature must be rejected"
        );
    }

    #[test]
    fn same_key_signing_different_messages_yields_different_signatures() {
        // Signatures bind to the message: the SAME key over two
        // DIFFERENT messages must produce different signature bytes.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/msg-diff",
            [151; 32],
        );
        let sig_a = keypair
            .sign_attestation(b"first-message-canary")
            .expect("sign a");
        let sig_b = keypair
            .sign_attestation(b"second-message-canary")
            .expect("sign b");
        assert_eq!(sig_a.len(), 64);
        assert_eq!(sig_b.len(), 64);
        assert_ne!(
            sig_a, sig_b,
            "the same key must not emit identical signatures over different messages"
        );
    }

    #[test]
    fn large_message_sign_and_verify_round_trips() {
        // Large-input edge case: a ~100KB message must sign and
        // verify exactly like small ones — ed25519 hashes internally,
        // so payload size never bypasses verification.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/large-message",
            [161; 32],
        );
        let mut payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(payload.len(), 100_000);

        let signature = keypair.sign_attestation(&payload).expect("large sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the large message must verify");

        // Control: flipping ONE byte anywhere in the 100KB blob —
        // including near the far end, past any plausible block
        // boundary — must be rejected.
        let last = payload.len() - 1;
        payload[last] ^= 0x01;
        assert_eq!(
            keypair.verify_attestation(&payload, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed),
            "a single flipped byte in the large message must invalidate the signature"
        );
    }

    #[test]
    fn one_byte_message_sign_and_verify_round_trips() {
        // Minimal non-empty input: a single-byte message signs and
        // verifies like any other — no special-casing on length 1.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/one-byte",
            [171; 32],
        );
        let payload = [0x42u8];
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the one-byte message must verify");

        // Control: a different single byte is not covered.
        let other = [0x43u8];
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn independent_keypairs_have_different_secret_keys() {
        // No secret reuse: two independently generated keypairs must
        // hold different signing-key material, not merely present
        // different public halves. White-box by necessity — the
        // signing_key field is deliberately inaccessible outside.
        let a = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/sk-distinct-a",
            [191; 32],
        );
        let b = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/sk-distinct-b",
            [192; 32],
        );
        let sk_a = a.signing_key.to_bytes();
        let sk_b = b.signing_key.to_bytes();
        assert_eq!(sk_a.len(), 32);
        assert_ne!(
            sk_a, sk_b,
            "distinct seeds must derive distinct secret keys"
        );
    }

    #[test]
    fn empty_slice_sign_then_verify_is_ok() {
        // Signing an empty byte slice succeeds and its signature
        // verifies with Ok — empty input is valid input.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/empty-slice",
            [201; 32],
        );
        let empty: &[u8] = &[];
        let result = keypair
            .sign_attestation(empty)
            .and_then(|sig| keypair.verify_attestation(empty, &sig).map(|_| sig));
        assert!(result.is_ok(), "empty-slice round-trip must return Ok");
        let sig = result.expect("sig").clone();
        assert_eq!(sig.len(), 64);

        // Control keeps the test mutation-sensitive: verification is
        // not a blanket accept-all.
        assert_eq!(
            keypair.verify_attestation(b"x", &sig).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn sign_verifies_against_same_keypairs_derived_public_key() {
        // Self-consistency: the public key derived FROM the secret
        // half (published as verifying_key_hex) must verify what the
        // secret half signs.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/self-consistency",
            [211; 32],
        );
        let message = b"self-consistency-canary";
        let signature = keypair.sign_attestation(message).expect("sign");

        // Reconstruct the verifier purely from the PUBLISHED public
        // half and check it accepts the signature.
        let vk_bytes = super::hex_decode(&keypair.verifying_key_hex()).expect("vk hex");
        let vk =
            ed25519_dalek::VerifyingKey::from_bytes(vk_bytes.as_slice().try_into().expect("32"))
                .expect("public key derives");
        let dalek_sig = ed25519_dalek::Signature::from_slice(&signature)
            .expect("signature bytes are well-formed");
        vk.verify_strict(message, &dalek_sig)
            .expect("derived public key must verify the signature");

        // Provider path agrees, and tampering is still rejected
        // (keeps this test sensitive to verification mutations).
        keypair
            .verify_attestation(message, &signature)
            .expect("provider verify accepts");
        let mut broken = signature.clone();
        broken[0] ^= 0x01;
        assert_eq!(
            keypair.verify_attestation(message, &broken).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn flipping_one_bit_in_the_message_breaks_verification() {
        // Avalanche: flipping ONE BIT anywhere in the message must
        // invalidate the signature. Here the flipped bit sits mid-
        // message with a non-trivial mask.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/message-bit-flip",
            [221; 32],
        );
        let mut payload = *b"bit-flip-message-canary";
        let signature = keypair.sign_attestation(&payload).expect("sign");
        keypair
            .verify_attestation(&payload, &signature)
            .expect("control signature must verify");

        let middle = payload.len() / 2;
        payload[middle] ^= 0x02; // flip a single bit
        assert_eq!(
            keypair.verify_attestation(&payload, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed),
            "one flipped message bit must break verification"
        );
    }

    #[test]
    fn all_zero_message_sign_and_verify_round_trips() {
        // A message of all-zero BYTES is a legitimate payload (it is
        // not the signature): sign and verify must round-trip. The
        // zero-sig test covers degenerate SIGNATURE bytes; this pins
        // the message side.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/zero-message",
            [231; 32],
        );
        let payload = [0u8; 32];
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the all-zero message must verify");

        // Control: any nonzero message is not covered.
        let mut other = payload;
        other[31] = 1;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn same_seed_across_provider_instances_signs_identically() {
        // Second determinism vector, distinct from the
        // single-instance pin (a9229479): key derivation AND signing
        // are functions of the SEED alone — two independently
        // constructed providers from the same seed produce
        // byte-identical signatures, even with different key
        // identifiers.
        let make =
            |id: &str| Ed25519SigningProvider::from_seed(SigningProviderKind::Kms, id, [241; 32]);
        let p1 = make("kms://rustynet/det-instance-1");
        let p2 = make("kms://rustynet/det-instance-2");

        let message = b"cross-instance-canary";
        let sig_1a = p1.sign_attestation(message).expect("sign 1a");
        let sig_2 = p2.sign_attestation(message).expect("sign 2");
        assert_eq!(sig_1a, sig_2, "same seed must sign identically everywhere");

        let sig_1b = p1.sign_attestation(message).expect("sign 1b");
        assert_eq!(sig_1a, sig_1b);
    }

    #[test]
    fn two_byte_message_order_is_bound_into_the_signature() {
        // [1,2] and [2,1] are different messages: the signature over
        // [1,2] verifies for [1,2] and is rejected for [2,1] — byte
        // ORDER is bound into the digest.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/two-byte-order",
            [251; 32],
        );
        let message = [1u8, 2];
        let signature = keypair.sign_attestation(&message).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&message, &signature)
            .expect("signature over [1,2] must verify");

        let swapped = [2u8, 1];
        assert_eq!(
            keypair.verify_attestation(&swapped, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed),
            "the signature over [1,2] must not verify against [2,1]"
        );
    }

    #[test]
    fn interleaved_signing_does_not_disturb_determinism() {
        // No hidden signing state: A, B, A again — the two A
        // signatures must be byte-identical even though a different
        // message was signed in between.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/interleaved-det",
            [5; 32],
        );
        let msg_a = b"interleaved-message-a";
        let msg_b = b"interleaved-message-b";

        let a1 = keypair.sign_attestation(msg_a).expect("sign a1");
        let b = keypair.sign_attestation(msg_b).expect("sign b");
        let a2 = keypair.sign_attestation(msg_a).expect("sign a2");

        assert_ne!(a1, b, "different messages must sign differently");
        assert_eq!(
            a1, a2,
            "re-signing message A after an interleaved B must reproduce A's signature exactly"
        );
    }

    #[test]
    fn zero_length_signature_buffer_returns_err_not_panic() {
        // A zero-length signature buffer must come back as a typed
        // error — never a panic, never an acceptance.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/zero-len-sig",
            [241; 32],
        );
        let payload = b"zero-length-sig-canary";
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            keypair.verify_attestation(payload, &[])
        }));
        assert!(
            result.is_ok(),
            "verify() must not panic on a zero-length signature buffer"
        );
        assert_eq!(
            result.expect("no panic").err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn three_byte_message_sign_and_verify_round_trips() {
        // Size matrix: 3-byte message ([9,9,9]) signs and verifies Ok.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/three-byte",
            [251; 32],
        );
        let payload = [9u8; 3];
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        assert!(
            keypair.verify_attestation(&payload, &signature).is_ok(),
            "signature over the 3-byte message must verify"
        );

        let mut other = payload;
        other[1] ^= 0x01;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn four_byte_message_verifies_with_correct_key() {
        // Size matrix: 4-byte message signs and verifies with the
        // correct key.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/four-byte",
            [5; 32],
        );
        let payload = [1u8, 2, 3, 4];
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the 4-byte message must verify");

        let mut other = payload;
        other[0] ^= 0x01;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn five_byte_message_signs_and_verifies() {
        // Size matrix: 5-byte message signs and verifies.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/five-byte",
            [10; 32],
        );
        let payload = [10u8, 20, 30, 40, 50];
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the 5-byte message must verify");

        let mut other = payload;
        other[4] ^= 0x80;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn six_byte_message_signs_and_verifies() {
        // Size matrix: 6-byte message signs and verifies.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/six-byte",
            [11; 32],
        );
        let payload = [11u8, 22, 33, 44, 55, 66];
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the 6-byte message must verify");

        let mut other = payload;
        other[0] ^= 0x80;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn seven_byte_message_signs_and_verifies() {
        // Size matrix: 7-byte message signs and verifies.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/seven-byte",
            [12; 32],
        );
        let payload = [12u8, 24, 36, 48, 60, 72, 84];
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the 7-byte message must verify");

        let mut other = payload;
        other[6] ^= 0x01;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn eight_byte_message_signs_and_verifies() {
        // Size matrix: 8-byte message signs and verifies.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/eight-byte",
            [13; 32],
        );
        let payload = [13u8, 26, 39, 52, 65, 78, 91, 104];
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the 8-byte message must verify");

        let mut other = payload;
        other[7] ^= 0x01;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn sixteen_byte_message_signs_and_verifies() {
        // Size matrix: 16-byte (AES-block-sized) message signs and verifies.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/sixteen-byte",
            [14; 32],
        );
        let payload: Vec<u8> = (0..16u8).map(|i| i.wrapping_mul(17)).collect();
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the 16-byte message must verify");

        let mut other = payload;
        other[15] ^= 0x01;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn thirty_two_byte_message_signs_and_verifies() {
        // Size matrix: 32-byte (key-sized) message signs and verifies.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/32b-message",
            [15; 32],
        );
        let payload: Vec<u8> = (0..32u8)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect();
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the 32-byte message must verify");

        let mut other = payload;
        other[0] ^= 0x01;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn sixty_four_byte_message_signs_and_verifies() {
        // Size matrix: 64-byte (signature-sized) message signs and verifies.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/64b-message",
            [16; 32],
        );
        let payload: Vec<u8> = (0..64u8)
            .map(|i| i.wrapping_mul(3).wrapping_add(1))
            .collect();
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the 64-byte message must verify");

        let mut other = payload;
        other[32] ^= 0x01;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn one_twenty_eight_byte_message_signs_and_verifies() {
        // Size matrix: 128-byte message signs and verifies.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/128b-message",
            [17; 32],
        );
        let payload: Vec<u8> = (0..128u16)
            .map(|i| (i.wrapping_mul(5) % 251) as u8)
            .collect();
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the 128-byte message must verify");

        let mut other = payload;
        other[127] ^= 0x01;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn two_fifty_six_byte_message_signs_and_verifies() {
        // Size matrix: 256-byte message signs and verifies.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/256b-message",
            [18; 32],
        );
        let payload: Vec<u8> = (0..256u16)
            .map(|i| (i.wrapping_mul(11) % 253) as u8)
            .collect();
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the 256-byte message must verify");

        let mut other = payload;
        other[128] ^= 0x01;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn five_twelve_byte_message_signs_and_verifies() {
        // Size matrix: 512-byte message signs and verifies.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/512b-message",
            [19; 32],
        );
        let payload: Vec<u8> = (0..512u16)
            .map(|i| (i.wrapping_mul(13) % 249) as u8)
            .collect();
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the 512-byte message must verify");

        let mut other = payload;
        other[511] ^= 0x01;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn one_thousand_twenty_four_byte_message_signs_and_verifies() {
        // Size matrix: 1KB message signs and verifies.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/1kb-message",
            [20; 32],
        );
        let payload: Vec<u8> = (0..1024u16)
            .map(|i| (i.wrapping_mul(29) % 255) as u8)
            .collect();
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the 1KB message must verify");

        let mut other = payload;
        other[1023] ^= 0x01;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn all_ff_message_signs_and_verifies() {
        // Edge-value matrix: an all-0xFF 32-byte message (max byte
        // value everywhere) signs and verifies like any other payload.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/all-ff-message",
            [21; 32],
        );
        let payload = [0xFFu8; 32];
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the all-0xFF message must verify");

        let mut other = payload;
        other[0] = 0xFE;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn two_thousand_forty_eight_byte_message_signs_and_verifies() {
        // Size matrix: 2KB message signs and verifies.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/2kb-message",
            [22; 32],
        );
        let payload: Vec<u8> = (0..2048u16)
            .map(|i| (i.wrapping_mul(31) % 250) as u8)
            .collect();
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the 2KB message must verify");

        let mut other = payload;
        other[0] ^= 0x01;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn four_kilobyte_message_signs_and_verifies() {
        // Size matrix: 4KB message signs and verifies.
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/4kb-message",
            [23; 32],
        );
        let payload: Vec<u8> = (0..4096u16)
            .map(|i| (i.wrapping_mul(37) % 251) as u8)
            .collect();
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the 4KB message must verify");

        let mut other = payload;
        other[2048] ^= 0x01;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn hundred_kb_message_signs_and_verifies() {
        // Size matrix: exactly 100KB message signs and verifies
        // (distinct construction from the large-message test in
        // 66953e42: repeating-block pattern).
        let keypair = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/100kb-message",
            [24; 32],
        );
        let block = b"rustynet";
        let payload: Vec<u8> = block.iter().cycle().take(100 * 1024).copied().collect();
        assert_eq!(payload.len(), 100 * 1024);
        let signature = keypair.sign_attestation(&payload).expect("sign");
        assert_eq!(signature.len(), 64);
        keypair
            .verify_attestation(&payload, &signature)
            .expect("signature over the 100KB message must verify");

        let mut other = payload;
        other[50_000] ^= 0x01;
        assert_eq!(
            keypair.verify_attestation(&other, &signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    #[test]
    fn signature_binds_to_seed_and_payload_not_key_identifier() {
        // Two providers sharing a SEED but carrying DIFFERENT
        // key_identifier strings must be cryptographically identical:
        // same signature bytes and mutual verification. Pins that the
        // label never leaks into the signed payload.
        let make =
            |id: &str| Ed25519SigningProvider::from_seed(SigningProviderKind::Kms, id, [241; 32]);
        let labelled = make("kms://rustynet/prod-label");
        let unlabelled = make("kms://rustynet/dev-label");

        assert_ne!(labelled.key_identifier(), unlabelled.key_identifier());

        let message = b"label-independence-canary";
        let sig_labelled = labelled.sign_attestation(message).expect("sign");
        let sig_unlabelled = unlabelled.sign_attestation(message).expect("sign");
        assert_eq!(
            sig_labelled, sig_unlabelled,
            "the identifier must not perturb signature bytes"
        );

        labelled
            .verify_attestation(message, &sig_unlabelled)
            .expect("cross-label verification must succeed for the same seed");
    }

    #[test]
    fn secret_key_ct_eq_same_local() {
        let a = super::SecretKey([1u8; 32]);
        let b = super::SecretKey([1u8; 32]);
        assert_eq!(a.ct_eq(&b).unwrap_u8(), 1);
    }

    #[test]
    fn secret_key_ct_eq_different_local() {
        let a = super::SecretKey([1u8; 32]);
        let mut b = [1u8; 32];
        b[0] = 2;
        let b = super::SecretKey(b);
        assert_eq!(a.ct_eq(&b).unwrap_u8(), 0);
    }

    #[test]
    fn ed25519_signing_provider_debug_redacts_seed() {
        // AQ-126: liveness witness for the `Ed25519SigningProvider` entry in
        // secret_log_audit::REVIEWED_REDACTING_DEBUG_IMPLS. Pins the Debug
        // impl's redacted OUTPUT: a real provider is constructed from a
        // fixed non-zero seed and the rendered form must never contain the
        // seed bytes (nor their decimal 171 / hex ab spellings).
        let provider = super::Ed25519SigningProvider::try_from_seed(
            super::SigningProviderKind::LocalEncryptedFile,
            "witness-key-id",
            [0xABu8; 32],
        )
        .expect("non-zero seed must construct");
        let rendered = format!("{provider:?}");
        assert!(
            rendered.contains("Ed25519SigningProvider") && rendered.contains("witness-key-id"),
            "Debug must keep the non-secret identity fields visible: {rendered}"
        );
        assert!(
            !rendered.contains("171") && !rendered.to_lowercase().contains("ab"),
            "Ed25519SigningProvider Debug must not surface the signing seed: {rendered}"
        );
    }

    #[test]
    fn secret_key_debug_redacts() {
        // RSA-0026: SecretKey is the canonical secret type; its Debug must
        // redact the inner bytes so a `{:?}` / structured-log call cannot leak
        // the private key. Pin the redaction so it cannot regress to a
        // byte-printing derive. (The secret-log-audit gate intentionally does
        // not put redacting-Debug types in its no-Debug forbidden list.)
        let key = super::SecretKey([0xABu8; 32]);
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "SecretKey(REDACTED)");
        assert!(
            !rendered.contains("171") && !rendered.to_lowercase().contains("ab"),
            "SecretKey Debug must not surface the inner key bytes: {rendered}"
        );
    }

    /// Add the ed25519 group order ℓ (little-endian) to the S scalar (the
    /// second 32 bytes) of a signature, with carry. For a canonical S < ℓ the
    /// result fits in 32 bytes and is a non-canonical encoding of the same
    /// scalar mod ℓ.
    fn add_ed25519_order_to_s(sig: &mut [u8; 64]) {
        const ORDER_LE: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let mut carry = 0u16;
        for i in 0..32 {
            let sum = u16::from(sig[32 + i]) + u16::from(ORDER_LE[i]) + carry;
            sig[32 + i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
    }

    /// RN-22: attestation verification must use ed25519 `verify_strict`, which
    /// rejects non-canonical signatures. Mauling `S := S + ℓ` yields a distinct
    /// byte encoding that still satisfies the non-strict verification equation
    /// (`[ℓ]B` is the identity), so a non-strict verifier would accept it.
    /// `verify_strict` must reject it, eliminating signature malleability.
    #[test]
    fn verify_attestation_rejects_tampered_message_and_foreign_key_directly() {
        // Negative coverage of the RAW trait method (not the
        // attestation-envelope wrappers): a genuine 64-byte signature
        // must be rejected when (a) any payload byte changed after
        // signing, or (b) it was produced by a different seed — even
        // under an identical key identifier.
        let provider = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/direct-negative",
            [13; 32],
        );
        let foreign = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/direct-negative",
            [14; 32],
        );
        let payload = b"direct-verify-canary";
        let signature = provider.sign_attestation(payload).expect("sign");
        assert_eq!(signature.len(), 64);
        provider
            .verify_attestation(payload, &signature)
            .expect("untampered signature from the right key must verify");

        let mut tampered_payload = *payload;
        tampered_payload[0] ^= 0x01;
        assert_eq!(
            provider
                .verify_attestation(&tampered_payload, &signature)
                .err(),
            Some(CryptoError::AttestationVerificationFailed),
            "a signature over different bytes must be rejected"
        );

        let foreign_signature = foreign.sign_attestation(payload).expect("sign");
        assert_eq!(
            provider
                .verify_attestation(payload, &foreign_signature)
                .err(),
            Some(CryptoError::AttestationVerificationFailed),
            "a signature from another key must be rejected"
        );
    }

    #[test]
    fn verify_attestation_rejects_non_canonical_malleable_signature() {
        let provider = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/malleability",
            [9; 32],
        );
        let payload = b"malleability-canary";
        let signature = provider.sign_attestation(payload).expect("sign");
        assert_eq!(signature.len(), 64);
        provider
            .verify_attestation(payload, &signature)
            .expect("canonical signature must verify");

        let mut mauled = [0u8; 64];
        mauled.copy_from_slice(&signature);
        add_ed25519_order_to_s(&mut mauled);
        assert_ne!(mauled[32..], signature[32..], "S must change");

        assert_eq!(
            provider.verify_attestation(payload, &mauled).err(),
            Some(CryptoError::AttestationVerificationFailed),
            "verify_strict must reject the non-canonical (mauled) signature"
        );
    }

    #[test]
    fn verify_attestation_rejects_wrong_signature_lengths() {
        let provider = Ed25519SigningProvider::from_seed(
            SigningProviderKind::Kms,
            "kms://rustynet/signature-length",
            [11; 32],
        );
        let payload = b"signature-length-canary";
        let signature = provider.sign_attestation(payload).expect("sign");
        assert_eq!(signature.len(), 64);

        let short_signature = &signature[..63];
        assert_eq!(
            provider.verify_attestation(payload, short_signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );

        let mut long_signature = signature.clone();
        long_signature.push(0);
        assert_eq!(
            provider.verify_attestation(payload, &long_signature).err(),
            Some(CryptoError::AttestationVerificationFailed)
        );
    }

    // ─── macOS Keychain System.keychain fallback (Gap H) ───────────────
    //
    // The store-side System.keychain fallback closes Phase 24 Gap H:
    // `PlatformOsSecureStore::store_key` on macOS previously hard-failed
    // when `set_generic_password` returned `errSecNoDefaultKeychain`
    // (the launchd-managed `rustynetd` service account has no
    // user-session default keychain). The load side already targets
    // `/Library/Keychains/System.keychain` via the `security` CLI; the
    // store side now mirrors that target via `SecKeychain::set_generic_password`.
    //
    // Source-pin tests below guard the contract without requiring a
    // live macOS host: they read this very source file and assert the
    // System.keychain path, the safe-Rust API call, and the strict
    // input validators are present. Live behaviour is exercised by
    // the Phase 24+ macOS bring-up smoke (`rustynetd key init` under
    // sudo, then `security find-generic-password ... /Library/Keychains/System.keychain`).

    #[cfg(target_os = "macos")]
    #[test]
    fn validate_macos_keychain_label_rejects_injection_vectors() {
        use super::validate_macos_keychain_label;
        // Empty.
        assert!(validate_macos_keychain_label("account", "").is_err());
        // Whitespace, control bytes, NUL, newline, semicolon, backtick — all
        // illegal under the strict allow-list. The label-allow-list is
        // narrower than what Keychain Services itself accepts so that any
        // future shell or `security` CLI re-introduction (e.g. for the
        // current load-side fallback) cannot be tricked by an attacker
        // controlling the label.
        for bad in [
            " account",
            "account ",
            "acc\tount",
            "acc\nount",
            "acc\0unt",
            "acc;rm",
            "acc$0",
            "acc`id`",
            "acc'or'1",
            "acc\"or\"1",
            "acc\\x",
            "acc|sh",
            "acc&bg",
            "acc*glob",
            "acc?glob",
            "acc(",
        ] {
            assert!(
                validate_macos_keychain_label("account", bad).is_err(),
                "label {bad:?} must be rejected"
            );
        }
        // Over-length: 129 chars exceeds the 128-cap.
        let too_long: String = "a".repeat(129);
        assert!(validate_macos_keychain_label("account", &too_long).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn validate_macos_keychain_label_accepts_canonical_descriptors() {
        use super::validate_macos_keychain_label;
        // Canonical service/account shapes the daemon and ops verbs hand to
        // the keychain backend. The validator is format-only (charset +
        // length), so these format-equivalent examples pin the same
        // behavior as the daemon's real labels — a tightening of the
        // allow-list cannot silently break the bootstrap. The daemon's
        // literal label constants are pinned by key_material.rs's own
        // tests in rustynetd.
        for good in [
            // Tunnel key custody shape (dotted service, hex suffix).
            "rustynet.tunnel-private-deadbeef01234567",
            "rustynet",
            // Tunnel passphrase service/account shape.
            "net.rustynet.tunnel-key-passphrase",
            "tunnel-passphrase-node-001",
            // Membership-owner signing-key passphrase (ops_e2e.rs:1026).
            "signing_key_passphrase",
            "membership-owner-signing-key",
            // Anchor enrollment HMAC secret (SecurityMinimumBar §6.C/4).
            "rustynet.anchor_enrollment_secret",
        ] {
            assert!(
                validate_macos_keychain_label("test", good).is_ok(),
                "label {good:?} must be accepted"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn store_macos_generic_password_rejects_invalid_labels_fail_closed() {
        use super::store_macos_generic_password;
        // Per CLAUDE.md §3 / §4: validation MUST be enforced before any
        // keychain mutation. An injection-shaped label must never reach
        // the keychain — assert the bad-label arm returns
        // `OsStoreUnavailable` rather than spawning a process or
        // touching the keychain.
        let result = store_macos_generic_password("svc;rm -rf /", "acct", b"secret");
        assert_eq!(result.err(), Some(CryptoError::OsStoreUnavailable));
        let result = store_macos_generic_password("svc", "acct\0name", b"secret");
        assert_eq!(result.err(), Some(CryptoError::OsStoreUnavailable));
        let result = store_macos_generic_password("", "acct", b"secret");
        assert_eq!(result.err(), Some(CryptoError::OsStoreUnavailable));
        let result = store_macos_generic_password("svc", "", b"secret");
        assert_eq!(result.err(), Some(CryptoError::OsStoreUnavailable));
    }

    /// Pin: the store-side System.keychain path keeps the safe Rust
    /// framework API as the **primary** attempt and only falls through
    /// to the `security` CLI when the framework call fails. macOS 26
    /// progressively deprecated the legacy SecKeychain framework path for
    /// headless / root contexts (verified against the Phase 24 lab VM:
    /// `SecKeychainAddGenericPassword` fails with an opaque error while
    /// `security add-generic-password ... /Library/Keychains/System.keychain`
    /// succeeds for the same uid + service + account). The CLI argv
    /// exposure is bounded — bootstrap runs as root in single-shot mode;
    /// the `security` exec window (~50 ms) is observable only by other
    /// root processes, which already have full system access.
    #[cfg(target_os = "macos")]
    #[test]
    fn store_macos_generic_password_prefers_framework_api_with_cli_fallback() {
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let body =
            std::fs::read_to_string(crate_root.join("src/lib.rs")).expect("crypto source readable");

        // Slice the exact body of `store_macos_generic_password_system_keychain`.
        // We end at the first top-level `\n}\n` after the signature so the
        // pin does not pick up the helper or the load-side fallback.
        let start = body
            .find("fn store_macos_generic_password_system_keychain(")
            .expect("System.keychain store helper must remain present");
        let rel_end = body[start..]
            .find("\n}\n")
            .expect("System.keychain store helper must have a closing brace");
        let window = &body[start..start + rel_end + 3];

        // Framework path must come first.
        assert!(
            window.contains("SecKeychain::open(MACOS_SYSTEM_KEYCHAIN_PATH)"),
            "store helper must attempt the safe Rust framework API first"
        );
        assert!(
            window.contains(".set_generic_password(service, account, secret)"),
            "store helper must call the safe Rust set_generic_password"
        );
        // CLI fallback is in a *separate* helper; the dispatcher must
        // delegate to it by name, not inline a Command::new spawn here.
        assert!(
            window.contains("store_macos_generic_password_system_keychain_via_security_cli"),
            "store helper must delegate to the CLI fallback by name (no inline spawn)"
        );
        assert!(
            !window.contains("Command::new"),
            "store helper dispatcher must NOT spawn `security` inline — keep the spawn in the named fallback so the audit trail is explicit"
        );

        // The CLI fallback must exist and explicitly target the System
        // keychain — no implicit "default keychain" writes.
        let cli_start = body
            .find("fn store_macos_generic_password_system_keychain_via_security_cli(")
            .expect("CLI fallback helper must remain present");
        let cli_end = body[cli_start..]
            .find("\n}\n")
            .expect("CLI fallback helper must have a closing brace");
        let cli_window = &body[cli_start..cli_start + cli_end + 3];
        assert!(
            cli_window.contains("/usr/bin/security"),
            "CLI fallback must spawn /usr/bin/security"
        );
        assert!(
            cli_window.contains("/Library/Keychains/System.keychain"),
            "CLI fallback must explicitly target the System keychain — no default-keychain ambiguity"
        );
        assert!(
            cli_window.contains("validated upstream")
                || cli_window.contains("validate_macos_keychain_label"),
            "service / account must remain validated before CLI invocation (caller validates upstream)"
        );
        assert!(
            cli_window.contains("secret.contains(&0)"),
            "CLI fallback must reject embedded NULs so password cannot be truncated by C-string handling"
        );
    }

    /// Pin: the System.keychain path is declared once, exported as
    /// `pub const`, and matches the reviewed path used by
    /// `MacosKeychainBackend::unwrap_credential` in `rustynet-control`.
    /// A drift between the two paths would split the trust-anchor for
    /// macOS key custody — load and store MUST target the same keychain
    /// file.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_system_keychain_path_constant_matches_reviewed_location() {
        use super::MACOS_SYSTEM_KEYCHAIN_PATH;
        assert_eq!(
            MACOS_SYSTEM_KEYCHAIN_PATH, "/Library/Keychains/System.keychain",
            "macOS System keychain path must remain the reviewed location"
        );
    }

    /// Pin: `store_macos_generic_password` tries the default keychain
    /// first, then falls back to System.keychain — symmetric with the
    /// load-side fallback in `load_macos_generic_password`. A future
    /// refactor that removed the fallback would re-open Gap H.
    #[cfg(target_os = "macos")]
    #[test]
    fn store_macos_generic_password_has_system_keychain_fallback() {
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let body =
            std::fs::read_to_string(crate_root.join("src/lib.rs")).expect("crypto source readable");

        let start = body
            .find("pub fn store_macos_generic_password(")
            .expect("store_macos_generic_password must remain present");
        let next_fn = body[start..]
            .find("\n#[cfg")
            .expect("store_macos_generic_password must be followed by another macOS-gated item");
        let window = &body[start..start + next_fn];

        assert!(
            window.contains("set_generic_password(service, account, secret)"),
            "default-keychain attempt must remain wired via security_framework"
        );
        assert!(
            window.contains("store_macos_generic_password_system_keychain("),
            "fallback to System.keychain must be wired (Gap H)"
        );
    }

    /// A root writer must store into the System keychain (owned store), never
    /// the default keychain: under `sudo` from a console user the default is
    /// that user's login keychain, which the launchd daemon cannot read
    /// (live macOS lab runs 27-29: gossip key stored in the operator's login
    /// keychain -> daemon "os secure store unavailable"). The root branch must
    /// come BEFORE the default-keychain attempt.
    #[cfg(target_os = "macos")]
    #[test]
    fn store_macos_generic_password_root_writer_targets_system_keychain_first() {
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let body =
            std::fs::read_to_string(crate_root.join("src/lib.rs")).expect("crypto source readable");
        let start = body
            .find("pub fn store_macos_generic_password(")
            .expect("store_macos_generic_password must remain present");
        let next_fn = body[start..]
            .find("\n#[cfg")
            .expect("store_macos_generic_password must be followed by another macOS-gated item");
        let window = &body[start..start + next_fn];
        let root_at = window
            .find("nix::unistd::Uid::effective().is_root()")
            .expect("root branch must exist");
        let owned_at = window
            .find("store_macos_generic_password_system_keychain_owned(service, account, secret)")
            .expect("root branch must use the owned System-keychain store");
        let default_at = window
            .find("set_generic_password(service, account, secret)")
            .expect("default-keychain attempt must remain for non-root callers");
        assert!(
            root_at < owned_at && owned_at < default_at,
            "the root/System-keychain branch must precede the default-keychain attempt"
        );
    }

    /// Fail-closed: the owned-identity System-keychain store MUST validate
    /// service/account labels and reject embedded NULs *before* touching the
    /// keychain or spawning the delete helper. An injection-shaped or
    /// NUL-bearing label must never reach `security delete-generic-password`'s
    /// argv nor `SecItemAdd`.
    #[cfg(target_os = "macos")]
    #[test]
    fn store_macos_generic_password_system_keychain_owned_rejects_invalid_input_fail_closed() {
        use super::store_macos_generic_password_system_keychain_owned;
        let cases: &[(&str, &str, &[u8])] = &[
            ("svc;rm -rf /", "acct", b"secret"),
            ("svc", "acct\0name", b"secret"),
            ("", "acct", b"secret"),
            ("svc", "", b"secret"),
            // valid labels but NUL in the secret — rejected before keychain I/O
            ("net.rustynet.test", "acct", b"sec\0ret"),
        ];
        for (service, account, secret) in cases {
            assert_eq!(
                store_macos_generic_password_system_keychain_owned(service, account, secret).err(),
                Some(CryptoError::OsStoreUnavailable),
                "owned store must fail closed for service={service:?} account={account:?}"
            );
        }
    }

    /// Pin the security properties of the owned-identity custody path:
    /// the tunnel passphrase is stored and read by the *same* signed
    /// `rustynetd` binary, so it uses `SecItemAdd`/`SecItemCopyMatching`
    /// (framework) bound to that binary's code-signing identity — NOT the
    /// `-A` `security`-CLI path, whose item is unreadable by the launchd
    /// daemon across the login-session boundary on macOS 26. Critically, the
    /// secret must NEVER appear in argv on this path (no `-w`): it flows only
    /// through `CFData`/`SecItemAdd`. Verified live on macOS 26.5.
    #[cfg(target_os = "macos")]
    #[test]
    fn store_macos_generic_password_system_keychain_owned_uses_framework_no_argv_secret() {
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let body =
            std::fs::read_to_string(crate_root.join("src/lib.rs")).expect("crypto source readable");

        let start = body
            .find("pub fn store_macos_generic_password_system_keychain_owned(")
            .expect("owned store must remain present");
        let rel_end = body[start..]
            .find("\n}\n")
            .expect("owned store must have a closing brace");
        let window = &body[start..start + rel_end + 3];

        assert!(
            window.contains("validate_macos_keychain_label")
                && window.contains("secret.contains(&0)"),
            "owned store must validate labels and reject NUL secrets before keychain I/O"
        );
        assert!(
            window.contains("ItemAddOptions::new(") && window.contains(".add()"),
            "owned store must use the modern SecItemAdd framework API"
        );
        assert!(
            window.contains("Location::FileKeychain")
                && window.contains("MACOS_SYSTEM_KEYCHAIN_PATH"),
            "owned store must target the System keychain explicitly"
        );
        assert!(
            window.contains("CFData::from_buffer(secret)"),
            "owned store must pass the secret as CFData (never as argv)"
        );
        assert!(
            !window.contains("\"-w\""),
            "owned store must NEVER place the secret in argv (`-w`) — the SecItemAdd path keeps it in-process"
        );
        assert!(
            window.contains("load_macos_generic_password_system_keychain_owned(service, account)"),
            "owned store must fail-closed read-back through the same SecItemCopyMatching path the daemon uses"
        );

        // Owned READ side: SecItemCopyMatching scoped to the System keychain.
        let lstart = body
            .find("pub fn load_macos_generic_password_system_keychain_owned(")
            .expect("owned load must remain present");
        let lrel_end = body[lstart..].find("\n}\n").expect("owned load brace");
        let lwindow = &body[lstart..lstart + lrel_end + 3];
        assert!(
            lwindow.contains("ItemSearchOptions::new()")
                && lwindow.contains(".keychains(")
                && lwindow.contains("SearchResult::Data"),
            "owned load must read via SecItemCopyMatching scoped to the explicit keychain"
        );

        // Delete helper carries no secret in argv.
        let dstart = body
            .find("fn delete_macos_system_keychain_generic_password_via_cli(")
            .expect("owned delete helper must remain present");
        let drel_end = body[dstart..].find("\n}\n").expect("delete helper brace");
        let dwindow = &body[dstart..dstart + drel_end + 3];
        assert!(
            dwindow.contains("delete-generic-password")
                && dwindow.contains("/Library/Keychains/System.keychain")
                && !dwindow.contains("\"-w\""),
            "delete helper must target the System keychain and carry no secret in argv"
        );
    }

    #[test]
    fn sha256_empty_input_produces_stable_defined_digest() {
        // SHA-256 of the empty string is a well-known constant:
        // e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"");
        let result = hasher.finalize();
        let hex = result
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_collision_sanity_distinct_inputs_distinct_digests() {
        use sha2::{Digest, Sha256};
        // Two different byte inputs must produce different SHA-256
        // digests. A collision here would compromise every
        // content-addressed integrity check in the codebase.
        let hash_a = Sha256::digest(b"collision-check-alpha");
        let hash_b = Sha256::digest(b"collision-check-beta");
        assert_ne!(hash_a.as_slice(), hash_b.as_slice());
    }

    #[test]
    fn sha256_known_answer_test_vector_abc() {
        // NIST FIPS 180-4 classic test vector: SHA-256("abc") is a
        // published constant. Pins algorithm-level correctness beyond
        // the empty-input case so a broken implementation cannot pass
        // by special-casing zero-length input.
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(b"abc");
        let hex = hash
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_incremental_update_matches_one_shot_digest() {
        // Streaming contract: feeding the same bytes through repeated
        // update() calls in arbitrary chunk boundaries must equal the
        // one-shot digest. A regression splitting this equivalence
        // would silently corrupt every incremental integrity check.
        use sha2::{Digest, Sha256};
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let one_shot = Sha256::digest(&data);
        let mut hasher = Sha256::new();
        // Deliberately awkward boundaries: 0-byte first chunk, a
        // single byte, an odd multi-byte slice, and the remainder.
        hasher.update(&data[..0]);
        hasher.update(&data[..1]);
        hasher.update(&data[1..3333]);
        hasher.update(&data[3333..]);
        let incremental = hasher.finalize();
        assert_eq!(one_shot.as_slice(), incremental.as_slice());
    }
    // ---- RSA-0001: unambiguous v0/v1 key-envelope detection ----------------
    //
    // A legacy v0 frame is [salt:16][nonce:24][len:4][ct]; its first byte is
    // salt[0], non-zero for 255/256 of real blobs. The pre-fix detection
    // routed every such 45+ byte blob to the v1 decoder, which failed, so
    // those key files never loaded and never reached the OI-13 re-seal path.
    // These tests pin the repaired rule: structural v0 re-parse after a
    // failed v1 frame parse, an authenticated-only v0 retry after a failed
    // v1 authentication, and no downgrade in either direction.

    /// Hand-builds a v0 frame from parts (no sealing): the decode layer does
    /// not authenticate, so framing tests can use synthetic ciphertext.
    fn rsa0001_v0_frame_from_parts(salt: [u8; 16], nonce: [u8; 24], ciphertext: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(44 + ciphertext.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(ciphertext);
        out
    }

    /// Seals `plaintext` under `passphrase` exactly the way legacy v0
    /// writers did (Argon2id + XChaCha20-Poly1305, empty AAD) and frames it
    /// as [salt:16][nonce:24][len:4][ct]. The salt is caller-chosen so the
    /// tests can pin first-byte shapes.
    #[cfg(unix)]
    fn rsa0001_seal_v0(
        passphrase: &str,
        plaintext: &[u8],
        salt: [u8; 16],
        nonce: [u8; 24],
    ) -> Vec<u8> {
        use super::{Argon2, XChaCha20Poly1305, XNonce};
        use chacha20poly1305::aead::{Aead, KeyInit};
        use zeroize::Zeroize;

        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
            .expect("kdf should succeed");
        let cipher = XChaCha20Poly1305::new((&key).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: b"",
                },
            )
            .expect("legacy v0 seal should succeed");
        key.zeroize();
        rsa0001_v0_frame_from_parts(salt, nonce, &ciphertext)
    }

    #[test]
    fn rsa0001_v0_frame_decodes_as_v0_for_every_first_byte() {
        // salt[0] is uniform-random salt material, so the detection rule
        // must be unambiguous for EVERY possible first byte: each frame
        // below must decode as v0 with its exact salt/nonce/ciphertext
        // round-tripped, never rejected as a failed v1 parse (the pre-fix
        // behaviour for 255 of these 256 shapes).
        for first in 0u8..=255 {
            let mut salt = [0u8; 16];
            salt[0] = first;
            salt[1] = 0x5a;
            salt[15] = 0xa5;
            let nonce = [0x33u8; 24];
            let ciphertext = [0xabu8; 48];
            let frame = rsa0001_v0_frame_from_parts(salt, nonce, &ciphertext);
            let blob = super::decode_encrypted_blob(&frame)
                .expect("a v0 frame must decode for every possible first byte");
            assert_eq!(blob.version, 0, "first byte {first} must decode as v0");
            assert_eq!(
                blob.salt, salt,
                "salt must round-trip for first byte {first}"
            );
            assert_eq!(blob.nonce, nonce);
            assert_eq!(blob.ciphertext, ciphertext);
        }
    }

    #[cfg(unix)]
    #[test]
    fn rsa0001_colliding_v0_corpus_round_trips_and_reseals_as_v1() {
        // THE witness: a corpus of real (sealed, authenticating) v0 envelopes
        // with first salt bytes spanning the colliding non-zero range plus
        // the zero byte the old heuristic happened to route correctly. Every
        // one must decrypt, be counted as a v0 read, and be re-sealed as v1
        // on disk (the OI-13 migration path the misroute used to skip).
        let _oi13_guard = OI13_V0_DISK_READ_LOCK.lock().expect("OI13 lock poisoned");
        let policy = KeyCustodyPermissionPolicy::default();
        let plaintext = b"rsa0001-key-00-0123456789abcdef".as_slice();
        for first in [0x00u8, 0x01, 0x2a, 0x7f, 0x80, 0xfe, 0xff] {
            let mut salt = [0u8; 16];
            salt[0] = first;
            salt[1] = 0x11;
            salt[15] = 0x99;
            let v0_bytes = rsa0001_seal_v0("rsa0001-pass", plaintext, salt, [0x55u8; 24]);
            let (directory, file) = oi13_temp_custody_dir("rsa0001-corpus");
            oi13_write_custody_file(&directory, &file, &v0_bytes);

            let reads_before = v0_envelope_reads_total();
            let loaded = read_encrypted_key_file(&directory, &file, "rsa0001-pass", policy)
                .unwrap_or_else(|e| {
                    panic!(
                        "salt[0]={first}: colliding v0 envelope must load and re-seal, got {e:?}"
                    )
                });
            assert_eq!(loaded.as_slice(), plaintext);
            assert_eq!(
                v0_envelope_reads_total(),
                reads_before + 1,
                "salt[0]={first}: the v0 read must be counted"
            );

            let on_disk = std::fs::read(&file).expect("upgraded file should be readable");
            let blob = super::decode_encrypted_blob(&on_disk)
                .expect("the re-sealed blob must decode cleanly");
            assert_eq!(
                blob.version, 1,
                "salt[0]={first}: the read must re-seal v0 as v1 on disk"
            );
            let again = decrypt_private_key_envelope(&blob, "rsa0001-pass")
                .expect("the v1 re-seal must decrypt under the same passphrase");
            assert_eq!(again.as_slice(), plaintext);

            let _ = std::fs::remove_file(&file);
            let _ = std::fs::remove_dir(&directory);
        }
    }

    #[cfg(unix)]
    #[test]
    fn rsa0001_v1_envelopes_are_unaffected_by_legacy_detection() {
        let _oi13_guard = OI13_V0_DISK_READ_LOCK.lock().expect("OI13 lock poisoned");
        let policy = KeyCustodyPermissionPolicy::default();
        let (directory, file) = oi13_temp_custody_dir("rsa0001-v1");
        write_encrypted_key_file(
            &directory,
            &file,
            b"rsa0001-v1-secret",
            "rsa0001-pass",
            policy,
        )
        .expect("v1 write should succeed");
        let reads_before = v0_envelope_reads_total();
        let fallbacks_before = v0_envelope_fallback_decodes_total();

        // Two reads: a genuine v1 blob must take the v1 path both times with
        // no v0 counting, no fallback counting, and a byte-stable file.
        let first = read_encrypted_key_file(&directory, &file, "rsa0001-pass", policy)
            .expect("v1 read should succeed");
        assert_eq!(first.as_slice(), b"rsa0001-v1-secret".as_slice());
        let on_disk_first = std::fs::read(&file).expect("v1 file should be readable");
        let second = read_encrypted_key_file(&directory, &file, "rsa0001-pass", policy)
            .expect("second v1 read should succeed");
        assert_eq!(second.as_slice(), b"rsa0001-v1-secret".as_slice());
        let on_disk_second = std::fs::read(&file).expect("v1 file should be readable");
        assert_eq!(
            on_disk_second, on_disk_first,
            "a v1 file must be byte-stable across reads"
        );
        assert_eq!(
            v0_envelope_reads_total(),
            reads_before,
            "v1 reads must not advance the v0 counter"
        );
        assert_eq!(
            v0_envelope_fallback_decodes_total(),
            fallbacks_before,
            "v1 reads must not advance the RSA-0001 fallback counter"
        );

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&directory);
    }

    #[cfg(unix)]
    #[test]
    fn rsa0001_tampered_v1_is_refused_and_never_retried_as_v0() {
        // A v1 blob whose tag fails must be refused outright: the bytes do
        // not form a v0 frame, so there must be no v0 retry, no re-seal and
        // no counter movement (in particular the file must never be
        // rewritten under the weaker scheme).
        let _oi13_guard = OI13_V0_DISK_READ_LOCK.lock().expect("OI13 lock poisoned");
        let policy = KeyCustodyPermissionPolicy::default();
        let (directory, file) = oi13_temp_custody_dir("rsa0001-tamper-v1");
        write_encrypted_key_file(
            &directory,
            &file,
            b"rsa0001-tamper-v1",
            "rsa0001-pass",
            policy,
        )
        .expect("v1 write should succeed");
        let mut on_disk = std::fs::read(&file).expect("v1 file should be readable");
        let last = on_disk.len() - 1;
        on_disk[last] ^= 0x01; // framing stays valid v1; the AEAD tag breaks
        std::fs::write(&file, &on_disk).expect("tampered file should be written");
        let reads_before = v0_envelope_reads_total();
        let fallbacks_before = v0_envelope_fallback_decodes_total();

        let result = read_encrypted_key_file(&directory, &file, "rsa0001-pass", policy);
        assert_eq!(
            result.err(),
            Some(CryptoError::DecryptionFailed),
            "a tampered v1 envelope must fail authentication and be refused"
        );
        assert_eq!(
            std::fs::read(&file).expect("file should survive a rejected read"),
            on_disk,
            "a refused tampered v1 must never be rewritten as v0 or re-sealed"
        );
        assert_eq!(
            v0_envelope_reads_total(),
            reads_before,
            "a tampered v1 must never be retried under the v0 scheme"
        );
        assert_eq!(
            v0_envelope_fallback_decodes_total(),
            fallbacks_before,
            "a tampered v1 must not fire the v0 fallback"
        );

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&directory);
    }

    #[cfg(unix)]
    #[test]
    fn rsa0001_misrouted_tampered_v0_is_refused_and_never_resealed() {
        // The downgrade control: a colliding (non-zero salt[0]) v0 blob whose
        // AEAD tag fails must be REFUSED — never accepted unauthenticated,
        // never re-sealed, never rewritten. The v0 read is still counted as
        // seen-but-rejected (OI-13 counter semantics).
        let _oi13_guard = OI13_V0_DISK_READ_LOCK.lock().expect("OI13 lock poisoned");
        let policy = KeyCustodyPermissionPolicy::default();
        let mut salt = [0u8; 16];
        salt[0] = 0xa7; // non-zero: misrouted by the old heuristic
        let v0_bytes = rsa0001_seal_v0(
            "rsa0001-pass",
            b"rsa0001-downgrade-probe",
            salt,
            [0x66u8; 24],
        );
        let mut tampered = v0_bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01; // framing stays valid v0; the AEAD tag breaks
        let (directory, file) = oi13_temp_custody_dir("rsa0001-tamper-v0");
        oi13_write_custody_file(&directory, &file, &tampered);
        let reads_before = v0_envelope_reads_total();

        let result = read_encrypted_key_file(&directory, &file, "rsa0001-pass", policy);
        assert_eq!(
            result.err(),
            Some(CryptoError::DecryptionFailed),
            "a v0 blob whose tag fails must be refused, never accepted unauthenticated"
        );
        assert_eq!(
            std::fs::read(&file).expect("file should survive a rejected read"),
            tampered,
            "a refused v0 read must not re-seal or rewrite the file"
        );
        assert_eq!(
            v0_envelope_reads_total(),
            reads_before + 1,
            "the seen-but-rejected v0 blob must still be counted"
        );

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&directory);
    }

    #[cfg(unix)]
    #[test]
    fn rsa0001_v1_auth_failure_fails_closed_without_v0_retry() {
        // The counter deltas below are exact, and the v0 counters are
        // process-global: serialize against every other v0-reading test.
        let _oi13_guard = OI13_V0_DISK_READ_LOCK.lock().expect("OI13 lock poisoned");
        // The double-parse collision shape. For a v0 frame with declared
        // length bytes [A,B,C,D] and first ciphertext byte ct0, the v1 frame
        // parse succeeds exactly when 45 + ((B<<24)|(C<<16)|(D<<8)|ct0) ==
        // 44 + ((A<<24)|(B<<16)|(C<<8)|D); the minimal solution is
        // A=B=C=D=1, ct0=0 — a ~16MB envelope, far above the 64KB on-disk
        // cap, which is why this exercise drives `decrypt_key_file_blob`
        // (the byte-level decision core) directly instead of the capped file
        // reader. The fixture is genuinely a legacy v0 envelope: it
        // authenticates under the empty-AAD v0 scheme with the right
        // passphrase. Because it ALSO parses as a non-v0 frame (the v1
        // parser takes any non-zero version byte, so the salt byte becomes
        // the routed version), the structural routing hands it to the
        // non-v0 arm, which must fail closed: no v0 retry, no plaintext,
        // no re-seal, no counter movement. Positive half:
        // authentic-under-v0 bytes are refused. Negative half: the same
        // shape with a broken tag is refused identically.
        let plaintext = vec![0x5cu8; (1 << 24) + (1 << 16) + (1 << 8) + 1 - 16];
        let mut salt = [0u8; 16];
        salt[0] = 0x42; // non-zero so the frame is v1-parseable
        // The collision needs ct[0] == 0 (the first ciphertext byte feeds
        // the v1 length field), but AEAD output is not controllable — so
        // derive the key once and sweep the nonce's first byte against a
        // 64-byte probe: XChaCha20-Poly1305 is a stream cipher, so the
        // probe's first ciphertext block equals the real envelope's (the
        // Poly1305 tag is appended at the end), making the sweep cheap.
        use super::{Argon2, XChaCha20Poly1305, XNonce};
        use chacha20poly1305::aead::{Aead, KeyInit};
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into("rsa0001-pass".as_bytes(), &salt, &mut key)
            .expect("kdf should succeed");
        let cipher = XChaCha20Poly1305::new((&key).into());
        let probe = &plaintext[..64];
        let mut nonce = [0x77u8; 24];
        let mut found = None;
        'outer: for first in 0..=255u8 {
            nonce[0] = first;
            for second in 0..=255u8 {
                nonce[1] = second;
                let ct = cipher
                    .encrypt(
                        XNonce::from_slice(&nonce),
                        chacha20poly1305::aead::Payload {
                            msg: probe,
                            aad: b"",
                        },
                    )
                    .expect("probe seal should succeed");
                if ct[0] == 0 {
                    found = Some((first, second));
                    break 'outer;
                }
            }
        }
        let (first, second) = found.expect("some nonce must seal a zero-leading ct");
        nonce[0] = first;
        nonce[1] = second;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: &plaintext,
                    aad: b"",
                },
            )
            .expect("legacy v0 seal should succeed");
        assert_eq!(ciphertext[0], 0, "the chosen nonce must yield ct[0]==0");
        let v0_bytes = {
            let mut out = Vec::with_capacity(44 + ciphertext.len());
            out.extend_from_slice(&salt);
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
            out.extend_from_slice(&ciphertext);
            out
        };
        assert_eq!(
            &v0_bytes[40..44],
            &[1, 1, 1, 1],
            "fixture must be the collision shape"
        );
        assert_eq!(v0_bytes[44], 0, "fixture must be the collision shape");
        // `PersistKeyFileFn` is `dyn Fn + 'static`, so the closure cannot
        // borrow locals; it records every persist attempt in this test-local
        // static and the assertions below inspect the log.
        static RSA0001_PERSIST_LOG: std::sync::Mutex<Vec<Vec<u8>>> =
            std::sync::Mutex::new(Vec::new());
        let persist: &super::PersistKeyFileFn = &|_, _, recovered, _, _| {
            RSA0001_PERSIST_LOG
                .lock()
                .expect("persist log poisoned")
                .push(recovered.to_vec());
            Ok(())
        };
        let fallbacks_before = v0_envelope_fallback_decodes_total();
        let reads_before = v0_envelope_reads_total();

        // Structural proof the fixture really is the double-parse shape:
        // the router returns it as a non-v0 blob (the v1 frame parser accepts
        // any non-zero version byte, so the salt-led frame decodes with the
        // salt byte as its version), which is exactly why its v0
        // authenticity can never be reached.
        let routed = super::decode_encrypted_blob(&v0_bytes)
            .expect("the collision shape must route structurally");
        assert_ne!(
            routed.version, 0,
            "the double-parse shape must route as non-v0"
        );

        // Positive half: authentic-under-v0 bytes, correct passphrase —
        // refused at the non-v0 arm (the routed salt byte is not a known
        // envelope version, so `DeniedAlgorithm` fires before any tag
        // check), nothing persisted, no counter moves.
        let result = super::decrypt_key_file_blob(
            &v0_bytes,
            std::path::Path::new("/unused"),
            std::path::Path::new("/unused"),
            "rsa0001-pass",
            KeyCustodyPermissionPolicy::default(),
            persist,
        );
        assert_eq!(
            result.err(),
            Some(CryptoError::DeniedAlgorithm),
            "a double-parse blob must fail closed, never reach the v0 path"
        );

        // Negative half: same shape, broken tag -> refused identically.
        let mut tampered = v0_bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let result = super::decrypt_key_file_blob(
            &tampered,
            std::path::Path::new("/unused"),
            std::path::Path::new("/unused"),
            "rsa0001-pass",
            KeyCustodyPermissionPolicy::default(),
            persist,
        );
        assert_eq!(
            result.err(),
            Some(CryptoError::DeniedAlgorithm),
            "a broken-tag collision-shape blob must fail closed"
        );

        // Fail-closed posture: no plaintext was persisted, and neither the
        // fallback-decode counter nor the v0-reads counter moved — the v0
        // path was never entered for either read.
        assert_eq!(
            RSA0001_PERSIST_LOG
                .lock()
                .expect("persist log poisoned")
                .len(),
            0,
            "a refused collision-shape blob must never be persisted"
        );
        assert_eq!(
            v0_envelope_fallback_decodes_total(),
            fallbacks_before,
            "no v0 fallback decode may fire for a structurally-v1 blob"
        );
        assert_eq!(
            v0_envelope_reads_total(),
            reads_before,
            "the v0 read path must never be entered after a v1 authentication failure"
        );
    }

    /// Review-side sealer for RSA-0001: frames `plaintext` exactly the way
    /// legacy v0 writers did (Argon2id + XChaCha20-Poly1305, empty AAD,
    /// [salt:16][nonce:24][len:4][ct]) with a caller-chosen salt so the
    /// corpus can pin first-byte shapes. Kept self-contained so the property
    /// below also runs against a tree without the RSA-0001 patch.
    #[cfg(unix)]
    fn rsa0001rev_seal_v0(
        passphrase: &str,
        plaintext: &[u8],
        salt: [u8; 16],
        nonce: [u8; 24],
    ) -> Vec<u8> {
        use super::{Argon2, XChaCha20Poly1305, XNonce};
        use chacha20poly1305::aead::{Aead, KeyInit};
        use zeroize::Zeroize;

        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
            .expect("kdf should succeed");
        let cipher = XChaCha20Poly1305::new((&key).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: b"",
                },
            )
            .expect("legacy v0 seal should succeed");
        key.zeroize();
        let mut out = Vec::with_capacity(44 + ciphertext.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&ciphertext);
        out
    }

    /// RSA-0001 review property: a randomized legacy-v0 corpus must load
    /// through the production reader regardless of its first byte — salt[0]
    /// is uniform-random salt material, so the old length+first-byte v1
    /// heuristic misrouted real v0 key files — and every load must re-seal
    /// the blob as v1 exactly once, while v1 blobs written by the production
    /// writer stay byte-stable on re-read with no v0-counter movement.
    /// Differential witness: this fails on a tree with the old heuristic
    /// (first byte != 0 routes the frame to the v1 decoder, which refuses it).
    #[cfg(unix)]
    #[test]
    fn rsa0001rev_legacy_v0_corpus_loads_and_reseals_for_random_first_bytes() {
        // The v0 counters are process-global: serialize against every other
        // v0-reading test.
        let _oi13_guard = OI13_V0_DISK_READ_LOCK.lock().expect("OI13 lock poisoned");
        let passphrase = "rsa0001rev-pass";
        let policy = KeyCustodyPermissionPolicy::default();

        // 40-blob corpus: six pinned first bytes (the heuristic's boundary
        // shapes, incl. the leading-zero salt and the top bit) plus 34
        // LCG-random first bytes, across three plaintext sizes.
        let mut lcg: u32 = 0x5a17_0001;
        let mut first_bytes = [0u8; 40];
        first_bytes[..6].copy_from_slice(&[0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff]);
        for slot in first_bytes[6..].iter_mut() {
            lcg = lcg.wrapping_mul(1664525).wrapping_add(1013904223);
            *slot = (lcg >> 24) as u8;
        }
        let sizes: [usize; 3] = [32, 48, 1024];

        for (index, first) in first_bytes.into_iter().enumerate() {
            let mut salt = [0u8; 16];
            salt[0] = first;
            for byte in salt[1..].iter_mut() {
                lcg = lcg.wrapping_mul(1664525).wrapping_add(1013904223);
                *byte = (lcg >> 24) as u8;
            }
            lcg = lcg.wrapping_mul(1664525).wrapping_add(1013904223);
            let nonce = lcg.to_be_bytes();
            lcg = lcg.wrapping_mul(1664525).wrapping_add(1013904223);
            let nonce_tail = lcg.to_be_bytes();

            let size = sizes[index % sizes.len()];
            let plaintext = vec![0x5cu8; size];
            let v0_bytes = rsa0001rev_seal_v0(
                passphrase,
                &plaintext,
                salt,
                [
                    nonce[0],
                    nonce[1],
                    nonce[2],
                    nonce[3],
                    nonce_tail[0],
                    nonce_tail[1],
                    nonce_tail[2],
                    nonce_tail[3],
                    0x11,
                    0x22,
                    0x33,
                    0x44,
                    0x55,
                    0x66,
                    0x77,
                    0x88,
                    0x99,
                    0xaa,
                    0xbb,
                    0xcc,
                    0xdd,
                    0xee,
                    0xff,
                    first,
                ],
            );

            let (directory, file) = oi13_temp_custody_dir("rsa0001rev-v0");
            oi13_write_custody_file(&directory, &file, &v0_bytes);
            let reads_before = v0_envelope_reads_total();

            let loaded = read_encrypted_key_file(&directory, &file, passphrase, policy)
                .unwrap_or_else(|err| {
                    panic!("v0 blob with first byte {first:#04x} (size {size}) must load: {err:?}")
                });
            assert_eq!(
                loaded.as_slice(),
                plaintext.as_slice(),
                "v0 blob with first byte {first:#04x} must decrypt to its plaintext"
            );
            assert_eq!(
                v0_envelope_reads_total(),
                reads_before + 1,
                "each legacy v0 load must be counted exactly once"
            );

            // The load must have re-sealed the blob as v1 on disk, once.
            let on_disk = std::fs::read(&file).expect("re-sealed file must be readable");
            assert_ne!(
                on_disk, v0_bytes,
                "the OI-13 re-seal must have replaced the v0 bytes on disk"
            );
            assert!(
                super::decode_encrypted_blob_v1(&on_disk).is_ok(),
                "the re-sealed blob must parse as v1"
            );
            assert!(
                super::decode_encrypted_blob_v0(&on_disk).is_err(),
                "the re-sealed blob must no longer parse as v0"
            );

            // A second read of the re-sealed blob must succeed and leave the
            // on-disk bytes byte-stable (no further re-seal).
            let again = read_encrypted_key_file(&directory, &file, passphrase, policy)
                .expect("the re-sealed v1 blob must load again");
            assert_eq!(again.as_slice(), plaintext.as_slice());
            let after_second = std::fs::read(&file).expect("v1 file must be readable");
            assert_eq!(
                after_second, on_disk,
                "a v1 blob must be byte-stable across reads"
            );
            assert_eq!(
                v0_envelope_reads_total(),
                reads_before + 1,
                "the re-sealed v1 blob must not touch the v0 read counter"
            );

            let _ = std::fs::remove_file(&file);
            let _ = std::fs::remove_dir(&directory);
        }

        // v1 half: blobs from the production writer are byte-stable across
        // reads and never move the v0 counters.
        let reads_before = v0_envelope_reads_total();
        for index in 0..8 {
            let plaintext = vec![0xa5u8; sizes[index % sizes.len()]];
            let (directory, file) = oi13_temp_custody_dir("rsa0001rev-v1");
            write_encrypted_key_file(&directory, &file, &plaintext, passphrase, policy)
                .expect("the production writer must seal a v1 blob");
            let on_disk = std::fs::read(&file).expect("v1 file must be readable");
            for round in 0..2 {
                let loaded = read_encrypted_key_file(&directory, &file, passphrase, policy)
                    .unwrap_or_else(|err| panic!("v1 blob round {round} must load: {err:?}"));
                assert_eq!(loaded.as_slice(), plaintext.as_slice());
                let now = std::fs::read(&file).expect("v1 file must be readable");
                assert_eq!(
                    now, on_disk,
                    "a production v1 blob must be byte-stable across reads"
                );
            }
            let _ = std::fs::remove_file(&file);
            let _ = std::fs::remove_dir(&directory);
        }
        assert_eq!(
            v0_envelope_reads_total(),
            reads_before,
            "v1 blobs must never move the v0 read counter"
        );
    }
}

// AQ-45 step 2: lookup / create-only custody surface.
#[cfg(test)]
mod atrest_key_lookup_tests {
    use super::*;

    #[test]
    fn classify_macos_framework_status_only_item_not_found_proves_absence() {
        assert_eq!(
            classify_macos_framework_status(MACOS_ERR_SEC_ITEM_NOT_FOUND),
            MacKeychainProbe::ItemNotFound
        );
        // errSecDuplicateItem and errSecNoDefaultKeychain are not absence proofs.
        assert_eq!(
            classify_macos_framework_status(-25299),
            MacKeychainProbe::Unavailable
        );
        assert_eq!(
            classify_macos_framework_status(-25307),
            MacKeychainProbe::Unavailable
        );
        assert_eq!(
            classify_macos_framework_status(0),
            MacKeychainProbe::Unavailable
        );
    }

    #[test]
    fn classify_macos_cli_exit_pins_empirical_exit_44() {
        assert_eq!(
            classify_macos_cli_exit(Some(MACOS_SECURITY_CLI_EXIT_ITEM_NOT_FOUND)),
            MacKeychainProbe::ItemNotFound
        );
        assert_eq!(MACOS_SECURITY_CLI_EXIT_ITEM_NOT_FOUND, 44);
        assert_eq!(MACOS_ERR_SEC_ITEM_NOT_FOUND, -25300);
        assert_eq!(
            classify_macos_cli_exit(Some(0)),
            MacKeychainProbe::Unavailable
        );
        assert_eq!(
            classify_macos_cli_exit(Some(1)),
            MacKeychainProbe::Unavailable
        );
        // Terminated by a signal: no exit code, inconclusive.
        assert_eq!(classify_macos_cli_exit(None), MacKeychainProbe::Unavailable);
    }

    #[test]
    fn classify_linux_secret_tool_search_only_success_with_empty_stdout_proves_absence() {
        assert_eq!(
            classify_linux_secret_tool_search(true, true),
            LinuxSecretToolProbe::ProvedNoItems
        );
        // Success WITH output means an item exists: inconclusive for absence.
        assert_eq!(
            classify_linux_secret_tool_search(true, false),
            LinuxSecretToolProbe::Inconclusive
        );
        // Failure (no secret service, transport error): inconclusive — verified
        // live, `search --all` exits 1 with "Could not connect" in that state.
        assert_eq!(
            classify_linux_secret_tool_search(false, true),
            LinuxSecretToolProbe::Inconclusive
        );
        assert_eq!(
            classify_linux_secret_tool_search(false, false),
            LinuxSecretToolProbe::Inconclusive
        );
    }

    #[test]
    fn classify_windows_dpapi_item_missing_only_not_found_proves_absence() {
        assert_eq!(
            classify_windows_dpapi_item_missing(std::io::ErrorKind::NotFound),
            WindowsDpapiProbe::ItemNotFound
        );
        assert_eq!(
            classify_windows_dpapi_item_missing(std::io::ErrorKind::PermissionDenied),
            WindowsDpapiProbe::Unavailable
        );
    }

    #[test]
    fn os_store_lookup_debug_redacts_found_payload() {
        let sentinel = vec![0xABu8; 32];
        let rendered = format!("{:?}", OsStoreLookup::Found(Zeroizing::new(sentinel)));
        assert!(rendered.contains("REDACTED"), "rendered: {rendered}");
        assert!(!rendered.contains("171"), "rendered: {rendered}");
        assert!(!rendered.contains("ab"), "rendered: {rendered}");
        assert_eq!(format!("{:?}", OsStoreLookup::ProvedAbsent), "ProvedAbsent");
        assert_eq!(format!("{:?}", OsStoreLookup::Unavailable), "Unavailable");
    }

    struct FailingStore;

    impl OsSecureStore for FailingStore {
        fn store_key(&self, _key_id: &str, _key_material: &[u8]) -> Result<(), CryptoError> {
            Err(CryptoError::OsStoreUnavailable)
        }
        fn load_key(&self, _key_id: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
            Err(CryptoError::OsStoreUnavailable)
        }
    }

    struct FixedStore;

    impl OsSecureStore for FixedStore {
        fn store_key(&self, _key_id: &str, _key_material: &[u8]) -> Result<(), CryptoError> {
            Err(CryptoError::OsStoreUnavailable)
        }
        fn load_key(&self, _key_id: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
            Ok(Zeroizing::new(vec![7u8, 8, 9]))
        }
    }

    #[test]
    fn default_lookup_key_never_reports_proved_absent() {
        // A backend that only implements the original two methods must never
        // trigger key minting in a caller: its lookup can be Found/Unavailable
        // only.
        assert_eq!(
            FailingStore.lookup_key("any-id"),
            OsStoreLookup::Unavailable
        );
        match FixedStore.lookup_key("any-id") {
            OsStoreLookup::Found(payload) => assert_eq!(&*payload, &[7u8, 8, 9]),
            other => panic!("expected Found, got {other:?}"),
        }
    }

    struct UpsertingStore {
        writes: std::sync::Mutex<Vec<String>>,
    }

    impl OsSecureStore for UpsertingStore {
        fn store_key(&self, key_id: &str, _key_material: &[u8]) -> Result<(), CryptoError> {
            self.writes.lock().unwrap().push(key_id.to_string());
            Ok(())
        }
        fn load_key(&self, _key_id: &str) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
            Err(CryptoError::OsStoreUnavailable)
        }
    }

    #[test]
    fn default_store_key_create_only_refuses() {
        assert_eq!(
            FailingStore.store_key_create_only("any-id", &[1u8; 32]),
            Err(CryptoError::OsStoreUnavailable)
        );
        assert_eq!(
            FixedStore.store_key_create_only("any-id", &[1u8; 32]),
            Err(CryptoError::OsStoreUnavailable)
        );
        // Discriminating fixture: `store_key` SUCCEEDS here, so a default
        // that degraded to the `store_key` upsert would return Ok and land
        // a write. FailingStore/FixedStore both refuse in `store_key`, so
        // they cannot detect that regression.
        let up = UpsertingStore {
            writes: std::sync::Mutex::new(Vec::new()),
        };
        assert_eq!(
            up.store_key_create_only("any-id", &[1u8; 32]),
            Err(CryptoError::OsStoreUnavailable)
        );
        assert!(
            up.writes.lock().unwrap().is_empty(),
            "create-only default must not write"
        );
    }

    #[test]
    fn classify_linux_secrets_name_has_owner_only_owned_completes_absence_proof() {
        // A secret service actually answered: the empty search result is
        // meaningful and completes the absence proof.
        assert_eq!(
            classify_linux_secrets_name_has_owner(Some(true)),
            LinuxSecretServicePresence::Owned
        );
        // The name exists on the bus but has NO owner: no secret service is
        // running, so the empty search result was vacuous.
        assert_eq!(
            classify_linux_secrets_name_has_owner(Some(false)),
            LinuxSecretServicePresence::Unavailable
        );
        // dbus-send missing (spawn error), no session bus, non-zero exit, or
        // a malformed reply all collapse to None: Unavailable.
        assert_eq!(
            classify_linux_secrets_name_has_owner(None),
            LinuxSecretServicePresence::Unavailable
        );
    }

    #[test]
    fn classify_macos_default_keychain_probe_pins_no_default_keychain_not_applicable() {
        assert_eq!(MACOS_ERR_SEC_NO_DEFAULT_KEYCHAIN, -25307);
        // Headless launchd daemon: not-applicable, never poisons absence.
        assert_eq!(
            classify_macos_default_keychain_probe(MACOS_ERR_SEC_NO_DEFAULT_KEYCHAIN),
            MacosDefaultKeychainProbe::NotApplicableNoDefaultKeychain
        );
        assert_eq!(
            classify_macos_default_keychain_probe(MACOS_ERR_SEC_ITEM_NOT_FOUND),
            MacosDefaultKeychainProbe::ItemNotFound
        );
        // Any other probe-1 error stays Unavailable.
        assert_eq!(
            classify_macos_default_keychain_probe(-25299),
            MacosDefaultKeychainProbe::Unavailable
        );
        assert_eq!(
            classify_macos_default_keychain_probe(0),
            MacosDefaultKeychainProbe::Unavailable
        );
    }

    #[test]
    fn combine_macos_absence_probes_not_applicable_probe1_does_not_poison() {
        // -25307 on probe 1 with BOTH System-keychain probes positively
        // absent: the conjunction holds (ProvedAbsent candidate).
        assert!(combine_macos_absence_probes(
            MacosDefaultKeychainProbe::NotApplicableNoDefaultKeychain,
            MacKeychainProbe::ItemNotFound,
            MacKeychainProbe::ItemNotFound,
        ));
        // -25307 with a System-keychain probe failing: Unavailable.
        assert!(!combine_macos_absence_probes(
            MacosDefaultKeychainProbe::NotApplicableNoDefaultKeychain,
            MacKeychainProbe::Unavailable,
            MacKeychainProbe::ItemNotFound,
        ));
        assert!(!combine_macos_absence_probes(
            MacosDefaultKeychainProbe::NotApplicableNoDefaultKeychain,
            MacKeychainProbe::ItemNotFound,
            MacKeychainProbe::Unavailable,
        ));
        // ANY other probe-1 error stays Unavailable even with both System
        // probes absent.
        assert!(!combine_macos_absence_probes(
            MacosDefaultKeychainProbe::Unavailable,
            MacKeychainProbe::ItemNotFound,
            MacKeychainProbe::ItemNotFound,
        ));
        // All three applicable and all positively absent: conjunction holds.
        assert!(combine_macos_absence_probes(
            MacosDefaultKeychainProbe::ItemNotFound,
            MacKeychainProbe::ItemNotFound,
            MacKeychainProbe::ItemNotFound,
        ));
    }
}

// KM-1: trusted system binary resolution for the Linux secret-service
// custody helpers (no PATH spawns).
#[cfg(all(test, unix))]
mod trusted_binary_resolution_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // A full to-root ancestor walk can NEVER accept a tempdir candidate for
    // euid: the fixed ancestors of a tempdir are root-owned (and sticky /
    // group-writable on both macOS /var/folders and Linux /tmp). Acceptance
    // is therefore exercised end-to-end against root-owned system binaries
    // with trusted_uid 0, and the ancestor-chain rule directly through the
    // list-taking validate_trusted_directory_chain.

    fn unique_test_dir(tag: &str) -> PathBuf {
        let unique = format!(
            "rustynet-km1-{}-{}",
            tag,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&directory).expect("test directory should be created");
        directory
    }

    fn effective_uid() -> u32 {
        nix::unistd::Uid::effective().as_raw()
    }

    fn root_owned_system_binary() -> PathBuf {
        for candidate in ["/bin/sh", "/usr/bin/env"] {
            if let Ok(resolved) = validate_trusted_binary(Path::new(candidate), 0) {
                return resolved;
            }
        }
        panic!("a root-owned system binary (/bin/sh or /usr/bin/env) should validate");
    }

    #[test]
    fn validate_trusted_binary_accepts_root_owned_system_binary() {
        let resolved = root_owned_system_binary();
        let canonical = resolved
            .canonicalize()
            .expect("resolved path should still exist");
        assert_eq!(
            resolved, canonical,
            "resolver must return the canonical path"
        );
        assert!(resolved.is_absolute());
        assert!(
            resolved.starts_with("/bin")
                || resolved.starts_with("/usr/bin")
                || resolved.starts_with("/usr/local/bin"),
            "resolved path must come from the fixed trusted directories: {resolved:?}"
        );
    }

    #[test]
    fn trusted_directory_chain_accepts_current_user_owned_0o755_directories() {
        let euid = effective_uid();
        let outer = unique_test_dir("chain-ok");
        let inner = outer.join("bin");
        std::fs::create_dir_all(&inner).expect("inner directory should be created");
        std::fs::set_permissions(&outer, std::fs::Permissions::from_mode(0o755))
            .expect("outer mode should be set");
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o755))
            .expect("inner mode should be set");
        let result = validate_trusted_directory_chain(&[outer.as_path(), inner.as_path()], euid);
        assert_eq!(result, Ok(()));
        let _ = std::fs::remove_dir_all(&outer);
    }

    #[test]
    fn validate_trusted_binary_rejects_group_writable_binary() {
        let euid = effective_uid();
        let directory = unique_test_dir("bin-gw");
        let file = directory.join("tool");
        std::fs::write(&file, b"#!/bin/sh\n").expect("binary should be written");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o775))
            .expect("mode should be set");
        let canonical = file.canonicalize().expect("file should exist");
        let err = validate_trusted_binary(&file, euid)
            .expect_err("a group-writable binary must be rejected");
        assert!(
            err.contains("group/other writable") && err.contains("mode 775"),
            "unexpected error: {err}"
        );
        assert!(
            err.contains(&canonical.display().to_string()),
            "error should name the canonical binary path: {err}"
        );
        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&directory);
    }

    #[test]
    fn validate_trusted_binary_rejects_world_writable_binary() {
        let euid = effective_uid();
        let directory = unique_test_dir("bin-ww");
        let file = directory.join("tool");
        std::fs::write(&file, b"#!/bin/sh\n").expect("binary should be written");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o777))
            .expect("mode should be set");
        let err = validate_trusted_binary(&file, euid)
            .expect_err("a world-writable binary must be rejected");
        assert!(
            err.contains("group/other writable"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&directory);
    }

    #[test]
    fn validate_trusted_binary_rejects_non_executable_file() {
        let euid = effective_uid();
        let directory = unique_test_dir("bin-noexec");
        let file = directory.join("tool");
        std::fs::write(&file, b"#!/bin/sh\n").expect("file should be written");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))
            .expect("mode should be set");
        let err = validate_trusted_binary(&file, euid)
            .expect_err("a non-executable file must be rejected");
        assert!(err.contains("is not executable"), "unexpected error: {err}");
        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&directory);
    }

    #[test]
    fn validate_trusted_binary_rejects_binary_owned_by_untrusted_uid() {
        // trusted_uid = 0 with a file owned by the effective user, pinned by
        // EXACT message: the ancestor-chain error has a different shape
        // ("ancestor directory ..."), so only the binary's own owner check
        // can satisfy this assertion.
        let euid = effective_uid();
        let directory = unique_test_dir("bin-foreign");
        let file = directory.join("tool");
        std::fs::write(&file, b"#!/bin/sh\n").expect("binary should be written");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755))
            .expect("mode should be set");
        let err = validate_trusted_binary(&file, 0)
            .expect_err("a binary owned by another uid must be rejected");
        assert_eq!(
            err,
            format!(
                "{} is owned by uid {euid}, expected trusted uid 0",
                file.canonicalize().expect("canonical path").display()
            ),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&directory);
    }

    #[test]
    fn trusted_directory_chain_rejects_group_writable_ancestor_directory() {
        let euid = effective_uid();
        let directory = unique_test_dir("anc-gw");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o775))
            .expect("mode should be set");
        let err = validate_trusted_directory_chain(&[directory.as_path()], euid)
            .expect_err("a group-writable ancestor must be rejected");
        assert!(
            err.contains("ancestor directory")
                && err.contains("group/other writable")
                && err.contains(directory.display().to_string().as_str()),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_dir(&directory);
    }

    #[test]
    fn trusted_directory_chain_rejects_ancestor_owned_by_untrusted_uid() {
        let euid = effective_uid();
        let directory = unique_test_dir("anc-foreign");
        let err = validate_trusted_directory_chain(&[directory.as_path()], euid + 1)
            .expect_err("an ancestor owned by another uid must be rejected");
        assert!(
            err.contains("ancestor directory") && err.contains("owned by uid"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_dir(&directory);
    }

    #[test]
    fn validate_trusted_binary_rejects_directory_candidate() {
        let euid = effective_uid();
        let directory = unique_test_dir("is-dir");
        let err = validate_trusted_binary(&directory, euid)
            .expect_err("a directory candidate must be rejected");
        assert!(
            err.contains("is not a regular file"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_dir(&directory);
    }

    #[test]
    fn validate_trusted_binary_rejects_dangling_symlink() {
        let euid = effective_uid();
        let directory = unique_test_dir("dangling");
        let link = directory.join("tool");
        std::os::unix::fs::symlink(directory.join("missing-target"), &link)
            .expect("symlink should be created");
        let err =
            validate_trusted_binary(&link, euid).expect_err("a dangling symlink must be rejected");
        assert!(
            err.contains("cannot canonicalize"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir(&directory);
    }

    #[test]
    fn validate_trusted_binary_returns_canonical_target_not_symlink_path() {
        let target = root_owned_system_binary();
        let directory = unique_test_dir("symlink");
        let link = directory.join("tool");
        std::os::unix::fs::symlink(&target, &link).expect("symlink should be created");
        let resolved =
            validate_trusted_binary(&link, 0).expect("symlink to a trusted binary should validate");
        assert_ne!(
            resolved, link,
            "must not return the unresolved symlink path"
        );
        assert_eq!(
            resolved,
            target.canonicalize().expect("target should exist"),
            "must return the canonical target path"
        );
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir(&directory);
    }

    #[test]
    fn validate_trusted_binary_rejects_candidate_beneath_writable_ancestor() {
        // The candidate itself is clean (owned by euid, mode 0o755) but its
        // ancestor chain passes through root-owned group/other-writable
        // directories (the tempdir parents), so the to-root walk must reject
        // it — this is the exact test that dies when the ancestor walk is
        // skipped.
        let euid = effective_uid();
        let directory = unique_test_dir("anc-walk");
        let file = directory.join("tool");
        std::fs::write(&file, b"#!/bin/sh\n").expect("binary should be written");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755))
            .expect("mode should be set");
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
            .expect("mode should be set");
        let err = validate_trusted_binary(&file, euid)
            .expect_err("a candidate beneath a writable ancestor must be rejected");
        assert!(
            err.contains("ancestor directory"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&directory);
    }

    #[test]
    fn lib_rs_never_spawns_secret_tool_or_dbus_send_by_bare_name() {
        let source = include_str!("lib.rs");
        assert!(
            !source.contains("Command::new(\"secret-tool\")"),
            "secret-tool must be spawned only via resolve_trusted_system_binary (KM-1)"
        );
        assert!(
            !source.contains("Command::new(\"dbus-send\")"),
            "dbus-send must be spawned only via resolve_trusted_system_binary (KM-1)"
        );
        // The scan is only meaningful while the resolver remains wired in at
        // every custody spawn site.
        assert!(
            source.contains("resolve_trusted_system_binary(\"secret-tool\")"),
            "secret-tool spawn must go through resolve_trusted_system_binary"
        );
        assert!(
            source.contains("resolve_trusted_system_binary(\"dbus-send\")"),
            "dbus-send spawn must go through resolve_trusted_system_binary"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_trusted_system_binary_refuses_when_no_trusted_candidate_exists() {
        let err = resolve_trusted_system_binary("rustynet-km1-nonexistent-helper")
            .expect_err("a missing helper must resolve to OsStoreUnavailable");
        assert_eq!(err, CryptoError::OsStoreUnavailable);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_trusted_system_binary_accepts_root_owned_system_helper() {
        let resolved = resolve_trusted_system_binary("true")
            .expect("a root-owned fixed-directory helper should resolve");
        assert!(
            resolved.starts_with("/usr/bin")
                || resolved.starts_with("/bin")
                || resolved.starts_with("/usr/local/bin"),
            "resolved path must come from the fixed trusted directories: {resolved:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_trusted_system_binary_never_consults_path() {
        // A 0o755 shim named like a helper that exists NOWHERE in the fixed
        // directories is put on PATH; the resolver must ignore PATH entirely
        // (KM-1) and refuse with OsStoreUnavailable. This kills a PATH-first
        // resolver and a fallback-to-PATH-after-miss alike, on every host,
        // regardless of what is installed: either mutant returns the shim's
        // path instead of the error.
        let directory = unique_test_dir("path-shadow");
        let shim = directory.join("rustynet-km1-path-shadow-helper");
        std::fs::write(&shim, b"#!/bin/sh\n").expect("shim should be written");
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))
            .expect("mode should be set");
        assert!(shim.is_file() && shim.canonicalize().is_ok());
        let previous = std::env::var_os("PATH");
        // SAFETY: test-only, minimal window; PATH is restored before any
        // assertion, so a failure never leaks the mutated environment.
        unsafe {
            std::env::set_var("PATH", &directory);
        }
        let resolved = resolve_trusted_system_binary("rustynet-km1-path-shadow-helper");
        match previous {
            Some(value) => unsafe { std::env::set_var("PATH", value) },
            None => unsafe { std::env::remove_var("PATH") },
        }
        assert_eq!(
            resolved,
            Err(CryptoError::OsStoreUnavailable),
            "resolver must never fall back to a PATH-resolved candidate"
        );
        let _ = std::fs::remove_file(&shim);
        let _ = std::fs::remove_dir(&directory);
    }
}

// AQ-213: per-crate compiled ground-truth gate for this crate's
// reviewed-redacting-impl registry entries; the source is shared with
// rustynetd via #[path] so every host crate runs the same gate.
#[cfg(test)]
#[path = "../../rustynetd/src/witness_listing.rs"]
mod witness_listing;
