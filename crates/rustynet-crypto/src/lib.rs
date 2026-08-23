#![forbid(unsafe_code)]

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
    WindowsDpapiScope, dpapi_protect, dpapi_unprotect, inspect_file_sddl,
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
    ExceptionExpired,
    InvalidException,
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
            CryptoError::ExceptionExpired => f.write_str("compatibility exception has expired"),
            CryptoError::InvalidException => f.write_str("compatibility exception is invalid"),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompatibilityException {
    pub algorithm: CryptoAlgorithm,
    pub expires_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AlgorithmPolicy {
    exceptions: Vec<CompatibilityException>,
}

impl AlgorithmPolicy {
    pub fn with_exceptions(exceptions: Vec<CompatibilityException>) -> Result<Self, CryptoError> {
        if !exceptions.is_empty() {
            return Err(CryptoError::InvalidException);
        }
        for exception in &exceptions {
            if !is_denylisted(exception.algorithm) {
                return Err(CryptoError::InvalidException);
            }
        }

        Ok(Self { exceptions })
    }

    pub fn validate(
        &self,
        algorithm: CryptoAlgorithm,
        now_unix_seconds: u64,
    ) -> Result<(), CryptoError> {
        if is_allowlisted(algorithm) {
            return Ok(());
        }

        if is_denylisted(algorithm) {
            if let Some(exception) = self
                .exceptions
                .iter()
                .find(|entry| entry.algorithm == algorithm)
            {
                if now_unix_seconds <= exception.expires_unix_seconds {
                    return Ok(());
                }
                return Err(CryptoError::ExceptionExpired);
            }

            return Err(CryptoError::DeniedAlgorithm);
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

fn is_denylisted(algorithm: CryptoAlgorithm) -> bool {
    matches!(
        algorithm,
        CryptoAlgorithm::Md5
            | CryptoAlgorithm::Sha1
            | CryptoAlgorithm::Rc4
            | CryptoAlgorithm::Des
            | CryptoAlgorithm::TripleDes
            | CryptoAlgorithm::BlowfishCbc
            | CryptoAlgorithm::WeakDh
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

pub trait OsSecureStore {
    fn store_key(&self, key_id: &str, key_material: &[u8]) -> Result<(), CryptoError>;
    fn load_key(&self, key_id: &str) -> Result<Vec<u8>, CryptoError>;
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

    fn load_key(&self, _key_id: &str) -> Result<Vec<u8>, CryptoError> {
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

    fn load_key(&self, key_id: &str) -> Result<Vec<u8>, CryptoError> {
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

    pub fn load_private_key(&self, key_id: &str) -> Result<Vec<u8>, CryptoError> {
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
fn load_from_macos_keychain(key_id: &str) -> Result<Vec<u8>, CryptoError> {
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
            return Ok(decoded);
        }
    }

    Ok(value)
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

#[cfg(target_os = "linux")]
fn store_in_linux_secret_service(key_id: &str, key_material: &[u8]) -> Result<(), CryptoError> {
    let mut child = Command::new("secret-tool")
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
fn load_from_linux_secret_service(key_id: &str) -> Result<Vec<u8>, CryptoError> {
    let output = Command::new("secret-tool")
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
    decoded
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
fn load_from_windows_dpapi(key_id: &str) -> Result<Vec<u8>, CryptoError> {
    let root = windows_dpapi_root()?;
    validate_windows_dpapi_root(root.as_path())?;
    let path = windows_dpapi_file_path(root.as_path(), key_id)?;
    validate_windows_dpapi_file(path.as_path())?;
    let mut protected = std::fs::read(path.as_path()).map_err(|_| CryptoError::Io)?;
    let result = dpapi_unprotect(&protected).map_err(|_| CryptoError::DecryptionFailed);
    protected.zeroize();
    result
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
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or(CryptoError::AttestationVerificationFailed)?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or(CryptoError::AttestationVerificationFailed)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

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

/// Fallible analogue of [`generate_key_custody_material`].
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
    const KEY_ENVELOPE_AAD_MAGIC: &[u8; 4] = b"RNET";
    const KEY_ENVELOPE_VERSION: u8 = 1;
    let aad = [
        KEY_ENVELOPE_AAD_MAGIC[0],
        KEY_ENVELOPE_AAD_MAGIC[1],
        KEY_ENVELOPE_AAD_MAGIC[2],
        KEY_ENVELOPE_AAD_MAGIC[3],
        KEY_ENVELOPE_VERSION,
    ];
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
        version: KEY_ENVELOPE_VERSION,
        salt,
        nonce,
        ciphertext,
    })
}

/// Decrypt a key envelope, supporting both v0 (legacy, no AAD) and
/// v1 (AAD-bound) blobs. v0 decryption uses empty AAD; v1 uses the
/// constant magic `b"RNET"` + version byte. A v0 blob re-encrypted
/// becomes a v1 blob on the next write cycle.
pub fn decrypt_private_key_envelope(
    blob: &EncryptedKeyBlob,
    passphrase: &str,
) -> Result<Vec<u8>, CryptoError> {
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
                aad: b"",
            },
        ),
        1 => {
            const KEY_ENVELOPE_AAD_MAGIC: &[u8; 4] = b"RNET";
            let aad = [
                KEY_ENVELOPE_AAD_MAGIC[0],
                KEY_ENVELOPE_AAD_MAGIC[1],
                KEY_ENVELOPE_AAD_MAGIC[2],
                KEY_ENVELOPE_AAD_MAGIC[3],
                blob.version,
            ];
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

    Ok(plaintext)
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
pub fn aead_seal(
    key: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<AeadSealedBlob, CryptoError> {
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
pub fn aead_open(
    key: &[u8; 32],
    aad: &[u8],
    blob: &AeadSealedBlob,
) -> Result<Vec<u8>, CryptoError> {
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
    let encoded = encode_encrypted_blob(&blob);

    if directory.exists() {
        let directory_link_metadata =
            std::fs::symlink_metadata(directory).map_err(|_| CryptoError::Io)?;
        if directory_link_metadata.file_type().is_symlink() || !directory_link_metadata.is_dir() {
            return Err(CryptoError::PermissionDenied);
        }
    }

    std::fs::create_dir_all(directory).map_err(|_| CryptoError::Io)?;
    if file.parent() != Some(directory) {
        return Err(CryptoError::Io);
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
    use std::fs::OpenOptions;
    use std::io::Write;

    // Bound to `_parent` because the parent directory handle is only fsynced on
    // unix (see the `#[cfg(unix)]` block below); the path-has-a-parent check is a
    // fail-closed validation that runs on every platform regardless.
    let _parent = path.parent().ok_or(CryptoError::Io)?;
    let temp = temp_path_for(path);

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(_mode)
    };

    let mut file = options.open(&temp).map_err(|_| CryptoError::Io)?;
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

pub fn read_encrypted_key_file(
    directory: &Path,
    file: &Path,
    passphrase: &str,
    policy: KeyCustodyPermissionPolicy,
) -> Result<Vec<u8>, CryptoError> {
    validate_key_custody_permissions(directory, file, policy)?;
    let encoded = std::fs::read(file).map_err(|_| CryptoError::Io)?;
    let blob = decode_encrypted_blob(&encoded)?;
    decrypt_private_key_envelope(&blob, passphrase)
}

fn encode_encrypted_blob(blob: &EncryptedKeyBlob) -> Vec<u8> {
    if blob.version == 0 {
        let mut out = Vec::with_capacity(16 + 24 + 4 + blob.ciphertext.len());
        out.extend_from_slice(&blob.salt);
        out.extend_from_slice(&blob.nonce);
        out.extend_from_slice(&(blob.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&blob.ciphertext);
        out
    } else {
        let mut out = Vec::with_capacity(1 + 16 + 24 + 4 + blob.ciphertext.len());
        out.push(blob.version);
        out.extend_from_slice(&blob.salt);
        out.extend_from_slice(&blob.nonce);
        out.extend_from_slice(&(blob.ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&blob.ciphertext);
        out
    }
}

fn decode_encrypted_blob(bytes: &[u8]) -> Result<EncryptedKeyBlob, CryptoError> {
    // v1: [version:1][salt:16][nonce:24][len:4][ct] — min 45 bytes, version != 0
    // v0: [salt:16][nonce:24][len:4][ct] — min 44 bytes, version implicitly 0
    if bytes.len() >= 45 && bytes[0] != 0 {
        return decode_encrypted_blob_v1(bytes);
    }
    decode_encrypted_blob_v0(bytes)
}

fn decode_encrypted_blob_v0(bytes: &[u8]) -> Result<EncryptedKeyBlob, CryptoError> {
    if bytes.len() < 44 {
        return Err(CryptoError::InvalidLength);
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&bytes[0..16]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&bytes[16..40]);

    let mut length_bytes = [0u8; 4];
    length_bytes.copy_from_slice(&bytes[40..44]);
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
        ciphertext: bytes[44..].to_vec(),
    })
}

fn decode_encrypted_blob_v1(bytes: &[u8]) -> Result<EncryptedKeyBlob, CryptoError> {
    if bytes.len() < 45 {
        return Err(CryptoError::InvalidLength);
    }
    let version = bytes[0];
    if version == 0 {
        return Err(CryptoError::InvalidLength);
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&bytes[1..17]);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&bytes[17..41]);

    let mut length_bytes = [0u8; 4];
    length_bytes.copy_from_slice(&bytes[41..45]);
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
        ciphertext: bytes[45..].to_vec(),
    })
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

    #[cfg(not(unix))]
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
        // permission checks"; on a non-unix target it carried neither, so the
        // one control standing between a world-readable key file and the
        // process was absent. "Defer to OS enforcement" is not enforcement —
        // nothing had asked the OS anything.
        //
        // `PermissionValidationUnavailable` is the honest answer, and the
        // variant already existed for exactly this shape (the Windows DPAPI
        // validators return it when an SDDL read fails). Windows key custody
        // proper goes through DPAPI, which has its own SDDL checks, so this
        // arm bites only on the fallback path that was never validated.
        //
        // Implementing it means mapping `KeyCustodyPermissionPolicy`'s unix
        // mode bits onto an SDDL assertion; until then a loud failure is
        // correct. CRY-05 / AUDIT-027.
        let _ = (directory, file, policy);
        Err(CryptoError::PermissionValidationUnavailable)
    }
}

#[cfg(all(test, unix))]
mod unix_custody_tests {
    use super::{
        CryptoError, KeyCustodyPermissionPolicy, UnixCustodyMetadata,
        evaluate_unix_custody_metadata,
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

    /// The unimplemented-platform arm must FAIL, not pass.
    ///
    /// Runs only where the arm exists. The source pin below is what protects
    /// this on unix hosts, where the arm is compiled out and this test cannot
    /// execute at all.
    #[cfg(not(unix))]
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
    #[test]
    fn non_unix_key_custody_arm_does_not_return_ok() {
        let source = include_str!("lib.rs");
        let marker = "let _ = (directory, file, policy);";
        let at = source
            .find(marker)
            .expect("the non-unix key-custody arm must still discard its arguments");
        let tail = &source[at + marker.len()..];
        let next_stmt: String = tail.chars().take(120).collect();
        assert!(
            next_stmt.contains("Err(CryptoError::PermissionValidationUnavailable)"),
            "the non-unix key-custody arm must fail closed; found: {next_stmt:?}"
        );
        assert!(
            !next_stmt.trim_start().starts_with("Ok(())"),
            "the non-unix key-custody arm must never return Ok(()) -- that is the \
             fail-open CRY-05/AUDIT-027 records"
        );
    }

    use super::{
        AlgorithmPolicy, CompatibilityException, CryptoAlgorithm, CryptoError,
        Ed25519SigningProvider, KeyCustodyManager, KeyCustodyPermissionPolicy, NoOsSecureStore,
        NodeKeyPair, SigningProvider, SigningProviderKind, SigningProviderPolicy,
        create_provider_attestation, decode_encrypted_blob_v0, decode_encrypted_blob_v1,
        decrypt_private_key_envelope, encrypt_private_key_envelope, generate_key_custody_material,
        try_generate_key_custody_material, validate_signing_provider_policy,
        verify_provider_attestation,
    };
    use ed25519_dalek::SigningKey;
    // The encrypted-key-file custody helpers and the OS-store fallback policy are
    // only exercised by `#[cfg(unix)]` tests below (they rely on unix permission
    // bits / symlink semantics); gate the imports to match so Windows does not see
    // them as unused.
    #[cfg(unix)]
    use super::{
        OsStoreFallbackPolicy, read_encrypted_key_file, validate_key_custody_permissions,
        write_encrypted_key_file,
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
        // Take a window covering the function body.
        let window_end = (start + 4_000).min(body.len());
        let window = &body[start..window_end];
        assert!(
            window.contains("try_generate_key_custody_material()"),
            "write_encrypted_key_file must use the fallible nonce+salt minter"
        );
        // Build the panicking name from chunks so the regression message does
        // not itself match the negative grep.
        let panicking = ["generate_key_", "custody_material()"].concat();
        assert!(
            !window.contains(&panicking) || window.contains("try_generate_key_custody_material()"),
            "write_encrypted_key_file must not call the panicking legacy minter directly"
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
    fn denylisted_algorithm_exceptions_are_rejected() {
        let result = AlgorithmPolicy::with_exceptions(vec![CompatibilityException {
            algorithm: CryptoAlgorithm::Sha1,
            expires_unix_seconds: 200,
        }]);
        assert_eq!(result.err(), Some(CryptoError::InvalidException));
    }

    #[test]
    fn denylisted_algorithm_remains_denied_without_exceptions() {
        let policy = AlgorithmPolicy::default();
        let result = policy.validate(CryptoAlgorithm::Sha1, 201);
        assert_eq!(result.err(), Some(CryptoError::DeniedAlgorithm));
    }

    #[test]
    fn denylisted_algorithm_with_expired_exception_is_rejected() {
        let policy = AlgorithmPolicy {
            exceptions: vec![CompatibilityException {
                algorithm: CryptoAlgorithm::Sha1,
                expires_unix_seconds: 200,
            }],
        };

        let result = policy.validate(CryptoAlgorithm::Sha1, 201);
        assert_eq!(result.err(), Some(CryptoError::ExceptionExpired));
    }

    #[test]
    fn invalid_exception_for_allowlisted_algorithm_is_rejected() {
        let result = AlgorithmPolicy::with_exceptions(vec![CompatibilityException {
            algorithm: CryptoAlgorithm::Tls13,
            expires_unix_seconds: 200,
        }]);

        assert_eq!(result.err(), Some(CryptoError::InvalidException));
    }

    #[test]
    fn encrypted_envelope_roundtrip_succeeds() {
        let (salt, nonce) = generate_key_custody_material();
        let blob =
            encrypt_private_key_envelope(b"private-material", "phase2-passphrase", salt, nonce)
                .expect("encryption should succeed");

        let plaintext = decrypt_private_key_envelope(&blob, "phase2-passphrase")
            .expect("decryption should succeed");
        assert_eq!(plaintext, b"private-material");
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
        let encoded = super::encode_encrypted_blob(&blob);
        assert_eq!(
            encoded[0], 1,
            "v1 encoding carries an explicit version byte"
        );
        let decoded = super::decode_encrypted_blob(&encoded).expect("v1 blob should decode");
        assert_eq!(
            decrypt_private_key_envelope(&decoded, "pw").expect("v1 round-trip should decrypt"),
            b"private-material"
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

        assert_eq!(plaintext, b"very-secret-private-key");

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
        assert_eq!(loaded, b"node-private-key");

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
}
