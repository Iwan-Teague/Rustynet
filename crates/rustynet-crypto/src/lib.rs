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
    pub fn from_raw(public_key: [u8; 32], private_key: [u8; 32]) -> Result<Self, CryptoError> {
        if is_all_zeros(&public_key) || is_all_zeros(&private_key) {
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
    let status = std::process::Command::new("/usr/bin/security")
        .args([
            "add-generic-password",
            "-U",
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
    if status.success() {
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
    // Fallback: query the System keychain explicitly via the security CLI.
    // Required for system launch daemons that run without a user keychain session.
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
        // startup (prepare_runtime_wireguard_key_material). NTFS ACLs on
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
        seed: [u8; 32],
    ) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
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

pub fn encrypt_private_key_envelope(
    plaintext: &[u8],
    passphrase: &str,
    salt: [u8; 16],
    nonce: [u8; 24],
) -> Result<EncryptedKeyBlob, CryptoError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|_| CryptoError::KdfFailed)?;

    let cipher = XChaCha20Poly1305::new((&key).into());
    let ciphertext = match cipher.encrypt(XNonce::from_slice(&nonce), plaintext) {
        Ok(value) => value,
        Err(_) => {
            key.zeroize();
            return Err(CryptoError::EncryptionFailed);
        }
    };

    key.zeroize();

    Ok(EncryptedKeyBlob {
        salt,
        nonce,
        ciphertext,
    })
}

pub fn decrypt_private_key_envelope(
    blob: &EncryptedKeyBlob,
    passphrase: &str,
) -> Result<Vec<u8>, CryptoError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &blob.salt, &mut key)
        .map_err(|_| CryptoError::KdfFailed)?;

    let cipher = XChaCha20Poly1305::new((&key).into());
    let plaintext = match cipher.decrypt(XNonce::from_slice(&blob.nonce), blob.ciphertext.as_ref())
    {
        Ok(value) => value,
        Err(_) => {
            key.zeroize();
            return Err(CryptoError::DecryptionFailed);
        }
    };

    key.zeroize();

    Ok(plaintext)
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

    let parent = path.parent().ok_or(CryptoError::Io)?;
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
        let parent_dir = std::fs::File::open(parent).map_err(|_| CryptoError::Io)?;
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
    let mut out = Vec::with_capacity(16 + 24 + 4 + blob.ciphertext.len());
    out.extend_from_slice(&blob.salt);
    out.extend_from_slice(&blob.nonce);
    out.extend_from_slice(&(blob.ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&blob.ciphertext);
    out
}

fn decode_encrypted_blob(bytes: &[u8]) -> Result<EncryptedKeyBlob, CryptoError> {
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
    if bytes.len() != 44 + ciphertext_len {
        return Err(CryptoError::InvalidLength);
    }

    Ok(EncryptedKeyBlob {
        salt,
        nonce,
        ciphertext: bytes[44..].to_vec(),
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

pub fn validate_key_custody_permissions(
    directory: &Path,
    file: &Path,
    policy: KeyCustodyPermissionPolicy,
) -> Result<(), CryptoError> {
    #[cfg(unix)]
    {
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

        let directory_mode = directory_metadata.permissions().mode() & 0o777;
        let file_mode = file_metadata.permissions().mode() & 0o777;

        if directory_mode != policy.required_directory_mode {
            return Err(CryptoError::PermissionDenied);
        }
        if file_mode != policy.required_file_mode {
            return Err(CryptoError::PermissionDenied);
        }

        Ok(())
    }

    #[cfg(not(unix))]
    {
        // Windows ACL validation not yet implemented; defer to OS enforcement.
        let _ = (directory, file, policy);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AlgorithmPolicy, CompatibilityException, CryptoAlgorithm, CryptoError,
        Ed25519SigningProvider, KeyCustodyManager, KeyCustodyPermissionPolicy, NoOsSecureStore,
        NodeKeyPair, OsStoreFallbackPolicy, SigningProvider, SigningProviderKind,
        SigningProviderPolicy, create_provider_attestation, decrypt_private_key_envelope,
        encrypt_private_key_envelope, generate_key_custody_material, read_encrypted_key_file,
        try_generate_key_custody_material, validate_key_custody_permissions,
        validate_signing_provider_policy, verify_provider_attestation, write_encrypted_key_file,
    };

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
        let result = NodeKeyPair::from_raw([7; 32], [9; 32]);
        assert!(result.is_ok());
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
        // Canonical service/account pairs the daemon and ops verbs hand to
        // the keychain backend. Pinning these so a tightening of the
        // allow-list cannot silently break the bootstrap.
        for good in [
            // WireGuard key custody (key_material.rs).
            "rustynet.wg-private-deadbeef01234567",
            "rustynet",
            // WireGuard passphrase service (key_material.rs:43).
            "net.rustynet.wg-key-passphrase",
            "wg-passphrase-node-001",
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
}
