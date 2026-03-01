#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(PartialEq, Eq)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(REDACTED)")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.fill(0);
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

pub struct KeyCustodyManager<S: OsSecureStore> {
    os_store: S,
    fallback_directory: PathBuf,
    fallback_passphrase: String,
    permission_policy: KeyCustodyPermissionPolicy,
}

impl<S: OsSecureStore> KeyCustodyManager<S> {
    pub fn new(
        os_store: S,
        fallback_directory: PathBuf,
        fallback_passphrase: String,
        permission_policy: KeyCustodyPermissionPolicy,
    ) -> Self {
        Self {
            os_store,
            fallback_directory,
            fallback_passphrase,
            permission_policy,
        }
    }

    pub fn store_private_key(
        &self,
        key_id: &str,
        key_material: &[u8],
    ) -> Result<KeyCustodyBackend, CryptoError> {
        match self.os_store.store_key(key_id, key_material) {
            Ok(()) => Ok(KeyCustodyBackend::OsSecureStore),
            Err(CryptoError::OsStoreUnavailable) => {
                let file_path = self.fallback_file_path(key_id)?;
                write_encrypted_key_file(
                    &self.fallback_directory,
                    &file_path,
                    key_material,
                    &self.fallback_passphrase,
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
                let file_path = self.fallback_file_path(key_id)?;
                read_encrypted_key_file(
                    &self.fallback_directory,
                    &file_path,
                    &self.fallback_passphrase,
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
            allow_local_fallback: true,
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
        self.verifying_key
            .verify(payload, &signature)
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
        key_identifier: provider.key_identifier().to_string(),
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
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
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
    let mut rng = rand::thread_rng();
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);
    (salt, nonce)
}

pub fn encrypt_private_key_fallback(
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
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    key.fill(0);

    Ok(EncryptedKeyBlob {
        salt,
        nonce,
        ciphertext,
    })
}

pub fn decrypt_private_key_fallback(
    blob: &EncryptedKeyBlob,
    passphrase: &str,
) -> Result<Vec<u8>, CryptoError> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &blob.salt, &mut key)
        .map_err(|_| CryptoError::KdfFailed)?;

    let cipher = XChaCha20Poly1305::new((&key).into());
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&blob.nonce), blob.ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)?;

    key.fill(0);

    Ok(plaintext)
}

pub fn write_encrypted_key_file(
    directory: &Path,
    file: &Path,
    plaintext: &[u8],
    passphrase: &str,
    policy: KeyCustodyPermissionPolicy,
) -> Result<(), CryptoError> {
    let (salt, nonce) = generate_key_custody_material();
    let blob = encrypt_private_key_fallback(plaintext, passphrase, salt, nonce)?;
    let encoded = encode_encrypted_blob(&blob);

    std::fs::create_dir_all(directory).map_err(|_| CryptoError::Io)?;
    std::fs::write(file, encoded).map_err(|_| CryptoError::Io)?;
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
        .map_err(|_| CryptoError::Io)?;
    }
    validate_key_custody_permissions(directory, file, policy)?;
    Ok(())
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
    decrypt_private_key_fallback(&blob, passphrase)
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
        let _ = (directory, file, policy);
        Err(CryptoError::PermissionValidationUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AlgorithmPolicy, CompatibilityException, CryptoAlgorithm, CryptoError,
        Ed25519SigningProvider, KeyCustodyManager, KeyCustodyPermissionPolicy, NoOsSecureStore,
        NodeKeyPair, SigningProviderKind, SigningProviderPolicy, create_provider_attestation,
        decrypt_private_key_fallback, encrypt_private_key_fallback, generate_key_custody_material,
        read_encrypted_key_file, validate_key_custody_permissions,
        validate_signing_provider_policy, verify_provider_attestation, write_encrypted_key_file,
    };

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
    fn denylisted_algorithm_with_active_exception_is_temporarily_accepted() {
        let policy = AlgorithmPolicy::with_exceptions(vec![CompatibilityException {
            algorithm: CryptoAlgorithm::Sha1,
            expires_unix_seconds: 200,
        }])
        .expect("exception should be valid for denylisted algorithm");

        let result = policy.validate(CryptoAlgorithm::Sha1, 150);
        assert!(result.is_ok());
    }

    #[test]
    fn denylisted_algorithm_exception_expires() {
        let policy = AlgorithmPolicy::with_exceptions(vec![CompatibilityException {
            algorithm: CryptoAlgorithm::Sha1,
            expires_unix_seconds: 200,
        }])
        .expect("exception should be valid for denylisted algorithm");

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
    fn encrypted_fallback_roundtrip_succeeds() {
        let (salt, nonce) = generate_key_custody_material();
        let blob =
            encrypt_private_key_fallback(b"private-material", "phase2-passphrase", salt, nonce)
                .expect("encryption should succeed");

        let plaintext = decrypt_private_key_fallback(&blob, "phase2-passphrase")
            .expect("decryption should succeed");
        assert_eq!(plaintext, b"private-material");
    }

    #[test]
    fn encrypted_fallback_rejects_wrong_passphrase() {
        let (salt, nonce) = generate_key_custody_material();
        let blob =
            encrypt_private_key_fallback(b"private-material", "phase2-passphrase", salt, nonce)
                .expect("encryption should succeed");

        let result = decrypt_private_key_fallback(&blob, "wrong-passphrase");
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
            "phase2-passphrase".to_string(),
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

    #[test]
    fn key_custody_manager_rejects_invalid_key_identifier() {
        let manager = KeyCustodyManager::new(
            NoOsSecureStore,
            std::env::temp_dir().join("rustynet-key-custody-invalid-id"),
            "phase2-passphrase".to_string(),
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
}
