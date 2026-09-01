//! Self-signed TLS identity and rustls server configuration for the two
//! anchor control-plane listeners (QH-26 item 4 / DA-01).
//!
//! Design contract (`documents/SecurityMinimumBar.md` §4):
//! - TLS 1.3 only: the workspace builds rustls without the `tls12` feature,
//!   and this module additionally restricts protocol versions to TLS 1.3.
//! - No CA / PKI: the anchor generates a self-signed ECDSA P-256 certificate
//!   at first startup (rcgen, ring backend) and reuses it across restarts.
//! - Distribution: the certificate fingerprint (SHA-256 of the DER
//!   certificate) is the pin. Clients refuse to send any secret (enrollment
//!   token, bundle-pull token) until the pin matches.
//! - Fail closed: any generation, permission, or parse failure aborts the
//!   bind; there is no plaintext fallback path.

use std::fs;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use sha2::Digest;

/// Common name / SAN carried by the anchor certificate. IP-address clients
/// send no SNI, so the certificate identity is only meaningful to the pin;
/// verification is by fingerprint, never by name.
pub const ANCHOR_TLS_CERT_NAME: &str = "rustynet-anchor.local";

/// Certificate lifetime in days. Long-lived on purpose: the anchor
/// certificate is provisioned once and pinned out-of-band.
const ANCHOR_TLS_CERT_LIFETIME_DAYS: i64 = 3650;

/// One hour of back-dating to tolerate clock skew between the anchor and
/// pulling nodes.
const ANCHOR_TLS_NOT_BEFORE_SKEW_SECS: i64 = 3600;

#[derive(Debug)]
pub enum AnchorTlsError {
    KeyGeneration(String),
    CertGeneration(String),
    FileWrite {
        path: PathBuf,
        context: &'static str,
        source: std::io::Error,
    },
    Io {
        path: PathBuf,
        context: &'static str,
        source: std::io::Error,
    },
    CertificateParse(String),
    KeyRejected(String),
    ServerConfig(String),
    PartialIdentity {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
}

impl std::fmt::Display for AnchorTlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyGeneration(what) => write!(f, "anchor TLS key generation failed: {what}"),
            Self::CertGeneration(what) => {
                write!(f, "anchor TLS certificate generation failed: {what}")
            }
            Self::FileWrite {
                path,
                context,
                source,
            } => {
                write!(f, "anchor TLS {}: {}: {source}", path.display(), context)
            }
            Self::Io {
                path,
                context,
                source,
            } => {
                write!(f, "anchor TLS {}: {}: {source}", path.display(), context)
            }
            Self::CertificateParse(what) => {
                write!(f, "anchor TLS certificate parse failed: {what}")
            }
            Self::KeyRejected(what) => write!(f, "anchor TLS key rejected: {what}"),
            Self::ServerConfig(what) => write!(f, "anchor TLS server config failed: {what}"),
            Self::PartialIdentity {
                cert_path,
                key_path,
            } => write!(
                f,
                "anchor TLS identity incomplete: certificate {} and key {} must both exist or both be absent; refusing to bind half an identity",
                cert_path.display(),
                key_path.display()
            ),
        }
    }
}

impl std::error::Error for AnchorTlsError {}

/// The anchor's long-lived TLS identity: DER certificate, DER private key,
/// and the SHA-256 fingerprint of the DER certificate that clients pin.
/// `Clone` is deliberately NOT derived: `PrivateKeyDer` is not `Clone` (key
/// material must not be silently duplicated), and every consumer re-loads the
/// same persisted identity instead of sharing a copy.
#[derive(Debug)]
pub struct AnchorTlsIdentity {
    pub certificate_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
    cert_fingerprint_sha256_hex: String,
}

impl AnchorTlsIdentity {
    pub fn cert_fingerprint_sha256_hex(&self) -> &str {
        &self.cert_fingerprint_sha256_hex
    }

    fn fingerprint(certificate_der: &CertificateDer<'_>) -> String {
        let digest = sha2::Sha256::digest(certificate_der.as_ref());
        hex_lower(&digest)
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Loads the persisted anchor TLS identity, generating and persisting a new
/// self-signed one when neither file exists yet. Fails closed whenever the
/// on-disk state is ambiguous, unreadable, or too permissive.
pub fn load_or_generate_anchor_tls_identity(
    cert_path: &Path,
    key_path: &Path,
    product_label: &str,
) -> Result<AnchorTlsIdentity, AnchorTlsError> {
    let cert_exists = cert_path.exists();
    let key_exists = key_path.exists();
    match (cert_exists, key_exists) {
        (false, false) => {
            generate_and_persist_anchor_tls_identity(cert_path, key_path, product_label)
        }
        (true, true) => load_anchor_tls_identity(cert_path, key_path),
        (true, false) | (false, true) => Err(AnchorTlsError::PartialIdentity {
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
        }),
    }
}

fn generate_and_persist_anchor_tls_identity(
    cert_path: &Path,
    key_path: &Path,
    product_label: &str,
) -> Result<AnchorTlsIdentity, AnchorTlsError> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|error| AnchorTlsError::KeyGeneration(error.to_string()))?;

    let mut params = rcgen::CertificateParams::new(vec![ANCHOR_TLS_CERT_NAME.to_string()])
        .map_err(|error| AnchorTlsError::CertGeneration(error.to_string()))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, product_label);
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "RustyNet");
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::seconds(ANCHOR_TLS_NOT_BEFORE_SKEW_SECS);
    params.not_after = now + time::Duration::days(ANCHOR_TLS_CERT_LIFETIME_DAYS);

    let certificate = params
        .self_signed(&key_pair)
        .map_err(|error| AnchorTlsError::CertGeneration(error.to_string()))?;

    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent).map_err(|source| AnchorTlsError::FileWrite {
            path: parent.to_path_buf(),
            context: "create parent directory",
            source,
        })?;
        #[cfg(unix)]
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|source| {
            AnchorTlsError::FileWrite {
                path: parent.to_path_buf(),
                context: "restrict parent directory to 0700",
                source,
            }
        })?;
    }

    let certificate_pem = certificate.pem();
    let key_pem = key_pair.serialize_pem();
    write_private_bytes(cert_path, certificate_pem.as_bytes(), 0o644)?;
    write_private_bytes(key_path, key_pem.as_bytes(), 0o600)?;

    load_anchor_tls_identity(cert_path, key_path)
}

fn write_private_bytes(path: &Path, bytes: &[u8], mode: u32) -> Result<(), AnchorTlsError> {
    use std::io::Write as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| AnchorTlsError::FileWrite {
            path: path.to_path_buf(),
            context: "create",
            source,
        })?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(mode))
        .map_err(|source| AnchorTlsError::FileWrite {
            path: path.to_path_buf(),
            context: "set permissions",
            source,
        })?;
    file.write_all(bytes)
        .map_err(|source| AnchorTlsError::FileWrite {
            path: path.to_path_buf(),
            context: "write",
            source,
        })?;
    Ok(())
}

/// Refuses symlinks and non-regular files (matching
/// `open_anchor_state_file` hardening) and enforces 0600 on the key and 0644
/// on the certificate.
fn read_tls_file(
    path: &Path,
    kind: &'static str,
    expected_mode: u32,
) -> Result<Vec<u8>, AnchorTlsError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| AnchorTlsError::Io {
        path: path.to_path_buf(),
        context: "stat",
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(AnchorTlsError::Io {
            path: path.to_path_buf(),
            context: "symlinks are not allowed",
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "symlink"),
        });
    }
    if !metadata.is_file() {
        return Err(AnchorTlsError::Io {
            path: path.to_path_buf(),
            context: "not a regular file",
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file"),
        });
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode != expected_mode {
            return Err(AnchorTlsError::Io {
                path: path.to_path_buf(),
                context: Box::leak(
                    format!(
                        "file permissions too open: {:o}; expected {:o}",
                        mode, expected_mode
                    )
                    .into_boxed_str(),
                ),
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permissions"),
            });
        }
    }
    let mut file = fs::File::open(path).map_err(|source| AnchorTlsError::Io {
        path: path.to_path_buf(),
        context: "open",
        source,
    })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| AnchorTlsError::Io {
            path: path.to_path_buf(),
            context: "read",
            source,
        })?;
    let _ = kind;
    Ok(bytes)
}

fn load_anchor_tls_identity(
    cert_path: &Path,
    key_path: &Path,
) -> Result<AnchorTlsIdentity, AnchorTlsError> {
    let cert_bytes = read_tls_file(cert_path, "certificate", 0o644)?;
    let key_bytes = read_tls_file(key_path, "key", 0o600)?;
    let certificate_der = CertificateDer::from_pem_slice(&cert_bytes)
        .map_err(|error| AnchorTlsError::CertificateParse(error.to_string()))?;
    let key_der = PrivateKeyDer::from_pem_slice(&key_bytes)
        .map_err(|error| AnchorTlsError::KeyRejected(error.to_string()))?;
    // Fail closed at startup if rustls cannot build a signer from the loaded
    // key: this is the earliest point a corrupt/mismatched key is detectable
    // without a handshake.
    build_certified_key(&certificate_der, &key_der)?;
    let cert_fingerprint_sha256_hex = AnchorTlsIdentity::fingerprint(&certificate_der);
    Ok(AnchorTlsIdentity {
        certificate_der,
        key_der,
        cert_fingerprint_sha256_hex,
    })
}

/// Builds the rustls `CertifiedKey` for the loaded identity. A cert/key
/// mismatch is not detectable without a signature round-trip, so a mismatched
/// persisted pair surfaces loudly at the first TLS handshake (the connection
/// is refused) rather than silently.
fn build_certified_key(
    certificate_der: &CertificateDer<'static>,
    key_der: &PrivateKeyDer<'static>,
) -> Result<Arc<CertifiedKey>, AnchorTlsError> {
    // rustls 0.23 names this module `sign` (the old `signer` path is gone);
    // the ring feature is pinned in Cargo.toml so this is the only provider.
    let signing_key = rustls::crypto::ring::sign::any_supported_type(key_der)
        .map_err(|error| AnchorTlsError::KeyRejected(error.to_string()))?;
    Ok(Arc::new(CertifiedKey {
        cert: vec![certificate_der.clone()],
        key: signing_key,
        ocsp: None,
    }))
}

/// Always resolves the anchor's single certificate. `ResolvesServerCertUsingSni`
/// cannot be used here: bundle-pull clients dial by IP address and send no
/// SNI extension.
#[derive(Debug)]
pub struct AnchorCertResolver(Arc<CertifiedKey>);

impl ResolvesServerCert for AnchorCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// Shared ring crypto provider. Repeated `install_default` calls from
/// concurrent listeners are harmless: the first wins and the rest reuse it.
fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
    });
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Builds a TLS 1.3-only server configuration presenting the anchor
/// certificate with no client authentication (client identity is still the
/// bearer-token / signed-snapshot logic, unchanged).
pub fn build_anchor_server_config(
    identity: &AnchorTlsIdentity,
) -> Result<rustls::ServerConfig, AnchorTlsError> {
    let certified_key = build_certified_key(&identity.certificate_der, &identity.key_der)?;
    let resolver: Arc<dyn ResolvesServerCert> = Arc::new(AnchorCertResolver(certified_key));
    Ok(rustls::ServerConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| AnchorTlsError::ServerConfig(error.to_string()))?
        .with_no_client_auth()
        .with_cert_resolver(resolver))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::{SocketAddr, TcpListener, TcpStream};

    struct TempTlsDir(PathBuf);

    impl TempTlsDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rustynet-anchor-tls-{}-{}",
                label,
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).expect("create temp tls dir");
            Self(dir)
        }

        fn cert_path(&self) -> PathBuf {
            self.0.join("anchor-tls-cert.pem")
        }

        fn key_path(&self) -> PathBuf {
            self.0.join("anchor-tls-key.pem")
        }
    }

    impl Drop for TempTlsDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn generated_identity_is_valid_and_fingerprinted() {
        let dir = TempTlsDir::new("generate");
        let identity = load_or_generate_anchor_tls_identity(
            &dir.cert_path(),
            &dir.key_path(),
            "RustyNet Anchor Test",
        )
        .expect("identity generation must succeed");
        assert_eq!(identity.cert_fingerprint_sha256_hex().len(), 64);
        assert!(
            identity
                .cert_fingerprint_sha256_hex()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[test]
    fn generated_identity_is_stable_when_reloaded() {
        let dir = TempTlsDir::new("stable");
        let first = load_or_generate_anchor_tls_identity(
            &dir.cert_path(),
            &dir.key_path(),
            "RustyNet Anchor Test",
        )
        .expect("first generation must succeed");
        let second = load_or_generate_anchor_tls_identity(
            &dir.cert_path(),
            &dir.key_path(),
            "RustyNet Anchor Test",
        )
        .expect("reload must succeed");
        assert_eq!(
            first.cert_fingerprint_sha256_hex(),
            second.cert_fingerprint_sha256_hex()
        );
    }

    #[cfg(unix)]
    #[test]
    fn generated_key_file_permissions_are_0600() {
        let dir = TempTlsDir::new("perms");
        let _ = load_or_generate_anchor_tls_identity(
            &dir.cert_path(),
            &dir.key_path(),
            "RustyNet Anchor Test",
        )
        .expect("generation must succeed");
        let key_mode = fs::metadata(dir.key_path())
            .expect("key metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(key_mode, 0o600);
        let cert_mode = fs::metadata(dir.cert_path())
            .expect("cert metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(cert_mode, 0o644);
    }

    #[test]
    fn partial_identity_is_refused() {
        let dir = TempTlsDir::new("partial");
        let identity = load_or_generate_anchor_tls_identity(
            &dir.cert_path(),
            &dir.key_path(),
            "RustyNet Anchor Test",
        )
        .expect("generation must succeed");
        let _ = identity;
        let cert_only = load_or_generate_anchor_tls_identity(
            &dir.cert_path(),
            &PathBuf::from("/nonexistent-key.pem"),
            "x",
        );
        assert!(matches!(
            cert_only,
            Err(AnchorTlsError::PartialIdentity { .. })
        ));
        let key_only = load_or_generate_anchor_tls_identity(
            &PathBuf::from("/nonexistent-cert.pem"),
            &dir.key_path(),
            "x",
        );
        assert!(matches!(
            key_only,
            Err(AnchorTlsError::PartialIdentity { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn over_permissive_key_file_is_refused_on_reload() {
        let dir = TempTlsDir::new("openkey");
        let _ = load_or_generate_anchor_tls_identity(
            &dir.cert_path(),
            &dir.key_path(),
            "RustyNet Anchor Test",
        )
        .expect("generation must succeed");
        fs::set_permissions(dir.key_path(), fs::Permissions::from_mode(0o644))
            .expect("open key perms");
        let error = load_or_generate_anchor_tls_identity(
            &dir.cert_path(),
            &dir.key_path(),
            "RustyNet Anchor Test",
        )
        .expect_err("over-permissive key must be refused");
        assert!(
            error.to_string().contains("permissions too open"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn tls_handshake_succeeds_with_pinned_fingerprint() {
        let dir = TempTlsDir::new("handshake");
        let identity = load_or_generate_anchor_tls_identity(
            &dir.cert_path(),
            &dir.key_path(),
            "RustyNet Anchor Test",
        )
        .expect("generation must succeed");
        let config = Arc::new(build_anchor_server_config(&identity).expect("server config"));
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let conn = rustls::ServerConnection::new(config).expect("server connection");
            let mut tls = rustls::StreamOwned::new(conn, stream);
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).expect("read inside TLS");
            assert_eq!(&buf, b"hello");
            tls.write_all(b"ok").expect("write inside TLS");
            let _ = tls.flush();
        });

        let mut client =
            connect_pinned(addr, identity.cert_fingerprint_sha256_hex()).expect("client handshake");
        client.write_all(b"hello").expect("write");
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).expect("read");
        assert_eq!(&reply, b"ok");
        server.join().expect("server thread");
    }

    #[test]
    fn tls_handshake_rejects_wrong_fingerprint() {
        let dir = TempTlsDir::new("mismatch");
        let identity = load_or_generate_anchor_tls_identity(
            &dir.cert_path(),
            &dir.key_path(),
            "RustyNet Anchor Test",
        )
        .expect("generation must succeed");
        let config = Arc::new(build_anchor_server_config(&identity).expect("server config"));
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let conn = rustls::ServerConnection::new(config).expect("server connection");
            let mut tls = rustls::StreamOwned::new(conn, stream);
            // Handshake fails as soon as the client aborts; drain quietly.
            let _ = std::io::copy(&mut tls, &mut std::io::sink());
        });

        let wrong = "00".repeat(32);
        let error = connect_pinned(addr, &wrong).expect_err("wrong fingerprint must be rejected");
        let message = error.to_string().to_lowercase();
        assert!(
            message.contains("fingerprint")
                || message.contains("bad certificate")
                || message.contains("alert"),
            "unexpected error: {error}"
        );
        server.join().expect("server thread");
    }

    fn connect_pinned(
        addr: SocketAddr,
        expected_fingerprint_hex: &str,
    ) -> std::io::Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
        let server_name = rustls::pki_types::ServerName::try_from(ANCHOR_TLS_CERT_NAME.to_string())
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad server name")
            })?;
        let verifier = Arc::new(PinnedFingerprintVerifier::new(expected_fingerprint_hex));
        let provider = ring_provider();
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
            })?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let stream = TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(5))?;
        let conn =
            rustls::ClientConnection::new(Arc::new(config), server_name).map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
            })?;
        let mut tls = rustls::StreamOwned::new(conn, stream);
        // Drive the handshake eagerly so pin failures surface here.
        tls.flush()?;
        Ok(tls)
    }

    #[derive(Debug)]
    struct PinnedFingerprintVerifier {
        expected: [u8; 32],
        algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
    }

    impl PinnedFingerprintVerifier {
        fn new(expected_fingerprint_hex: &str) -> Self {
            let mut expected = [0u8; 32];
            for (index, chunk) in expected_fingerprint_hex.as_bytes().chunks(2).enumerate() {
                expected[index] = u8::from_str_radix(std::str::from_utf8(chunk).expect("hex"), 16)
                    .expect("hex digit");
            }
            Self {
                expected,
                algorithms: rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms,
            }
        }
    }

    impl rustls::client::danger::ServerCertVerifier for PinnedFingerprintVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            let digest = sha2::Sha256::digest(end_entity.as_ref());
            if digest.as_slice() == self.expected.as_slice() {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::General(
                    "anchor TLS certificate fingerprint does not match the pinned value"
                        .to_string(),
                ))
            }
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _certificate: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::General(
                "TLS 1.2 is not supported".to_string(),
            ))
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            certificate: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(message, certificate, dss, &self.algorithms)
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.algorithms.supported_schemes()
        }
    }
}
