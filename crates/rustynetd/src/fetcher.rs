#![forbid(unsafe_code)]

//! Control-plane state fetcher with signature verification and watermark anti-replay.
//!
//! This module implements StateFetcher for pull-based signed bundle retrieval
//! with strict verification order and fail-closed semantics.

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

#[derive(Debug, Clone)]
pub enum FetchError {
    Network(String),
    SignatureInvalid(String),
    Stale(String),
    WatermarkRejected(String),
    InvalidResponse(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Network(e) => write!(f, "network error: {e}"),
            FetchError::SignatureInvalid(e) => write!(f, "signature invalid: {e}"),
            FetchError::Stale(e) => write!(f, "bundle stale: {e}"),
            FetchError::WatermarkRejected(e) => write!(f, "watermark rejected: {e}"),
            FetchError::InvalidResponse(e) => write!(f, "invalid response: {e}"),
        }
    }
}

impl std::error::Error for FetchError {}

pub struct StateFetcher {
    control_endpoint: String,
    watermark_store: WatermarkStore,
    verifying_key: VerifyingKey,
}

impl StateFetcher {
    pub fn new(
        control_endpoint: String,
        watermark_path: impl AsRef<Path>,
        verifying_key: VerifyingKey,
    ) -> Result<Self, String> {
        let watermark_store = WatermarkStore::new(watermark_path)?;
        Ok(Self {
            control_endpoint,
            watermark_store,
            verifying_key,
        })
    }

    pub fn fetch_assignment(&mut self) -> Result<SignedBundle, FetchError> {
        self.fetch_bundle("assignment")
    }

    pub fn fetch_traversal(&mut self) -> Result<SignedBundle, FetchError> {
        self.fetch_bundle("traversal")
    }

    pub fn fetch_trust(&mut self) -> Result<SignedBundle, FetchError> {
        self.fetch_bundle("trust")
    }

    pub fn fetch_dns_zone(&mut self) -> Result<SignedBundle, FetchError> {
        self.fetch_bundle("dns_zone")
    }

    fn fetch_bundle(&mut self, bundle_type: &str) -> Result<SignedBundle, FetchError> {
        // Step 1: Perform HTTP GET with mTLS client auth
        // For now, simulate fetch (in production would use reqwest with mTLS)
        let response_bytes =
            self.http_get_raw(&format!("{}/{}", self.control_endpoint, bundle_type))?;

        // Step 2: Parse response into signed bundle
        let bundle = SignedBundle::parse(&response_bytes).map_err(FetchError::InvalidResponse)?;

        // Step 3: Verify signature (fail → SignatureInvalid, watermark NOT advanced)
        self.verify_signature(&bundle)
            .map_err(FetchError::SignatureInvalid)?;

        // Step 4: Check freshness (fail → Stale, watermark NOT advanced)
        self.check_freshness(&bundle).map_err(FetchError::Stale)?;

        // Step 5: Advance watermark (fail → WatermarkRejected)
        self.watermark_store
            .advance(bundle_type, bundle.watermark)
            .map_err(FetchError::WatermarkRejected)?;

        Ok(bundle)
    }

    fn http_get_raw(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        // Minimal HTTP/1.1 GET implementation using std::net::TcpStream
        let url = url.trim();
        if !url.starts_with("http://") {
            return Err(FetchError::Network(
                "only http:// URLs are supported in this minimal fetcher".to_string(),
            ));
        }
        let without_proto = &url[7..];
        let parts: Vec<&str> = without_proto.splitn(2, '/').collect();
        let host_port = parts
            .first()
            .ok_or_else(|| FetchError::Network("invalid url".to_string()))?;
        let path = format!("/{}", parts.get(1).unwrap_or(&""));
        let mut host = host_port.to_string();
        let mut port = 80u16;
        if host_port.contains(':') {
            let mut hp = host_port.splitn(2, ':');
            host = hp.next().unwrap_or("").to_string();
            if let Some(p) = hp.next() {
                port = p
                    .parse::<u16>()
                    .map_err(|_| FetchError::Network("invalid port in url".to_string()))?;
            }
        }
        let addr = format!("{host}:{port}");

        let socket_addrs = addr
            .to_socket_addrs()
            .map_err(|e| FetchError::Network(format!("resolve failed: {e}")))?;
        let mut stream = match socket_addrs.into_iter().next() {
            Some(sa) => TcpStream::connect_timeout(&sa, Duration::from_secs(3))
                .map_err(|_| FetchError::Network("network unreachable".to_string()))?,
            None => {
                return Err(FetchError::Network(
                    "resolve returned no addresses".to_string(),
                ));
            }
        };

        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .map_err(|e| FetchError::Network(format!("write failed: {e}")))?;

        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .map_err(|e| FetchError::Network(format!("read failed: {e}")))?;

        if let Some(idx) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            Ok(buf.split_off(idx + 4))
        } else {
            Err(FetchError::InvalidResponse(
                "malformed http response".to_string(),
            ))
        }
    }

    fn verify_signature(&self, bundle: &SignedBundle) -> Result<(), String> {
        let signature = Signature::from_bytes(&bundle.signature);
        self.verifying_key
            .verify(bundle.payload.as_bytes(), &signature)
            .map_err(|e| format!("signature verification failed: {e}"))
    }

    fn check_freshness(&self, bundle: &SignedBundle) -> Result<(), String> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if bundle.expires_at_unix < now_unix {
            return Err(format!(
                "bundle expired at {} (now: {})",
                bundle.expires_at_unix, now_unix
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBundle {
    pub payload: String,
    pub signature: [u8; 64],
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub watermark: u64,
}

impl SignedBundle {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| "bundle is not valid utf8".to_string())?;

        let sig_marker = "signature=";
        let mut signature_bytes = [0u8; 64];
        let mut found_sig = false;

        let mut issued_at_unix = 0;
        let mut expires_at_unix = 0;
        let mut watermark = 0;

        for line in text.lines() {
            if let Some(rest) = line.strip_prefix(sig_marker) {
                let hex_str = rest.trim();
                let decoded = hex_decode(hex_str)?;
                if decoded.len() != 64 {
                    return Err("invalid signature length".to_string());
                }
                signature_bytes.copy_from_slice(&decoded);
                found_sig = true;
            } else if let Some(rest) = line.strip_prefix("generated_at_unix=") {
                issued_at_unix = rest.trim().parse().unwrap_or(0);
            } else if let Some(rest) = line.strip_prefix("expires_at_unix=") {
                expires_at_unix = rest.trim().parse().unwrap_or(0);
            } else if let Some(rest) = line.strip_prefix("nonce=") {
                watermark = rest.trim().parse().unwrap_or(0);
            }
        }

        if !found_sig {
            return Err("missing signature".to_string());
        }

        let sig_idx = text.rfind(sig_marker).ok_or("signature marker missing")?;
        let payload = text[..sig_idx].to_string();

        Ok(Self {
            payload,
            signature: signature_bytes,
            issued_at_unix,
            expires_at_unix,
            watermark,
        })
    }
}

pub struct WatermarkStore {
    path: std::path::PathBuf,
    watermarks: std::collections::HashMap<String, u64>,
}

impl WatermarkStore {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        let watermarks = if path.exists() {
            Self::load_from_disk(&path)?
        } else {
            std::collections::HashMap::new()
        };

        Ok(Self { path, watermarks })
    }

    pub fn advance(&mut self, bundle_type: &str, new_watermark: u64) -> Result<(), String> {
        let current = self.watermarks.get(bundle_type).copied().unwrap_or(0);

        if new_watermark <= current {
            return Err(format!(
                "watermark replay: new={new_watermark} <= current={current}"
            ));
        }

        self.watermarks
            .insert(bundle_type.to_string(), new_watermark);
        self.persist_to_disk()?;

        Ok(())
    }

    pub fn get(&self, bundle_type: &str) -> Option<u64> {
        self.watermarks.get(bundle_type).copied()
    }

    fn load_from_disk(path: &Path) -> Result<std::collections::HashMap<String, u64>, String> {
        let content =
            fs::read_to_string(path).map_err(|e| format!("failed to read watermark store: {e}"))?;

        let mut watermarks = std::collections::HashMap::new();
        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split('=').collect();
            if parts.len() != 2 {
                return Err(format!("malformed watermark line: {line}"));
            }
            let key = parts[0].to_string();
            let value = parts[1]
                .parse::<u64>()
                .map_err(|e| format!("invalid watermark value: {e}"))?;
            watermarks.insert(key, value);
        }

        Ok(watermarks)
    }

    fn persist_to_disk(&self) -> Result<(), String> {
        let mut content = String::new();
        for (key, value) in &self.watermarks {
            content.push_str(&format!("{key}={value}\n"));
        }

        fs::write(&self.path, content)
            .map_err(|e| format!("failed to write watermark store: {e}"))?;

        // Ensure 0600 permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&self.path)
                .map_err(|e| format!("failed to read watermark metadata: {e}"))?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&self.path, permissions)
                .map_err(|e| format!("failed to set watermark permissions: {e}"))?;
        }

        Ok(())
    }
}

pub struct RefreshScheduler {
    pre_expiry_margin_secs: u64,
    jitter_max_secs: u64,
}

impl Default for RefreshScheduler {
    fn default() -> Self {
        Self {
            pre_expiry_margin_secs: 120,
            jitter_max_secs: 30,
        }
    }
}

impl RefreshScheduler {
    pub fn new(pre_expiry_margin_secs: u64, jitter_max_secs: u64) -> Self {
        Self {
            pre_expiry_margin_secs,
            jitter_max_secs,
        }
    }

    pub fn next_refresh_at(&self, bundle_expires_at: SystemTime) -> Instant {
        let now = SystemTime::now();
        let target = bundle_expires_at - Duration::from_secs(self.pre_expiry_margin_secs);

        let jitter_secs = rand::random::<u64>() % self.jitter_max_secs;
        let target_with_jitter = target + Duration::from_secs(jitter_secs);

        if target_with_jitter <= now {
            // Already past, schedule soon
            Instant::now() + Duration::from_secs(5)
        } else {
            let duration_until_target = target_with_jitter
                .duration_since(now)
                .unwrap_or(Duration::from_secs(5));
            Instant::now() + duration_until_target
        }
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("hex string has odd length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex char".to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::time::Duration;

    fn make_test_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    #[test]
    fn test_watermark_store_advance() {
        let temp_dir = tempfile::tempdir().unwrap();
        let watermark_path = temp_dir.path().join("watermarks.txt");
        let mut store = WatermarkStore::new(&watermark_path).unwrap();

        // First advance should succeed
        assert!(store.advance("assignment", 100).is_ok());
        assert_eq!(store.get("assignment"), Some(100));

        // Advancing to higher watermark should succeed
        assert!(store.advance("assignment", 200).is_ok());
        assert_eq!(store.get("assignment"), Some(200));

        // Replay should be rejected
        assert!(store.advance("assignment", 200).is_err());
        assert!(store.advance("assignment", 150).is_err());
    }

    #[test]
    fn test_watermark_store_persistence() {
        let temp_dir = tempfile::tempdir().unwrap();
        let watermark_path = temp_dir.path().join("watermarks.txt");

        {
            let mut store = WatermarkStore::new(&watermark_path).unwrap();
            store.advance("assignment", 100).unwrap();
            store.advance("traversal", 200).unwrap();
        }

        // Load from disk
        let store = WatermarkStore::new(&watermark_path).unwrap();
        assert_eq!(store.get("assignment"), Some(100));
        assert_eq!(store.get("traversal"), Some(200));
    }

    #[test]
    fn test_watermark_store_file_permissions() {
        let temp_dir = tempfile::tempdir().unwrap();
        let watermark_path = temp_dir.path().join("watermarks.txt");
        let mut store = WatermarkStore::new(&watermark_path).unwrap();
        store.advance("assignment", 100).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&watermark_path).unwrap();
            let permissions = metadata.permissions();
            assert_eq!(permissions.mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn test_refresh_scheduler_fires_before_expiry() {
        let scheduler = RefreshScheduler::default();
        let expires_at = SystemTime::now() + Duration::from_secs(300);
        let next_refresh = scheduler.next_refresh_at(expires_at);

        // Should be scheduled before expiry
        let time_until_refresh = next_refresh.duration_since(Instant::now()).as_secs();
        assert!(time_until_refresh < 300);
    }

    #[test]
    fn test_refresh_scheduler_jitter_bounded() {
        let scheduler = RefreshScheduler::new(120, 30);
        let expires_at = SystemTime::now() + Duration::from_secs(300);

        // Run multiple times to check jitter is bounded
        for _ in 0..10 {
            let next_refresh = scheduler.next_refresh_at(expires_at);
            let time_until_refresh = next_refresh.duration_since(Instant::now()).as_secs();

            // Should be within margin ± jitter
            assert!(time_until_refresh >= 120);
            assert!(time_until_refresh <= 300);
        }
    }

    #[test]
    fn test_refresh_scheduler_past_expiry_schedules_soon() {
        let scheduler = RefreshScheduler::default();
        let expires_at = SystemTime::now() - Duration::from_secs(100);
        let next_refresh = scheduler.next_refresh_at(expires_at);

        // Should be scheduled within 10s
        let time_until_refresh = next_refresh.duration_since(Instant::now()).as_secs();
        assert!(time_until_refresh <= 10);
    }

    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn test_fetch_bundle_signature_invalid() {
        let (_signing_key, verifying_key) = make_test_keypair();
        let wrong_key = SigningKey::from_bytes(&[2u8; 32]);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let expires = now + 300;
            let payload = format!(
                "version=1\ngenerated_at_unix={now}\nexpires_at_unix={expires}\nnonce=100\n"
            );
            let signature = wrong_key.sign(payload.as_bytes());
            let body = format!(
                "{}signature={}\n",
                payload,
                hex_encode(&signature.to_bytes())
            );
            let response = format!("HTTP/1.1 200 OK\r\n\r\n{body}");
            stream.write_all(response.as_bytes()).unwrap();
        });

        let dir = tempfile::tempdir().unwrap();
        let mut fetcher =
            StateFetcher::new(url, dir.path().join("watermark"), verifying_key).unwrap();

        match fetcher.fetch_trust() {
            Err(FetchError::SignatureInvalid(_)) => {}
            res => panic!("expected SignatureInvalid, got {res:?}"),
        }
        handle.join().unwrap();
    }

    #[test]
    fn test_fetch_bundle_watermark_replay() {
        let (signing_key, verifying_key) = make_test_keypair();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let expires = now + 300;
            let payload = format!(
                "version=1\ngenerated_at_unix={now}\nexpires_at_unix={expires}\nnonce=400\n"
            );
            let signature = signing_key.sign(payload.as_bytes());
            let body = format!(
                "{}signature={}\n",
                payload,
                hex_encode(&signature.to_bytes())
            );
            let response = format!("HTTP/1.1 200 OK\r\n\r\n{body}");
            stream.write_all(response.as_bytes()).unwrap();
        });

        let dir = tempfile::tempdir().unwrap();
        let watermark_path = dir.path().join("watermark");
        {
            let mut store = WatermarkStore::new(&watermark_path).unwrap();
            store.advance("trust", 500).unwrap();
        }

        let mut fetcher = StateFetcher::new(url, watermark_path, verifying_key).unwrap();

        match fetcher.fetch_trust() {
            Err(FetchError::WatermarkRejected(_)) => {}
            res => panic!("expected WatermarkRejected, got {res:?}"),
        }
        handle.join().unwrap();
    }

    #[test]
    fn test_fetch_bundle_stale() {
        let (signing_key, verifying_key) = make_test_keypair();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let expires = now - 100;
            let payload = format!(
                "version=1\ngenerated_at_unix={}\nexpires_at_unix={}\nnonce=600\n",
                now - 200,
                expires
            );
            let signature = signing_key.sign(payload.as_bytes());
            let body = format!(
                "{}signature={}\n",
                payload,
                hex_encode(&signature.to_bytes())
            );
            let response = format!("HTTP/1.1 200 OK\r\n\r\n{body}");
            stream.write_all(response.as_bytes()).unwrap();
        });

        let dir = tempfile::tempdir().unwrap();
        let mut fetcher =
            StateFetcher::new(url, dir.path().join("watermark"), verifying_key).unwrap();

        match fetcher.fetch_trust() {
            Err(FetchError::Stale(_)) => {}
            res => panic!("expected Stale, got {res:?}"),
        }
        handle.join().unwrap();
    }

    #[test]
    fn test_fetch_bundle_network_error_is_network_error() {
        let (_signing_key, verifying_key) = make_test_keypair();
        let dir = tempfile::tempdir().unwrap();
        let watermark_path = dir.path().join("watermark");

        // Use a port that is unlikely to be listening (e.g. 1) or just an invalid address?
        // 127.0.0.1:9 is good (discard protocol), or just a random high port.
        // But 127.0.0.1:9 might be blocked or filtered differently.
        // Use a random port that we don't bind.
        let url = "http://127.0.0.1:54321";

        let mut fetcher =
            StateFetcher::new(url.to_string(), watermark_path, verifying_key).unwrap();

        match fetcher.fetch_trust() {
            Err(FetchError::Network(_)) => {}
            res => panic!("expected Network error, got {res:?}"),
        }
    }
}
