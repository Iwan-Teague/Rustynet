#![forbid(unsafe_code)]

//! Control-plane state fetcher with signature verification and watermark anti-replay.
//!
//! This module implements `StateFetcher` for pull-based signed bundle retrieval
//! with strict verification order and fail-closed semantics.

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};

/// Hard cap on the HTTP response body the fetcher will consume.
///
/// A hijacked or malicious `control_endpoint` could otherwise push
/// gigabytes of data to exhaust daemon memory via the unbounded
/// `read_to_end`. Real signed bundles are well under 1 MB
/// (membership snapshots, traversal bundles, trust bundles) — the
/// 4 MB cap leaves generous slack while bounding the worst-case
/// allocation.
pub const MAX_FETCHER_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Parse an HTTP/1.x status line and extract the numeric status code.
/// Returns `InvalidResponse` if the line doesn't follow the
/// `HTTP/<v> <code> <reason>` shape.
fn parse_http_status_code(status_line: &str) -> Result<u16, FetchError> {
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next();
    let code_str = parts.next().ok_or_else(|| {
        FetchError::InvalidResponse("http response missing status code".to_owned())
    })?;
    code_str
        .parse::<u16>()
        .map_err(|e| FetchError::InvalidResponse(format!("malformed HTTP status code: {e}")))
}

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

        self.process_response_bytes(bundle_type, &response_bytes)
    }

    fn process_response_bytes(
        &mut self,
        bundle_type: &str,
        response_bytes: &[u8],
    ) -> Result<SignedBundle, FetchError> {
        // Step 2: Parse response into signed bundle
        let bundle = SignedBundle::parse(response_bytes).map_err(FetchError::InvalidResponse)?;

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
        // **Security**: reject control characters in the URL so a
        // hijacked-or-malicious `control_endpoint` config value
        // cannot inject extra HTTP headers via CR/LF (would be
        // smuggled into `Host: {host}` or `GET {path}`).
        if url.chars().any(|c| c.is_control()) {
            return Err(FetchError::Network(
                "control endpoint URL contains a control character; refusing".to_owned(),
            ));
        }
        if !url.starts_with("http://") {
            return Err(FetchError::Network(
                "only http:// URLs are supported in this minimal fetcher".to_owned(),
            ));
        }
        let without_proto = &url[7..];
        let parts: Vec<&str> = without_proto.splitn(2, '/').collect();
        let host_port = parts
            .first()
            .ok_or_else(|| FetchError::Network("invalid url".to_owned()))?;
        let path = format!("/{}", parts.get(1).unwrap_or(&""));
        let mut host = host_port.to_string();
        let mut port = 80u16;
        if host_port.contains(':') {
            let mut hp = host_port.splitn(2, ':');
            host = hp.next().unwrap_or("").to_owned();
            if let Some(p) = hp.next() {
                port = p
                    .parse::<u16>()
                    .map_err(|_| FetchError::Network("invalid port in url".to_owned()))?;
            }
        }
        let addr = format!("{host}:{port}");

        let socket_addrs = addr
            .to_socket_addrs()
            .map_err(|e| FetchError::Network(format!("resolve failed: {e}")))?;
        let stream = match socket_addrs.into_iter().next() {
            Some(sa) => TcpStream::connect_timeout(&sa, Duration::from_secs(3))
                .map_err(|_| FetchError::Network("network unreachable".to_owned()))?,
            None => {
                return Err(FetchError::Network(
                    "resolve returned no addresses".to_owned(),
                ));
            }
        };

        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        (&stream)
            .write_all(request.as_bytes())
            .map_err(|e| FetchError::Network(format!("write failed: {e}")))?;

        // **Security**: cap the response body at `MAX_FETCHER_BODY_BYTES`.
        // Unbounded `read_to_end` would let a hijacked or malicious
        // control endpoint exhaust daemon memory by pushing GBs.
        // `Read::take(cap + 1)` lets us detect a body that exceeds
        // the cap without ever allocating beyond `cap + 1` bytes.
        let mut buf = Vec::new();
        (&stream)
            .take(MAX_FETCHER_BODY_BYTES as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| FetchError::Network(format!("read failed: {e}")))?;
        if buf.len() > MAX_FETCHER_BODY_BYTES {
            return Err(FetchError::InvalidResponse(format!(
                "response body exceeds {MAX_FETCHER_BODY_BYTES}-byte cap; refusing to consume"
            )));
        }

        // Parse the response shape: status line + headers + body.
        // Validate the status code to a 2xx success before trusting
        // the body — a hijacked endpoint returning 500 + signed
        // garbage would otherwise reach the signature verifier.
        let header_end = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| FetchError::InvalidResponse("malformed http response".to_owned()))?;
        let head_bytes = &buf[..header_end];
        let head = String::from_utf8_lossy(head_bytes);
        let status_line = head.lines().next().unwrap_or("");
        let status_code = parse_http_status_code(status_line)?;
        if !(200..=299).contains(&status_code) {
            return Err(FetchError::Network(format!(
                "control endpoint returned HTTP {status_code}; refusing to trust body"
            )));
        }
        Ok(buf.split_off(header_end + 4))
    }

    fn verify_signature(&self, bundle: &SignedBundle) -> Result<(), String> {
        let signature = Signature::from_bytes(&bundle.signature);
        self.verifying_key
            .verify_strict(bundle.payload.as_bytes(), &signature)
            .map_err(|e| format!("signature verification failed: {e}"))
    }

    fn check_freshness(&self, bundle: &SignedBundle) -> Result<(), String> {
        // System clock before UNIX_EPOCH is fail-closed evidence of a
        // misconfigured / attacker-rolled-back host clock. Refuse to
        // accept any signed bundle in that state rather than panic
        // and crash the daemon (which would tear down enforced
        // routes). Net effect: stale-bundle rejection by another
        // name — same fail-closed posture, no crash.
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| {
                format!(
                    "host clock is before UNIX_EPOCH ({err}); refusing signed bundle freshness check until clock is corrected"
                )
            })?
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
        let text = std::str::from_utf8(bytes).map_err(|_| "bundle is not valid utf8".to_owned())?;

        let sig_marker = "signature=";
        let mut signature_bytes = [0u8; 64];
        let mut found_sig = false;

        let mut issued_at_unix = 0;
        let mut expires_at_unix = 0;
        let mut watermark = 0;

        // Reject malformed integer fields explicitly. The previous
        // `unwrap_or(0)` silently mapped bad input to 0, which:
        //   - was fail-closed for `expires_at_unix` (0 < now_unix
        //     means "expired", caller rejects);
        //   - was fail-closed for `nonce` IF the watermark store
        //     already had a non-zero current watermark (replay
        //     check rejects 0);
        //   - but on a freshly-initialised host with no prior
        //     watermark, a `nonce=garbage` bundle parses as
        //     watermark=0 and the watermark store accepts it (its
        //     check is `new <= current` and current=0 here means
        //     "no prior bundle accepted" — but a malformed nonce
        //     is NOT the same as a nonce of 0). Tightening this
        //     means a malformed bundle is rejected at parse time,
        //     never reaching the verifier or watermark store.
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix(sig_marker) {
                let hex_str = rest.trim();
                let decoded = hex_decode(hex_str)?;
                if decoded.len() != 64 {
                    return Err("invalid signature length".to_owned());
                }
                signature_bytes.copy_from_slice(&decoded);
                found_sig = true;
            } else if let Some(rest) = line.strip_prefix("generated_at_unix=") {
                issued_at_unix = rest
                    .trim()
                    .parse()
                    .map_err(|err| format!("invalid generated_at_unix: {err}"))?;
            } else if let Some(rest) = line.strip_prefix("expires_at_unix=") {
                expires_at_unix = rest
                    .trim()
                    .parse()
                    .map_err(|err| format!("invalid expires_at_unix: {err}"))?;
            } else if let Some(rest) = line.strip_prefix("nonce=") {
                watermark = rest
                    .trim()
                    .parse()
                    .map_err(|err| format!("invalid nonce: {err}"))?;
            }
        }

        if !found_sig {
            return Err("missing signature".to_owned());
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
            .insert(bundle_type.to_owned(), new_watermark);
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
            let key = parts[0].to_owned();
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
                .map_err(|e| format!("failed to set watermark permissions: {e}"))?
        };

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
    if !s.len().is_multiple_of(2) {
        return Err("hex string has odd length".to_owned());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid hex char".to_owned()))
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
            store.advance("traversal", 200).unwrap()
        };

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

    fn signed_bundle_bytes(
        signing_key: &SigningKey,
        generated_at_unix: u64,
        expires_at_unix: u64,
        nonce: u64,
    ) -> Vec<u8> {
        let payload = format!(
            "version=1\ngenerated_at_unix={generated_at_unix}\nexpires_at_unix={expires_at_unix}\nnonce={nonce}\n"
        );
        let signature = signing_key.sign(payload.as_bytes());
        format!(
            "{}signature={}\n",
            payload,
            hex_encode(&signature.to_bytes())
        )
        .into_bytes()
    }

    #[test]
    fn test_signed_bundle_parse_rejects_malformed_generated_at_unix() {
        // Adversarial input: a bundle whose generated_at_unix isn't
        // parseable. Previously SignedBundle::parse used
        // `unwrap_or(0)` which silently accepted malformed input.
        // After the tightening, parse rejects with a precise reason.
        let body =
            b"version=1\ngenerated_at_unix=garbage\nexpires_at_unix=10\nnonce=1\nsignature=00\n";
        let err = super::SignedBundle::parse(body).expect_err("malformed integer must reject");
        assert!(
            err.contains("invalid generated_at_unix"),
            "rejection must cite the field: {err}"
        );
    }

    #[test]
    fn test_signed_bundle_parse_rejects_malformed_expires_at_unix() {
        let body = b"version=1\ngenerated_at_unix=1\nexpires_at_unix=not-a-number\nnonce=1\nsignature=00\n";
        let err = super::SignedBundle::parse(body).expect_err("malformed integer must reject");
        assert!(
            err.contains("invalid expires_at_unix"),
            "rejection must cite the field: {err}"
        );
    }

    #[test]
    fn test_signed_bundle_parse_rejects_malformed_nonce() {
        // Most security-relevant of the three: a bundle with
        // `nonce=garbage` previously parsed as watermark=0, which on
        // a fresh watermark store (no prior bundle) would pass the
        // replay check (`new <= current` with current=0). Tightening
        // the parse rejects garbage at the bundle layer so the
        // watermark store never sees it.
        let body =
            b"version=1\ngenerated_at_unix=1\nexpires_at_unix=10\nnonce=garbage\nsignature=00\n";
        let err = super::SignedBundle::parse(body).expect_err("malformed nonce must reject");
        assert!(
            err.contains("invalid nonce"),
            "rejection must cite the field: {err}"
        );
    }

    #[test]
    fn test_signed_bundle_parse_rejects_overflow_nonce() {
        // u64 max is 18446744073709551615; appending a digit
        // overflows the parse.
        let body = b"version=1\ngenerated_at_unix=1\nexpires_at_unix=10\nnonce=184467440737095516159\nsignature=00\n";
        let err = super::SignedBundle::parse(body).expect_err("overflow nonce must reject");
        assert!(err.contains("invalid nonce"), "unexpected error: {err}");
    }

    #[test]
    fn test_signed_bundle_parse_rejects_negative_generated_at_unix() {
        // unsigned integer parser rejects '-1'.
        let body = b"version=1\ngenerated_at_unix=-1\nexpires_at_unix=10\nnonce=1\nsignature=00\n";
        let err =
            super::SignedBundle::parse(body).expect_err("negative generated_at_unix must reject");
        assert!(
            err.contains("invalid generated_at_unix"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_signed_bundle_parse_rejects_empty_input() {
        let err = super::SignedBundle::parse(b"").expect_err("empty input must reject");
        // Empty body has no signature= line — falls into the
        // `missing signature` rejection arm, which is the same
        // failure-shape an attacker would get with any signature-
        // less payload.
        assert!(err.contains("missing signature"), "unexpected error: {err}");
    }

    #[test]
    fn test_signed_bundle_parse_rejects_non_utf8_input() {
        let body: &[u8] = &[0xff, 0xfe, 0xfd, 0xfc];
        let err = super::SignedBundle::parse(body).expect_err("non-utf8 input must reject");
        assert!(err.contains("not valid utf8"), "unexpected error: {err}");
    }

    #[test]
    fn test_signed_bundle_parse_rejects_signature_with_odd_hex_length() {
        // hex_decode rejects odd-length hex strings. Even though the
        // length check on the decoded bytes (== 64) would also
        // reject this, catching the parse error earlier means we
        // never allocate the (possibly huge) buffer for the decode.
        let body = b"version=1\ngenerated_at_unix=1\nexpires_at_unix=10\nnonce=1\nsignature=abc\n";
        let err = super::SignedBundle::parse(body).expect_err("odd-length hex must reject");
        assert!(err.contains("odd length"), "unexpected error: {err}");
    }

    #[test]
    fn test_signed_bundle_parse_rejects_signature_short_decoded() {
        // Even-length hex but decodes to fewer than 64 bytes.
        let body = b"version=1\ngenerated_at_unix=1\nexpires_at_unix=10\nnonce=1\nsignature=abcd\n";
        let err = super::SignedBundle::parse(body).expect_err("short signature must reject");
        assert!(
            err.contains("invalid signature length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_signed_bundle_parse_rejects_signature_invalid_hex_char() {
        let body = b"version=1\ngenerated_at_unix=1\nexpires_at_unix=10\nnonce=1\nsignature=ZZZZ\n";
        let err = super::SignedBundle::parse(body).expect_err("invalid hex char must reject");
        assert!(err.contains("invalid hex char"), "unexpected error: {err}");
    }

    #[test]
    fn test_fetch_bundle_signature_invalid() {
        let (_signing_key, verifying_key) = make_test_keypair();
        let wrong_key = SigningKey::from_bytes(&[2u8; 32]);
        let dir = tempfile::tempdir().unwrap();
        let mut fetcher = StateFetcher::new(
            "http://unit.test".to_owned(),
            dir.path().join("watermark"),
            verifying_key,
        )
        .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = signed_bundle_bytes(&wrong_key, now, now + 300, 100);

        match fetcher.process_response_bytes("trust", &body) {
            Err(FetchError::SignatureInvalid(_)) => {}
            res => panic!("expected SignatureInvalid, got {res:?}"),
        }
    }

    #[test]
    fn test_fetch_bundle_watermark_replay() {
        let (signing_key, verifying_key) = make_test_keypair();
        let dir = tempfile::tempdir().unwrap();
        let watermark_path = dir.path().join("watermark");
        {
            let mut store = WatermarkStore::new(&watermark_path).unwrap();
            store.advance("trust", 500).unwrap()
        };

        let mut fetcher =
            StateFetcher::new("http://unit.test".to_owned(), watermark_path, verifying_key)
                .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = signed_bundle_bytes(&signing_key, now, now + 300, 400);

        match fetcher.process_response_bytes("trust", &body) {
            Err(FetchError::WatermarkRejected(_)) => {}
            res => panic!("expected WatermarkRejected, got {res:?}"),
        }
    }

    #[test]
    fn test_fetch_bundle_stale() {
        let (signing_key, verifying_key) = make_test_keypair();
        let dir = tempfile::tempdir().unwrap();
        let mut fetcher = StateFetcher::new(
            "http://unit.test".to_owned(),
            dir.path().join("watermark"),
            verifying_key,
        )
        .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = signed_bundle_bytes(&signing_key, now - 200, now - 100, 600);

        match fetcher.process_response_bytes("trust", &body) {
            Err(FetchError::Stale(_)) => {}
            res => panic!("expected Stale, got {res:?}"),
        }
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

        let mut fetcher = StateFetcher::new(url.to_owned(), watermark_path, verifying_key).unwrap();

        match fetcher.fetch_trust() {
            Err(FetchError::Network(_)) => {}
            res => panic!("expected Network error, got {res:?}"),
        }
    }
}
