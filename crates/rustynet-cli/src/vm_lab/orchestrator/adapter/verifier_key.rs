#![allow(dead_code)]
//! Shared verifier-key decoding for the relay-deploy adapter paths.
//!
//! Every per-OS relay adapter (`linux_install`, `macos_install`, and in
//! future `windows_install`) needs to turn the hex-encoded ed25519 assignment
//! authority public key the orchestrator already distributed to a node into the
//! raw 32-byte form the `rustynet-relay --verifier-key` loader requires. The
//! decode is OS-agnostic, so it lives here rather than in any one adapter — a
//! macOS adapter importing it from `linux_install` would be backwards coupling.

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::vm_lab::orchestrator::error::AdapterError;

/// Decode the hex-encoded ed25519 assignment authority public key (as stored in
/// each OS's `trust/assignment.pub`: 64 hex chars, optionally newline-terminated)
/// into the raw 32-byte form the `rustynet-relay --verifier-key` loader
/// requires. Fail-closed: rejects short or non-hex input rather than shipping a
/// malformed trust key. Mirrors the proven bash `head -c 64 | xxd -r -p`, done
/// in Rust so the guest needs no `xxd`.
pub(crate) fn decode_assignment_pubkey_hex(raw: &str) -> Result<Vec<u8>, String> {
    let hex64: Vec<char> = raw.trim().chars().take(64).collect();
    if hex64.len() < 64 {
        return Err(format!(
            "assignment.pub too short to be a 32-byte ed25519 key: {} hex chars (need >= 64)",
            hex64.len()
        ));
    }
    let mut bytes = Vec::with_capacity(32);
    for pair in hex64.chunks(2) {
        let hi = pair[0]
            .to_digit(16)
            .ok_or_else(|| format!("assignment.pub contains a non-hex character: {:?}", pair[0]))?;
        let lo = pair[1]
            .to_digit(16)
            .ok_or_else(|| format!("assignment.pub contains a non-hex character: {:?}", pair[1]))?;
        bytes.push((hi * 16 + lo) as u8);
    }
    Ok(bytes)
}

/// Validate a locally-issued verifier key and return the SHA-256 of the exact
/// bytes copied to the guest. Adapters compare this digest after installation,
/// so an empty, truncated, malformed, or stale active key fails closed.
pub(crate) fn validated_verifier_key_sha256(path: &Path) -> Result<String, AdapterError> {
    let bytes = std::fs::read(path).map_err(|err| AdapterError::Io {
        message: format!("read verifier key '{}': {err}", path.display()),
    })?;
    if bytes.is_empty() {
        return Err(AdapterError::Protocol {
            message: format!("verifier key '{}' is empty", path.display()),
        });
    }
    let text = std::str::from_utf8(&bytes).map_err(|err| AdapterError::Protocol {
        message: format!("verifier key '{}' is not UTF-8: {err}", path.display()),
    })?;
    if text.trim().len() != 64 {
        return Err(AdapterError::Protocol {
            message: format!(
                "verifier key '{}' must contain exactly 64 hex characters",
                path.display()
            ),
        });
    }
    decode_assignment_pubkey_hex(text).map_err(|message| AdapterError::Protocol { message })?;

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn decode_assignment_pubkey_hex_decodes_64_hex_to_32_bytes() {
        let hex = "ff".repeat(32); // 64 hex chars
        let bytes = decode_assignment_pubkey_hex(&hex).expect("valid 64-hex key");
        assert_eq!(bytes.len(), 32);
        assert!(bytes.iter().all(|&b| b == 0xff));
    }

    #[test]
    fn decode_assignment_pubkey_hex_tolerates_trailing_newline() {
        // assignment.pub is newline-terminated on disk.
        let hex = format!("{}\n", "00".repeat(32));
        let bytes = decode_assignment_pubkey_hex(&hex).expect("trailing newline tolerated");
        assert_eq!(bytes, vec![0u8; 32]);
    }

    #[test]
    fn decode_assignment_pubkey_hex_decodes_mixed_case() {
        // Upper + lower hex must both decode (0x0a, 0xb1, then 30 zero bytes).
        let hex = format!("0aB1{}", "00".repeat(30));
        let bytes = decode_assignment_pubkey_hex(&hex).expect("mixed-case hex");
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0x0a);
        assert_eq!(bytes[1], 0xb1);
    }

    #[test]
    fn decode_assignment_pubkey_hex_rejects_short_key_fail_closed() {
        // Fewer than 64 hex chars must fail closed rather than ship a short key.
        let err = decode_assignment_pubkey_hex("deadbeef").expect_err("short key must fail");
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn decode_assignment_pubkey_hex_rejects_non_hex_fail_closed() {
        // 64 chars but not all hex (leading 'z') must fail closed.
        let bad = format!("zz{}", "00".repeat(31)); // 64 chars, leading non-hex
        let err = decode_assignment_pubkey_hex(&bad).expect_err("non-hex must fail");
        assert!(err.contains("non-hex"), "got: {err}");
    }

    #[test]
    fn verifier_key_digest_rejects_missing_empty_and_malformed_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(validated_verifier_key_sha256(&dir.path().join("missing.pub")).is_err());

        let empty = dir.path().join("empty.pub");
        std::fs::write(&empty, []).expect("empty file");
        assert!(validated_verifier_key_sha256(&empty).is_err());

        let malformed = dir.path().join("malformed.pub");
        std::fs::write(&malformed, "z".repeat(64)).expect("malformed file");
        assert!(validated_verifier_key_sha256(&malformed).is_err());
    }

    #[test]
    fn verifier_key_digest_hashes_exact_deployed_bytes() {
        let mut file = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(file, "{}", "ab".repeat(32)).expect("write key");
        let digest = validated_verifier_key_sha256(file.path()).expect("valid key");
        let mut expected = Sha256::new();
        expected.update(format!("{}\n", "ab".repeat(32)).as_bytes());
        assert_eq!(digest, format!("{:x}", expected.finalize()));
    }
}
