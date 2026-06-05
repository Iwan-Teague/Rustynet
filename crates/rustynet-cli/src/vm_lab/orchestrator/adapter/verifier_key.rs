#![allow(dead_code)]
//! Shared verifier-key decoding for the relay-deploy adapter paths.
//!
//! Every per-OS relay adapter (`linux_install`, `macos_install`, and in
//! future `windows_install`) needs to turn the hex-encoded ed25519 assignment
//! authority public key the orchestrator already distributed to a node into the
//! raw 32-byte form the `rustynet-relay --verifier-key` loader requires. The
//! decode is OS-agnostic, so it lives here rather than in any one adapter — a
//! macOS adapter importing it from `linux_install` would be backwards coupling.

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
