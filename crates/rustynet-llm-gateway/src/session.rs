//! Short-lived, single-audience, node-signed session tokens
//! (LLM design §5.3; SecurityMinimumBar §6.E control E4).
//!
//! SPIFFE-style: issued after the tunnel-identity + signed-policy
//! gate passed, bound to one peer, one service, one audience (this
//! host), with a short TTL. The token is **defence-in-depth only**:
//! verification requires the caller to supply the CURRENT signed
//! policy decision for the peer, and a `Deny` kills the token
//! regardless of its remaining TTL. A token is never an identity
//! source and never a substitute for the tunnel.
//!
//! Signing uses the node's existing ed25519 identity primitives —
//! no new crypto, no new PKI; the membership signing root remains
//! the only trust anchor.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rustynet_policy::Decision;
use sha2::{Digest, Sha256};

/// Maximum token lifetime. Issuance clamps to this even if a caller
/// asks for more.
pub const MAX_TOKEN_TTL_SECONDS: u64 = 15 * 60;

const TOKEN_CONTEXT: &str = "rustynet-llm-session-token-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionTokenError {
    /// TTL of zero or a clock that cannot produce a valid window.
    InvalidLifetime,
    /// Canonical payload failed signature verification (tampered or
    /// signed by a different node key).
    SignatureInvalid,
    /// Token expired (or not yet valid — clock skew is not granted).
    OutsideValidity { now_unix: u64 },
    /// Token presented to a different audience (host) than it was
    /// minted for.
    AudienceMismatch,
    /// Token presented by a different peer than it was minted for.
    PeerMismatch,
    /// Current signed policy denies the peer — the token cannot
    /// exceed policy (E4), regardless of TTL.
    PolicyDenied,
    /// Malformed wire form.
    Malformed(&'static str),
}

impl fmt::Display for SessionTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionTokenError::InvalidLifetime => write!(f, "invalid token lifetime"),
            SessionTokenError::SignatureInvalid => write!(f, "token signature invalid"),
            SessionTokenError::OutsideValidity { now_unix } => {
                write!(f, "token outside validity window at {now_unix}")
            }
            SessionTokenError::AudienceMismatch => write!(f, "token audience mismatch"),
            SessionTokenError::PeerMismatch => write!(f, "token peer mismatch"),
            SessionTokenError::PolicyDenied => {
                write!(f, "signed policy denies the peer; token rejected (E4)")
            }
            SessionTokenError::Malformed(field) => write!(f, "token malformed: {field}"),
        }
    }
}

impl std::error::Error for SessionTokenError {}

/// A minted session token. The wire form is the canonical payload
/// plus the signature; the canonical payload is line-oriented
/// `key=value` (same discipline as the membership pre-images — no
/// serde ambiguity in signed material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionToken {
    pub peer_node_id: String,
    pub audience_node_id: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub signature: Signature,
}

fn canonical_payload(
    peer_node_id: &str,
    audience_node_id: &str,
    issued_at_unix: u64,
    expires_at_unix: u64,
) -> String {
    format!(
        "context={TOKEN_CONTEXT}\npeer={peer_node_id}\naudience={audience_node_id}\nissued_at={issued_at_unix}\nexpires_at={expires_at_unix}\n"
    )
}

impl SessionToken {
    /// Short hash thumbprint for audit logs. The token itself is
    /// never logged.
    pub fn thumbprint(&self) -> String {
        let payload = canonical_payload(
            &self.peer_node_id,
            &self.audience_node_id,
            self.issued_at_unix,
            self.expires_at_unix,
        );
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        hasher.update(self.signature.to_bytes());
        let digest = hasher.finalize();
        let mut out = String::with_capacity(16);
        for byte in digest.iter().take(8) {
            use fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

/// Mint a token for a peer that ALREADY passed the tunnel-identity
/// and signed-policy gate (the caller passes that decision in; a
/// `Deny` refuses issuance — a token can never originate access).
pub fn issue_session_token(
    node_signing_key: &SigningKey,
    peer_node_id: &str,
    audience_node_id: &str,
    now_unix: u64,
    requested_ttl_seconds: u64,
    current_policy_decision: Decision,
) -> Result<SessionToken, SessionTokenError> {
    if current_policy_decision != Decision::Allow {
        return Err(SessionTokenError::PolicyDenied);
    }
    if requested_ttl_seconds == 0 {
        return Err(SessionTokenError::InvalidLifetime);
    }
    let ttl = requested_ttl_seconds.min(MAX_TOKEN_TTL_SECONDS);
    let expires_at_unix = now_unix
        .checked_add(ttl)
        .ok_or(SessionTokenError::InvalidLifetime)?;
    let payload = canonical_payload(peer_node_id, audience_node_id, now_unix, expires_at_unix);
    let signature = node_signing_key.sign(payload.as_bytes());
    Ok(SessionToken {
        peer_node_id: peer_node_id.to_owned(),
        audience_node_id: audience_node_id.to_owned(),
        issued_at_unix: now_unix,
        expires_at_unix,
        signature,
    })
}

/// Verify a token on EVERY use. Order: signature first, then
/// validity window, then peer/audience binding, then — always —
/// the CURRENT signed-policy decision. A revoked peer's token dies
/// here before its TTL does (E4).
pub fn verify_session_token(
    node_verifying_key: &VerifyingKey,
    token: &SessionToken,
    presenting_peer_node_id: &str,
    audience_node_id: &str,
    now_unix: u64,
    current_policy_decision: Decision,
) -> Result<(), SessionTokenError> {
    let payload = canonical_payload(
        &token.peer_node_id,
        &token.audience_node_id,
        token.issued_at_unix,
        token.expires_at_unix,
    );
    node_verifying_key
        .verify(payload.as_bytes(), &token.signature)
        .map_err(|_| SessionTokenError::SignatureInvalid)?;
    if now_unix < token.issued_at_unix || now_unix >= token.expires_at_unix {
        return Err(SessionTokenError::OutsideValidity { now_unix });
    }
    if token.audience_node_id != audience_node_id {
        return Err(SessionTokenError::AudienceMismatch);
    }
    if token.peer_node_id != presenting_peer_node_id {
        return Err(SessionTokenError::PeerMismatch);
    }
    if current_policy_decision != Decision::Allow {
        return Err(SessionTokenError::PolicyDenied);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "node:laptop-1";
    const AUDIENCE: &str = "node:llm-box";
    const NOW: u64 = 1_750_000_000;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn issue_valid(now_unix: u64, ttl: u64) -> SessionToken {
        issue_session_token(
            &signing_key(),
            PEER,
            AUDIENCE,
            now_unix,
            ttl,
            Decision::Allow,
        )
        .expect("issuance under Allow must succeed")
    }

    #[test]
    fn issue_then_verify_round_trip() {
        let key = signing_key();
        let token = issue_valid(NOW, 60);
        assert_eq!(token.peer_node_id, PEER);
        assert_eq!(token.audience_node_id, AUDIENCE);
        assert_eq!(token.issued_at_unix, NOW);
        assert_eq!(token.expires_at_unix, NOW + 60);
        verify_session_token(
            &key.verifying_key(),
            &token,
            PEER,
            AUDIENCE,
            NOW + 30,
            Decision::Allow,
        )
        .expect("round-trip verification must succeed");
    }

    #[test]
    fn issuance_refused_under_deny_token_never_originates_access() {
        let err = issue_session_token(&signing_key(), PEER, AUDIENCE, NOW, 60, Decision::Deny)
            .expect_err("Deny must refuse issuance");
        assert_eq!(err, SessionTokenError::PolicyDenied);
    }

    #[test]
    fn tampered_peer_fails_signature() {
        let key = signing_key();
        let mut token = issue_valid(NOW, 60);
        token.peer_node_id = "node:attacker".to_owned();
        let err = verify_session_token(
            &key.verifying_key(),
            &token,
            "node:attacker",
            AUDIENCE,
            NOW + 1,
            Decision::Allow,
        )
        .expect_err("tampered peer must fail");
        assert_eq!(err, SessionTokenError::SignatureInvalid);
    }

    #[test]
    fn tampered_audience_fails_signature() {
        let key = signing_key();
        let mut token = issue_valid(NOW, 60);
        token.audience_node_id = "node:other-host".to_owned();
        let err = verify_session_token(
            &key.verifying_key(),
            &token,
            PEER,
            "node:other-host",
            NOW + 1,
            Decision::Allow,
        )
        .expect_err("tampered audience must fail");
        assert_eq!(err, SessionTokenError::SignatureInvalid);
    }

    #[test]
    fn tampered_expiry_fails_signature() {
        let key = signing_key();
        let mut token = issue_valid(NOW, 60);
        token.expires_at_unix += 3600;
        let err = verify_session_token(
            &key.verifying_key(),
            &token,
            PEER,
            AUDIENCE,
            NOW + 1,
            Decision::Allow,
        )
        .expect_err("tampered expiry must fail");
        assert_eq!(err, SessionTokenError::SignatureInvalid);
    }

    #[test]
    fn expired_token_rejected() {
        let key = signing_key();
        let token = issue_valid(NOW, 60);
        // now == expires_at is already outside the window.
        let err = verify_session_token(
            &key.verifying_key(),
            &token,
            PEER,
            AUDIENCE,
            NOW + 60,
            Decision::Allow,
        )
        .expect_err("expired token must fail");
        assert_eq!(
            err,
            SessionTokenError::OutsideValidity { now_unix: NOW + 60 }
        );
    }

    #[test]
    fn not_yet_valid_token_rejected() {
        let key = signing_key();
        let token = issue_valid(NOW, 60);
        let err = verify_session_token(
            &key.verifying_key(),
            &token,
            PEER,
            AUDIENCE,
            NOW - 1,
            Decision::Allow,
        )
        .expect_err("not-yet-valid token must fail");
        assert_eq!(
            err,
            SessionTokenError::OutsideValidity { now_unix: NOW - 1 }
        );
    }

    #[test]
    fn wrong_audience_rejected() {
        let key = signing_key();
        let token = issue_valid(NOW, 60);
        let err = verify_session_token(
            &key.verifying_key(),
            &token,
            PEER,
            "node:different-host",
            NOW + 1,
            Decision::Allow,
        )
        .expect_err("wrong audience must fail");
        assert_eq!(err, SessionTokenError::AudienceMismatch);
    }

    #[test]
    fn different_presenting_peer_rejected() {
        let key = signing_key();
        let token = issue_valid(NOW, 60);
        let err = verify_session_token(
            &key.verifying_key(),
            &token,
            "node:laptop-2",
            AUDIENCE,
            NOW + 1,
            Decision::Allow,
        )
        .expect_err("different presenting peer must fail");
        assert_eq!(err, SessionTokenError::PeerMismatch);
    }

    /// THE E4 pin: a signature-valid, inside-TTL token is STILL
    /// rejected when the current signed policy says Deny — revocation
    /// kills tokens before their TTL does.
    #[test]
    fn e4_pin_valid_in_ttl_token_dies_under_current_deny() {
        let key = signing_key();
        let token = issue_valid(NOW, MAX_TOKEN_TTL_SECONDS);
        // Prove the token would otherwise pass.
        verify_session_token(
            &key.verifying_key(),
            &token,
            PEER,
            AUDIENCE,
            NOW + 1,
            Decision::Allow,
        )
        .expect("token is otherwise valid");
        // Same token, same instant, policy now Deny.
        let err = verify_session_token(
            &key.verifying_key(),
            &token,
            PEER,
            AUDIENCE,
            NOW + 1,
            Decision::Deny,
        )
        .expect_err("current Deny must kill the token inside its TTL");
        assert_eq!(err, SessionTokenError::PolicyDenied);
    }

    #[test]
    fn requested_ttl_clamped_to_max() {
        let token = issue_valid(NOW, MAX_TOKEN_TTL_SECONDS + 1);
        assert_eq!(token.expires_at_unix, NOW + MAX_TOKEN_TTL_SECONDS);
    }

    #[test]
    fn zero_ttl_refused() {
        let err = issue_session_token(&signing_key(), PEER, AUDIENCE, NOW, 0, Decision::Allow)
            .expect_err("zero TTL must be refused");
        assert_eq!(err, SessionTokenError::InvalidLifetime);
    }

    #[test]
    fn thumbprint_stable_distinct_short_and_no_signature_leak() {
        let token = issue_valid(NOW, 60);
        let other = issue_valid(NOW + 1, 60);

        // Stable for the same token.
        assert_eq!(token.thumbprint(), token.thumbprint());
        // Differs for a different token.
        assert_ne!(token.thumbprint(), other.thumbprint());

        // 16 lowercase hex chars.
        let thumb = token.thumbprint();
        assert_eq!(thumb.len(), 16);
        assert!(thumb.chars().all(|c| c.is_ascii_hexdigit()));

        // Does not contain the signature bytes hex in full.
        let sig_hex: String =
            token
                .signature
                .to_bytes()
                .iter()
                .fold(String::new(), |mut acc, b| {
                    use fmt::Write as _;
                    let _ = write!(acc, "{b:02x}");
                    acc
                });
        assert!(!thumb.contains(&sig_hex));
        // And the thumbprint is not a verbatim slice of the
        // signature hex either.
        assert!(!sig_hex.contains(&thumb));
    }
}
