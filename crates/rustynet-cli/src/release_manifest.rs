//! Signed multi-artifact release manifest — the trust root for the installer's
//! `verified-download` acquisition path (SR-017: pinned, digest+signature
//! verified before execution).
//!
//! This is the aggregate form of the existing per-artifact provenance document
//! (`artifacts/release/rustynetd.provenance.json`): one manifest lists every
//! shipping binary × target-triple with its sha256, signed once with the release
//! Ed25519 key. The installer **pins the verifier public key** and refuses any
//! binary whose sha256 is not listed under a valid signature.
//!
//! Signing (CI side) reuses `rustynet_crypto::Ed25519SigningProvider`. Verifying
//! (installer side, public key only) uses `ed25519_dalek::VerifyingKey::verify_strict`
//! — the same RFC-8032-strict / ZIP-215 anti-malleability check the crypto crate
//! performs internally, so a valid signature cannot be mauled into a distinct
//! accepted encoding.

use ed25519_dalek::{Signature, VerifyingKey};
use rustynet_crypto::{Ed25519SigningProvider, SigningProvider, SigningProviderKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Bump only on an incompatible manifest schema change. Verification rejects any
/// other value (fail-closed): an installer must never trust a manifest whose
/// shape it does not understand.
pub const RELEASE_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Domain-separation prefix mixed into the signed payload so a release-manifest
/// signature can never be replayed as any other Rustynet Ed25519 attestation.
const MANIFEST_DOMAIN: &str = "rustynet-release-manifest-v1";

/// One published binary: `<name>` for target `<target>`, delivered as `<filename>`,
/// with its content `sha256` (lowercase hex) and size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestArtifact {
    pub name: String,
    pub target: String,
    pub filename: String,
    pub sha256: String,
    pub size_bytes: u64,
}

/// The signed release manifest published alongside the binaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub release_track: String,
    pub generated_at_unix: u64,
    pub signer_key_id: String,
    pub verifier_key_hex: String,
    pub artifacts: Vec<ManifestArtifact>,
    pub signature_hex: String,
}

/// Typed, fail-closed verification outcomes. Every non-`Ok` path means "do not
/// trust this artifact"; callers must treat any error as install-abort.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    SchemaMismatch { found: u32, expected: u32 },
    PinnedKeyMismatch,
    MalformedVerifierKey,
    MalformedSignature,
    SignatureInvalid,
    UnknownArtifact { name: String, target: String },
    DigestMismatch { name: String, target: String },
    SizeMismatch { name: String, target: String },
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SchemaMismatch { found, expected } => write!(
                f,
                "release manifest schema_version {found} is not the supported {expected}"
            ),
            Self::PinnedKeyMismatch => write!(
                f,
                "release manifest verifier key does not match the installer's pinned key"
            ),
            Self::MalformedVerifierKey => write!(f, "release manifest verifier key is malformed"),
            Self::MalformedSignature => write!(f, "release manifest signature is malformed"),
            Self::SignatureInvalid => write!(f, "release manifest signature failed verification"),
            Self::UnknownArtifact { name, target } => {
                write!(f, "no manifest entry for artifact {name} ({target})")
            }
            Self::DigestMismatch { name, target } => {
                write!(f, "sha256 mismatch for artifact {name} ({target})")
            }
            Self::SizeMismatch { name, target } => {
                write!(f, "size mismatch for artifact {name} ({target})")
            }
        }
    }
}

impl std::error::Error for ManifestError {}

/// Lowercase-hex sha256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&Sha256::digest(bytes))
}

/// CI side: build and sign a manifest over `artifacts` with the release `seed`.
/// The stored artifact order is normalized (sorted) so the serialized manifest is
/// deterministic; verification re-sorts, so it is robust to any later reordering.
pub fn build_signed_manifest(
    release_track: &str,
    generated_at_unix: u64,
    key_id: &str,
    seed: [u8; 32],
    mut artifacts: Vec<ManifestArtifact>,
) -> ReleaseManifest {
    sort_artifacts(&mut artifacts);
    let provider =
        Ed25519SigningProvider::from_seed(SigningProviderKind::LocalEncryptedFile, key_id, seed);
    let verifier_key_hex = provider.verifying_key_hex();
    let payload = canonical_payload(
        release_track,
        generated_at_unix,
        key_id,
        &verifier_key_hex,
        &artifacts,
    );
    // sign_attestation is infallible for the Ed25519 provider; fall back to an
    // empty signature only in the theoretically-impossible error case, which then
    // fails closed at verification time.
    let signature_hex = provider
        .sign_attestation(&payload)
        .map(|sig| to_hex(&sig))
        .unwrap_or_default();
    ReleaseManifest {
        schema_version: RELEASE_MANIFEST_SCHEMA_VERSION,
        release_track: release_track.to_owned(),
        generated_at_unix,
        signer_key_id: key_id.to_owned(),
        verifier_key_hex,
        artifacts,
        signature_hex,
    }
}

impl ReleaseManifest {
    /// The exact bytes covered by the signature: a domain-separated, deterministic
    /// (sorted-artifact) rendering of every field EXCEPT `signature_hex`. Any
    /// tamper — a changed sha256, an added/removed artifact, a swapped verifier
    /// key — changes these bytes and invalidates the signature.
    fn canonical_payload_bytes(&self) -> Vec<u8> {
        let mut artifacts = self.artifacts.clone();
        sort_artifacts(&mut artifacts);
        canonical_payload(
            &self.release_track,
            self.generated_at_unix,
            &self.signer_key_id,
            &self.verifier_key_hex,
            &artifacts,
        )
    }

    /// Installer side: verify the manifest is (1) a schema we understand,
    /// (2) signed by the operator's **pinned** verifier key, and (3) carries a
    /// valid strict-Ed25519 signature over its canonical payload. Fail-closed on
    /// every deviation. Call this BEFORE trusting any artifact digest (§10.5).
    pub fn verify_signed_with_pinned_key(
        &self,
        pinned_verifier_key_hex: &str,
    ) -> Result<(), ManifestError> {
        if self.schema_version != RELEASE_MANIFEST_SCHEMA_VERSION {
            return Err(ManifestError::SchemaMismatch {
                found: self.schema_version,
                expected: RELEASE_MANIFEST_SCHEMA_VERSION,
            });
        }
        // The manifest must claim exactly the key the installer trusts. Comparing
        // here (not just verifying against the embedded key) is what makes the
        // pin load-bearing: a manifest signed by any other key is rejected before
        // signature math.
        if !constant_time_eq(
            self.verifier_key_hex.as_bytes(),
            pinned_verifier_key_hex.as_bytes(),
        ) {
            return Err(ManifestError::PinnedKeyMismatch);
        }
        let key_bytes: [u8; 32] = from_hex(pinned_verifier_key_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(ManifestError::MalformedVerifierKey)?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| ManifestError::MalformedVerifierKey)?;
        let sig_bytes: [u8; 64] = from_hex(&self.signature_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(ManifestError::MalformedSignature)?;
        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify_strict(&self.canonical_payload_bytes(), &signature)
            .map_err(|_| ManifestError::SignatureInvalid)
    }

    /// Installer side: confirm a downloaded artifact's bytes match the manifest
    /// entry for `(name, target)` by sha256 AND size. MUST be called only after
    /// `verify_signed_with_pinned_key` has succeeded — otherwise the sha256 being
    /// compared against is untrusted.
    pub fn verify_artifact(
        &self,
        name: &str,
        target: &str,
        bytes: &[u8],
    ) -> Result<&ManifestArtifact, ManifestError> {
        let entry = self
            .artifacts
            .iter()
            .find(|a| a.name == name && a.target == target)
            .ok_or_else(|| ManifestError::UnknownArtifact {
                name: name.to_owned(),
                target: target.to_owned(),
            })?;
        if entry.size_bytes != bytes.len() as u64 {
            return Err(ManifestError::SizeMismatch {
                name: name.to_owned(),
                target: target.to_owned(),
            });
        }
        let actual = sha256_hex(bytes);
        if !constant_time_eq(actual.as_bytes(), entry.sha256.as_bytes()) {
            return Err(ManifestError::DigestMismatch {
                name: name.to_owned(),
                target: target.to_owned(),
            });
        }
        Ok(entry)
    }
}

fn sort_artifacts(artifacts: &mut [ManifestArtifact]) {
    artifacts.sort_by(|a, b| (a.name.as_str(), a.target.as_str()).cmp(&(&b.name, &b.target)));
}

fn canonical_payload(
    release_track: &str,
    generated_at_unix: u64,
    signer_key_id: &str,
    verifier_key_hex: &str,
    artifacts: &[ManifestArtifact],
) -> Vec<u8> {
    let mut s = String::new();
    s.push_str(MANIFEST_DOMAIN);
    s.push('\n');
    s.push_str(&format!(
        "schema_version={RELEASE_MANIFEST_SCHEMA_VERSION}\n"
    ));
    s.push_str(&format!("release_track={release_track}\n"));
    s.push_str(&format!("generated_at_unix={generated_at_unix}\n"));
    s.push_str(&format!("signer_key_id={signer_key_id}\n"));
    s.push_str(&format!("verifier_key_hex={verifier_key_hex}\n"));
    for a in artifacts {
        // Tab-delimited fixed field order. Names/targets/filenames come from the
        // build matrix (not untrusted input); tabs/newlines are not part of any
        // valid target-triple or artifact name.
        s.push_str(&format!(
            "artifact\t{}\t{}\t{}\t{}\t{}\n",
            a.name, a.target, a.filename, a.sha256, a.size_bytes
        ));
    }
    s.into_bytes()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn from_hex(value: &str) -> Result<Vec<u8>, ()> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || (bytes.len() & 1) != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).ok_or(())?;
        let lo = (pair[1] as char).to_digit(16).ok_or(())?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

/// Length-independent-leak constant-time-ish byte compare (the inputs here are
/// public hex, so this is defense-in-depth against digest/key-compare timing).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_seed() -> [u8; 32] {
        // Fixed non-zero seed for deterministic tests.
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        seed
    }

    fn verifier_hex_for(seed: [u8; 32]) -> String {
        to_hex(SigningKey::from_bytes(&seed).verifying_key().as_bytes())
    }

    fn sample_artifacts() -> Vec<ManifestArtifact> {
        vec![
            ManifestArtifact {
                name: "rustynetd".into(),
                target: "x86_64-unknown-linux-gnu".into(),
                filename: "rustynetd-x86_64-unknown-linux-gnu".into(),
                sha256: sha256_hex(b"rustynetd-linux-bytes"),
                size_bytes: b"rustynetd-linux-bytes".len() as u64,
            },
            ManifestArtifact {
                name: "rustynet".into(),
                target: "aarch64-apple-darwin".into(),
                filename: "rustynet-aarch64-apple-darwin".into(),
                sha256: sha256_hex(b"rustynet-macos-bytes"),
                size_bytes: b"rustynet-macos-bytes".len() as u64,
            },
        ]
    }

    fn signed() -> ReleaseManifest {
        build_signed_manifest(
            "beta",
            1_700_000_000,
            "ed25519:test",
            test_seed(),
            sample_artifacts(),
        )
    }

    #[test]
    fn sign_then_verify_with_pinned_key_succeeds() {
        let m = signed();
        m.verify_signed_with_pinned_key(&verifier_hex_for(test_seed()))
            .expect("freshly signed manifest verifies under its pinned key");
    }

    #[test]
    fn verify_artifact_matches_known_bytes() {
        let m = signed();
        m.verify_signed_with_pinned_key(&verifier_hex_for(test_seed()))
            .unwrap();
        m.verify_artifact(
            "rustynetd",
            "x86_64-unknown-linux-gnu",
            b"rustynetd-linux-bytes",
        )
        .expect("matching bytes verify");
    }

    #[test]
    fn verify_artifact_rejects_tampered_bytes() {
        let m = signed();
        let err = m
            .verify_artifact(
                "rustynetd",
                "x86_64-unknown-linux-gnu",
                b"rustynetd-linux-bytes-TAMPERED",
            )
            .expect_err("tampered bytes must fail closed");
        // Size differs here, so SizeMismatch fires first; both are fail-closed.
        assert!(matches!(
            err,
            ManifestError::SizeMismatch { .. } | ManifestError::DigestMismatch { .. }
        ));
    }

    #[test]
    fn verify_artifact_rejects_same_length_different_content() {
        let m = signed();
        // 21-byte payloads: same length as "rustynetd-linux-bytes", different content.
        let entry_len = b"rustynetd-linux-bytes".len();
        let forged = vec![b'x'; entry_len];
        let err = m
            .verify_artifact("rustynetd", "x86_64-unknown-linux-gnu", &forged)
            .expect_err("same-length different-content must fail on digest");
        assert!(matches!(err, ManifestError::DigestMismatch { .. }), "{err}");
    }

    #[test]
    fn verify_artifact_rejects_unknown_name_or_target() {
        let m = signed();
        assert!(matches!(
            m.verify_artifact("rustynet-relay", "x86_64-unknown-linux-gnu", b"x"),
            Err(ManifestError::UnknownArtifact { .. })
        ));
        assert!(matches!(
            m.verify_artifact("rustynetd", "riscv64-unknown-linux-gnu", b"x"),
            Err(ManifestError::UnknownArtifact { .. })
        ));
    }

    #[test]
    fn verify_rejects_wrong_pinned_key() {
        let m = signed();
        let mut other_seed = test_seed();
        other_seed[0] ^= 0xff;
        let err = m
            .verify_signed_with_pinned_key(&verifier_hex_for(other_seed))
            .expect_err("a different pinned key must be rejected");
        assert_eq!(err, ManifestError::PinnedKeyMismatch);
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let mut m = signed();
        // Flip the last signature nibble.
        let mut chars: Vec<char> = m.signature_hex.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        m.signature_hex = chars.into_iter().collect();
        let err = m
            .verify_signed_with_pinned_key(&verifier_hex_for(test_seed()))
            .expect_err("tampered signature must fail");
        assert_eq!(err, ManifestError::SignatureInvalid);
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let mut m = signed();
        // Change an artifact digest after signing: canonical payload changes,
        // signature no longer matches. (verifier key unchanged, so we reach sig math.)
        m.artifacts[0].sha256 = sha256_hex(b"a-different-artifact");
        let err = m
            .verify_signed_with_pinned_key(&verifier_hex_for(test_seed()))
            .expect_err("mutated artifact list must invalidate the signature");
        assert_eq!(err, ManifestError::SignatureInvalid);
    }

    #[test]
    fn verify_rejects_unknown_schema() {
        let mut m = signed();
        m.schema_version = 999;
        assert!(matches!(
            m.verify_signed_with_pinned_key(&verifier_hex_for(test_seed())),
            Err(ManifestError::SchemaMismatch { .. })
        ));
    }

    #[test]
    fn signature_is_order_independent() {
        let mut m = signed();
        m.artifacts.reverse();
        // canonical_payload re-sorts, so reordering the stored vec must NOT break
        // verification (defends against JSON round-trips reordering the array).
        m.verify_signed_with_pinned_key(&verifier_hex_for(test_seed()))
            .expect("artifact reorder must not invalidate the signature");
    }

    #[test]
    fn manifest_round_trips_through_json() {
        let m = signed();
        let json = serde_json::to_string(&m).unwrap();
        let back: ReleaseManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
        back.verify_signed_with_pinned_key(&verifier_hex_for(test_seed()))
            .expect("round-tripped manifest still verifies");
    }
}
