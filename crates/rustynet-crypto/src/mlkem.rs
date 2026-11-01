//! ML-KEM-768 (FIPS 203) key encapsulation and tunnel PSK derivation.
//!
//! AQ-35 step S6 of `charter/design/rustynet-d3-seams-plan-v0.4.md`:
//!
//! * plan section 4.5 defines the normative PSK derivation
//!   (HKDF-SHA256, asserted byte-for-byte against the plan's golden vector
//!   in the tests below);
//! * plan section 4.7 requires zeroization of every ML-KEM secret: the
//!   `zeroize` feature is enabled on `ml-kem`, so decapsulation keys
//!   zeroize on drop; the transient shared-key array `ml-kem` returns is
//!   wiped explicitly after it is copied (its type has no zeroizing
//!   `Drop`); the raw shared secret is held as [`MlKemSharedSecret`] and
//!   the derived PSK as `zeroize::Zeroizing`, the bytes the S5
//!   `PresharedKey` custody wrapper in `rustynet-backend-api` consumes;
//! * the raw ML-KEM shared secret is NOT a tunnel PSK. It has its own
//!   type, [`MlKemSharedSecret`], with no `Debug`, no `Clone` and no byte
//!   accessor outside this crate, and [`derive_tunnel_psk`] is the only way to
//!   turn it into a PSK, so a caller cannot skip the network and node-pair
//!   binding of plan section 4.5;
//! * plan section 6 pins `ml-kem` to exactly 0.3.2: pure Rust, no C build
//!   step (owner rule OI-22: no C crypto).
//!
//! # Implicit rejection
//!
//! ML-KEM never fails decapsulation: a malformed or substituted ciphertext
//! decapsulates to a deterministic *rejection* secret that does not match
//! the encapsulator's shared secret. This module preserves that property —
//! [`MlKem768DecapsulationKey::decapsulate`] only errors on a ciphertext of
//! the wrong length and never panics on substituted bytes (tested below).

use std::fmt;

use hkdf::Hkdf;
use ml_kem::{Ciphertext, Decapsulate, Encapsulate, Kem, KeyExport, MlKem768};
use rand_core::CryptoRng;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// Length in bytes of an ML-KEM-768 seed (`d || z`).
pub const ML_KEM_768_SEED_LEN: usize = 64;
/// Length in bytes of an ML-KEM-768 encapsulation (public) key.
pub const ML_KEM_768_ENCAPSULATION_KEY_LEN: usize = 1184;
/// Length in bytes of an ML-KEM-768 ciphertext.
pub const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;
/// Length in bytes of an ML-KEM-768 shared secret.
pub const ML_KEM_768_SHARED_SECRET_LEN: usize = 32;
/// Length in bytes of a tunnel preshared key (the backend PSK slot).
pub const TUNNEL_PSK_LEN: usize = 32;

/// The only PSK derivation format version this module understands
/// (plan section 4.5). It is also the trailing info byte.
pub const TUNNEL_PSK_DERIVATION_VERSION: u16 = 1;

/// Domain-separation prefix of the PSK `info` string (plan section 4.5).
const TUNNEL_PSK_INFO_PREFIX: &[u8] = b"rustynet-tunnel-psk-v1";
/// Trailing literal version byte of the PSK `info` string (plan section 4.5).
const TUNNEL_PSK_INFO_VERSION_BYTE: u8 = 0x01;

/// Errors produced by this module.
///
/// No variant carries secret material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlKemError {
    /// Seed handed to [`MlKem768DecapsulationKey::from_seed`] did not have
    /// exactly [`ML_KEM_768_SEED_LEN`] bytes.
    InvalidSeedLength {
        /// Required length.
        expected: usize,
        /// Observed length.
        got: usize,
    },
    /// Encapsulation key bytes did not have exactly
    /// [`ML_KEM_768_ENCAPSULATION_KEY_LEN`] bytes.
    InvalidEncapsulationKeyLength {
        /// Required length.
        expected: usize,
        /// Observed length.
        got: usize,
    },
    /// Ciphertext bytes did not have exactly [`ML_KEM_768_CIPHERTEXT_LEN`]
    /// bytes.
    InvalidCiphertextLength {
        /// Required length.
        expected: usize,
        /// Observed length.
        got: usize,
    },
    /// The encapsulation key bytes were rejected by ML-KEM's validation.
    EncapsulationKeyRejected,
    /// The network id handed to [`derive_tunnel_psk`] was empty.
    EmptyNetworkId,
    /// A node id handed to [`derive_tunnel_psk`] was empty.
    EmptyNodeId,
    /// A node id was longer than `u16::MAX` bytes and therefore cannot be
    /// length-prefixed in the derivation input.
    NodeIdTooLong {
        /// Maximum accepted length.
        max: usize,
        /// Observed length.
        got: usize,
    },
    /// [`derive_tunnel_psk`] was called with a version other than
    /// [`TUNNEL_PSK_DERIVATION_VERSION`].
    UnsupportedPskDerivationVersion {
        /// The refused version.
        got: u16,
    },
    /// HKDF refused to expand to the requested length. Unreachable for a
    /// [`TUNNEL_PSK_LEN`]-byte output; carried so the caller always gets a
    /// `Result`.
    PskExpansionFailed,
}

impl fmt::Display for MlKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSeedLength { expected, got } => {
                write!(f, "ML-KEM seed must be {expected} bytes, got {got}")
            }
            Self::InvalidEncapsulationKeyLength { expected, got } => write!(
                f,
                "ML-KEM encapsulation key must be {expected} bytes, got {got}"
            ),
            Self::InvalidCiphertextLength { expected, got } => {
                write!(f, "ML-KEM ciphertext must be {expected} bytes, got {got}")
            }
            Self::EncapsulationKeyRejected => {
                write!(f, "ML-KEM encapsulation key failed validation")
            }
            Self::EmptyNetworkId => write!(f, "network id must not be empty"),
            Self::EmptyNodeId => write!(f, "node id must not be empty"),
            Self::NodeIdTooLong { max, got } => {
                write!(f, "node id must be at most {max} bytes, got {got}")
            }
            Self::UnsupportedPskDerivationVersion { got } => {
                write!(f, "unsupported tunnel PSK derivation version {got}")
            }
            Self::PskExpansionFailed => write!(f, "HKDF-Expand refused the PSK length"),
        }
    }
}

impl std::error::Error for MlKemError {}

/// ML-KEM-768 public encapsulation key. Safe to transmit and to log.
#[derive(Clone, PartialEq, Eq)]
pub struct MlKem768EncapsulationKey(ml_kem::EncapsulationKey768);

impl MlKem768EncapsulationKey {
    /// Parses a 1184-byte encapsulation key, validating it.
    ///
    /// # Errors
    /// [`MlKemError::InvalidEncapsulationKeyLength`] on the wrong length,
    /// [`MlKemError::EncapsulationKeyRejected`] if ML-KEM rejects the bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlKemError> {
        let encoded =
            <ml_kem::Key<ml_kem::EncapsulationKey768>>::try_from(bytes).map_err(|_| {
                MlKemError::InvalidEncapsulationKeyLength {
                    expected: ML_KEM_768_ENCAPSULATION_KEY_LEN,
                    got: bytes.len(),
                }
            })?;
        let inner = ml_kem::EncapsulationKey768::new(&encoded)
            .map_err(|_| MlKemError::EncapsulationKeyRejected)?;
        Ok(Self(inner))
    }

    /// Serializes the key to its 1184-byte encoding.
    pub fn as_bytes(&self) -> [u8; ML_KEM_768_ENCAPSULATION_KEY_LEN] {
        let mut out = [0u8; ML_KEM_768_ENCAPSULATION_KEY_LEN];
        for (dst, src) in out.iter_mut().zip(self.0.to_bytes().as_slice()) {
            *dst = *src;
        }
        out
    }

    /// Encapsulates a fresh shared secret to this key.
    ///
    /// Returns the ciphertext to transmit together with the raw shared
    /// secret, zeroized on drop. The secret equals what the holder of the
    /// matching decapsulation key derives, unless the ciphertext is modified
    /// in transit (then the decapsulator's implicit rejection takes over and
    /// the handshake fails closed). The secret is not a PSK: pass it to
    /// [`derive_tunnel_psk`].
    pub fn encapsulate<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> (MlKem768Ciphertext, MlKemSharedSecret) {
        let (ciphertext, shared_key) = self.0.encapsulate_with_rng(rng);
        (
            MlKem768Ciphertext::from_array(&ciphertext),
            take_shared_secret(shared_key),
        )
    }
}

/// ML-KEM-768 ciphertext produced by encapsulation.
///
/// Public (transmitted) data, so `Debug` is allowed. The inner vector always
/// holds exactly [`ML_KEM_768_CIPHERTEXT_LEN`] bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKem768Ciphertext(Vec<u8>);

impl MlKem768Ciphertext {
    /// Adopts ciphertext bytes of exactly [`ML_KEM_768_CIPHERTEXT_LEN`].
    ///
    /// # Errors
    /// [`MlKemError::InvalidCiphertextLength`] on any other length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MlKemError> {
        if bytes.len() != ML_KEM_768_CIPHERTEXT_LEN {
            return Err(MlKemError::InvalidCiphertextLength {
                expected: ML_KEM_768_CIPHERTEXT_LEN,
                got: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// The 1088-byte ciphertext encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn from_array(ciphertext: &Ciphertext<MlKem768>) -> Self {
        Self(ciphertext.as_slice().to_vec())
    }

    fn as_array(&self) -> Result<Ciphertext<MlKem768>, MlKemError> {
        Ciphertext::<MlKem768>::try_from(self.0.as_slice()).map_err(|_| {
            MlKemError::InvalidCiphertextLength {
                expected: ML_KEM_768_CIPHERTEXT_LEN,
                got: self.0.len(),
            }
        })
    }
}

/// The raw 32-byte ML-KEM-768 shared secret from [`MlKem768EncapsulationKey::encapsulate`]
/// or [`MlKem768DecapsulationKey::decapsulate`].
///
/// This is NOT a tunnel preshared key. Plan section 4.5 binds the PSK to
/// the network and the node pair through HKDF, and [`derive_tunnel_psk`] is the
/// only way to turn this secret into one. The type has no `Debug`, no
/// `Clone` and no byte accessor outside this crate, so the raw secret cannot
/// be handed to a tunnel by mistake. The bytes are zeroized on drop.
pub struct MlKemSharedSecret(Zeroizing<[u8; ML_KEM_768_SHARED_SECRET_LEN]>);

impl MlKemSharedSecret {
    /// The raw bytes, for this crate only (the HKDF input of
    /// [`derive_tunnel_psk`] and this crate's known-answer tests).
    pub(crate) fn expose(&self) -> &[u8; ML_KEM_768_SHARED_SECRET_LEN] {
        &self.0
    }

    /// Wraps fixed bytes: the plan's golden vector and the FIPS 203
    /// known-answer tests need a secret with known contents.
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; ML_KEM_768_SHARED_SECRET_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// ML-KEM-768 decapsulation (secret) key.
///
/// The underlying key zeroizes on drop (`ml-kem`'s `zeroize` feature, plan
/// section 4.7). This wrapper deliberately does **not** implement `Debug`:
/// the underlying type's derived `Debug` would print the 64-byte seed.
pub struct MlKem768DecapsulationKey(ml_kem::DecapsulationKey768);

impl MlKem768DecapsulationKey {
    /// Rebuilds a decapsulation key from its 64-byte seed (`d || z`).
    ///
    /// # Errors
    /// [`MlKemError::InvalidSeedLength`] on any other length.
    pub fn from_seed(seed: &[u8]) -> Result<Self, MlKemError> {
        let seed = ml_kem::Seed::try_from(seed).map_err(|_| MlKemError::InvalidSeedLength {
            expected: ML_KEM_768_SEED_LEN,
            got: seed.len(),
        })?;
        Ok(Self(ml_kem::DecapsulationKey768::from_seed(seed)))
    }

    /// The matching public encapsulation key.
    pub fn encapsulation_key(&self) -> MlKem768EncapsulationKey {
        MlKem768EncapsulationKey(self.0.encapsulation_key().clone())
    }

    /// Decapsulates a ciphertext into the raw shared secret (not a PSK: pass
    /// it to [`derive_tunnel_psk`]).
    ///
    /// Never panics on malformed *content*: a well-formed-length ciphertext
    /// that was substituted or corrupted decapsulates (via ML-KEM's implicit
    /// rejection) to a deterministic secret that does not match the
    /// encapsulator's, and the caller's handshake then fails closed.
    ///
    /// # Errors
    /// [`MlKemError::InvalidCiphertextLength`] only.
    pub fn decapsulate(
        &self,
        ciphertext: &MlKem768Ciphertext,
    ) -> Result<MlKemSharedSecret, MlKemError> {
        let ciphertext = ciphertext.as_array()?;
        let shared_key = self.0.decapsulate(&ciphertext);
        Ok(take_shared_secret(shared_key))
    }
}

/// Generates a fresh ML-KEM-768 keypair from `rng`.
pub fn generate_keypair<R: CryptoRng>(
    rng: &mut R,
) -> (MlKem768DecapsulationKey, MlKem768EncapsulationKey) {
    let (dk, ek) = MlKem768::generate_keypair_from_rng(rng);
    (MlKem768DecapsulationKey(dk), MlKem768EncapsulationKey(ek))
}

/// Derives the tunnel preshared key (the backend PSK slot) binding an ML-KEM-768 shared secret
/// to a network and an unordered pair of node ids (plan section 4.5).
///
/// ```text
/// PSK = HKDF-SHA256(ikm   = ss,
///                   salt  = network_id as UTF-8 bytes,
///                   info  = "rustynet-tunnel-psk-v1"
///                           || u16be(len(node_lo)) || node_lo
///                           || u16be(len(node_hi)) || node_hi
///                           || 0x01,
///                   L     = 32)
/// ```
///
/// `node_lo`/`node_hi` are `node_a`/`node_b` in lexicographic byte order,
/// so the order the caller passes them in does not matter. The u16 length
/// prefixes make the `info` string injective, so `(a, bc)` and `(ab, c)`
/// derive different PSKs.
///
/// Callers pass the control plane's validated single-line forms of the
/// network id and node ids (plan section 4.5); this function checks only
/// what the derivation itself needs.
///
/// # Errors
/// * [`MlKemError::UnsupportedPskDerivationVersion`] unless `version == 1`;
/// * [`MlKemError::EmptyNetworkId`] if the network id is empty;
/// * [`MlKemError::EmptyNodeId`] if either node id is empty;
/// * [`MlKemError::NodeIdTooLong`] if either node id exceeds `u16::MAX` bytes;
/// * [`MlKemError::PskExpansionFailed`] if HKDF refuses the output length
///   (unreachable for a 32-byte PSK).
pub fn derive_tunnel_psk(
    shared_secret: &MlKemSharedSecret,
    network_id: &str,
    node_a: &str,
    node_b: &str,
    version: u16,
) -> Result<Zeroizing<[u8; TUNNEL_PSK_LEN]>, MlKemError> {
    if version != TUNNEL_PSK_DERIVATION_VERSION {
        return Err(MlKemError::UnsupportedPskDerivationVersion { got: version });
    }
    if network_id.is_empty() {
        return Err(MlKemError::EmptyNetworkId);
    }
    let (node_lo, node_hi) = canonical_node_order(node_a, node_b)?;

    let mut info = Vec::with_capacity(
        TUNNEL_PSK_INFO_PREFIX.len() + 2 + node_lo.len() + 2 + node_hi.len() + 1,
    );
    info.extend_from_slice(TUNNEL_PSK_INFO_PREFIX);
    extend_len_prefixed(&mut info, node_lo);
    extend_len_prefixed(&mut info, node_hi);
    info.push(TUNNEL_PSK_INFO_VERSION_BYTE);

    // Write the PSK straight into its zeroizing buffer: a plain array moved
    // into `Zeroizing` afterwards would leave an unwiped copy behind.
    let mut okm = Zeroizing::new([0u8; TUNNEL_PSK_LEN]);
    Hkdf::<Sha256>::new(Some(network_id.as_bytes()), shared_secret.expose())
        .expand(&info, okm.as_mut_slice())
        .map_err(|_| MlKemError::PskExpansionFailed)?;
    Ok(okm)
}

/// Orders two validated node ids into the canonical (lo, hi) byte order.
fn canonical_node_order<'a>(
    node_a: &'a str,
    node_b: &'a str,
) -> Result<(&'a str, &'a str), MlKemError> {
    check_node_id(node_a)?;
    check_node_id(node_b)?;
    if node_a.as_bytes() <= node_b.as_bytes() {
        Ok((node_a, node_b))
    } else {
        Ok((node_b, node_a))
    }
}

fn check_node_id(node_id: &str) -> Result<(), MlKemError> {
    if node_id.is_empty() {
        return Err(MlKemError::EmptyNodeId);
    }
    if node_id.len() > u16::MAX as usize {
        return Err(MlKemError::NodeIdTooLong {
            max: u16::MAX as usize,
            got: node_id.len(),
        });
    }
    Ok(())
}

fn extend_len_prefixed(info: &mut Vec<u8>, node_id: &str) {
    // Length was bounded by `check_node_id` before this is reached.
    let len = node_id.len() as u16;
    info.extend_from_slice(&len.to_be_bytes());
    info.extend_from_slice(node_id.as_bytes());
}

fn take_shared_secret(mut shared_key: ml_kem::SharedKey) -> MlKemSharedSecret {
    // Copy straight into the zeroizing buffer (no plain intermediate array).
    let mut secret = Zeroizing::new([0u8; ML_KEM_768_SHARED_SECRET_LEN]);
    for (dst, src) in secret.iter_mut().zip(shared_key.as_slice()) {
        *dst = *src;
    }
    // `hybrid-array`'s `Array` implements `Zeroize` but has no `Drop` impl,
    // so the raw shared secret would otherwise linger in freed memory (plan
    // section 4.7). Zeroize it explicitly before it goes out of scope.
    shared_key.zeroize();
    MlKemSharedSecret(secret)
}

#[cfg(test)]
mod tests;
