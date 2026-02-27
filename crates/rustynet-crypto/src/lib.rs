#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;

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
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidLength => f.write_str("invalid key length"),
            CryptoError::WeakMaterial => f.write_str("weak key material"),
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

#[cfg(test)]
mod tests {
    use super::{CryptoError, NodeKeyPair};

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
}
