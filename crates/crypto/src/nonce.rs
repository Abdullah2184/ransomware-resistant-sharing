use std::fmt;

use crate::CryptoError;

/// Random 64-bit prefix for the version-specific AES-GCM nonce space.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NoncePrefix([u8; 8]);

impl NoncePrefix {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0; 8];
        getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }

    pub(crate) fn for_chunk_index(self, index: u32) -> [u8; 12] {
        let mut nonce = [0; 12];
        nonce[..8].copy_from_slice(&self.0);
        nonce[8..].copy_from_slice(&index.to_be_bytes());
        nonce
    }
}

impl fmt::Debug for NoncePrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NoncePrefix([REDACTED])")
    }
}
