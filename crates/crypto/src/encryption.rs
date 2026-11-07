use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use domain::{EpochId, FileId, VersionNumber};
use zeroize::Zeroizing;

use crate::NoncePrefix;

const AAD_DOMAIN: &[u8] = b"rrds/encrypted-content/v1";
const GCM_TAG_BYTES: usize = 16;

pub const DEFAULT_CHUNK_SIZE_BYTES: usize = 4 * 1024 * 1024;

/// Errors from the versioned AES-256-GCM chunk format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    RandomnessUnavailable,
    InvalidKey,
    InvalidChunkSize,
    TooManyChunks,
    UnexpectedChunk,
    InvalidChunkLayout,
    MissingChunks,
    AuthenticationFailed,
    InvalidRecipientPublicKey,
    InvalidEnvelope,
    HpkeOperationFailed,
    InvalidManifest,
    ManifestEncodingFailed,
    InvalidEnvelopeSet,
    EnvelopeSetEncodingFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::RandomnessUnavailable => "cryptographic randomness unavailable",
            Self::InvalidKey => "invalid encryption key",
            Self::InvalidChunkSize => "invalid encryption chunk size",
            Self::TooManyChunks => "encrypted file exceeds the nonce index limit",
            Self::UnexpectedChunk => "unexpected or repeated file chunk",
            Self::InvalidChunkLayout => "encrypted file chunk layout is invalid",
            Self::MissingChunks => "encrypted file is missing one or more chunks",
            Self::AuthenticationFailed => "encrypted chunk authentication failed",
            Self::InvalidRecipientPublicKey => "invalid HPKE recipient public key",
            Self::InvalidEnvelope => "invalid HPKE key envelope",
            Self::HpkeOperationFailed => "HPKE operation failed",
            Self::InvalidManifest => "invalid encrypted content manifest",
            Self::ManifestEncodingFailed => "encrypted content manifest encoding failed",
            Self::InvalidEnvelopeSet => "invalid key envelope set",
            Self::EnvelopeSetEncodingFailed => "key envelope set encoding failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CryptoError {}

/// A version-specific 256-bit data-encryption key held in a zeroizing buffer.
pub struct DataEncryptionKey(Zeroizing<[u8; 32]>);

impl DataEncryptionKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Takes ownership of a transient key returned by a key-custody operation.
    pub fn from_secret(secret: Zeroizing<[u8; 32]>) -> Self {
        Self(secret)
    }

    pub fn into_zeroizing_bytes(self) -> Zeroizing<[u8; 32]> {
        self.0
    }

    pub(crate) fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn cipher(&self) -> Result<Aes256Gcm, CryptoError> {
        Aes256Gcm::new_from_slice(&self.0[..]).map_err(|_| CryptoError::InvalidKey)
    }
}

/// Context bound to every chunk's authenticated data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptionContext {
    file_id: FileId,
    version_number: VersionNumber,
    epoch_id: EpochId,
}

impl EncryptionContext {
    pub const fn new(file_id: FileId, version_number: VersionNumber, epoch_id: EpochId) -> Self {
        Self {
            file_id,
            version_number,
            epoch_id,
        }
    }

    fn associated_data(self, index: u32, total_chunks: u32) -> Vec<u8> {
        let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 32 + 8 + 32 + 4 + 4);
        aad.extend_from_slice(AAD_DOMAIN);
        aad.extend_from_slice(self.file_id.as_bytes());
        aad.extend_from_slice(&self.version_number.get().to_be_bytes());
        aad.extend_from_slice(self.epoch_id.as_bytes());
        aad.extend_from_slice(&index.to_be_bytes());
        aad.extend_from_slice(&total_chunks.to_be_bytes());
        aad
    }
}

/// One encrypted content chunk. The tag is appended to the ciphertext.
#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedChunk {
    index: u32,
    ciphertext_and_tag: Vec<u8>,
}

impl EncryptedChunk {
    pub const fn index(&self) -> u32 {
        self.index
    }

    pub fn ciphertext_and_tag(&self) -> &[u8] {
        &self.ciphertext_and_tag
    }
}

/// Stateful encryptor that emits chunks in nonce-index order without reuse.
pub struct ChunkEncryptor {
    cipher: Aes256Gcm,
    nonce_prefix: NoncePrefix,
    context: EncryptionContext,
    chunk_size_bytes: usize,
    total_chunks: u32,
    next_chunk_index: u64,
}

impl ChunkEncryptor {
    pub fn new(
        key: DataEncryptionKey,
        nonce_prefix: NoncePrefix,
        context: EncryptionContext,
        chunk_size_bytes: usize,
        total_chunks: u32,
    ) -> Result<Self, CryptoError> {
        validate_chunk_size(chunk_size_bytes)?;
        let cipher = key.cipher()?;
        drop(key);
        Ok(Self {
            cipher,
            nonce_prefix,
            context,
            chunk_size_bytes,
            total_chunks,
            next_chunk_index: 1,
        })
    }

    pub fn encrypt_next(&mut self, plaintext: &[u8]) -> Result<EncryptedChunk, CryptoError> {
        let index =
            u32::try_from(self.next_chunk_index).map_err(|_| CryptoError::UnexpectedChunk)?;
        if index > self.total_chunks {
            return Err(CryptoError::UnexpectedChunk);
        }
        validate_plaintext_chunk(plaintext, index, self.total_chunks, self.chunk_size_bytes)?;

        let nonce_bytes = self.nonce_prefix.for_chunk_index(index);
        let nonce = Nonce::from(nonce_bytes);
        let aad = self.context.associated_data(index, self.total_chunks);
        let ciphertext_and_tag = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::InvalidKey)?;
        self.next_chunk_index += 1;

        Ok(EncryptedChunk {
            index,
            ciphertext_and_tag,
        })
    }

    pub fn finish(self) -> Result<(), CryptoError> {
        if self.next_chunk_index != u64::from(self.total_chunks) + 1 {
            return Err(CryptoError::MissingChunks);
        }
        Ok(())
    }
}

/// Stateful decryptor that rejects missing, reordered, altered, or transplanted chunks.
pub struct ChunkDecryptor {
    cipher: Aes256Gcm,
    nonce_prefix: NoncePrefix,
    context: EncryptionContext,
    chunk_size_bytes: usize,
    total_chunks: u32,
    next_chunk_index: u64,
}

impl ChunkDecryptor {
    pub fn new(
        key: DataEncryptionKey,
        nonce_prefix: NoncePrefix,
        context: EncryptionContext,
        chunk_size_bytes: usize,
        total_chunks: u32,
    ) -> Result<Self, CryptoError> {
        validate_chunk_size(chunk_size_bytes)?;
        let cipher = key.cipher()?;
        drop(key);
        Ok(Self {
            cipher,
            nonce_prefix,
            context,
            chunk_size_bytes,
            total_chunks,
            next_chunk_index: 1,
        })
    }

    pub fn decrypt_next(
        &mut self,
        chunk: &EncryptedChunk,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let expected_index =
            u32::try_from(self.next_chunk_index).map_err(|_| CryptoError::UnexpectedChunk)?;
        if expected_index > self.total_chunks {
            return Err(CryptoError::UnexpectedChunk);
        }
        if chunk.index != expected_index {
            return Err(CryptoError::InvalidChunkLayout);
        }
        if chunk.ciphertext_and_tag.len() < GCM_TAG_BYTES {
            return Err(CryptoError::InvalidChunkLayout);
        }

        let nonce_bytes = self.nonce_prefix.for_chunk_index(expected_index);
        let aad = self
            .context
            .associated_data(expected_index, self.total_chunks);
        let nonce = Nonce::from(nonce_bytes);
        let plaintext = Zeroizing::new(
            self.cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &chunk.ciphertext_and_tag,
                        aad: &aad,
                    },
                )
                .map_err(|_| CryptoError::AuthenticationFailed)?,
        );
        validate_plaintext_chunk(
            &plaintext,
            expected_index,
            self.total_chunks,
            self.chunk_size_bytes,
        )?;
        self.next_chunk_index += 1;

        Ok(plaintext)
    }

    pub fn finish(self) -> Result<(), CryptoError> {
        if self.next_chunk_index != u64::from(self.total_chunks) + 1 {
            return Err(CryptoError::MissingChunks);
        }
        Ok(())
    }
}

/// Calculates the number of content chunks while preserving index zero for metadata.
pub fn chunk_count_for_len(
    plaintext_len: u64,
    chunk_size_bytes: usize,
) -> Result<u32, CryptoError> {
    validate_chunk_size(chunk_size_bytes)?;
    let chunk_size = u64::try_from(chunk_size_bytes).map_err(|_| CryptoError::TooManyChunks)?;
    let count = if plaintext_len == 0 {
        0
    } else {
        1 + (plaintext_len - 1) / chunk_size
    };
    u32::try_from(count).map_err(|_| CryptoError::TooManyChunks)
}

fn validate_chunk_size(chunk_size_bytes: usize) -> Result<(), CryptoError> {
    if chunk_size_bytes == 0 || chunk_size_bytes > DEFAULT_CHUNK_SIZE_BYTES {
        return Err(CryptoError::InvalidChunkSize);
    }
    Ok(())
}

fn validate_plaintext_chunk(
    plaintext: &[u8],
    index: u32,
    total_chunks: u32,
    chunk_size_bytes: usize,
) -> Result<(), CryptoError> {
    let is_final = index == total_chunks;
    if plaintext.is_empty()
        || plaintext.len() > chunk_size_bytes
        || (!is_final && plaintext.len() != chunk_size_bytes)
    {
        return Err(CryptoError::InvalidChunkLayout);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CHUNK_SIZE: usize = 64;

    fn test_context(file: u8, version: u64, epoch: u8) -> EncryptionContext {
        EncryptionContext::new(
            FileId::from_bytes([file; 32]),
            VersionNumber::new(version).unwrap(),
            EpochId::from_bytes([epoch; 32]),
        )
    }

    fn key(seed: u8) -> DataEncryptionKey {
        DataEncryptionKey::from_secret(Zeroizing::new([seed; 32]))
    }

    fn encrypt_chunks(
        plaintext: &[u8],
        context: EncryptionContext,
        chunk_size: usize,
        key_seed: u8,
    ) -> (NoncePrefix, Vec<EncryptedChunk>) {
        let total_chunks = chunk_count_for_len(plaintext.len() as u64, chunk_size).unwrap();
        let nonce_prefix = NoncePrefix::from_bytes([key_seed; 8]);
        let mut encryptor = ChunkEncryptor::new(
            key(key_seed),
            nonce_prefix,
            context,
            chunk_size,
            total_chunks,
        )
        .unwrap();
        let mut chunks = Vec::new();
        for bytes in plaintext.chunks(chunk_size) {
            chunks.push(encryptor.encrypt_next(bytes).unwrap());
        }
        encryptor.finish().unwrap();
        (nonce_prefix, chunks)
    }

    fn decrypt_chunks(
        chunks: &[EncryptedChunk],
        nonce_prefix: NoncePrefix,
        context: EncryptionContext,
        chunk_size: usize,
        key_seed: u8,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let total_chunks = u32::try_from(chunks.len()).unwrap();
        let mut decryptor = ChunkDecryptor::new(
            key(key_seed),
            nonce_prefix,
            context,
            chunk_size,
            total_chunks,
        )?;
        let mut plaintext = Zeroizing::new(Vec::new());
        for chunk in chunks {
            plaintext.extend_from_slice(&decryptor.decrypt_next(chunk)?);
        }
        decryptor.finish()?;
        Ok(plaintext)
    }

    #[test]
    fn empty_small_boundary_and_multi_chunk_inputs_round_trip() {
        for (index, plaintext) in [
            Vec::new(),
            b"small file".to_vec(),
            vec![0x31; DEFAULT_CHUNK_SIZE_BYTES],
            vec![0x73; DEFAULT_CHUNK_SIZE_BYTES + 1],
        ]
        .into_iter()
        .enumerate()
        {
            let key_seed = u8::try_from(index + 1).unwrap();
            let context = test_context(1, 1, 1);
            let chunk_size = if plaintext.len() > TEST_CHUNK_SIZE {
                DEFAULT_CHUNK_SIZE_BYTES
            } else {
                TEST_CHUNK_SIZE
            };
            let (nonce_prefix, chunks) = encrypt_chunks(&plaintext, context, chunk_size, key_seed);

            let decrypted =
                decrypt_chunks(&chunks, nonce_prefix, context, chunk_size, key_seed).unwrap();
            assert_eq!(decrypted.as_slice(), plaintext.as_slice());
        }
    }

    #[test]
    fn rejects_tampered_ciphertext_and_transplanted_context() {
        let context = test_context(1, 1, 1);
        let (nonce_prefix, mut chunks) =
            encrypt_chunks(b"authenticated chunk", context, TEST_CHUNK_SIZE, 5);
        chunks[0].ciphertext_and_tag[0] ^= 1;
        assert_eq!(
            decrypt_chunks(&chunks, nonce_prefix, context, TEST_CHUNK_SIZE, 5),
            Err(CryptoError::AuthenticationFailed)
        );

        let (nonce_prefix, chunks) =
            encrypt_chunks(b"bound to one file", context, TEST_CHUNK_SIZE, 6);
        assert_eq!(
            decrypt_chunks(
                &chunks,
                nonce_prefix,
                test_context(2, 1, 1),
                TEST_CHUNK_SIZE,
                6
            ),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            decrypt_chunks(
                &chunks,
                nonce_prefix,
                test_context(1, 2, 1),
                TEST_CHUNK_SIZE,
                6
            ),
            Err(CryptoError::AuthenticationFailed)
        );
        assert_eq!(
            decrypt_chunks(
                &chunks,
                nonce_prefix,
                test_context(1, 1, 2),
                TEST_CHUNK_SIZE,
                6
            ),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn rejects_reordered_and_missing_chunks() {
        let context = test_context(1, 1, 1);
        let (nonce_prefix, mut chunks) =
            encrypt_chunks(&[9; TEST_CHUNK_SIZE + 1], context, TEST_CHUNK_SIZE, 7);
        chunks.swap(0, 1);
        assert_eq!(
            decrypt_chunks(&chunks, nonce_prefix, context, TEST_CHUNK_SIZE, 7),
            Err(CryptoError::InvalidChunkLayout)
        );

        let (nonce_prefix, chunks) =
            encrypt_chunks(&[9; TEST_CHUNK_SIZE + 1], context, TEST_CHUNK_SIZE, 8);
        let mut decryptor = ChunkDecryptor::new(
            key(8),
            nonce_prefix,
            context,
            TEST_CHUNK_SIZE,
            chunks.len() as u32,
        )
        .unwrap();
        decryptor.decrypt_next(&chunks[0]).unwrap();
        assert_eq!(decryptor.finish(), Err(CryptoError::MissingChunks));
    }

    #[test]
    fn chunk_indices_and_aad_bind_total_chunk_count() {
        let prefix = NoncePrefix::from_bytes([0x09; 8]);
        assert_ne!(prefix.for_chunk_index(1), prefix.for_chunk_index(2));

        let context = test_context(1, 1, 1);
        let (nonce_prefix, chunks) =
            encrypt_chunks(&[4; TEST_CHUNK_SIZE + 1], context, TEST_CHUNK_SIZE, 9);
        let mut decryptor =
            ChunkDecryptor::new(key(9), nonce_prefix, context, TEST_CHUNK_SIZE, 3).unwrap();
        assert_eq!(
            decryptor.decrypt_next(&chunks[0]),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn rejects_invalid_chunk_sizes_and_nonce_index_overflow() {
        assert_eq!(
            chunk_count_for_len(0, 0),
            Err(CryptoError::InvalidChunkSize)
        );
        assert_eq!(
            chunk_count_for_len(u64::MAX, 1),
            Err(CryptoError::TooManyChunks)
        );
        assert_eq!(
            chunk_count_for_len(1, DEFAULT_CHUNK_SIZE_BYTES + 1),
            Err(CryptoError::InvalidChunkSize)
        );
    }

    #[test]
    fn generates_keys_and_nonce_prefixes_from_os_randomness() {
        let _key = DataEncryptionKey::generate().unwrap();
        let nonce_prefix = NoncePrefix::generate().unwrap();

        assert_eq!(nonce_prefix.as_bytes().len(), 8);
    }

    #[test]
    fn encryptor_rejects_reuse_after_the_final_nonce_index() {
        let context = test_context(1, 1, 1);
        let nonce_prefix = NoncePrefix::from_bytes([11; 8]);
        let mut encryptor =
            ChunkEncryptor::new(key(11), nonce_prefix, context, TEST_CHUNK_SIZE, 1).unwrap();

        encryptor.encrypt_next(b"once").unwrap();
        assert!(matches!(
            encryptor.encrypt_next(b"again"),
            Err(CryptoError::UnexpectedChunk)
        ));
    }
}
