//! Cryptographic primitives and versioned encrypted-content formats.

pub mod encryption;
pub mod envelope_set;
pub mod key_wrapping;
pub mod manifest;
pub mod nonce;
pub mod signing;

pub use encryption::{
    ChunkDecryptor, ChunkEncryptor, CryptoError, DEFAULT_CHUNK_SIZE_BYTES, DataEncryptionKey,
    EncryptedChunk, EncryptionContext, chunk_count_for_len, decrypt_private_metadata,
    encrypt_private_metadata,
};
pub use envelope_set::{KeyEnvelopeEntry, KeyEnvelopeSet, MAX_ENVELOPE_SET_ENTRIES};
pub use key_wrapping::{HpkeRecipientKeyPair, HpkeRecipientPublicKey, KeyEnvelope, WrapContext};
pub use manifest::{
    EncryptedChunkRef, EncryptedFileManifest, MAX_PRIVATE_METADATA_BYTES,
    PrivateMetadataCiphertext, raw_sha256_cid, verify_sha256_cid,
};
pub use nonce::NoncePrefix;
pub use signing::{
    AccessLookup, ChainId, Eip712Domain, EnvelopeSetUpdate, LoginChallengeDigestInput,
    MemberKeyProof, SigningError, TypedDigest, UnixDeadline, VerifyingContractKind, VersionAppend,
};
