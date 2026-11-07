//! Ports that isolate application workflows from key-custody infrastructure.

pub mod blob_store;

use std::{fmt, future::Future, pin::Pin};

use crypto::{HpkeRecipientPublicKey, KeyEnvelope, TypedDigest, WrapContext};
use domain::{EvmAddress, KeyVersion, MemberId};
use zeroize::Zeroizing;

pub use blob_store::{
    BlobStore, ContentChunk, ContentPackage, ReplicationReceipt, StorageCid, StorageError,
    StorageFuture, StorageReader, StoredContent, StoredEnvelopeSet,
};

/// Opaque identifier for one key held by a custody provider.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyId([u8; 32]);

impl KeyId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyId([REDACTED])")
    }
}

/// Recoverable EVM ECDSA signature in `r || s || v` form, with `v` equal to 27 or 28.
#[derive(Clone, Eq, PartialEq)]
pub struct EvmSignature([u8; 65]);

impl EvmSignature {
    pub const fn from_bytes(bytes: [u8; 65]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 65] {
        &self.0
    }
}

impl fmt::Debug for EvmSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("EvmSignature")
            .field(&"65-byte signature")
            .finish()
    }
}

/// Public keys and IDs registered for one consortium member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicIdentityKeys {
    pub member_id: MemberId,
    pub signing_key_id: KeyId,
    pub signing_key_version: KeyVersion,
    pub signing_address: EvmAddress,
    pub encryption_key_id: KeyId,
    pub encryption_key_version: KeyVersion,
    pub encryption_public_key: HpkeRecipientPublicKey,
}

/// Capability report returned by a key-custody provider health check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyCapabilities {
    pub secp256k1_signing: bool,
    pub hpke_x25519_unwrap: bool,
    pub private_keys_non_exportable: bool,
    pub test_only: bool,
}

/// Health and feature report for the active custody provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyHealth {
    pub healthy: bool,
    pub capabilities: CustodyCapabilities,
}

/// Errors surfaced by the key-custody boundary without provider secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustodyError {
    KeyNotFound,
    KeyGenerationFailed,
    RandomnessUnavailable,
    SigningFailed,
    UnwrapFailed,
    ProviderUnavailable,
}

impl fmt::Display for CustodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::KeyNotFound => "custody key not found",
            Self::KeyGenerationFailed => "custody key generation failed",
            Self::RandomnessUnavailable => "cryptographic randomness unavailable",
            Self::SigningFailed => "typed-digest signing failed",
            Self::UnwrapFailed => "DEK unwrap failed",
            Self::ProviderUnavailable => "key-custody provider unavailable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CustodyError {}

/// Sendable future returned by an asynchronous custody operation.
pub type CustodyFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, CustodyError>> + Send + 'a>>;

/// Boundary for registered keys, typed-digest signing, and envelope unwrapping.
pub trait KeyCustodyProvider: Send + Sync {
    fn public_identity(&self) -> CustodyFuture<'_, PublicIdentityKeys>;

    fn sign_typed_digest<'a>(
        &'a self,
        key_id: &'a KeyId,
        digest: &'a TypedDigest,
    ) -> CustodyFuture<'a, EvmSignature>;

    fn unwrap_dek<'a>(
        &'a self,
        key_id: &'a KeyId,
        envelope: &'a KeyEnvelope,
        context: WrapContext,
    ) -> CustodyFuture<'a, Zeroizing<[u8; 32]>>;

    fn health_check(&self) -> CustodyFuture<'_, CustodyHealth>;
}
