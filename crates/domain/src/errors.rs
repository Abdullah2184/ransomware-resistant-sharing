use std::{error::Error, fmt};

/// Stable errors that may cross the domain/application boundary.
///
/// Variants intentionally carry no request data, credentials, or lower-level
/// error strings that could leak sensitive information.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainError {
    InvalidIdentifier,
    InvalidCid,
    InvalidKeyVersion,
    InvalidVersionNumber,
    FileIdMismatch,
    DuplicateEpochId,
    Unauthenticated,
    Unauthorized,
    MemberSuspended,
    InvalidSignature,
    ReplayDetected,
    ExpiredRequest,
    StaleHead,
    InvalidManifest,
    UnsupportedCryptoSuite,
    IntegrityCheckFailed,
    StorageUnavailable,
    ReplicationInsufficient,
    KeyCustodyUnavailable,
    ContractRejected,
    GovernancePending,
    RateLimited,
    IndexerLagging,
    OrphanedUpload,
    Internal,
}

impl fmt::Display for DomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidIdentifier => "invalid identifier",
            Self::InvalidCid => "invalid CID",
            Self::InvalidKeyVersion => "invalid key version",
            Self::InvalidVersionNumber => "invalid version number",
            Self::FileIdMismatch => "version belongs to a different file",
            Self::DuplicateEpochId => "version reuses an existing key epoch",
            Self::Unauthenticated => "authentication required",
            Self::Unauthorized => "operation is not authorized",
            Self::MemberSuspended => "member is suspended",
            Self::InvalidSignature => "invalid signature",
            Self::ReplayDetected => "operation has already been used",
            Self::ExpiredRequest => "request has expired",
            Self::StaleHead => "version parent does not match the current head",
            Self::InvalidManifest => "invalid version manifest",
            Self::UnsupportedCryptoSuite => "unsupported cryptographic suite",
            Self::IntegrityCheckFailed => "integrity check failed",
            Self::StorageUnavailable => "storage is unavailable",
            Self::ReplicationInsufficient => "storage replication requirement not met",
            Self::KeyCustodyUnavailable => "key custody is unavailable",
            Self::ContractRejected => "contract rejected the operation",
            Self::GovernancePending => "governance approval is pending",
            Self::RateLimited => "request rate limit exceeded",
            Self::IndexerLagging => "indexer is not sufficiently current",
            Self::OrphanedUpload => "upload is not referenced by finalized state",
            Self::Internal => "internal error",
        };
        formatter.write_str(message)
    }
}

impl Error for DomainError {}
