//! Infrastructure-independent domain types and invariants.

pub mod errors;
pub mod ids;
pub mod version;

pub use errors::DomainError;
pub use ids::{
    ContentCid, EnvelopeSetCid, EpochId, EvmAddress, FileId, KeyVersion, ManifestHash, MemberId,
    OperationNonce, OrganizationId, ProposalId, VersionNumber,
};
pub use version::{VersionGraph, VersionRecord};
