//! Infrastructure-independent domain types and invariants.

pub mod errors;
pub mod hex;
pub mod ids;
pub mod model;
pub mod version;

pub use errors::DomainError;
pub use ids::{
    ContentCid, EnvelopeSetCid, EpochId, EvmAddress, FileId, FolderId, KeyVersion, ManifestHash,
    MemberId, OperationNonce, OrganizationId, ProposalId, VersionNumber,
};
pub use model::{
    AccessReference, FileMetadata, FileStatus, LoginChallenge, MemberStatus, PublicMemberIdentity,
    TransactionReceipt,
};
pub use version::{VersionGraph, VersionRecord};
