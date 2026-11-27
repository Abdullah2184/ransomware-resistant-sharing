use std::fmt;

use crate::{
    ContentCid, EnvelopeSetCid, EpochId, EvmAddress, FileId, FolderId, KeyVersion, ManifestHash,
    MemberId, OperationNonce, OrganizationId, VersionNumber,
};

/// Lifecycle status of a consortium member registered in `AccessGovernance`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberStatus {
    Active,
    Suspended,
    Revoked,
}

/// Lifecycle status of a file registered in `FileRegistry`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileStatus {
    Active,
    Archived,
}

/// Authoritative public identity fields for one consortium member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicMemberIdentity {
    pub member_id: MemberId,
    pub organization_id: OrganizationId,
    pub signing_address: EvmAddress,
    pub signing_key_version: KeyVersion,
    pub encryption_key_version: KeyVersion,
    pub encryption_public_key: [u8; 32],
    pub status: MemberStatus,
    pub finalized_block: u64,
}

impl PublicMemberIdentity {
    pub const fn is_active(&self) -> bool {
        matches!(self.status, MemberStatus::Active)
    }
}

/// Visible file metadata and current-head summary from `FileRegistry`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileMetadata {
    pub file_id: FileId,
    pub display_name: String,
    pub parent_folder_id: FolderId,
    pub creator_member_id: MemberId,
    pub organization_id: OrganizationId,
    pub status: FileStatus,
    pub current_version: VersionNumber,
    pub current_head_manifest_hash: ManifestHash,
}

/// Authoritative references returned after a signed read-access lookup succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessReference {
    pub file_id: FileId,
    pub version_number: VersionNumber,
    pub manifest_hash: ManifestHash,
    pub content_cid: ContentCid,
    pub envelope_set_cid: EnvelopeSetCid,
    pub epoch_id: EpochId,
    pub envelope_revision: u32,
    pub finalized_block: u64,
}

/// One-time EIP-712 login challenge issued by the gateway.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoginChallenge {
    pub member_id: MemberId,
    pub nonce: OperationNonce,
    pub issued_at: u64,
    pub expires_at: u64,
    pub audience: String,
    pub protocol_version: u32,
}

/// Finalized blockchain transaction receipt surfaced to application callers.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct TransactionReceipt {
    pub transaction_hash: [u8; 32],
    pub block_number: u64,
    pub finalized: bool,
    pub succeeded: bool,
}

impl fmt::Debug for TransactionReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransactionReceipt")
            .field("block_number", &self.block_number)
            .field("finalized", &self.finalized)
            .field("succeeded", &self.succeeded)
            .finish_non_exhaustive()
    }
}
