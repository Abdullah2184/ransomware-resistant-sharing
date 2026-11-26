use std::{fmt, future::Future, pin::Pin};

use domain::{
    AccessReference, ContentCid, DomainError, EnvelopeSetCid, EpochId, EvmAddress, FileId,
    FileStatus, FolderId, KeyVersion, LoginChallenge, ManifestHash, MemberId, OperationNonce,
    ProposalId, PublicMemberIdentity, TransactionReceipt, VersionNumber,
};
use zeroize::Zeroizing;

use crate::EvmSignature;

/// Sendable future returned by an asynchronous gateway or ledger port operation.
pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, DomainError>> + Send + 'a>>;

/// Short-lived bearer session returned after a signed challenge-response login.
///
/// Session tokens are redacted in debug output and held in a zeroizing buffer.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthenticatedSession {
    token: Zeroizing<String>,
    pub member_id: MemberId,
    pub expires_at: u64,
}

impl AuthenticatedSession {
    pub fn new(token: String, member_id: MemberId, expires_at: u64) -> Self {
        Self {
            token: Zeroizing::new(token),
            member_id,
            expires_at,
        }
    }

    pub fn bearer_token(&self) -> &str {
        &self.token
    }
}

impl fmt::Debug for AuthenticatedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedSession")
            .field("member_id", &self.member_id)
            .field("expires_at", &self.expires_at)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Authoritative file-head state queried from `FileRegistry`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeadState {
    pub file_id: FileId,
    pub status: FileStatus,
    pub current_version: VersionNumber,
    pub current_head_manifest_hash: ManifestHash,
}

/// Signed request to create a new file and its initial version on-chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedCreateFileRequest {
    pub file_id: FileId,
    pub display_name: String,
    pub parent_folder_id: FolderId,
    pub version_number: VersionNumber,
    pub parent_manifest_hash: ManifestHash,
    pub manifest_hash: ManifestHash,
    pub content_cid: ContentCid,
    pub envelope_set_cid: EnvelopeSetCid,
    pub epoch_id: EpochId,
    pub author_member_id: MemberId,
    pub signer_address: EvmAddress,
    pub operation_nonce: OperationNonce,
    pub deadline: u64,
    pub signature: EvmSignature,
}

/// Signed request to append a new version (modify or append-only restore).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAppendVersionRequest {
    pub file_id: FileId,
    pub version_number: VersionNumber,
    pub parent_manifest_hash: ManifestHash,
    pub manifest_hash: ManifestHash,
    pub content_cid: ContentCid,
    pub envelope_set_cid: EnvelopeSetCid,
    pub epoch_id: EpochId,
    pub author_member_id: MemberId,
    pub signer_address: EvmAddress,
    pub operation_nonce: OperationNonce,
    pub deadline: u64,
    pub signature: EvmSignature,
}

/// Signed request to authorize retrieval of a specific file version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedAccessLookupRequest {
    pub member_id: MemberId,
    pub file_id: FileId,
    pub version_number: VersionNumber,
    pub encryption_key_version: KeyVersion,
    pub operation_nonce: OperationNonce,
    pub deadline: u64,
    pub signature: EvmSignature,
}

/// Signed request to advance an existing version's envelope-set pointer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedEnvelopeUpdateRequest {
    pub file_id: FileId,
    pub version_number: VersionNumber,
    pub epoch_id: EpochId,
    pub old_envelope_set_cid: EnvelopeSetCid,
    pub new_envelope_set_cid: EnvelopeSetCid,
    pub actor_member_id: MemberId,
    pub proposal_id: ProposalId,
    pub operation_nonce: OperationNonce,
    pub deadline: u64,
    pub signature: EvmSignature,
}

/// Gateway authentication boundary for challenge-response session establishment.
pub trait GatewayAuthPort: Send + Sync {
    fn request_challenge(&self, member_id: MemberId) -> PortFuture<'_, LoginChallenge>;

    fn exchange_challenge<'a>(
        &'a self,
        challenge: &'a LoginChallenge,
        signature: &'a EvmSignature,
    ) -> PortFuture<'a, AuthenticatedSession>;
}

/// Authoritative ledger and gateway-relayed contract operations boundary.
pub trait LedgerPort: Send + Sync {
    fn get_member(&self, member_id: MemberId) -> PortFuture<'_, Option<PublicMemberIdentity>>;

    fn get_file_head(&self, file_id: FileId) -> PortFuture<'_, Option<HeadState>>;

    fn authorize_read<'a>(
        &'a self,
        request: &'a SignedAccessLookupRequest,
    ) -> PortFuture<'a, AccessReference>;

    fn create_file<'a>(
        &'a self,
        request: &'a SignedCreateFileRequest,
    ) -> PortFuture<'a, TransactionReceipt>;

    fn append_version<'a>(
        &'a self,
        request: &'a SignedAppendVersionRequest,
    ) -> PortFuture<'a, TransactionReceipt>;

    fn update_envelope_set<'a>(
        &'a self,
        request: &'a SignedEnvelopeUpdateRequest,
    ) -> PortFuture<'a, TransactionReceipt>;
}
