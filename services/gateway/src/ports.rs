use std::{future::Future, pin::Pin};

use chain_adapter::{
    BesuClient, ChainError, EnvelopeSetState, EnvelopeSetUpdateCall, FileHeadState,
    FileVersionState, FinalizedBlock, MemberIdentityState, RelayError, RelayOutcome,
    TransactionRelayer, VersionAppendCall, encode_append_version_calldata,
    encode_create_file_calldata, encode_update_envelope_set_calldata,
};
use domain::EvmAddress;

use crate::{
    auth::LoginChallenge,
    store::{
        AuditEventRecord, FileListingResult, GatewayStore, OrphanBlobCandidate,
        RelayedTransactionRecord, VersionHistoryResult,
    },
};

pub type ChainFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ChainError>> + Send + 'a>>;
pub type RelayFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, RelayError>> + Send + 'a>>;
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, sqlx::Error>> + Send + 'a>>;

/// Read-only authoritative Besu contract query boundary used by gateway routes.
pub trait GatewayChainPort: Send + Sync {
    fn finalized_block(&self) -> ChainFuture<'_, FinalizedBlock>;

    fn member_identity<'a>(
        &'a self,
        access_governance: &'a EvmAddress,
        member_id: &'a [u8; 32],
        block_number: u64,
    ) -> ChainFuture<'a, Option<MemberIdentityState>>;

    fn has_read_access<'a>(
        &'a self,
        access_governance: &'a EvmAddress,
        member_id: &'a [u8; 32],
        file_id: &'a [u8; 32],
        block_number: u64,
    ) -> ChainFuture<'a, bool>;

    fn has_write_access<'a>(
        &'a self,
        access_governance: &'a EvmAddress,
        member_id: &'a [u8; 32],
        file_id: &'a [u8; 32],
        block_number: u64,
    ) -> ChainFuture<'a, bool>;

    fn has_historical_read_access<'a>(
        &'a self,
        access_governance: &'a EvmAddress,
        member_id: &'a [u8; 32],
        file_id: &'a [u8; 32],
        version_number: u64,
        block_number: u64,
    ) -> ChainFuture<'a, bool>;

    fn file_head_at<'a>(
        &'a self,
        file_registry: &'a EvmAddress,
        file_id: &'a [u8; 32],
        block_number: u64,
    ) -> ChainFuture<'a, Option<FileHeadState>>;

    fn file_version<'a>(
        &'a self,
        file_registry: &'a EvmAddress,
        file_id: &'a [u8; 32],
        version_number: u64,
        block_number: u64,
    ) -> ChainFuture<'a, Option<FileVersionState>>;

    fn current_envelope_set<'a>(
        &'a self,
        access_governance: &'a EvmAddress,
        file_id: &'a [u8; 32],
        version_number: u64,
        block_number: u64,
    ) -> ChainFuture<'a, Option<EnvelopeSetState>>;
}

impl GatewayChainPort for BesuClient {
    fn finalized_block(&self) -> ChainFuture<'_, FinalizedBlock> {
        Box::pin(self.finalized_block())
    }

    fn member_identity<'a>(
        &'a self,
        access_governance: &'a EvmAddress,
        member_id: &'a [u8; 32],
        block_number: u64,
    ) -> ChainFuture<'a, Option<MemberIdentityState>> {
        Box::pin(self.member_identity(access_governance, member_id, block_number))
    }

    fn has_read_access<'a>(
        &'a self,
        access_governance: &'a EvmAddress,
        member_id: &'a [u8; 32],
        file_id: &'a [u8; 32],
        block_number: u64,
    ) -> ChainFuture<'a, bool> {
        Box::pin(self.has_read_access(access_governance, member_id, file_id, block_number))
    }

    fn has_write_access<'a>(
        &'a self,
        access_governance: &'a EvmAddress,
        member_id: &'a [u8; 32],
        file_id: &'a [u8; 32],
        block_number: u64,
    ) -> ChainFuture<'a, bool> {
        Box::pin(self.has_write_access(access_governance, member_id, file_id, block_number))
    }

    fn has_historical_read_access<'a>(
        &'a self,
        access_governance: &'a EvmAddress,
        member_id: &'a [u8; 32],
        file_id: &'a [u8; 32],
        version_number: u64,
        block_number: u64,
    ) -> ChainFuture<'a, bool> {
        Box::pin(self.has_historical_read_access(
            access_governance,
            member_id,
            file_id,
            version_number,
            block_number,
        ))
    }

    fn file_head_at<'a>(
        &'a self,
        file_registry: &'a EvmAddress,
        file_id: &'a [u8; 32],
        block_number: u64,
    ) -> ChainFuture<'a, Option<FileHeadState>> {
        Box::pin(self.file_head_at(file_registry, file_id, block_number))
    }

    fn file_version<'a>(
        &'a self,
        file_registry: &'a EvmAddress,
        file_id: &'a [u8; 32],
        version_number: u64,
        block_number: u64,
    ) -> ChainFuture<'a, Option<FileVersionState>> {
        Box::pin(self.file_version(file_registry, file_id, version_number, block_number))
    }

    fn current_envelope_set<'a>(
        &'a self,
        access_governance: &'a EvmAddress,
        file_id: &'a [u8; 32],
        version_number: u64,
        block_number: u64,
    ) -> ChainFuture<'a, Option<EnvelopeSetState>> {
        Box::pin(self.current_envelope_set(
            access_governance,
            file_id,
            version_number,
            block_number,
        ))
    }
}

/// Contract write-relaying boundary for state-changing gateway routes.
pub trait GatewayRelayerPort: Send + Sync {
    fn relay_create_file(
        &self,
        call: VersionAppendCall,
        display_name: String,
        parent_folder_id: [u8; 32],
        signature: Vec<u8>,
    ) -> RelayFuture<'_, RelayOutcome>;

    fn relay_append_version(
        &self,
        call: VersionAppendCall,
        signature: Vec<u8>,
    ) -> RelayFuture<'_, RelayOutcome>;

    fn relay_update_envelope_set(
        &self,
        call: EnvelopeSetUpdateCall,
        signature: Vec<u8>,
    ) -> RelayFuture<'_, RelayOutcome>;

    #[allow(dead_code)]
    fn reconcile_transaction(&self, tx_hash: [u8; 32]) -> RelayFuture<'_, Option<RelayOutcome>>;
}

/// Production relayer adapter targeting deployed `FileRegistry` and `AccessGovernance`.
#[allow(dead_code)]
pub struct BesuContractRelayer {
    relayer: TransactionRelayer,
    file_registry: EvmAddress,
    access_governance: EvmAddress,
    gas_limit: u64,
}

#[allow(dead_code)]
impl BesuContractRelayer {
    pub fn new(
        relayer: TransactionRelayer,
        file_registry: EvmAddress,
        access_governance: EvmAddress,
        gas_limit: u64,
    ) -> Self {
        Self {
            relayer,
            file_registry,
            access_governance,
            gas_limit,
        }
    }
}

impl GatewayRelayerPort for BesuContractRelayer {
    fn relay_create_file(
        &self,
        call: VersionAppendCall,
        display_name: String,
        parent_folder_id: [u8; 32],
        signature: Vec<u8>,
    ) -> RelayFuture<'_, RelayOutcome> {
        let calldata =
            encode_create_file_calldata(&call, &display_name, parent_folder_id, &signature);
        let to = self.file_registry;
        let gas = Some(self.gas_limit);
        Box::pin(async move { self.relayer.submit_and_confirm(to, calldata, gas).await })
    }

    fn relay_append_version(
        &self,
        call: VersionAppendCall,
        signature: Vec<u8>,
    ) -> RelayFuture<'_, RelayOutcome> {
        let calldata = encode_append_version_calldata(&call, &signature);
        let to = self.file_registry;
        let gas = Some(self.gas_limit);
        Box::pin(async move { self.relayer.submit_and_confirm(to, calldata, gas).await })
    }

    fn relay_update_envelope_set(
        &self,
        call: EnvelopeSetUpdateCall,
        signature: Vec<u8>,
    ) -> RelayFuture<'_, RelayOutcome> {
        let calldata = encode_update_envelope_set_calldata(&call, &signature);
        let to = self.access_governance;
        let gas = Some(self.gas_limit);
        Box::pin(async move { self.relayer.submit_and_confirm(to, calldata, gas).await })
    }

    fn reconcile_transaction(&self, tx_hash: [u8; 32]) -> RelayFuture<'_, Option<RelayOutcome>> {
        Box::pin(async move { self.relayer.reconcile_transaction(tx_hash).await })
    }
}

/// PostgreSQL operational state, projection read, and audit boundary for gateway routes.
pub trait GatewayStorePort: Send + Sync {
    fn take_rate_limit_token<'a>(
        &'a self,
        key: &'a str,
        capacity: f64,
        refill_per_second: f64,
    ) -> StoreFuture<'a, bool>;

    fn create_challenge<'a>(
        &'a self,
        challenge: &'a LoginChallenge,
        source_id: &'a str,
        chain_id: u64,
    ) -> StoreFuture<'a, ()>;

    fn record_auth_failure<'a>(
        &'a self,
        action: &'static str,
        source_id: &'a str,
        reason_code: &'static str,
        operation_id: Option<&'a str>,
        chain_id: u64,
    ) -> StoreFuture<'a, ()>;

    fn record_session_validation<'a>(
        &'a self,
        member_id: Option<&'a str>,
        source_id: &'a str,
        outcome: &'static str,
        reason_code: Option<&'static str>,
        chain_id: u64,
    ) -> StoreFuture<'a, ()>;

    fn complete_login<'a>(
        &'a self,
        challenge: &'a LoginChallenge,
        token_hash: &'a [u8; 32],
        session_expires_at: u64,
        source_id: &'a str,
        chain_id: u64,
        block_number: u64,
    ) -> StoreFuture<'a, bool>;

    #[allow(clippy::too_many_arguments)]
    fn record_access_attempt<'a>(
        &'a self,
        member_id: &'a str,
        source_id: &'a str,
        file_id: &'a str,
        version: u64,
        nonce: &'a [u8; 32],
        deadline: u64,
        chain_id: u64,
        block_number: u64,
        authorized: bool,
        reason_code: Option<&'static str>,
    ) -> StoreFuture<'a, bool>;

    #[allow(clippy::too_many_arguments)]
    fn record_content_attempt<'a>(
        &'a self,
        member_id: Option<&'a str>,
        source_id: &'a str,
        file_id: &'a str,
        version: u64,
        chain_id: u64,
        block_number: Option<u64>,
        outcome: &'static str,
        reason_code: Option<&'static str>,
    ) -> StoreFuture<'a, ()>;

    #[allow(clippy::too_many_arguments)]
    fn record_envelope_attempt<'a>(
        &'a self,
        member_id: Option<&'a str>,
        source_id: &'a str,
        file_id: &'a str,
        version: u64,
        chain_id: u64,
        block_number: Option<u64>,
        outcome: &'static str,
        reason_code: Option<&'static str>,
    ) -> StoreFuture<'a, ()>;

    #[allow(clippy::too_many_arguments)]
    fn record_write_attempt<'a>(
        &'a self,
        action: &'static str,
        member_id: Option<&'a str>,
        source_id: &'a str,
        file_id: &'a str,
        version: u64,
        operation_id: Option<&'a str>,
        chain_id: u64,
        block_number: Option<u64>,
        outcome: &'static str,
        reason_code: Option<&'static str>,
        restored_from_version: Option<u64>,
    ) -> StoreFuture<'a, ()>;

    fn member_organization_id<'a>(&'a self, member_id: &'a str) -> StoreFuture<'a, Option<String>>;

    fn record_relayed_transaction<'a>(
        &'a self,
        record: &'a RelayedTransactionRecord,
    ) -> StoreFuture<'a, ()>;

    fn get_relayed_transaction<'a>(
        &'a self,
        tx_hash: &'a str,
    ) -> StoreFuture<'a, Option<RelayedTransactionRecord>>;

    fn update_relayed_transaction_status<'a>(
        &'a self,
        tx_hash: &'a str,
        status: &'a str,
        block_number: Option<u64>,
        block_hash: Option<&'a str>,
        gas_used: Option<u64>,
    ) -> StoreFuture<'a, ()>;

    #[allow(clippy::too_many_arguments)]
    fn record_orphan_blob_candidate<'a>(
        &'a self,
        cid: &'a str,
        blob_kind: &'a str,
        uploader_member_id: &'a str,
        file_id: Option<&'a str>,
        version_number: Option<u64>,
        tx_hash: Option<&'a str>,
        reason: &'a str,
    ) -> StoreFuture<'a, ()>;

    fn mark_blob_referenced<'a>(&'a self, cid: &'a str) -> StoreFuture<'a, ()>;

    fn is_cid_referenced_in_projections<'a>(&'a self, cid: &'a str) -> StoreFuture<'a, bool>;

    fn list_eligible_orphan_candidates<'a>(
        &'a self,
        min_age_seconds: u64,
        limit: u32,
    ) -> StoreFuture<'a, Vec<OrphanBlobCandidate>>;

    fn mark_orphan_blob_unpinned<'a>(&'a self, cid: &'a str) -> StoreFuture<'a, ()>;

    fn active_session_member<'a>(
        &'a self,
        token_hash: &'a [u8; 32],
    ) -> StoreFuture<'a, Option<String>>;

    fn revoke_session<'a>(
        &'a self,
        token_hash: &'a [u8; 32],
        source_id: &'a str,
        chain_id: u64,
    ) -> StoreFuture<'a, bool>;

    fn list_files_and_folders<'a>(
        &'a self,
        chain_id: u64,
        member_id: &'a str,
        organization_id: &'a str,
        parent_folder_id: &'a str,
    ) -> StoreFuture<'a, FileListingResult>;

    fn list_file_versions<'a>(
        &'a self,
        chain_id: u64,
        file_id: &'a str,
        member_id: &'a str,
    ) -> StoreFuture<'a, VersionHistoryResult>;

    fn query_member_audit_events<'a>(
        &'a self,
        member_id: &'a str,
        source_id: &'a str,
        chain_id: u64,
        block_number: u64,
        action_filter: Option<&'a str>,
        limit: u32,
    ) -> StoreFuture<'a, Vec<AuditEventRecord>>;
}

impl GatewayStorePort for GatewayStore {
    fn take_rate_limit_token<'a>(
        &'a self,
        key: &'a str,
        capacity: f64,
        refill_per_second: f64,
    ) -> StoreFuture<'a, bool> {
        Box::pin(self.take_rate_limit_token(key, capacity, refill_per_second))
    }

    fn create_challenge<'a>(
        &'a self,
        challenge: &'a LoginChallenge,
        source_id: &'a str,
        chain_id: u64,
    ) -> StoreFuture<'a, ()> {
        Box::pin(self.create_challenge(challenge, source_id, chain_id))
    }

    fn record_auth_failure<'a>(
        &'a self,
        action: &'static str,
        source_id: &'a str,
        reason_code: &'static str,
        operation_id: Option<&'a str>,
        chain_id: u64,
    ) -> StoreFuture<'a, ()> {
        Box::pin(self.record_auth_failure(action, source_id, reason_code, operation_id, chain_id))
    }

    fn record_session_validation<'a>(
        &'a self,
        member_id: Option<&'a str>,
        source_id: &'a str,
        outcome: &'static str,
        reason_code: Option<&'static str>,
        chain_id: u64,
    ) -> StoreFuture<'a, ()> {
        Box::pin(self.record_session_validation(
            member_id,
            source_id,
            outcome,
            reason_code,
            chain_id,
        ))
    }

    fn complete_login<'a>(
        &'a self,
        challenge: &'a LoginChallenge,
        token_hash: &'a [u8; 32],
        session_expires_at: u64,
        source_id: &'a str,
        chain_id: u64,
        block_number: u64,
    ) -> StoreFuture<'a, bool> {
        Box::pin(self.complete_login(
            challenge,
            token_hash,
            session_expires_at,
            source_id,
            chain_id,
            block_number,
        ))
    }

    fn record_access_attempt<'a>(
        &'a self,
        member_id: &'a str,
        source_id: &'a str,
        file_id: &'a str,
        version: u64,
        nonce: &'a [u8; 32],
        deadline: u64,
        chain_id: u64,
        block_number: u64,
        authorized: bool,
        reason_code: Option<&'static str>,
    ) -> StoreFuture<'a, bool> {
        Box::pin(self.record_access_attempt(
            member_id,
            source_id,
            file_id,
            version,
            nonce,
            deadline,
            chain_id,
            block_number,
            authorized,
            reason_code,
        ))
    }

    fn record_content_attempt<'a>(
        &'a self,
        member_id: Option<&'a str>,
        source_id: &'a str,
        file_id: &'a str,
        version: u64,
        chain_id: u64,
        block_number: Option<u64>,
        outcome: &'static str,
        reason_code: Option<&'static str>,
    ) -> StoreFuture<'a, ()> {
        Box::pin(self.record_content_attempt(
            member_id,
            source_id,
            file_id,
            version,
            chain_id,
            block_number,
            outcome,
            reason_code,
        ))
    }

    fn record_envelope_attempt<'a>(
        &'a self,
        member_id: Option<&'a str>,
        source_id: &'a str,
        file_id: &'a str,
        version: u64,
        chain_id: u64,
        block_number: Option<u64>,
        outcome: &'static str,
        reason_code: Option<&'static str>,
    ) -> StoreFuture<'a, ()> {
        Box::pin(self.record_envelope_attempt(
            member_id,
            source_id,
            file_id,
            version,
            chain_id,
            block_number,
            outcome,
            reason_code,
        ))
    }

    fn record_write_attempt<'a>(
        &'a self,
        action: &'static str,
        member_id: Option<&'a str>,
        source_id: &'a str,
        file_id: &'a str,
        version: u64,
        operation_id: Option<&'a str>,
        chain_id: u64,
        block_number: Option<u64>,
        outcome: &'static str,
        reason_code: Option<&'static str>,
        restored_from_version: Option<u64>,
    ) -> StoreFuture<'a, ()> {
        Box::pin(self.record_write_attempt(
            action,
            member_id,
            source_id,
            file_id,
            version,
            operation_id,
            chain_id,
            block_number,
            outcome,
            reason_code,
            restored_from_version,
        ))
    }

    fn member_organization_id<'a>(&'a self, member_id: &'a str) -> StoreFuture<'a, Option<String>> {
        Box::pin(self.member_organization_id(member_id))
    }

    fn record_relayed_transaction<'a>(
        &'a self,
        record: &'a RelayedTransactionRecord,
    ) -> StoreFuture<'a, ()> {
        Box::pin(self.record_relayed_transaction(record))
    }

    fn get_relayed_transaction<'a>(
        &'a self,
        tx_hash: &'a str,
    ) -> StoreFuture<'a, Option<RelayedTransactionRecord>> {
        Box::pin(self.get_relayed_transaction(tx_hash))
    }

    fn update_relayed_transaction_status<'a>(
        &'a self,
        tx_hash: &'a str,
        status: &'a str,
        block_number: Option<u64>,
        block_hash: Option<&'a str>,
        gas_used: Option<u64>,
    ) -> StoreFuture<'a, ()> {
        Box::pin(self.update_relayed_transaction_status(
            tx_hash,
            status,
            block_number,
            block_hash,
            gas_used,
        ))
    }

    fn record_orphan_blob_candidate<'a>(
        &'a self,
        cid: &'a str,
        blob_kind: &'a str,
        uploader_member_id: &'a str,
        file_id: Option<&'a str>,
        version_number: Option<u64>,
        tx_hash: Option<&'a str>,
        reason: &'a str,
    ) -> StoreFuture<'a, ()> {
        Box::pin(self.record_orphan_blob_candidate(
            cid,
            blob_kind,
            uploader_member_id,
            file_id,
            version_number,
            tx_hash,
            reason,
        ))
    }

    fn mark_blob_referenced<'a>(&'a self, cid: &'a str) -> StoreFuture<'a, ()> {
        Box::pin(self.mark_blob_referenced(cid))
    }

    fn is_cid_referenced_in_projections<'a>(&'a self, cid: &'a str) -> StoreFuture<'a, bool> {
        Box::pin(self.is_cid_referenced_in_projections(cid))
    }

    fn list_eligible_orphan_candidates<'a>(
        &'a self,
        min_age_seconds: u64,
        limit: u32,
    ) -> StoreFuture<'a, Vec<OrphanBlobCandidate>> {
        Box::pin(self.list_eligible_orphan_candidates(min_age_seconds, limit))
    }

    fn mark_orphan_blob_unpinned<'a>(&'a self, cid: &'a str) -> StoreFuture<'a, ()> {
        Box::pin(self.mark_orphan_blob_unpinned(cid))
    }

    fn active_session_member<'a>(
        &'a self,
        token_hash: &'a [u8; 32],
    ) -> StoreFuture<'a, Option<String>> {
        Box::pin(self.active_session_member(token_hash))
    }

    fn revoke_session<'a>(
        &'a self,
        token_hash: &'a [u8; 32],
        source_id: &'a str,
        chain_id: u64,
    ) -> StoreFuture<'a, bool> {
        Box::pin(self.revoke_session(token_hash, source_id, chain_id))
    }

    fn list_files_and_folders<'a>(
        &'a self,
        chain_id: u64,
        member_id: &'a str,
        organization_id: &'a str,
        parent_folder_id: &'a str,
    ) -> StoreFuture<'a, FileListingResult> {
        Box::pin(self.list_files_and_folders(
            chain_id,
            member_id,
            organization_id,
            parent_folder_id,
        ))
    }

    fn list_file_versions<'a>(
        &'a self,
        chain_id: u64,
        file_id: &'a str,
        member_id: &'a str,
    ) -> StoreFuture<'a, VersionHistoryResult> {
        Box::pin(self.list_file_versions(chain_id, file_id, member_id))
    }

    fn query_member_audit_events<'a>(
        &'a self,
        member_id: &'a str,
        source_id: &'a str,
        chain_id: u64,
        block_number: u64,
        action_filter: Option<&'a str>,
        limit: u32,
    ) -> StoreFuture<'a, Vec<AuditEventRecord>> {
        Box::pin(self.query_member_audit_events(
            member_id,
            source_id,
            chain_id,
            block_number,
            action_filter,
            limit,
        ))
    }
}
