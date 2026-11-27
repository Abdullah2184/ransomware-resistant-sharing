use std::{collections::BTreeMap, error::Error, fmt, io::Cursor};

use crypto::{
    ChainId, DataEncryptionKey, Eip712Domain, EnvelopeSetUpdate, HpkeRecipientPublicKey,
    KeyEnvelope, KeyEnvelopeEntry, KeyEnvelopeSet, MAX_ENVELOPE_SET_ENTRIES, UnixDeadline,
    WrapContext, raw_sha256_cid,
};
use domain::{
    AccessReference, DomainError, EnvelopeSetCid, EvmAddress, MemberId, OperationNonce, ProposalId,
    TransactionReceipt,
};
use ports::{
    BlobStore, Clock, KeyCustodyProvider, LedgerPort, ReplicationReceipt,
    SignedEnvelopeUpdateRequest, StorageReader,
};

use crate::{
    download::{map_unwrap_custody_error, read_bounded},
    upload::{map_storage_error, random_nonzero_bytes32},
};

const MAX_ENVELOPE_SET_BYTES: usize = 512 * 1024;

/// Configuration for governed envelope-set updates (sharing without re-encryption).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareConfig {
    pub chain_id: u64,
    pub access_governance: EvmAddress,
    pub min_pin_replicas: usize,
    pub operation_ttl_seconds: u64,
}

impl ShareConfig {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.chain_id == 0 || self.min_pin_replicas == 0 || self.operation_ttl_seconds == 0 {
            return Err(DomainError::Internal);
        }
        Ok(())
    }
}

/// Receipt for a finalized envelope-set pointer update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareReceipt {
    pub old_envelope_set_cid: EnvelopeSetCid,
    pub new_envelope_set_cid: EnvelopeSetCid,
    pub new_revision: u32,
    pub replication: ReplicationReceipt,
    pub transaction: TransactionReceipt,
}

/// Orphaned envelope reference when pinning succeeded but ledger update failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrphanedEnvelopeDetails {
    pub new_envelope_set_cid: EnvelopeSetCid,
    pub cause: DomainError,
}

/// Share errors, preserving the orphan envelope-set CID if chain commit fails after pinning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShareError {
    Domain(DomainError),
    OrphanedEnvelopeUpload(Box<OrphanedEnvelopeDetails>),
}

impl fmt::Display for ShareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(error) => error.fmt(formatter),
            Self::OrphanedEnvelopeUpload(details) => {
                write!(
                    formatter,
                    "new envelope set pinned but ledger update failed ({}); object retained as orphan candidate",
                    details.cause
                )
            }
        }
    }
}

impl Error for ShareError {}

impl From<DomainError> for ShareError {
    fn from(error: DomainError) -> Self {
        Self::Domain(error)
    }
}

/// Shares an existing version by wrapping its DEK for a new active recipient
/// and publishing a new immutable envelope set without re-encrypting ciphertext.
pub struct ShareService<K, B, L, C> {
    custody: K,
    blob_store: B,
    ledger: L,
    clock: C,
    config: ShareConfig,
}

impl<K, B, L, C> ShareService<K, B, L, C>
where
    K: KeyCustodyProvider,
    B: BlobStore,
    L: LedgerPort,
    C: Clock,
{
    pub fn new(custody: K, blob_store: B, ledger: L, clock: C, config: ShareConfig) -> Self {
        Self {
            custody,
            blob_store,
            ledger,
            clock,
            config,
        }
    }

    /// Unwraps the version's DEK as an already-authorized reader, adds (or rotates)
    /// a recipient envelope for `recipient_member_id`, pins the new canonical envelope set,
    /// and submits a signed `EnvelopeSetUpdate`.
    pub async fn share_version_envelope(
        &self,
        access: &AccessReference,
        recipient_member_id: MemberId,
        proposal_id: ProposalId,
    ) -> Result<ShareReceipt, ShareError> {
        self.config.validate()?;
        if recipient_member_id.as_bytes() == &[0; 32] {
            return Err(DomainError::InvalidIdentifier.into());
        }
        let actor = self
            .custody
            .public_identity()
            .await
            .map_err(|_| DomainError::KeyCustodyUnavailable)?;
        let recipient = self
            .ledger
            .get_member(recipient_member_id)
            .await?
            .ok_or(DomainError::Unauthorized)?;
        if !recipient.is_active() {
            return Err(DomainError::MemberSuspended.into());
        }

        let existing_bytes = read_bounded(
            self.blob_store
                .get_envelope_set(&access.envelope_set_cid)
                .await
                .map_err(map_storage_error)?,
            MAX_ENVELOPE_SET_BYTES,
        )
        .await?;
        let actual_existing_cid =
            raw_sha256_cid(&existing_bytes).map_err(|_| DomainError::IntegrityCheckFailed)?;
        if actual_existing_cid.to_string() != access.envelope_set_cid.to_string() {
            return Err(DomainError::IntegrityCheckFailed.into());
        }
        let existing_set = KeyEnvelopeSet::parse_canonical(&existing_bytes)
            .map_err(|_| DomainError::IntegrityCheckFailed)?;
        if existing_set.file_id() != access.file_id
            || existing_set.version_number() != access.version_number
            || existing_set.epoch_id() != access.epoch_id
            || existing_set.revision() != access.envelope_revision
        {
            return Err(DomainError::IntegrityCheckFailed.into());
        }
        // Reject redundant no-op shares when the recipient already has an
        // envelope for their current encryption key version; re-sharing after
        // key rotation (new encryption_key_version) remains allowed.
        if existing_set.envelopes().iter().any(|entry| {
            entry.member_id() == recipient.member_id
                && entry.encryption_key_version() == recipient.encryption_key_version
        }) {
            return Err(DomainError::ContractRejected.into());
        }

        let actor_entry = existing_set
            .envelopes()
            .iter()
            .find(|entry| {
                entry.member_id() == actor.member_id
                    && entry.encryption_key_version() == actor.encryption_key_version
            })
            .ok_or(DomainError::Unauthorized)?;
        let actor_wrap_context = WrapContext::new(
            access.file_id,
            access.version_number,
            access.epoch_id,
            actor.member_id,
            actor.encryption_key_version,
        );
        let dek_secret = self
            .custody
            .unwrap_dek(
                &actor.encryption_key_id,
                actor_entry.envelope(),
                actor_wrap_context,
            )
            .await
            .map_err(map_unwrap_custody_error)?;
        let dek = DataEncryptionKey::from_secret(dek_secret);

        let recipient_public_key =
            HpkeRecipientPublicKey::from_bytes(&recipient.encryption_public_key)
                .map_err(|_| DomainError::UnsupportedCryptoSuite)?;
        let recipient_wrap_context = WrapContext::new(
            access.file_id,
            access.version_number,
            access.epoch_id,
            recipient.member_id,
            recipient.encryption_key_version,
        );
        let wrapped = KeyEnvelope::wrap(&dek, &recipient_public_key, recipient_wrap_context)
            .map_err(|_| DomainError::Internal)?;
        drop(dek);

        let mut merged = BTreeMap::new();
        for entry in existing_set.envelopes() {
            merged.insert(entry.member_id(), entry.clone());
        }
        merged.insert(
            recipient.member_id,
            KeyEnvelopeEntry::new(
                recipient.member_id,
                recipient.encryption_key_version,
                wrapped,
            ),
        );
        if merged.len() > MAX_ENVELOPE_SET_ENTRIES {
            return Err(DomainError::InvalidManifest.into());
        }
        let new_revision = existing_set
            .revision()
            .checked_add(1)
            .ok_or(DomainError::InvalidManifest)?;
        let new_set = KeyEnvelopeSet::new(
            access.file_id,
            access.version_number,
            access.epoch_id,
            new_revision,
            merged.into_values().collect(),
        )
        .map_err(|_| DomainError::InvalidManifest)?;
        let new_bytes = new_set
            .canonical_bytes()
            .map_err(|_| DomainError::InvalidManifest)?;
        let new_len = u64::try_from(new_bytes.len()).map_err(|_| DomainError::Internal)?;

        let stored = self
            .blob_store
            .put_envelope_set(
                Box::pin(Cursor::new(new_bytes)) as StorageReader,
                new_len,
                self.config.min_pin_replicas,
            )
            .await
            .map_err(map_storage_error)?;
        if !stored.replication.is_satisfied() {
            return Err(DomainError::ReplicationInsufficient.into());
        }

        let operation_nonce = OperationNonce::from_bytes(random_nonzero_bytes32()?);
        let now = self.clock.now_unix_seconds()?;
        let deadline = now
            .checked_add(self.config.operation_ttl_seconds)
            .ok_or(DomainError::Internal)?;
        let unix_deadline =
            UnixDeadline::from_unix_seconds(deadline).map_err(|_| DomainError::ExpiredRequest)?;

        let update = EnvelopeSetUpdate::new(
            access.file_id,
            access.version_number,
            access.epoch_id,
            access.envelope_set_cid.clone(),
            stored.cid.clone(),
            actor.member_id,
            proposal_id,
            operation_nonce,
            unix_deadline,
        )
        .map_err(|_| DomainError::InvalidManifest)?;
        let domain = Eip712Domain::access_governance(
            ChainId::from_u64(self.config.chain_id),
            self.config.access_governance,
        );
        let digest = update.digest(&domain).map_err(|_| DomainError::Internal)?;
        let signature = self
            .custody
            .sign_typed_digest(&actor.signing_key_id, &digest)
            .await
            .map_err(|_| DomainError::KeyCustodyUnavailable)?;

        let request = SignedEnvelopeUpdateRequest {
            file_id: access.file_id,
            version_number: access.version_number,
            epoch_id: access.epoch_id,
            old_envelope_set_cid: access.envelope_set_cid.clone(),
            new_envelope_set_cid: stored.cid.clone(),
            actor_member_id: actor.member_id,
            proposal_id,
            operation_nonce,
            deadline,
            signature,
        };
        let transaction = match self.ledger.update_envelope_set(&request).await {
            Ok(receipt) if receipt.finalized && receipt.succeeded => receipt,
            Ok(_) => {
                return Err(ShareError::OrphanedEnvelopeUpload(Box::new(
                    OrphanedEnvelopeDetails {
                        new_envelope_set_cid: stored.cid,
                        cause: DomainError::ContractRejected,
                    },
                )));
            }
            Err(cause) => {
                return Err(ShareError::OrphanedEnvelopeUpload(Box::new(
                    OrphanedEnvelopeDetails {
                        new_envelope_set_cid: stored.cid,
                        cause,
                    },
                )));
            }
        };

        Ok(ShareReceipt {
            old_envelope_set_cid: access.envelope_set_cid.clone(),
            new_envelope_set_cid: stored.cid,
            new_revision,
            replication: stored.replication,
            transaction,
        })
    }
}
