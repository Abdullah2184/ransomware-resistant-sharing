use std::{collections::BTreeMap, error::Error, fmt, io::Cursor, sync::Arc};

use crypto::{
    ChainId, ChunkEncryptor, CryptoError, DEFAULT_CHUNK_SIZE_BYTES, DataEncryptionKey,
    Eip712Domain, EncryptedChunkRef, EncryptedFileManifest, EncryptionContext,
    HpkeRecipientPublicKey, KeyEnvelope, KeyEnvelopeEntry, KeyEnvelopeSet,
    MAX_ENVELOPE_SET_ENTRIES, NoncePrefix, UnixDeadline, VersionAppend, WrapContext,
    chunk_count_for_len, encrypt_private_metadata, raw_sha256_cid,
};
use domain::{
    ContentCid, DomainError, EnvelopeSetCid, EpochId, EvmAddress, FileId, FileStatus, FolderId,
    ManifestHash, MemberId, OperationNonce, PublicMemberIdentity, TransactionReceipt,
    VersionNumber,
};
use ports::{
    BlobStore, Clock, ContentChunk, ContentPackage, KeyCustodyProvider, LedgerPort,
    PreUploadScanner, ReplicationReceipt, ScanVerdict, SignedAppendVersionRequest,
    SignedCreateFileRequest, StorageError, StorageReader,
};

/// Configuration for client-side encryption, pinning, and version submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadConfig {
    pub chain_id: u64,
    pub file_registry: EvmAddress,
    pub min_pin_replicas: usize,
    pub chunk_size_bytes: usize,
    pub max_file_bytes: u64,
    pub operation_ttl_seconds: u64,
}

impl UploadConfig {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.chain_id == 0
            || self.min_pin_replicas == 0
            || self.chunk_size_bytes == 0
            || self.chunk_size_bytes > DEFAULT_CHUNK_SIZE_BYTES
            || self.max_file_bytes == 0
            || self.operation_ttl_seconds == 0
        {
            return Err(DomainError::Internal);
        }
        Ok(())
    }
}

/// Receipt returned only after IPFS pinning quorum and finalized chain commit succeed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadReceipt {
    pub file_id: FileId,
    pub version_number: VersionNumber,
    pub parent_manifest_hash: ManifestHash,
    pub manifest_hash: ManifestHash,
    pub epoch_id: EpochId,
    pub content_cid: ContentCid,
    pub envelope_set_cid: EnvelopeSetCid,
    pub content_replication: ReplicationReceipt,
    pub envelope_replication: ReplicationReceipt,
    pub transaction: TransactionReceipt,
    pub scan_warning: Option<String>,
}

/// Orphaned storage references returned when pinning succeeded but ledger commit failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrphanedUploadDetails {
    pub content_cid: ContentCid,
    pub envelope_set_cid: EnvelopeSetCid,
    pub cause: DomainError,
}

/// Upload errors, explicitly preserving orphan CIDs if chain commit fails after pinning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UploadError {
    Domain(DomainError),
    BlockedByScanner { reason: String },
    OrphanedUpload(Box<OrphanedUploadDetails>),
}

impl UploadError {
    pub const fn domain_error(&self) -> DomainError {
        match self {
            Self::Domain(error) => *error,
            Self::BlockedByScanner { .. } => DomainError::Unauthorized,
            Self::OrphanedUpload(_) => DomainError::OrphanedUpload,
        }
    }
}

impl fmt::Display for UploadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(error) => error.fmt(formatter),
            Self::BlockedByScanner { reason } => {
                write!(formatter, "upload blocked by pre-upload scanner: {reason}")
            }
            Self::OrphanedUpload(details) => {
                write!(
                    formatter,
                    "encrypted objects pinned but ledger commit failed ({}); objects retained as orphan candidates",
                    details.cause
                )
            }
        }
    }
}

impl Error for UploadError {}

impl From<DomainError> for UploadError {
    fn from(error: DomainError) -> Self {
        Self::Domain(error)
    }
}

/// Client-side upload, modify, and append-only restore workflow service.
pub struct UploadService<K, B, L, C> {
    custody: K,
    blob_store: B,
    ledger: L,
    clock: C,
    config: UploadConfig,
    scanner: Option<Arc<dyn PreUploadScanner>>,
}

impl<K, B, L, C> UploadService<K, B, L, C>
where
    K: KeyCustodyProvider,
    B: BlobStore,
    L: LedgerPort,
    C: Clock,
{
    pub fn new(custody: K, blob_store: B, ledger: L, clock: C, config: UploadConfig) -> Self {
        Self {
            custody,
            blob_store,
            ledger,
            clock,
            config,
            scanner: None,
        }
    }

    /// Attaches an optional endpoint-local pre-upload plaintext scanner.
    ///
    /// Runs strictly on the client before encryption; disabled by default.
    pub fn with_scanner(mut self, scanner: Arc<dyn PreUploadScanner>) -> Self {
        self.scanner = Some(scanner);
        self
    }

    async fn run_pre_upload_scan(
        &self,
        label: &str,
        plaintext: &[u8],
    ) -> Result<Option<String>, UploadError> {
        let Some(scanner) = &self.scanner else {
            return Ok(None);
        };
        match scanner.evaluate(label, plaintext).await? {
            ScanVerdict::Allow => Ok(None),
            ScanVerdict::AllowWithWarning { reason } => Ok(Some(reason)),
            ScanVerdict::Block { reason } => Err(UploadError::BlockedByScanner { reason }),
        }
    }

    /// Encrypts plaintext locally with a fresh DEK, pins content & envelope set,
    /// then registers a new file (version 1) on-chain.
    pub async fn create_file(
        &self,
        file_id: Option<FileId>,
        display_name: String,
        parent_folder_id: FolderId,
        plaintext: &[u8],
        private_metadata: Option<&[u8]>,
        reader_member_ids: &[MemberId],
    ) -> Result<UploadReceipt, UploadError> {
        self.config.validate()?;
        if display_name.is_empty()
            || display_name.len() > 255
            || display_name.chars().any(char::is_control)
        {
            return Err(DomainError::InvalidManifest.into());
        }
        let scan_warning = self.run_pre_upload_scan(&display_name, plaintext).await?;
        let file_id = match file_id {
            Some(id) if id.as_bytes() != &[0; 32] => id,
            Some(_) => return Err(DomainError::InvalidIdentifier.into()),
            None => FileId::from_bytes(random_nonzero_bytes32()?),
        };
        let identity = self
            .custody
            .public_identity()
            .await
            .map_err(|_| DomainError::KeyCustodyUnavailable)?;
        let recipients = self
            .resolve_active_recipients(&identity, reader_member_ids)
            .await?;

        let prepared = self
            .encrypt_and_pin(
                file_id,
                VersionNumber::ONE,
                ManifestHash::ZERO,
                plaintext,
                private_metadata,
                &recipients,
            )
            .await?;

        let operation_nonce = OperationNonce::from_bytes(random_nonzero_bytes32()?);
        let deadline = self.operation_deadline()?;
        let signature = self
            .sign_append(
                &identity,
                file_id,
                VersionNumber::ONE,
                ManifestHash::ZERO,
                prepared.manifest_hash,
                &prepared.content_cid,
                &prepared.envelope_set_cid,
                prepared.epoch_id,
                operation_nonce,
                deadline,
            )
            .await?;

        let request = SignedCreateFileRequest {
            file_id,
            display_name,
            parent_folder_id,
            version_number: VersionNumber::ONE,
            parent_manifest_hash: ManifestHash::ZERO,
            manifest_hash: prepared.manifest_hash,
            content_cid: prepared.content_cid.clone(),
            envelope_set_cid: prepared.envelope_set_cid.clone(),
            epoch_id: prepared.epoch_id,
            author_member_id: identity.member_id,
            signer_address: identity.signing_address,
            operation_nonce,
            deadline,
            signature,
        };
        let transaction = match self.ledger.create_file(&request).await {
            Ok(receipt) if receipt.finalized && receipt.succeeded => receipt,
            Ok(_) => {
                return Err(UploadError::OrphanedUpload(Box::new(
                    OrphanedUploadDetails {
                        content_cid: prepared.content_cid,
                        envelope_set_cid: prepared.envelope_set_cid,
                        cause: DomainError::ContractRejected,
                    },
                )));
            }
            Err(cause) => {
                return Err(UploadError::OrphanedUpload(Box::new(
                    OrphanedUploadDetails {
                        content_cid: prepared.content_cid,
                        envelope_set_cid: prepared.envelope_set_cid,
                        cause,
                    },
                )));
            }
        };

        Ok(UploadReceipt {
            file_id,
            version_number: VersionNumber::ONE,
            parent_manifest_hash: ManifestHash::ZERO,
            manifest_hash: prepared.manifest_hash,
            epoch_id: prepared.epoch_id,
            content_cid: prepared.content_cid,
            envelope_set_cid: prepared.envelope_set_cid,
            content_replication: prepared.content_replication,
            envelope_replication: prepared.envelope_replication,
            transaction,
            scan_warning,
        })
    }

    /// Encrypts updated plaintext under a fresh DEK and appends a new version
    /// parented to the observed current head.
    pub async fn append_version(
        &self,
        file_id: FileId,
        expected_parent_head: Option<(VersionNumber, ManifestHash)>,
        plaintext: &[u8],
        private_metadata: Option<&[u8]>,
        reader_member_ids: &[MemberId],
    ) -> Result<UploadReceipt, UploadError> {
        self.config.validate()?;
        if file_id.as_bytes() == &[0; 32] {
            return Err(DomainError::InvalidIdentifier.into());
        }
        let scan_label = file_id.to_string();
        let scan_warning = self.run_pre_upload_scan(&scan_label, plaintext).await?;
        let head = self
            .ledger
            .get_file_head(file_id)
            .await?
            .ok_or(DomainError::ContractRejected)?;
        if head.status != FileStatus::Active {
            return Err(DomainError::Unauthorized.into());
        }
        if let Some((expected_version, expected_manifest)) = expected_parent_head
            && (head.current_version != expected_version
                || head.current_head_manifest_hash != expected_manifest)
        {
            return Err(DomainError::StaleHead.into());
        }

        let next_version = head.current_version.next()?;
        let identity = self
            .custody
            .public_identity()
            .await
            .map_err(|_| DomainError::KeyCustodyUnavailable)?;
        let recipients = self
            .resolve_active_recipients(&identity, reader_member_ids)
            .await?;

        let prepared = self
            .encrypt_and_pin(
                file_id,
                next_version,
                head.current_head_manifest_hash,
                plaintext,
                private_metadata,
                &recipients,
            )
            .await?;

        let operation_nonce = OperationNonce::from_bytes(random_nonzero_bytes32()?);
        let deadline = self.operation_deadline()?;
        let signature = self
            .sign_append(
                &identity,
                file_id,
                next_version,
                head.current_head_manifest_hash,
                prepared.manifest_hash,
                &prepared.content_cid,
                &prepared.envelope_set_cid,
                prepared.epoch_id,
                operation_nonce,
                deadline,
            )
            .await?;

        let request = SignedAppendVersionRequest {
            file_id,
            version_number: next_version,
            parent_manifest_hash: head.current_head_manifest_hash,
            manifest_hash: prepared.manifest_hash,
            content_cid: prepared.content_cid.clone(),
            envelope_set_cid: prepared.envelope_set_cid.clone(),
            epoch_id: prepared.epoch_id,
            author_member_id: identity.member_id,
            signer_address: identity.signing_address,
            operation_nonce,
            deadline,
            signature,
        };
        let transaction = match self.ledger.append_version(&request).await {
            Ok(receipt) if receipt.finalized && receipt.succeeded => receipt,
            Ok(_) => {
                return Err(UploadError::OrphanedUpload(Box::new(
                    OrphanedUploadDetails {
                        content_cid: prepared.content_cid,
                        envelope_set_cid: prepared.envelope_set_cid,
                        cause: DomainError::ContractRejected,
                    },
                )));
            }
            Err(cause) => {
                return Err(UploadError::OrphanedUpload(Box::new(
                    OrphanedUploadDetails {
                        content_cid: prepared.content_cid,
                        envelope_set_cid: prepared.envelope_set_cid,
                        cause,
                    },
                )));
            }
        };

        Ok(UploadReceipt {
            file_id,
            version_number: next_version,
            parent_manifest_hash: head.current_head_manifest_hash,
            manifest_hash: prepared.manifest_hash,
            epoch_id: prepared.epoch_id,
            content_cid: prepared.content_cid,
            envelope_set_cid: prepared.envelope_set_cid,
            content_replication: prepared.content_replication,
            envelope_replication: prepared.envelope_replication,
            transaction,
            scan_warning,
        })
    }

    /// Append-only restore: re-encrypts verified historical plaintext under a fresh DEK
    /// and appends it against the current head without deleting or rewinding history.
    pub async fn restore_version(
        &self,
        file_id: FileId,
        expected_current_head: Option<(VersionNumber, ManifestHash)>,
        recovered_plaintext: &[u8],
        private_metadata: Option<&[u8]>,
        current_reader_member_ids: &[MemberId],
    ) -> Result<UploadReceipt, UploadError> {
        self.append_version(
            file_id,
            expected_current_head,
            recovered_plaintext,
            private_metadata,
            current_reader_member_ids,
        )
        .await
    }

    async fn resolve_active_recipients(
        &self,
        author_custody: &ports::PublicIdentityKeys,
        reader_member_ids: &[MemberId],
    ) -> Result<Vec<PublicMemberIdentity>, DomainError> {
        let mut unique = BTreeMap::new();
        for &member_id in std::iter::once(&author_custody.member_id).chain(reader_member_ids.iter())
        {
            if member_id.as_bytes() == &[0; 32] {
                return Err(DomainError::InvalidIdentifier);
            }
            if unique.contains_key(&member_id) {
                continue;
            }
            let identity = self
                .ledger
                .get_member(member_id)
                .await?
                .ok_or(DomainError::Unauthorized)?;
            if !identity.is_active() {
                return Err(DomainError::MemberSuspended);
            }
            // Fail fast before pinning if local custody holds a stale signing key.
            if member_id == author_custody.member_id
                && identity.signing_address != author_custody.signing_address
            {
                return Err(DomainError::Unauthorized);
            }
            unique.insert(member_id, identity);
        }
        if unique.len() > MAX_ENVELOPE_SET_ENTRIES {
            return Err(DomainError::InvalidManifest);
        }
        Ok(unique.into_values().collect())
    }

    async fn encrypt_and_pin(
        &self,
        file_id: FileId,
        version_number: VersionNumber,
        parent_manifest_hash: ManifestHash,
        plaintext: &[u8],
        private_metadata: Option<&[u8]>,
        recipients: &[PublicMemberIdentity],
    ) -> Result<PreparedUpload, DomainError> {
        let plaintext_len = u64::try_from(plaintext.len()).map_err(|_| DomainError::Internal)?;
        if plaintext_len > self.config.max_file_bytes {
            return Err(DomainError::InvalidManifest);
        }

        let dek = DataEncryptionKey::generate().map_err(|_| DomainError::Internal)?;
        let epoch_id = EpochId::from_bytes(random_nonzero_bytes32()?);
        let nonce_prefix = NoncePrefix::generate().map_err(|_| DomainError::Internal)?;
        let total_chunks = chunk_count_for_len(plaintext_len, self.config.chunk_size_bytes)
            .map_err(|_| DomainError::InvalidManifest)?;
        let context = EncryptionContext::new(file_id, version_number, epoch_id);

        let encrypted_private_metadata = private_metadata
            .map(|metadata| {
                encrypt_private_metadata(&dek, nonce_prefix, context, total_chunks, metadata)
            })
            .transpose()
            .map_err(|err| match err {
                CryptoError::InvalidManifest => DomainError::InvalidManifest,
                _ => DomainError::Internal,
            })?;

        let mut entries = Vec::with_capacity(recipients.len());
        for recipient in recipients {
            let public_key = HpkeRecipientPublicKey::from_bytes(&recipient.encryption_public_key)
                .map_err(|_| DomainError::UnsupportedCryptoSuite)?;
            let wrap_context = WrapContext::new(
                file_id,
                version_number,
                epoch_id,
                recipient.member_id,
                recipient.encryption_key_version,
            );
            let wrapped = KeyEnvelope::wrap(&dek, &public_key, wrap_context)
                .map_err(|_| DomainError::Internal)?;
            entries.push(KeyEnvelopeEntry::new(
                recipient.member_id,
                recipient.encryption_key_version,
                wrapped,
            ));
        }
        let envelope_set = KeyEnvelopeSet::new(file_id, version_number, epoch_id, 1, entries)
            .map_err(|_| DomainError::InvalidManifest)?;
        let envelope_bytes = envelope_set
            .canonical_bytes()
            .map_err(|_| DomainError::InvalidManifest)?;

        let mut encryptor = ChunkEncryptor::new(
            dek,
            nonce_prefix,
            context,
            self.config.chunk_size_bytes,
            total_chunks,
        )
        .map_err(|_| DomainError::InvalidManifest)?;
        let mut chunk_refs = Vec::with_capacity(total_chunks as usize);
        let mut content_chunks = Vec::with_capacity(total_chunks as usize);
        for slice in plaintext.chunks(self.config.chunk_size_bytes) {
            let encrypted = encryptor
                .encrypt_next(slice)
                .map_err(|_| DomainError::Internal)?;
            let bytes = encrypted.ciphertext_and_tag().to_vec();
            let cid = raw_sha256_cid(&bytes).map_err(|_| DomainError::Internal)?;
            let byte_len = u64::try_from(bytes.len()).map_err(|_| DomainError::Internal)?;
            chunk_refs.push(
                EncryptedChunkRef::new(encrypted.index(), cid, byte_len)
                    .map_err(|_| DomainError::InvalidManifest)?,
            );
            content_chunks.push(ContentChunk::new(
                encrypted.index(),
                byte_len,
                Box::pin(Cursor::new(bytes)) as StorageReader,
            ));
        }
        encryptor.finish().map_err(|_| DomainError::Internal)?;

        let chunk_size_u32 = u32::try_from(self.config.chunk_size_bytes)
            .map_err(|_| DomainError::InvalidManifest)?;
        let manifest = EncryptedFileManifest::new(
            file_id,
            version_number,
            parent_manifest_hash,
            epoch_id,
            nonce_prefix,
            chunk_size_u32,
            chunk_refs,
            encrypted_private_metadata,
        )
        .map_err(|_| DomainError::InvalidManifest)?;
        let manifest_hash = manifest
            .manifest_hash()
            .map_err(|_| DomainError::InvalidManifest)?;
        let package = ContentPackage::new(manifest, content_chunks).map_err(map_storage_error)?;

        let stored_content = self
            .blob_store
            .put_content(package, self.config.min_pin_replicas)
            .await
            .map_err(map_storage_error)?;
        if !stored_content.replication.is_satisfied() {
            return Err(DomainError::ReplicationInsufficient);
        }

        let envelope_len =
            u64::try_from(envelope_bytes.len()).map_err(|_| DomainError::Internal)?;
        let stored_envelope = self
            .blob_store
            .put_envelope_set(
                Box::pin(Cursor::new(envelope_bytes)) as StorageReader,
                envelope_len,
                self.config.min_pin_replicas,
            )
            .await
            .map_err(map_storage_error)?;
        if !stored_envelope.replication.is_satisfied() {
            return Err(DomainError::ReplicationInsufficient);
        }

        Ok(PreparedUpload {
            epoch_id,
            manifest_hash,
            content_cid: stored_content.cid,
            envelope_set_cid: stored_envelope.cid,
            content_replication: stored_content.replication,
            envelope_replication: stored_envelope.replication,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn sign_append(
        &self,
        identity: &ports::PublicIdentityKeys,
        file_id: FileId,
        version_number: VersionNumber,
        parent_manifest_hash: ManifestHash,
        manifest_hash: ManifestHash,
        content_cid: &ContentCid,
        envelope_set_cid: &EnvelopeSetCid,
        epoch_id: EpochId,
        operation_nonce: OperationNonce,
        deadline: u64,
    ) -> Result<ports::EvmSignature, DomainError> {
        let unix_deadline =
            UnixDeadline::from_unix_seconds(deadline).map_err(|_| DomainError::ExpiredRequest)?;
        let append = VersionAppend::new(
            file_id,
            version_number,
            parent_manifest_hash,
            manifest_hash,
            content_cid.clone(),
            envelope_set_cid.clone(),
            epoch_id,
            identity.member_id,
            identity.signing_address,
            operation_nonce,
            unix_deadline,
        )
        .map_err(|_| DomainError::InvalidManifest)?;
        let domain = Eip712Domain::file_registry(
            ChainId::from_u64(self.config.chain_id),
            self.config.file_registry,
        );
        let digest = append.digest(&domain).map_err(|_| DomainError::Internal)?;
        self.custody
            .sign_typed_digest(&identity.signing_key_id, &digest)
            .await
            .map_err(|_| DomainError::KeyCustodyUnavailable)
    }

    fn operation_deadline(&self) -> Result<u64, DomainError> {
        let now = self.clock.now_unix_seconds()?;
        now.checked_add(self.config.operation_ttl_seconds)
            .ok_or(DomainError::Internal)
    }
}

struct PreparedUpload {
    epoch_id: EpochId,
    manifest_hash: ManifestHash,
    content_cid: ContentCid,
    envelope_set_cid: EnvelopeSetCid,
    content_replication: ReplicationReceipt,
    envelope_replication: ReplicationReceipt,
}

pub(crate) fn random_nonzero_bytes32() -> Result<[u8; 32], DomainError> {
    loop {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| DomainError::Internal)?;
        if bytes != [0; 32] {
            return Ok(bytes);
        }
    }
}

pub(crate) fn map_storage_error(error: StorageError) -> DomainError {
    match error {
        StorageError::ReplicationInsufficient => DomainError::ReplicationInsufficient,
        StorageError::IntegrityCheckFailed => DomainError::IntegrityCheckFailed,
        StorageError::InvalidPackage
        | StorageError::InvalidCid
        | StorageError::SizeLimitExceeded => DomainError::InvalidManifest,
        StorageError::InvalidReplicaCount => DomainError::Internal,
        StorageError::TransportUnavailable
        | StorageError::InvalidResponse
        | StorageError::TimedOut => DomainError::StorageUnavailable,
    }
}
