use crypto::{
    AccessLookup, ChainId, ChunkDecryptor, DataEncryptionKey, Eip712Domain, EncryptedChunk,
    EncryptedFileManifest, EncryptionContext, KeyEnvelopeSet, UnixDeadline, WrapContext,
    decrypt_private_metadata, raw_sha256_cid,
};
use domain::{AccessReference, DomainError, EvmAddress, FileId, ManifestHash, VersionNumber};
use ports::{
    BlobStore, Clock, CustodyError, KeyCustodyProvider, LedgerPort, SignedAccessLookupRequest,
};
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

use crate::upload::{map_storage_error, random_nonzero_bytes32};

const MAX_ENVELOPE_SET_BYTES: usize = 512 * 1024;

/// Configuration for signed access lookups and local decryption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadConfig {
    pub chain_id: u64,
    pub access_governance: EvmAddress,
    pub operation_ttl_seconds: u64,
}

impl DownloadConfig {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.chain_id == 0 || self.operation_ttl_seconds == 0 {
            return Err(DomainError::Internal);
        }
        Ok(())
    }
}

/// Verified encrypted content package extracted from IPFS storage for local decryption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedPackageBytes {
    pub manifest_bytes: Vec<u8>,
    pub chunks: Vec<(u32, Vec<u8>)>,
}

/// Verified decrypted plaintext and optional decrypted private metadata.
pub struct DecryptedVersion {
    pub access: AccessReference,
    pub manifest_hash: ManifestHash,
    pub plaintext: Zeroizing<Vec<u8>>,
    pub private_metadata: Option<Zeroizing<Vec<u8>>>,
}

/// Client-side authorized retrieval and verified decryption service.
pub struct DownloadService<K, B, L, C> {
    custody: K,
    blob_store: B,
    ledger: L,
    clock: C,
    config: DownloadConfig,
}

impl<K, B, L, C> DownloadService<K, B, L, C>
where
    K: KeyCustodyProvider,
    B: BlobStore,
    L: LedgerPort,
    C: Clock,
{
    pub fn new(custody: K, blob_store: B, ledger: L, clock: C, config: DownloadConfig) -> Self {
        Self {
            custody,
            blob_store,
            ledger,
            clock,
            config,
        }
    }

    /// Signs an EIP-712 `AccessLookup` request and obtains authoritative CID references.
    pub async fn authorize_version(
        &self,
        file_id: FileId,
        version_number: VersionNumber,
    ) -> Result<AccessReference, DomainError> {
        self.config.validate()?;
        if file_id.as_bytes() == &[0; 32] {
            return Err(DomainError::InvalidIdentifier);
        }
        let identity = self
            .custody
            .public_identity()
            .await
            .map_err(|_| DomainError::KeyCustodyUnavailable)?;
        let operation_nonce = domain::OperationNonce::from_bytes(random_nonzero_bytes32()?);
        let now = self.clock.now_unix_seconds()?;
        let deadline = now
            .checked_add(self.config.operation_ttl_seconds)
            .ok_or(DomainError::Internal)?;
        let unix_deadline =
            UnixDeadline::from_unix_seconds(deadline).map_err(|_| DomainError::ExpiredRequest)?;

        let lookup = AccessLookup::new(
            identity.member_id,
            file_id,
            version_number,
            identity.encryption_key_version,
            operation_nonce,
            unix_deadline,
        )
        .map_err(|_| DomainError::InvalidManifest)?;
        let domain = Eip712Domain::access_governance(
            ChainId::from_u64(self.config.chain_id),
            self.config.access_governance,
        );
        let digest = lookup.digest(&domain).map_err(|_| DomainError::Internal)?;
        let signature = self
            .custody
            .sign_typed_digest(&identity.signing_key_id, &digest)
            .await
            .map_err(|_| DomainError::KeyCustodyUnavailable)?;

        let request = SignedAccessLookupRequest {
            member_id: identity.member_id,
            file_id,
            version_number,
            encryption_key_version: identity.encryption_key_version,
            operation_nonce,
            deadline,
            signature,
        };
        self.ledger.authorize_read(&request).await
    }

    /// Fetches the canonical envelope set for an authorized reference, unwraps the DEK
    /// via key custody, validates the manifest and every chunk CID, and decrypts all chunks.
    pub async fn decrypt_authorized_package(
        &self,
        access: AccessReference,
        expected_manifest_hash: Option<ManifestHash>,
        package: &EncryptedPackageBytes,
    ) -> Result<DecryptedVersion, DomainError> {
        let identity = self
            .custody
            .public_identity()
            .await
            .map_err(|_| DomainError::KeyCustodyUnavailable)?;

        let envelope_bytes = read_bounded(
            self.blob_store
                .get_envelope_set(&access.envelope_set_cid)
                .await
                .map_err(map_storage_error)?,
            MAX_ENVELOPE_SET_BYTES,
        )
        .await?;
        let actual_envelope_cid =
            raw_sha256_cid(&envelope_bytes).map_err(|_| DomainError::IntegrityCheckFailed)?;
        if actual_envelope_cid.to_string() != access.envelope_set_cid.to_string() {
            return Err(DomainError::IntegrityCheckFailed);
        }
        let envelope_set = KeyEnvelopeSet::parse_canonical(&envelope_bytes)
            .map_err(|_| DomainError::IntegrityCheckFailed)?;
        if envelope_set.file_id() != access.file_id
            || envelope_set.version_number() != access.version_number
            || envelope_set.epoch_id() != access.epoch_id
            || envelope_set.revision() != access.envelope_revision
        {
            return Err(DomainError::IntegrityCheckFailed);
        }

        let recipient_entry = envelope_set
            .envelopes()
            .iter()
            .find(|entry| {
                entry.member_id() == identity.member_id
                    && entry.encryption_key_version() == identity.encryption_key_version
            })
            .ok_or(DomainError::Unauthorized)?;

        // Verify the untrusted manifest, manifest hash, chunk layout, and every
        // chunk CID BEFORE invoking key custody so corrupted packages never
        // unwrap a DEK into client memory (§5.5, §9.3, §14).
        let manifest = EncryptedFileManifest::parse_canonical(&package.manifest_bytes)
            .map_err(|_| DomainError::InvalidManifest)?;
        if manifest.file_id() != access.file_id
            || manifest.version_number() != access.version_number
            || manifest.epoch_id() != access.epoch_id
        {
            return Err(DomainError::IntegrityCheckFailed);
        }
        let manifest_hash = manifest
            .manifest_hash()
            .map_err(|_| DomainError::InvalidManifest)?;
        if access.manifest_hash == ManifestHash::ZERO || manifest_hash != access.manifest_hash {
            return Err(DomainError::IntegrityCheckFailed);
        }
        if let Some(expected) = expected_manifest_hash
            && manifest_hash != expected
        {
            return Err(DomainError::IntegrityCheckFailed);
        }
        if package.chunks.len() != manifest.chunks().len() {
            return Err(DomainError::IntegrityCheckFailed);
        }
        for (manifest_chunk, (chunk_index, chunk_bytes)) in
            manifest.chunks().iter().zip(&package.chunks)
        {
            if *chunk_index != manifest_chunk.index()
                || u64::try_from(chunk_bytes.len()).ok() != Some(manifest_chunk.ciphertext_bytes())
            {
                return Err(DomainError::IntegrityCheckFailed);
            }
            let actual_cid =
                raw_sha256_cid(chunk_bytes).map_err(|_| DomainError::IntegrityCheckFailed)?;
            if actual_cid != *manifest_chunk.cid() {
                return Err(DomainError::IntegrityCheckFailed);
            }
        }

        let context = EncryptionContext::new(
            manifest.file_id(),
            manifest.version_number(),
            manifest.epoch_id(),
        );
        let chunk_size = usize::try_from(manifest.chunk_size_bytes())
            .map_err(|_| DomainError::InvalidManifest)?;

        let wrap_context = WrapContext::new(
            access.file_id,
            access.version_number,
            access.epoch_id,
            identity.member_id,
            identity.encryption_key_version,
        );
        let dek_secret = self
            .custody
            .unwrap_dek(
                &identity.encryption_key_id,
                recipient_entry.envelope(),
                wrap_context,
            )
            .await
            .map_err(map_unwrap_custody_error)?;

        let dek = DataEncryptionKey::from_secret(dek_secret);
        let private_metadata = manifest
            .private_metadata()
            .map(|encrypted| {
                decrypt_private_metadata(
                    &dek,
                    manifest.nonce_prefix(),
                    context,
                    manifest.chunk_count(),
                    encrypted,
                )
            })
            .transpose()
            .map_err(|_| DomainError::IntegrityCheckFailed)?;

        let mut decryptor = ChunkDecryptor::new(
            dek,
            manifest.nonce_prefix(),
            context,
            chunk_size,
            manifest.chunk_count(),
        )
        .map_err(|_| DomainError::InvalidManifest)?;

        let mut plaintext = Zeroizing::new(Vec::new());
        for (chunk_index, chunk_bytes) in &package.chunks {
            let chunk = build_encrypted_chunk(*chunk_index, chunk_bytes.clone());
            let decrypted = decryptor
                .decrypt_next(&chunk)
                .map_err(|_| DomainError::IntegrityCheckFailed)?;
            plaintext.extend_from_slice(&decrypted);
        }
        decryptor
            .finish()
            .map_err(|_| DomainError::IntegrityCheckFailed)?;

        Ok(DecryptedVersion {
            access,
            manifest_hash,
            plaintext,
            private_metadata,
        })
    }
}

fn build_encrypted_chunk(index: u32, ciphertext_and_tag: Vec<u8>) -> EncryptedChunk {
    EncryptedChunk::from_parts(index, ciphertext_and_tag)
}

pub(crate) fn map_unwrap_custody_error(error: CustodyError) -> DomainError {
    match error {
        CustodyError::ProviderUnavailable | CustodyError::RandomnessUnavailable => {
            DomainError::KeyCustodyUnavailable
        }
        CustodyError::UnwrapFailed
        | CustodyError::KeyNotFound
        | CustodyError::KeyGenerationFailed
        | CustodyError::SigningFailed => DomainError::IntegrityCheckFailed,
    }
}

pub(crate) async fn read_bounded(
    mut reader: ports::StorageReader,
    max_bytes: usize,
) -> Result<Vec<u8>, DomainError> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 8 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|_| DomainError::StorageUnavailable)?;
        if read == 0 {
            break;
        }
        if output.len().saturating_add(read) > max_bytes {
            return Err(DomainError::InvalidManifest);
        }
        output.extend_from_slice(&buffer[..read]);
    }
    Ok(output)
}
