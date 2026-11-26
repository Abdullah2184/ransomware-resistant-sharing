//! Infrastructure-independent application use cases for RRDS client workflows.
//!
//! Orchestrates challenge-response authentication, local AES-256-GCM encryption
//! and HPKE recipient wrapping, pin-before-commit upload/modify/restore,
//! governed envelope-set sharing without re-encryption, and verified decryption.

pub mod auth;
pub mod download;
pub mod share;
pub mod upload;

pub use auth::{AuthConfig, AuthService};
pub use download::{DecryptedVersion, DownloadConfig, DownloadService, EncryptedPackageBytes};
pub use share::{OrphanedEnvelopeDetails, ShareConfig, ShareError, ShareReceipt, ShareService};
pub use upload::{OrphanedUploadDetails, UploadConfig, UploadError, UploadReceipt, UploadService};

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap},
        io::Cursor,
        sync::{Arc, Mutex},
    };

    use crypto::raw_sha256_cid;
    use domain::{
        AccessReference, ContentCid, DomainError, EnvelopeSetCid, EpochId, EvmAddress, FileId,
        FileStatus, FolderId, KeyVersion, LoginChallenge, ManifestHash, MemberId, MemberStatus,
        OperationNonce, OrganizationId, ProposalId, PublicMemberIdentity, TransactionReceipt,
        VersionNumber,
    };
    use key_custody::DevelopmentKeyCustody;
    use ports::{
        AuthenticatedSession, BlobStore, Clock, ContentPackage, EvmSignature, GatewayAuthPort,
        HeadState, KeyCustodyProvider, LedgerPort, PortFuture, ReplicationReceipt,
        SignedAccessLookupRequest, SignedAppendVersionRequest, SignedCreateFileRequest,
        SignedEnvelopeUpdateRequest, StorageCid, StorageError, StorageFuture, StorageReader,
        StoredContent, StoredEnvelopeSet,
    };
    use tokio::io::AsyncReadExt;

    use super::*;

    #[derive(Clone)]
    struct FixedClock(u64);

    impl Clock for FixedClock {
        fn now_unix_seconds(&self) -> Result<u64, DomainError> {
            Ok(self.0)
        }
    }

    #[derive(Clone, Default)]
    struct InMemoryBlobStore {
        contents: Arc<Mutex<HashMap<String, EncryptedPackageBytes>>>,
        envelopes: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        replica_peers: Arc<Mutex<Vec<String>>>,
    }

    impl InMemoryBlobStore {
        fn with_peers(peers: &[&str]) -> Self {
            Self {
                contents: Arc::new(Mutex::new(HashMap::new())),
                envelopes: Arc::new(Mutex::new(HashMap::new())),
                replica_peers: Arc::new(Mutex::new(
                    peers.iter().map(|peer| (*peer).to_owned()).collect(),
                )),
            }
        }

        fn stored_package(&self, cid: &ContentCid) -> EncryptedPackageBytes {
            self.contents
                .lock()
                .unwrap()
                .get(&cid.to_string())
                .cloned()
                .expect("stored content package")
        }
    }

    impl BlobStore for InMemoryBlobStore {
        fn put_content<'a>(
            &'a self,
            package: ContentPackage,
            min_replicas: usize,
        ) -> StorageFuture<'a, StoredContent> {
            Box::pin(async move {
                let (manifest, chunks) = package.into_parts();
                let manifest_bytes = manifest
                    .canonical_bytes()
                    .map_err(|_| StorageError::InvalidPackage)?;
                let mut total_bytes = manifest_bytes.len() as u64;
                let mut stored_chunks = Vec::with_capacity(chunks.len());
                for chunk in chunks {
                    let index = chunk.index();
                    let expected_len = chunk.ciphertext_bytes();
                    let mut bytes = Vec::new();
                    chunk
                        .into_reader()
                        .read_to_end(&mut bytes)
                        .await
                        .map_err(|_| StorageError::TransportUnavailable)?;
                    if bytes.len() as u64 != expected_len {
                        return Err(StorageError::InvalidPackage);
                    }
                    total_bytes += expected_len;
                    stored_chunks.push((index, bytes));
                }

                let peers = self.replica_peers.lock().unwrap().clone();
                if peers.len() < min_replicas {
                    return Err(StorageError::ReplicationInsufficient);
                }

                let cid = raw_sha256_cid(&manifest_bytes)
                    .map_err(|_| StorageError::IntegrityCheckFailed)?;
                self.contents.lock().unwrap().insert(
                    cid.to_string(),
                    EncryptedPackageBytes {
                        manifest_bytes,
                        chunks: stored_chunks,
                    },
                );
                Ok(StoredContent {
                    cid: cid.clone(),
                    bytes_written: total_bytes,
                    replication: ReplicationReceipt {
                        cid: StorageCid::Content(cid),
                        required_replicas: min_replicas,
                        pinned_peers: peers,
                    },
                })
            })
        }

        fn put_envelope_set<'a>(
            &'a self,
            mut reader: StorageReader,
            byte_length: u64,
            min_replicas: usize,
        ) -> StorageFuture<'a, StoredEnvelopeSet> {
            Box::pin(async move {
                let mut bytes = Vec::new();
                reader
                    .read_to_end(&mut bytes)
                    .await
                    .map_err(|_| StorageError::TransportUnavailable)?;
                if bytes.len() as u64 != byte_length {
                    return Err(StorageError::InvalidPackage);
                }
                let peers = self.replica_peers.lock().unwrap().clone();
                if peers.len() < min_replicas {
                    return Err(StorageError::ReplicationInsufficient);
                }
                let content_cid =
                    raw_sha256_cid(&bytes).map_err(|_| StorageError::IntegrityCheckFailed)?;
                let cid = EnvelopeSetCid::parse(&content_cid.to_string())
                    .map_err(|_| StorageError::InvalidCid)?;
                self.envelopes
                    .lock()
                    .unwrap()
                    .insert(cid.to_string(), bytes);
                Ok(StoredEnvelopeSet {
                    cid: cid.clone(),
                    bytes_written: byte_length,
                    replication: ReplicationReceipt {
                        cid: StorageCid::EnvelopeSet(cid),
                        required_replicas: min_replicas,
                        pinned_peers: peers,
                    },
                })
            })
        }

        fn get_content<'a>(&'a self, cid: &'a ContentCid) -> StorageFuture<'a, StorageReader> {
            Box::pin(async move {
                let package = self
                    .contents
                    .lock()
                    .unwrap()
                    .get(&cid.to_string())
                    .cloned()
                    .ok_or(StorageError::TransportUnavailable)?;
                Ok(Box::pin(Cursor::new(package.manifest_bytes)) as StorageReader)
            })
        }

        fn get_envelope_set<'a>(
            &'a self,
            cid: &'a EnvelopeSetCid,
        ) -> StorageFuture<'a, StorageReader> {
            Box::pin(async move {
                let bytes = self
                    .envelopes
                    .lock()
                    .unwrap()
                    .get(&cid.to_string())
                    .cloned()
                    .ok_or(StorageError::TransportUnavailable)?;
                Ok(Box::pin(Cursor::new(bytes)) as StorageReader)
            })
        }

        fn ensure_replication<'a>(
            &'a self,
            cid: StorageCid,
            min_replicas: usize,
        ) -> StorageFuture<'a, ReplicationReceipt> {
            Box::pin(async move {
                let peers = self.replica_peers.lock().unwrap().clone();
                if peers.len() < min_replicas {
                    return Err(StorageError::ReplicationInsufficient);
                }
                Ok(ReplicationReceipt {
                    cid,
                    required_replicas: min_replicas,
                    pinned_peers: peers,
                })
            })
        }

        fn verify_retrievable<'a>(&'a self, _cid: StorageCid) -> StorageFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    #[derive(Clone)]
    struct StoredVersion {
        content_cid: ContentCid,
        envelope_set_cid: EnvelopeSetCid,
        epoch_id: EpochId,
        envelope_revision: u32,
        manifest_hash: ManifestHash,
        parent_manifest_hash: ManifestHash,
    }

    #[derive(Default)]
    struct MockLedgerState {
        members: BTreeMap<MemberId, PublicMemberIdentity>,
        heads: BTreeMap<FileId, HeadState>,
        versions: BTreeMap<(FileId, u64), StoredVersion>,
        read_acl: BTreeMap<(FileId, MemberId), bool>,
        historical_read: BTreeMap<(FileId, u64, MemberId), bool>,
        fail_next_write: Option<DomainError>,
        block_number: u64,
    }

    #[derive(Clone, Default)]
    struct InMemoryLedger {
        state: Arc<Mutex<MockLedgerState>>,
    }

    impl InMemoryLedger {
        fn register_member(&self, identity: PublicMemberIdentity) {
            self.state
                .lock()
                .unwrap()
                .members
                .insert(identity.member_id, identity);
        }

        fn grant_read(&self, file_id: FileId, member_id: MemberId) {
            self.state
                .lock()
                .unwrap()
                .read_acl
                .insert((file_id, member_id), true);
        }

        fn revoke_read(&self, file_id: FileId, member_id: MemberId) {
            let mut state = self.state.lock().unwrap();
            state.read_acl.insert((file_id, member_id), false);
            for ((stored_file, _, stored_member), allowed) in &mut state.historical_read {
                if *stored_file == file_id && *stored_member == member_id {
                    *allowed = false;
                }
            }
        }

        fn grant_historical_read(&self, file_id: FileId, version: u64, member_id: MemberId) {
            self.state
                .lock()
                .unwrap()
                .historical_read
                .insert((file_id, version, member_id), true);
        }

        fn fail_next_write(&self, error: DomainError) {
            self.state.lock().unwrap().fail_next_write = Some(error);
        }

        fn version(&self, file_id: FileId, version: u64) -> StoredVersion {
            self.state
                .lock()
                .unwrap()
                .versions
                .get(&(file_id, version))
                .cloned()
                .expect("stored version")
        }
    }

    impl LedgerPort for InMemoryLedger {
        fn get_member(&self, member_id: MemberId) -> PortFuture<'_, Option<PublicMemberIdentity>> {
            Box::pin(async move { Ok(self.state.lock().unwrap().members.get(&member_id).cloned()) })
        }

        fn get_file_head(&self, file_id: FileId) -> PortFuture<'_, Option<HeadState>> {
            Box::pin(async move { Ok(self.state.lock().unwrap().heads.get(&file_id).cloned()) })
        }

        fn authorize_read<'a>(
            &'a self,
            request: &'a SignedAccessLookupRequest,
        ) -> PortFuture<'a, AccessReference> {
            Box::pin(async move {
                let state = self.state.lock().unwrap();
                let member = state
                    .members
                    .get(&request.member_id)
                    .ok_or(DomainError::Unauthorized)?;
                if !member.is_active() {
                    return Err(DomainError::MemberSuspended);
                }
                let head = state
                    .heads
                    .get(&request.file_id)
                    .ok_or(DomainError::Unauthorized)?;
                if !state
                    .read_acl
                    .get(&(request.file_id, request.member_id))
                    .copied()
                    .unwrap_or(false)
                {
                    return Err(DomainError::Unauthorized);
                }
                if request.version_number.get() < head.current_version.get()
                    && !state
                        .historical_read
                        .get(&(
                            request.file_id,
                            request.version_number.get(),
                            request.member_id,
                        ))
                        .copied()
                        .unwrap_or(false)
                {
                    return Err(DomainError::Unauthorized);
                }
                let version = state
                    .versions
                    .get(&(request.file_id, request.version_number.get()))
                    .ok_or(DomainError::Unauthorized)?;
                Ok(AccessReference {
                    file_id: request.file_id,
                    version_number: request.version_number,
                    content_cid: version.content_cid.clone(),
                    envelope_set_cid: version.envelope_set_cid.clone(),
                    epoch_id: version.epoch_id,
                    envelope_revision: version.envelope_revision,
                    finalized_block: state.block_number,
                })
            })
        }

        fn create_file<'a>(
            &'a self,
            request: &'a SignedCreateFileRequest,
        ) -> PortFuture<'a, TransactionReceipt> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                if let Some(error) = state.fail_next_write.take() {
                    return Err(error);
                }
                if state.heads.contains_key(&request.file_id) {
                    return Err(DomainError::ContractRejected);
                }
                state.block_number += 1;
                let block = state.block_number;
                state.heads.insert(
                    request.file_id,
                    HeadState {
                        file_id: request.file_id,
                        status: FileStatus::Active,
                        current_version: request.version_number,
                        current_head_manifest_hash: request.manifest_hash,
                    },
                );
                state.versions.insert(
                    (request.file_id, request.version_number.get()),
                    StoredVersion {
                        content_cid: request.content_cid.clone(),
                        envelope_set_cid: request.envelope_set_cid.clone(),
                        epoch_id: request.epoch_id,
                        envelope_revision: 1,
                        manifest_hash: request.manifest_hash,
                        parent_manifest_hash: request.parent_manifest_hash,
                    },
                );
                state
                    .read_acl
                    .insert((request.file_id, request.author_member_id), true);
                Ok(TransactionReceipt {
                    transaction_hash: [0xaa; 32],
                    block_number: block,
                    finalized: true,
                    succeeded: true,
                })
            })
        }

        fn append_version<'a>(
            &'a self,
            request: &'a SignedAppendVersionRequest,
        ) -> PortFuture<'a, TransactionReceipt> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                if let Some(error) = state.fail_next_write.take() {
                    return Err(error);
                }
                let head = state
                    .heads
                    .get(&request.file_id)
                    .cloned()
                    .ok_or(DomainError::ContractRejected)?;
                if request.parent_manifest_hash != head.current_head_manifest_hash {
                    return Err(DomainError::StaleHead);
                }
                if request.version_number != head.current_version.next()? {
                    return Err(DomainError::InvalidVersionNumber);
                }
                state.block_number += 1;
                let block = state.block_number;
                state.heads.insert(
                    request.file_id,
                    HeadState {
                        file_id: request.file_id,
                        status: FileStatus::Active,
                        current_version: request.version_number,
                        current_head_manifest_hash: request.manifest_hash,
                    },
                );
                state.versions.insert(
                    (request.file_id, request.version_number.get()),
                    StoredVersion {
                        content_cid: request.content_cid.clone(),
                        envelope_set_cid: request.envelope_set_cid.clone(),
                        epoch_id: request.epoch_id,
                        envelope_revision: 1,
                        manifest_hash: request.manifest_hash,
                        parent_manifest_hash: request.parent_manifest_hash,
                    },
                );
                Ok(TransactionReceipt {
                    transaction_hash: [0xbb; 32],
                    block_number: block,
                    finalized: true,
                    succeeded: true,
                })
            })
        }

        fn update_envelope_set<'a>(
            &'a self,
            request: &'a SignedEnvelopeUpdateRequest,
        ) -> PortFuture<'a, TransactionReceipt> {
            Box::pin(async move {
                let mut state = self.state.lock().unwrap();
                if let Some(error) = state.fail_next_write.take() {
                    return Err(error);
                }
                state.block_number += 1;
                let block = state.block_number;
                let version = state
                    .versions
                    .get_mut(&(request.file_id, request.version_number.get()))
                    .ok_or(DomainError::ContractRejected)?;
                if version.envelope_set_cid != request.old_envelope_set_cid {
                    return Err(DomainError::StaleHead);
                }
                version.envelope_set_cid = request.new_envelope_set_cid.clone();
                version.envelope_revision += 1;
                Ok(TransactionReceipt {
                    transaction_hash: [0xcc; 32],
                    block_number: block,
                    finalized: true,
                    succeeded: true,
                })
            })
        }
    }

    struct MockGatewayAuth {
        challenge: LoginChallenge,
    }

    impl GatewayAuthPort for MockGatewayAuth {
        fn request_challenge(&self, _member_id: MemberId) -> PortFuture<'_, LoginChallenge> {
            let challenge = self.challenge.clone();
            Box::pin(async move { Ok(challenge) })
        }

        fn exchange_challenge<'a>(
            &'a self,
            challenge: &'a LoginChallenge,
            _signature: &'a EvmSignature,
        ) -> PortFuture<'a, AuthenticatedSession> {
            Box::pin(async move {
                Ok(AuthenticatedSession::new(
                    format!("0x{}", "77".repeat(32)),
                    challenge.member_id,
                    challenge.expires_at + 600,
                ))
            })
        }
    }

    async fn make_member(
        seed: u8,
        status: MemberStatus,
    ) -> (Arc<DevelopmentKeyCustody>, PublicMemberIdentity) {
        let member_id = MemberId::from_bytes([seed; 32]);
        let custody = Arc::new(
            DevelopmentKeyCustody::generate(
                member_id,
                KeyVersion::new(1).unwrap(),
                KeyVersion::new(1).unwrap(),
            )
            .unwrap(),
        );
        let pub_keys = custody.public_identity().await.unwrap();
        let mut enc_key = [0u8; 32];
        enc_key.copy_from_slice(&pub_keys.encryption_public_key.to_bytes());
        let identity = PublicMemberIdentity {
            member_id,
            organization_id: OrganizationId::from_bytes([0x01; 32]),
            signing_address: pub_keys.signing_address,
            signing_key_version: pub_keys.signing_key_version,
            encryption_key_version: pub_keys.encryption_key_version,
            encryption_public_key: enc_key,
            status,
            finalized_block: 1,
        };
        (custody, identity)
    }

    struct ArcCustody(Arc<DevelopmentKeyCustody>);

    impl KeyCustodyProvider for ArcCustody {
        fn public_identity(&self) -> ports::CustodyFuture<'_, ports::PublicIdentityKeys> {
            self.0.public_identity()
        }

        fn sign_typed_digest<'a>(
            &'a self,
            key_id: &'a ports::KeyId,
            digest: &'a crypto::TypedDigest,
        ) -> ports::CustodyFuture<'a, EvmSignature> {
            self.0.sign_typed_digest(key_id, digest)
        }

        fn unwrap_dek<'a>(
            &'a self,
            key_id: &'a ports::KeyId,
            envelope: &'a crypto::KeyEnvelope,
            context: crypto::WrapContext,
        ) -> ports::CustodyFuture<'a, zeroize::Zeroizing<[u8; 32]>> {
            self.0.unwrap_dek(key_id, envelope, context)
        }

        fn health_check(&self) -> ports::CustodyFuture<'_, ports::CustodyHealth> {
            self.0.health_check()
        }
    }

    fn upload_config() -> UploadConfig {
        UploadConfig {
            chain_id: 1337,
            file_registry: EvmAddress::from_bytes([0x11; 20]),
            min_pin_replicas: 2,
            chunk_size_bytes: 64,
            max_file_bytes: 1024 * 1024,
            operation_ttl_seconds: 120,
        }
    }

    fn download_config() -> DownloadConfig {
        DownloadConfig {
            chain_id: 1337,
            access_governance: EvmAddress::from_bytes([0x22; 20]),
            operation_ttl_seconds: 120,
        }
    }

    fn share_config() -> ShareConfig {
        ShareConfig {
            chain_id: 1337,
            access_governance: EvmAddress::from_bytes([0x22; 20]),
            min_pin_replicas: 2,
            operation_ttl_seconds: 120,
        }
    }

    #[tokio::test]
    async fn login_validates_challenge_and_rejects_wrong_audience_or_expired() {
        let (alice_custody, alice) = make_member(1, MemberStatus::Active).await;
        let challenge = LoginChallenge {
            member_id: alice.member_id,
            nonce: OperationNonce::from_bytes([0x44; 32]),
            issued_at: 1_800_000_000,
            expires_at: 1_800_000_120,
            audience: "rrds-local".to_owned(),
            protocol_version: 1,
        };
        let service = AuthService::new(
            ArcCustody(alice_custody.clone()),
            MockGatewayAuth {
                challenge: challenge.clone(),
            },
            FixedClock(1_800_000_010),
            AuthConfig {
                chain_id: 1337,
                access_governance: EvmAddress::from_bytes([0x22; 20]),
                expected_audience: "rrds-local".to_owned(),
                max_challenge_ttl_seconds: 120,
            },
        );
        let session = service.login().await.unwrap();
        assert_eq!(session.member_id, alice.member_id);
        assert!(format!("{session:?}").contains("[REDACTED]"));

        let wrong_audience = AuthService::new(
            ArcCustody(alice_custody.clone()),
            MockGatewayAuth {
                challenge: challenge.clone(),
            },
            FixedClock(1_800_000_010),
            AuthConfig {
                chain_id: 1337,
                access_governance: EvmAddress::from_bytes([0x22; 20]),
                expected_audience: "other-gateway".to_owned(),
                max_challenge_ttl_seconds: 120,
            },
        );
        assert_eq!(
            wrong_audience.login().await,
            Err(DomainError::Unauthenticated)
        );

        let expired = AuthService::new(
            ArcCustody(alice_custody),
            MockGatewayAuth { challenge },
            FixedClock(1_800_000_200),
            AuthConfig {
                chain_id: 1337,
                access_governance: EvmAddress::from_bytes([0x22; 20]),
                expected_audience: "rrds-local".to_owned(),
                max_challenge_ttl_seconds: 120,
            },
        );
        assert_eq!(expired.login().await, Err(DomainError::Unauthenticated));
    }

    #[tokio::test]
    async fn full_lifecycle_upload_download_share_revoke_restore_and_tamper_detection() {
        let (alice_custody, alice) = make_member(1, MemberStatus::Active).await;
        let (bob_custody, bob) = make_member(2, MemberStatus::Active).await;
        let (charlie_custody, charlie) = make_member(3, MemberStatus::Active).await;
        let (_suspended_custody, suspended) = make_member(4, MemberStatus::Suspended).await;

        let store = InMemoryBlobStore::with_peers(&["peer-org-a", "peer-org-b"]);
        let ledger = InMemoryLedger::default();
        for member in [&alice, &bob, &charlie, &suspended] {
            ledger.register_member(member.clone());
        }

        let alice_upload = UploadService::new(
            ArcCustody(alice_custody.clone()),
            store.clone(),
            ledger.clone(),
            FixedClock(1_800_000_000),
            upload_config(),
        );
        let alice_download = DownloadService::new(
            ArcCustody(alice_custody.clone()),
            store.clone(),
            ledger.clone(),
            FixedClock(1_800_000_010),
            download_config(),
        );
        let alice_share = ShareService::new(
            ArcCustody(alice_custody.clone()),
            store.clone(),
            ledger.clone(),
            FixedClock(1_800_000_020),
            share_config(),
        );
        let bob_download = DownloadService::new(
            ArcCustody(bob_custody.clone()),
            store.clone(),
            ledger.clone(),
            FixedClock(1_800_000_030),
            download_config(),
        );
        let charlie_download = DownloadService::new(
            ArcCustody(charlie_custody.clone()),
            store.clone(),
            ledger.clone(),
            FixedClock(1_800_000_030),
            download_config(),
        );

        // Suspended recipients must be rejected before encryption/upload.
        assert_eq!(
            alice_upload
                .create_file(
                    None,
                    "blocked.txt".to_owned(),
                    FolderId::ROOT,
                    b"secret",
                    None,
                    &[suspended.member_id],
                )
                .await
                .unwrap_err()
                .domain_error(),
            DomainError::MemberSuspended
        );

        // 1. Alice creates V1 (multi-chunk + private metadata).
        let v1_plaintext = vec![0x41u8; 150];
        let v1 = alice_upload
            .create_file(
                None,
                "financial-report.txt".to_owned(),
                FolderId::ROOT,
                &v1_plaintext,
                Some(b"confidential-original-name.xlsx"),
                &[],
            )
            .await
            .unwrap();
        assert_eq!(v1.version_number, VersionNumber::ONE);
        assert_eq!(v1.parent_manifest_hash, ManifestHash::ZERO);
        assert!(v1.content_replication.is_satisfied());
        assert!(v1.envelope_replication.is_satisfied());

        // 2. Alice authorizes & decrypts V1.
        let alice_v1_access = alice_download
            .authorize_version(v1.file_id, VersionNumber::ONE)
            .await
            .unwrap();
        let v1_pkg = store.stored_package(&alice_v1_access.content_cid);
        let alice_v1_decrypted = alice_download
            .decrypt_authorized_package(alice_v1_access.clone(), Some(v1.manifest_hash), &v1_pkg)
            .await
            .unwrap();
        assert_eq!(
            alice_v1_decrypted.plaintext.as_slice(),
            v1_plaintext.as_slice()
        );
        assert_eq!(
            alice_v1_decrypted
                .private_metadata
                .as_deref()
                .map(Vec::as_slice),
            Some(b"confidential-original-name.xlsx".as_slice())
        );

        // Tampered ciphertext chunk fails closed with IntegrityCheckFailed.
        let mut tampered_pkg = v1_pkg.clone();
        tampered_pkg.chunks[0].1[0] ^= 0xff;
        assert_eq!(
            alice_download
                .decrypt_authorized_package(
                    alice_v1_access.clone(),
                    Some(v1.manifest_hash),
                    &tampered_pkg
                )
                .await
                .err(),
            Some(DomainError::IntegrityCheckFailed)
        );

        // 3. Share V1 to Bob without re-encrypting ciphertext (revision 1 -> 2).
        ledger.grant_read(v1.file_id, bob.member_id);
        let share_receipt = alice_share
            .share_version_envelope(
                &alice_v1_access,
                bob.member_id,
                ProposalId::from_bytes([0x99; 32]),
            )
            .await
            .unwrap();
        assert_eq!(share_receipt.new_revision, 2);
        assert_ne!(
            share_receipt.old_envelope_set_cid,
            share_receipt.new_envelope_set_cid
        );

        let bob_v1_access = bob_download
            .authorize_version(v1.file_id, VersionNumber::ONE)
            .await
            .unwrap();
        assert_eq!(bob_v1_access.content_cid, v1.content_cid);
        assert_eq!(
            bob_v1_access.envelope_set_cid,
            share_receipt.new_envelope_set_cid
        );
        let bob_v1_decrypted = bob_download
            .decrypt_authorized_package(bob_v1_access.clone(), Some(v1.manifest_hash), &v1_pkg)
            .await
            .unwrap();
        assert_eq!(
            bob_v1_decrypted.plaintext.as_slice(),
            v1_plaintext.as_slice()
        );

        // Charlie lacks an envelope and fails closed even if handed Bob's AccessReference + ciphertext.
        assert_eq!(
            charlie_download
                .decrypt_authorized_package(bob_v1_access.clone(), None, &v1_pkg)
                .await
                .err(),
            Some(DomainError::Unauthorized)
        );

        // 4. Modify file -> V2 (simulating ransomware-corrupted upload) with fresh DEK & epoch.
        let v2_corrupted = b"ENCRYPTED-BY-RANSOMWARE-PAYLOAD".to_vec();
        let v2 = alice_upload
            .append_version(
                v1.file_id,
                Some((VersionNumber::ONE, v1.manifest_hash)),
                &v2_corrupted,
                None,
                &[bob.member_id],
            )
            .await
            .unwrap();
        assert_eq!(v2.version_number.get(), 2);
        assert_eq!(v2.parent_manifest_hash, v1.manifest_hash);
        assert_ne!(v2.epoch_id, v1.epoch_id);

        // Stale-head concurrent write referencing V1 fails closed with StaleHead.
        assert_eq!(
            alice_upload
                .append_version(
                    v1.file_id,
                    Some((VersionNumber::ONE, v1.manifest_hash)),
                    b"stale-edit",
                    None,
                    &[],
                )
                .await
                .unwrap_err()
                .domain_error(),
            DomainError::StaleHead
        );

        // Historical access requires explicit version grant: Bob has file Read (can read head V2)
        // but is now denied V1 until explicitly granted historical access.
        assert_eq!(
            bob_download
                .authorize_version(v1.file_id, VersionNumber::ONE)
                .await
                .err(),
            Some(DomainError::Unauthorized)
        );
        ledger.grant_historical_read(v1.file_id, 1, bob.member_id);
        assert!(
            bob_download
                .authorize_version(v1.file_id, VersionNumber::ONE)
                .await
                .is_ok()
        );

        // 5. Revoke Bob's Read ACL and restore clean V1 plaintext as V3 (append-only, parent = V2).
        ledger.revoke_read(v1.file_id, bob.member_id);
        assert_eq!(
            bob_download
                .authorize_version(v1.file_id, VersionNumber::ONE)
                .await
                .err(),
            Some(DomainError::Unauthorized)
        );

        let v3_restored = alice_upload
            .restore_version(
                v1.file_id,
                Some((v2.version_number, v2.manifest_hash)),
                &alice_v1_decrypted.plaintext,
                None,
                &[], // Bob excluded after revocation
            )
            .await
            .unwrap();
        assert_eq!(v3_restored.version_number.get(), 3);
        assert_eq!(v3_restored.parent_manifest_hash, v2.manifest_hash);
        assert_ne!(v3_restored.epoch_id, v1.epoch_id);
        assert_ne!(v3_restored.epoch_id, v2.epoch_id);

        // Historical versions V1 and V2 remain immutable on the ledger.
        assert_eq!(
            ledger.version(v1.file_id, 1).manifest_hash,
            v1.manifest_hash
        );
        assert_eq!(
            ledger.version(v1.file_id, 2).manifest_hash,
            v2.manifest_hash
        );
        assert_eq!(
            ledger.version(v1.file_id, 3).parent_manifest_hash,
            v2.manifest_hash
        );

        // Bob cannot decrypt V3 even if handed the V3 reference & ciphertext (omitted from envelope set).
        let alice_v3_access = alice_download
            .authorize_version(v1.file_id, v3_restored.version_number)
            .await
            .unwrap();
        let v3_pkg = store.stored_package(&alice_v3_access.content_cid);
        assert_eq!(
            bob_download
                .decrypt_authorized_package(alice_v3_access.clone(), None, &v3_pkg)
                .await
                .err(),
            Some(DomainError::Unauthorized)
        );
        // Explicitly document & test the known limitation (§15.4 #7): if Bob kept his prior V1
        // reference + ciphertext + V1 envelope set, cryptographic access to already-shared V1
        // cannot be retroactively erased, even though the gateway refuses new V1 authorizations.
        let bob_cached_v1 = bob_download
            .decrypt_authorized_package(bob_v1_access, Some(v1.manifest_hash), &v1_pkg)
            .await
            .unwrap();
        assert_eq!(bob_cached_v1.plaintext.as_slice(), v1_plaintext.as_slice());

        // Alice decrypts restored V3 and recovers the exact clean V1 bytes.
        let alice_v3_decrypted = alice_download
            .decrypt_authorized_package(alice_v3_access, Some(v3_restored.manifest_hash), &v3_pkg)
            .await
            .unwrap();
        assert_eq!(
            alice_v3_decrypted.plaintext.as_slice(),
            v1_plaintext.as_slice()
        );
    }

    #[tokio::test]
    async fn ledger_failure_after_pinning_reports_orphaned_upload_without_claiming_commit() {
        let (alice_custody, alice) = make_member(9, MemberStatus::Active).await;
        let store = InMemoryBlobStore::with_peers(&["peer-1", "peer-2"]);
        let ledger = InMemoryLedger::default();
        ledger.register_member(alice);
        ledger.fail_next_write(DomainError::ContractRejected);

        let upload = UploadService::new(
            ArcCustody(alice_custody),
            store,
            ledger.clone(),
            FixedClock(1_800_000_000),
            upload_config(),
        );
        let file_id = FileId::from_bytes([0x55; 32]);
        let error = upload
            .create_file(
                Some(file_id),
                "orphan.bin".to_owned(),
                FolderId::ROOT,
                b"pinned-but-not-committed",
                None,
                &[],
            )
            .await
            .unwrap_err();

        assert_eq!(error.domain_error(), DomainError::OrphanedUpload);
        assert!(matches!(
            error,
            UploadError::OrphanedUpload(details)
                if details.cause == DomainError::ContractRejected
        ));
        assert_eq!(ledger.get_file_head(file_id).await.unwrap(), None);
    }

    #[tokio::test]
    async fn insufficient_pin_quorum_blocks_ledger_submission() {
        let (alice_custody, alice) = make_member(10, MemberStatus::Active).await;
        let store = InMemoryBlobStore::with_peers(&["only-one-peer"]);
        let ledger = InMemoryLedger::default();
        ledger.register_member(alice);

        let upload = UploadService::new(
            ArcCustody(alice_custody),
            store,
            ledger.clone(),
            FixedClock(1_800_000_000),
            upload_config(),
        );
        let file_id = FileId::from_bytes([0x66; 32]);
        let error = upload
            .create_file(
                Some(file_id),
                "unreplicated.bin".to_owned(),
                FolderId::ROOT,
                b"needs-two-replicas",
                None,
                &[],
            )
            .await
            .unwrap_err();

        assert_eq!(error.domain_error(), DomainError::ReplicationInsufficient);
        assert_eq!(ledger.get_file_head(file_id).await.unwrap(), None);
    }
}
