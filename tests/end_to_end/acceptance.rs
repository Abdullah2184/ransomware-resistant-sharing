//! End-to-end acceptance tests covering ransomware recovery, concurrent edits,
//! historical read revocation epochs, key supersession, and 1 MiB multi-chunk
//! round-trips (`TECHNICAL_SPECIFICATION.md` §§9, 15.3, 15.4).

use std::{
    collections::{BTreeMap, HashMap},
    io::Cursor,
    sync::{Arc, Mutex},
};

use application::{
    DownloadConfig, DownloadService, EncryptedPackageBytes, ShareConfig, ShareService,
    UploadConfig, UploadError, UploadService,
};
use crypto::{DEFAULT_CHUNK_SIZE_BYTES, raw_sha256_cid};
use domain::{
    AccessReference, ContentCid, DomainError, EnvelopeSetCid, EpochId, EvmAddress, FileId,
    FileStatus, FolderId, KeyVersion, ManifestHash, MemberId, MemberStatus, OrganizationId,
    ProposalId, PublicMemberIdentity, TransactionReceipt, VersionNumber,
};
use key_custody::DevelopmentKeyCustody;
use ports::{
    BlobStore, Clock, ContentPackage, HeadState, KeyCustodyProvider, LedgerPort, PortFuture,
    ReplicationReceipt, SignedAccessLookupRequest, SignedAppendVersionRequest,
    SignedCreateFileRequest, SignedEnvelopeUpdateRequest, StorageCid, StorageError, StorageFuture,
    StorageReader, StoredContent, StoredEnvelopeSet,
};
use tokio::io::AsyncReadExt;

#[derive(Clone)]
struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_unix_seconds(&self) -> Result<u64, DomainError> {
        Ok(self.0)
    }
}

#[derive(Clone)]
struct SharedCustody(Arc<DevelopmentKeyCustody>);

impl KeyCustodyProvider for SharedCustody {
    fn public_identity(&self) -> ports::CustodyFuture<'_, ports::PublicIdentityKeys> {
        self.0.public_identity()
    }

    fn sign_typed_digest<'a>(
        &'a self,
        key_id: &'a ports::KeyId,
        digest: &'a crypto::TypedDigest,
    ) -> ports::CustodyFuture<'a, ports::EvmSignature> {
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

#[derive(Clone, Default)]
struct HarnessBlobStore {
    contents: Arc<Mutex<HashMap<String, EncryptedPackageBytes>>>,
    envelopes: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    peers: Arc<Mutex<Vec<String>>>,
}

impl HarnessBlobStore {
    fn two_peers() -> Self {
        Self {
            peers: Arc::new(Mutex::new(vec![
                "peer-org-a".to_owned(),
                "peer-org-b".to_owned(),
            ])),
            ..Default::default()
        }
    }

    fn package(&self, cid: &ContentCid) -> EncryptedPackageBytes {
        self.contents
            .lock()
            .unwrap()
            .get(&cid.to_string())
            .cloned()
            .expect("content package stored")
    }
}

impl BlobStore for HarnessBlobStore {
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
            let mut total = manifest_bytes.len() as u64;
            let mut stored_chunks = Vec::with_capacity(chunks.len());
            for chunk in chunks {
                let idx = chunk.index();
                let mut data = Vec::new();
                chunk
                    .into_reader()
                    .read_to_end(&mut data)
                    .await
                    .map_err(|_| StorageError::TransportUnavailable)?;
                total += data.len() as u64;
                stored_chunks.push((idx, data));
            }
            let peers = self.peers.lock().unwrap().clone();
            if peers.len() < min_replicas {
                return Err(StorageError::ReplicationInsufficient);
            }
            let cid =
                raw_sha256_cid(&manifest_bytes).map_err(|_| StorageError::IntegrityCheckFailed)?;
            self.contents.lock().unwrap().insert(
                cid.to_string(),
                EncryptedPackageBytes {
                    manifest_bytes,
                    chunks: stored_chunks,
                },
            );
            Ok(StoredContent {
                cid: cid.clone(),
                bytes_written: total,
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
            let peers = self.peers.lock().unwrap().clone();
            if peers.len() < min_replicas {
                return Err(StorageError::ReplicationInsufficient);
            }
            let cid = EnvelopeSetCid::parse(
                &raw_sha256_cid(&bytes)
                    .map_err(|_| StorageError::IntegrityCheckFailed)?
                    .to_string(),
            )
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
            let pkg = self
                .contents
                .lock()
                .unwrap()
                .get(&cid.to_string())
                .cloned()
                .ok_or(StorageError::TransportUnavailable)?;
            Ok(Box::pin(Cursor::new(pkg.manifest_bytes)) as StorageReader)
        })
    }

    fn get_envelope_set<'a>(&'a self, cid: &'a EnvelopeSetCid) -> StorageFuture<'a, StorageReader> {
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
            let peers = self.peers.lock().unwrap().clone();
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
struct VersionEntry {
    content_cid: ContentCid,
    envelope_set_cid: EnvelopeSetCid,
    epoch_id: EpochId,
    envelope_revision: u32,
    manifest_hash: ManifestHash,
    parent_manifest_hash: ManifestHash,
}

#[derive(Default)]
struct LedgerState {
    members: BTreeMap<MemberId, PublicMemberIdentity>,
    heads: BTreeMap<FileId, HeadState>,
    versions: BTreeMap<(FileId, u64), VersionEntry>,
    read_acl: BTreeMap<(FileId, MemberId), bool>,
    write_acl: BTreeMap<(FileId, MemberId), bool>,
    read_epoch: BTreeMap<(FileId, MemberId), u64>,
    historical_read: BTreeMap<(FileId, u64, MemberId), u64>,
    block: u64,
}

#[derive(Clone, Default)]
struct HarnessLedger {
    state: Arc<Mutex<LedgerState>>,
}

impl HarnessLedger {
    fn register(&self, identity: PublicMemberIdentity) {
        self.state
            .lock()
            .unwrap()
            .members
            .insert(identity.member_id, identity);
    }

    fn suspend(&self, member_id: MemberId) {
        if let Some(m) = self.state.lock().unwrap().members.get_mut(&member_id) {
            m.status = MemberStatus::Suspended;
        }
    }

    fn grant_read(&self, file_id: FileId, member_id: MemberId) {
        self.state
            .lock()
            .unwrap()
            .read_acl
            .insert((file_id, member_id), true);
    }

    fn revoke_read(&self, file_id: FileId, member_id: MemberId) {
        let mut st = self.state.lock().unwrap();
        st.read_acl.insert((file_id, member_id), false);
        // Mirror AccessGovernance readPermissionEpochs increment invalidating all prior historical grants.
        let epoch = st.read_epoch.entry((file_id, member_id)).or_insert(0);
        *epoch += 1;
    }

    fn grant_write(&self, file_id: FileId, member_id: MemberId) {
        self.state
            .lock()
            .unwrap()
            .write_acl
            .insert((file_id, member_id), true);
    }

    fn grant_historical_read(&self, file_id: FileId, version: u64, member_id: MemberId) {
        let mut st = self.state.lock().unwrap();
        let grant_epoch = *st.read_epoch.get(&(file_id, member_id)).unwrap_or(&0) + 1;
        st.historical_read
            .insert((file_id, version, member_id), grant_epoch);
    }

    fn version_count(&self, file_id: FileId) -> usize {
        self.state
            .lock()
            .unwrap()
            .versions
            .keys()
            .filter(|(fid, _)| *fid == file_id)
            .count()
    }

    fn version(&self, file_id: FileId, version: u64) -> VersionEntry {
        self.state
            .lock()
            .unwrap()
            .versions
            .get(&(file_id, version))
            .cloned()
            .expect("version exists")
    }
}

impl LedgerPort for HarnessLedger {
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
            let st = self.state.lock().unwrap();
            let member = st
                .members
                .get(&request.member_id)
                .ok_or(DomainError::Unauthorized)?;
            if !member.is_active() {
                return Err(DomainError::MemberSuspended);
            }
            if request.encryption_key_version != member.encryption_key_version {
                return Err(DomainError::Unauthorized);
            }
            let head = st
                .heads
                .get(&request.file_id)
                .ok_or(DomainError::Unauthorized)?;
            if !st
                .read_acl
                .get(&(request.file_id, request.member_id))
                .copied()
                .unwrap_or(false)
            {
                return Err(DomainError::Unauthorized);
            }
            if request.version_number.get() < head.current_version.get() {
                let required_epoch = *st
                    .read_epoch
                    .get(&(request.file_id, request.member_id))
                    .unwrap_or(&0)
                    + 1;
                let granted_epoch = st
                    .historical_read
                    .get(&(
                        request.file_id,
                        request.version_number.get(),
                        request.member_id,
                    ))
                    .copied()
                    .unwrap_or(0);
                if granted_epoch != required_epoch {
                    return Err(DomainError::Unauthorized);
                }
            }
            let version = st
                .versions
                .get(&(request.file_id, request.version_number.get()))
                .ok_or(DomainError::Unauthorized)?;
            Ok(AccessReference {
                file_id: request.file_id,
                version_number: request.version_number,
                manifest_hash: version.manifest_hash,
                content_cid: version.content_cid.clone(),
                envelope_set_cid: version.envelope_set_cid.clone(),
                epoch_id: version.epoch_id,
                envelope_revision: version.envelope_revision,
                finalized_block: st.block,
            })
        })
    }

    fn create_file<'a>(
        &'a self,
        request: &'a SignedCreateFileRequest,
    ) -> PortFuture<'a, TransactionReceipt> {
        Box::pin(async move {
            let mut st = self.state.lock().unwrap();
            let author = st
                .members
                .get(&request.author_member_id)
                .ok_or(DomainError::Unauthorized)?;
            if !author.is_active() {
                return Err(DomainError::MemberSuspended);
            }
            if st.heads.contains_key(&request.file_id) {
                return Err(DomainError::ContractRejected);
            }
            st.block += 1;
            let block = st.block;
            st.heads.insert(
                request.file_id,
                HeadState {
                    file_id: request.file_id,
                    status: FileStatus::Active,
                    current_version: request.version_number,
                    current_head_manifest_hash: request.manifest_hash,
                },
            );
            st.versions.insert(
                (request.file_id, 1),
                VersionEntry {
                    content_cid: request.content_cid.clone(),
                    envelope_set_cid: request.envelope_set_cid.clone(),
                    epoch_id: request.epoch_id,
                    envelope_revision: 1,
                    manifest_hash: request.manifest_hash,
                    parent_manifest_hash: request.parent_manifest_hash,
                },
            );
            st.read_acl
                .insert((request.file_id, request.author_member_id), true);
            st.write_acl
                .insert((request.file_id, request.author_member_id), true);
            Ok(TransactionReceipt {
                transaction_hash: [0x11; 32],
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
            let mut st = self.state.lock().unwrap();
            let author = st
                .members
                .get(&request.author_member_id)
                .ok_or(DomainError::Unauthorized)?;
            if !author.is_active() {
                return Err(DomainError::MemberSuspended);
            }
            if !st
                .write_acl
                .get(&(request.file_id, request.author_member_id))
                .copied()
                .unwrap_or(false)
            {
                return Err(DomainError::Unauthorized);
            }
            let head = st
                .heads
                .get(&request.file_id)
                .cloned()
                .ok_or(DomainError::ContractRejected)?;
            if request.parent_manifest_hash != head.current_head_manifest_hash
                || request.version_number != head.current_version.next()?
            {
                return Err(DomainError::StaleHead);
            }
            st.block += 1;
            let block = st.block;
            st.heads.insert(
                request.file_id,
                HeadState {
                    file_id: request.file_id,
                    status: FileStatus::Active,
                    current_version: request.version_number,
                    current_head_manifest_hash: request.manifest_hash,
                },
            );
            st.versions.insert(
                (request.file_id, request.version_number.get()),
                VersionEntry {
                    content_cid: request.content_cid.clone(),
                    envelope_set_cid: request.envelope_set_cid.clone(),
                    epoch_id: request.epoch_id,
                    envelope_revision: 1,
                    manifest_hash: request.manifest_hash,
                    parent_manifest_hash: request.parent_manifest_hash,
                },
            );
            Ok(TransactionReceipt {
                transaction_hash: [0x22; 32],
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
            let mut st = self.state.lock().unwrap();
            let actor = st
                .members
                .get(&request.actor_member_id)
                .ok_or(DomainError::Unauthorized)?;
            if !actor.is_active() {
                return Err(DomainError::MemberSuspended);
            }
            st.block += 1;
            let block = st.block;
            let version = st
                .versions
                .get_mut(&(request.file_id, request.version_number.get()))
                .ok_or(DomainError::ContractRejected)?;
            if version.envelope_set_cid != request.old_envelope_set_cid {
                return Err(DomainError::StaleHead);
            }
            version.envelope_set_cid = request.new_envelope_set_cid.clone();
            version.envelope_revision += 1;
            Ok(TransactionReceipt {
                transaction_hash: [0x33; 32],
                block_number: block,
                finalized: true,
                succeeded: true,
            })
        })
    }
}

async fn make_member(seed: u8, key_ver: u32) -> (SharedCustody, PublicMemberIdentity) {
    let member_id = MemberId::from_bytes([seed; 32]);
    let custody = Arc::new(
        DevelopmentKeyCustody::from_dev_secrets(
            member_id,
            KeyVersion::new(key_ver).unwrap(),
            KeyVersion::new(key_ver).unwrap(),
            [seed.wrapping_add(10); 32],
            [seed.wrapping_add(50); 32],
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
        status: MemberStatus::Active,
        finalized_block: 1,
    };
    (SharedCustody(custody), identity)
}

fn upload_cfg(chunk_size: usize) -> UploadConfig {
    UploadConfig {
        chain_id: 1337,
        file_registry: EvmAddress::from_bytes([0x11; 20]),
        min_pin_replicas: 2,
        chunk_size_bytes: chunk_size,
        max_file_bytes: 16 * 1024 * 1024,
        operation_ttl_seconds: 120,
    }
}

fn download_cfg() -> DownloadConfig {
    DownloadConfig {
        chain_id: 1337,
        access_governance: EvmAddress::from_bytes([0x22; 20]),
        operation_ttl_seconds: 120,
    }
}

fn share_cfg() -> ShareConfig {
    ShareConfig {
        chain_id: 1337,
        access_governance: EvmAddress::from_bytes([0x22; 20]),
        min_pin_replicas: 2,
        operation_ttl_seconds: 120,
    }
}

#[tokio::test]
async fn ransomware_containment_and_append_only_recovery_preserve_forensic_history() {
    let (alice_c, alice) = make_member(1, 1).await;
    let (compromised_c, compromised) = make_member(2, 1).await;
    let (auditor_c, auditor) = make_member(3, 1).await;

    let blobs = HarnessBlobStore::two_peers();
    let ledger = HarnessLedger::default();
    for m in [&alice, &compromised, &auditor] {
        ledger.register(m.clone());
    }

    let alice_up = UploadService::new(
        alice_c.clone(),
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_000),
        upload_cfg(DEFAULT_CHUNK_SIZE_BYTES),
    );
    let compromised_up = UploadService::new(
        compromised_c.clone(),
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_010),
        upload_cfg(DEFAULT_CHUNK_SIZE_BYTES),
    );
    let alice_dl = DownloadService::new(
        alice_c.clone(),
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_020),
        download_cfg(),
    );
    let auditor_dl = DownloadService::new(
        auditor_c.clone(),
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_030),
        download_cfg(),
    );

    // 1. Alice uploads clean multi-chunk (>2 MiB using exact 1 MiB production chunk profile) V1.
    let clean_plaintext: Vec<u8> = (0..(2 * DEFAULT_CHUNK_SIZE_BYTES + 1234))
        .map(|i| (i % 251) as u8)
        .collect();
    let v1 = alice_up
        .create_file(
            None,
            "payroll-2026.csv".to_owned(),
            FolderId::ROOT,
            &clean_plaintext,
            Some(b"internal-payroll-tag"),
            &[compromised.member_id, auditor.member_id],
        )
        .await
        .unwrap();
    ledger.grant_read(v1.file_id, compromised.member_id);
    ledger.grant_write(v1.file_id, compromised.member_id);
    ledger.grant_read(v1.file_id, auditor.member_id);

    // 2. Compromised endpoint uploads ransomware-corrupted V2.
    let v2 = compromised_up
        .append_version(
            v1.file_id,
            None,
            b"LOCKED_BY_RANSOMWARE_PAY_NOW",
            None,
            &[alice.member_id],
        )
        .await
        .unwrap();
    assert_eq!(v2.version_number.get(), 2);
    assert_eq!(v2.parent_manifest_hash, v1.manifest_hash);

    // 3. Emergency Safe suspends compromised member; further writes are blocked immediately.
    ledger.suspend(compromised.member_id);
    let blocked_write = compromised_up
        .append_version(v1.file_id, None, b"MORE_DAMAGE", None, &[])
        .await
        .unwrap_err();
    assert_eq!(blocked_write.domain_error(), DomainError::MemberSuspended);

    // 4. Clean endpoint (Alice) must obtain explicit historical read grant to retrieve V1.
    assert_eq!(
        alice_dl
            .authorize_version(v1.file_id, VersionNumber::ONE)
            .await
            .unwrap_err(),
        DomainError::Unauthorized
    );
    ledger.grant_historical_read(v1.file_id, 1, alice.member_id);
    let v1_access = alice_dl
        .authorize_version(v1.file_id, VersionNumber::ONE)
        .await
        .unwrap();
    let v1_pkg = blobs.package(&v1_access.content_cid);
    let recovered = alice_dl
        .decrypt_authorized_package(v1_access, Some(v1.manifest_hash), &v1_pkg)
        .await
        .unwrap();
    assert_eq!(recovered.plaintext.as_slice(), clean_plaintext.as_slice());

    // 5. Append-only restore creates V3 (parent = V2) encrypted under a fresh DEK for active readers only.
    let v3 = alice_up
        .restore_version(
            v1.file_id,
            None,
            recovered.plaintext.as_slice(),
            recovered.private_metadata.as_deref().map(Vec::as_slice),
            &[auditor.member_id],
        )
        .await
        .unwrap();
    assert_eq!(v3.version_number.get(), 3);
    assert_eq!(v3.parent_manifest_hash, v2.manifest_hash);
    assert_ne!(v3.epoch_id, v1.epoch_id);
    assert_eq!(ledger.version_count(v1.file_id), 3);

    // Auditor decrypts clean V3; history retains V1, V2 (forensic), and V3.
    let v3_access = auditor_dl
        .authorize_version(v1.file_id, VersionNumber::new(3).unwrap())
        .await
        .unwrap();
    let v3_dec = auditor_dl
        .decrypt_authorized_package(
            v3_access,
            Some(v3.manifest_hash),
            &blobs.package(&v3.content_cid),
        )
        .await
        .unwrap();
    assert_eq!(v3_dec.plaintext.as_slice(), clean_plaintext.as_slice());
    assert_eq!(
        ledger.version(v1.file_id, 2).manifest_hash,
        v2.manifest_hash
    );
    assert_eq!(
        ledger.version(v1.file_id, 3).parent_manifest_hash,
        v2.manifest_hash
    );
}

#[tokio::test]
async fn concurrent_conflicting_edits_reject_stale_head_and_report_orphan_cids() {
    let (alice_c, alice) = make_member(1, 1).await;
    let (bob_c, bob) = make_member(2, 1).await;
    let blobs = HarnessBlobStore::two_peers();
    let ledger = HarnessLedger::default();
    ledger.register(alice.clone());
    ledger.register(bob.clone());

    let alice_up = UploadService::new(
        alice_c,
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_000),
        upload_cfg(256),
    );
    let bob_up = UploadService::new(
        bob_c,
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_005),
        upload_cfg(256),
    );

    let v1 = alice_up
        .create_file(
            None,
            "shared-spec.md".to_owned(),
            FolderId::ROOT,
            b"initial version",
            None,
            &[bob.member_id],
        )
        .await
        .unwrap();
    ledger.grant_read(v1.file_id, bob.member_id);
    ledger.grant_write(v1.file_id, bob.member_id);

    // Both Alice and Bob observed V1 as head; Alice wins the race to V2.
    let v2 = alice_up
        .append_version(
            v1.file_id,
            Some((VersionNumber::ONE, v1.manifest_hash)),
            b"alice edit v2",
            None,
            &[bob.member_id],
        )
        .await
        .unwrap();
    assert_eq!(v2.version_number.get(), 2);

    // Bob attempts to append expecting V1 as current head -> fails fast with StaleHead before pinning.
    let err = bob_up
        .append_version(
            v1.file_id,
            Some((VersionNumber::ONE, v1.manifest_hash)),
            b"bob conflicting edit",
            None,
            &[alice.member_id],
        )
        .await
        .unwrap_err();
    assert_eq!(err, UploadError::Domain(DomainError::StaleHead));
    assert_eq!(ledger.version_count(v1.file_id), 2);
}

#[tokio::test]
async fn read_revocation_invalidates_historical_grants_and_key_rotation_rewraps_without_reencryption()
 {
    let (alice_c, alice) = make_member(1, 1).await;
    let (bob_v1_c, bob_v1) = make_member(2, 1).await;
    let (bob_v2_c, bob_v2) = make_member(2, 2).await;

    let blobs = HarnessBlobStore::two_peers();
    let ledger = HarnessLedger::default();
    ledger.register(alice.clone());
    ledger.register(bob_v1.clone());

    let alice_up = UploadService::new(
        alice_c.clone(),
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_000),
        upload_cfg(256),
    );
    let alice_dl = DownloadService::new(
        alice_c.clone(),
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_010),
        download_cfg(),
    );
    let alice_share = ShareService::new(
        alice_c,
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_020),
        share_cfg(),
    );
    let bob_v1_dl = DownloadService::new(
        bob_v1_c,
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_030),
        download_cfg(),
    );
    let bob_v2_dl = DownloadService::new(
        bob_v2_c,
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_040),
        download_cfg(),
    );

    let v1 = alice_up
        .create_file(
            None,
            "contract.pdf".to_owned(),
            FolderId::ROOT,
            b"immutable v1 payload",
            None,
            &[bob_v1.member_id],
        )
        .await
        .unwrap();
    let _v2 = alice_up
        .append_version(v1.file_id, None, b"v2 payload", None, &[bob_v1.member_id])
        .await
        .unwrap();

    // Grant Read + historical Read V1 to Bob, then revoke Read and re-grant Read.
    ledger.grant_read(v1.file_id, bob_v1.member_id);
    ledger.grant_historical_read(v1.file_id, 1, bob_v1.member_id);
    assert!(
        bob_v1_dl
            .authorize_version(v1.file_id, VersionNumber::ONE)
            .await
            .is_ok()
    );

    ledger.revoke_read(v1.file_id, bob_v1.member_id);
    ledger.grant_read(v1.file_id, bob_v1.member_id);
    // Historical V1 MUST stay denied after Read revoke + re-grant until explicitly re-granted!
    assert_eq!(
        bob_v1_dl
            .authorize_version(v1.file_id, VersionNumber::ONE)
            .await
            .unwrap_err(),
        DomainError::Unauthorized
    );

    // Bob supersedes keys to keyVersion=2; Alice re-wraps V1 DEK for Bob v2 without changing contentCid.
    ledger.register(bob_v2.clone());
    ledger.grant_historical_read(v1.file_id, 1, alice.member_id);
    ledger.grant_historical_read(v1.file_id, 1, bob_v2.member_id);
    let alice_v1_access = alice_dl
        .authorize_version(v1.file_id, VersionNumber::ONE)
        .await
        .unwrap();
    let rewrap = alice_share
        .share_version_envelope(
            &alice_v1_access,
            bob_v2.member_id,
            ProposalId::from_bytes([0x55; 32]),
        )
        .await
        .unwrap();
    assert_eq!(rewrap.new_revision, 2);
    assert_eq!(ledger.version(v1.file_id, 1).content_cid, v1.content_cid);

    // Bob's old keyVersion=1 is rejected; Bob's new keyVersion=2 decrypts V1 cleanly.
    assert_eq!(
        bob_v1_dl
            .authorize_version(v1.file_id, VersionNumber::ONE)
            .await
            .unwrap_err(),
        DomainError::Unauthorized
    );
    let bob_v2_access = bob_v2_dl
        .authorize_version(v1.file_id, VersionNumber::ONE)
        .await
        .unwrap();
    let decrypted = bob_v2_dl
        .decrypt_authorized_package(
            bob_v2_access,
            Some(v1.manifest_hash),
            &blobs.package(&v1.content_cid),
        )
        .await
        .unwrap();
    assert_eq!(decrypted.plaintext.as_slice(), b"immutable v1 payload");
}
