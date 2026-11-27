//! Security invariant and negative test suite (`TECHNICAL_SPECIFICATION.md` §§14, 15).

use std::sync::Arc;

use chain_adapter::{
    BesuClient, DevelopmentRelayerSigner, RelayError, RelayerConfig, RelayerStartupPolicy,
    TransactionRelayer,
};
use crypto::{
    ChainId, ChunkDecryptor, ChunkEncryptor, DataEncryptionKey, Eip712Domain, EncryptedChunk,
    EncryptionContext, HpkeRecipientKeyPair, KeyEnvelope, NoncePrefix, UnixDeadline, VersionAppend,
    WrapContext, chunk_count_for_len,
};
use domain::{
    ContentCid, EnvelopeSetCid, EpochId, EvmAddress, FileId, KeyVersion, ManifestHash, MemberId,
    OperationNonce, VersionNumber,
};
use key_custody::{
    CustodyPolicyError, CustodyStartupPolicy, DevelopmentKeyCustody, verify_provider_policy,
};
use ports::{
    PreUploadScanner, ScanOutcome, ScanVerdict, ScannerMode, StorageError,
    decode_content_package_frame,
};
use scanner::DisabledScanner;

#[test]
fn ciphertext_tamper_chunk_swap_and_context_transplant_all_fail_closed() {
    let dek_bytes = DataEncryptionKey::generate()
        .unwrap()
        .into_zeroizing_bytes();
    let nonce_prefix = NoncePrefix::generate().unwrap();
    let file_id = FileId::from_bytes([0x11; 32]);
    let epoch_id = EpochId::from_bytes([0x22; 32]);
    let context = EncryptionContext::new(file_id, VersionNumber::ONE, epoch_id);
    let total_chunks = chunk_count_for_len(128, 64).unwrap();

    let mut enc = ChunkEncryptor::new(
        DataEncryptionKey::from_secret(dek_bytes.clone()),
        nonce_prefix,
        context,
        64,
        total_chunks,
    )
    .unwrap();
    let c1 = enc.encrypt_next(&[0x41; 64]).unwrap();
    let c2 = enc.encrypt_next(&[0x42; 64]).unwrap();
    enc.finish().unwrap();

    // 1. Single-bit ciphertext mutation fails AEAD verification.
    let mut bad_bytes = c1.ciphertext_and_tag().to_vec();
    bad_bytes[0] ^= 0x01;
    let mut dec = ChunkDecryptor::new(
        DataEncryptionKey::from_secret(dek_bytes.clone()),
        nonce_prefix,
        context,
        64,
        total_chunks,
    )
    .unwrap();
    assert!(
        dec.decrypt_next(&EncryptedChunk::from_parts(1, bad_bytes))
            .is_err()
    );

    // 2. Chunk swap (passing c2 as index 1) fails AAD index binding.
    let mut dec_swap = ChunkDecryptor::new(
        DataEncryptionKey::from_secret(dek_bytes.clone()),
        nonce_prefix,
        context,
        64,
        total_chunks,
    )
    .unwrap();
    assert!(
        dec_swap
            .decrypt_next(&EncryptedChunk::from_parts(
                1,
                c2.ciphertext_and_tag().to_vec()
            ))
            .is_err()
    );

    // 3. Context transplant (different fileId or versionNumber) fails AAD binding.
    let wrong_ctx =
        EncryptionContext::new(FileId::from_bytes([0x99; 32]), VersionNumber::ONE, epoch_id);
    let mut dec_ctx = ChunkDecryptor::new(
        DataEncryptionKey::from_secret(dek_bytes),
        nonce_prefix,
        wrong_ctx,
        64,
        total_chunks,
    )
    .unwrap();
    assert!(dec_ctx.decrypt_next(&c1).is_err());
}

#[test]
fn hpke_envelope_rejects_wrong_recipient_and_context_substitution() {
    let dek = DataEncryptionKey::generate().unwrap();
    let alice = HpkeRecipientKeyPair::generate().unwrap();
    let mallory = HpkeRecipientKeyPair::generate().unwrap();
    let ctx = WrapContext::new(
        FileId::from_bytes([0x01; 32]),
        VersionNumber::ONE,
        EpochId::from_bytes([0x02; 32]),
        MemberId::from_bytes([0x03; 32]),
        KeyVersion::new(1).unwrap(),
    );
    let envelope = KeyEnvelope::wrap(&dek, alice.public_key(), ctx).unwrap();

    // Wrong recipient key fails.
    assert!(mallory.open_dek(&envelope, ctx).is_err());

    // Wrong key version in AAD context fails even for the legitimate recipient key.
    let wrong_ver_ctx = WrapContext::new(
        FileId::from_bytes([0x01; 32]),
        VersionNumber::ONE,
        EpochId::from_bytes([0x02; 32]),
        MemberId::from_bytes([0x03; 32]),
        KeyVersion::new(2).unwrap(),
    );
    assert!(alice.open_dek(&envelope, wrong_ver_ctx).is_err());
}

#[test]
fn eip712_domain_separation_rejects_cross_contract_and_cross_chain_reuse() {
    let cid =
        ContentCid::parse("bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku").unwrap();
    let env_cid =
        EnvelopeSetCid::parse("bafkreifjjcie6lypi6ny7amxnfftagclbuxndqonfipmb64f2uf2nuiuqa")
            .unwrap();
    let append = VersionAppend::new(
        FileId::from_bytes([0x11; 32]),
        VersionNumber::ONE,
        ManifestHash::ZERO,
        ManifestHash::from_bytes([0x22; 32]),
        cid,
        env_cid,
        EpochId::from_bytes([0x33; 32]),
        MemberId::from_bytes([0x44; 32]),
        EvmAddress::from_bytes([0x55; 20]),
        OperationNonce::from_bytes([0x66; 32]),
        UnixDeadline::from_unix_seconds(1_800_000_000).unwrap(),
    )
    .unwrap();

    let file_domain =
        Eip712Domain::file_registry(ChainId::from_u64(1337), EvmAddress::from_bytes([0xaa; 20]));
    let other_chain =
        Eip712Domain::file_registry(ChainId::from_u64(1338), EvmAddress::from_bytes([0xaa; 20]));
    let wrong_contract_kind = Eip712Domain::access_governance(
        ChainId::from_u64(1337),
        EvmAddress::from_bytes([0xaa; 20]),
    );

    assert_ne!(
        append.digest(&file_domain).unwrap(),
        append.digest(&other_chain).unwrap()
    );
    assert!(append.digest(&wrong_contract_kind).is_err());
}

#[tokio::test]
async fn production_startup_policies_reject_software_custody_and_relayer_keys() {
    let custody = DevelopmentKeyCustody::generate(
        MemberId::from_bytes([1; 32]),
        KeyVersion::new(1).unwrap(),
        KeyVersion::new(1).unwrap(),
    )
    .unwrap();
    assert_eq!(
        verify_provider_policy(&custody, CustodyStartupPolicy::Production).await,
        Err(CustodyPolicyError::TestProviderRejectedInProduction)
    );

    let client = BesuClient::new("http://127.0.0.1:8545").unwrap();
    let relayer_signer = Arc::new(DevelopmentRelayerSigner::from_secret_bytes([0x33; 32]).unwrap());
    assert_eq!(
        TransactionRelayer::new(
            client,
            relayer_signer,
            RelayerStartupPolicy::Production,
            RelayerConfig::local_default(1337),
        )
        .unwrap_err(),
        RelayError::UnsafeSignerInProduction
    );
}

#[tokio::test]
async fn plaintext_package_frame_rejected_and_default_scanner_stays_disabled() {
    assert_eq!(
        decode_content_package_frame(b"PLAINTEXT_NOT_ENCRYPTED").err(),
        Some(StorageError::InvalidPackage)
    );
    let scanner = DisabledScanner;
    assert_eq!(scanner.mode(), ScannerMode::Disabled);
    assert_eq!(
        scanner.scan_plaintext("doc.txt", b"hello").await.unwrap(),
        ScanOutcome::Skipped
    );
    assert_eq!(
        scanner.evaluate("doc.txt", b"hello").await.unwrap(),
        ScanVerdict::Allow
    );
}

#[tokio::test]
async fn custody_encryption_and_envelope_negative_integration_matrix() {
    use std::{
        collections::{BTreeMap, HashMap},
        io::Cursor,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use application::{
        AuthConfig, AuthService, DownloadConfig, DownloadService, EncryptedPackageBytes,
        ShareConfig, ShareService, UploadConfig, UploadService,
    };
    use crypto::{EncryptedFileManifest, KeyEnvelopeEntry, KeyEnvelopeSet, raw_sha256_cid};
    use domain::{
        AccessReference, DomainError, FileStatus, FolderId, LoginChallenge, MemberStatus,
        OrganizationId, ProposalId, PublicMemberIdentity, TransactionReceipt,
    };
    use ports::{
        AuthenticatedSession, BlobStore, Clock, ContentPackage, CustodyCapabilities, CustodyError,
        CustodyFuture, CustodyHealth, EvmSignature, GatewayAuthPort, HeadState, KeyCustodyProvider,
        KeyId, LedgerPort, PortFuture, PublicIdentityKeys, ReplicationReceipt,
        SignedAccessLookupRequest, SignedAppendVersionRequest, SignedCreateFileRequest,
        SignedEnvelopeUpdateRequest, StorageCid, StorageFuture, StorageReader, StoredContent,
        StoredEnvelopeSet,
    };
    use tokio::io::AsyncReadExt;

    #[derive(Clone)]
    struct FixedClock(u64);
    impl Clock for FixedClock {
        fn now_unix_seconds(&self) -> Result<u64, DomainError> {
            Ok(self.0)
        }
    }

    struct CountingCustody {
        inner: Arc<DevelopmentKeyCustody>,
        unwrap_calls: Arc<AtomicUsize>,
    }

    impl KeyCustodyProvider for CountingCustody {
        fn public_identity(&self) -> CustodyFuture<'_, PublicIdentityKeys> {
            self.inner.public_identity()
        }
        fn sign_typed_digest<'a>(
            &'a self,
            key_id: &'a KeyId,
            digest: &'a crypto::TypedDigest,
        ) -> CustodyFuture<'a, EvmSignature> {
            self.inner.sign_typed_digest(key_id, digest)
        }
        fn unwrap_dek<'a>(
            &'a self,
            key_id: &'a KeyId,
            envelope: &'a KeyEnvelope,
            context: WrapContext,
        ) -> CustodyFuture<'a, zeroize::Zeroizing<[u8; 32]>> {
            self.unwrap_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.unwrap_dek(key_id, envelope, context)
        }
        fn health_check(&self) -> CustodyFuture<'_, CustodyHealth> {
            self.inner.health_check()
        }
    }

    struct UnavailableCustody;
    impl KeyCustodyProvider for UnavailableCustody {
        fn public_identity(&self) -> CustodyFuture<'_, PublicIdentityKeys> {
            Box::pin(async { Err(CustodyError::ProviderUnavailable) })
        }
        fn sign_typed_digest<'a>(
            &'a self,
            _key_id: &'a KeyId,
            _digest: &'a crypto::TypedDigest,
        ) -> CustodyFuture<'a, EvmSignature> {
            Box::pin(async { Err(CustodyError::ProviderUnavailable) })
        }
        fn unwrap_dek<'a>(
            &'a self,
            _key_id: &'a KeyId,
            _envelope: &'a KeyEnvelope,
            _context: WrapContext,
        ) -> CustodyFuture<'a, zeroize::Zeroizing<[u8; 32]>> {
            Box::pin(async { Err(CustodyError::ProviderUnavailable) })
        }
        fn health_check(&self) -> CustodyFuture<'_, CustodyHealth> {
            Box::pin(async {
                Ok(CustodyHealth {
                    healthy: false,
                    capabilities: CustodyCapabilities {
                        secp256k1_signing: true,
                        hpke_x25519_unwrap: true,
                        private_keys_non_exportable: true,
                        test_only: false,
                    },
                })
            })
        }
    }

    #[derive(Clone, Default)]
    struct TestBlobs {
        contents: Arc<Mutex<HashMap<String, EncryptedPackageBytes>>>,
        envelopes: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }
    impl TestBlobs {
        fn insert_envelope(&self, bytes: Vec<u8>) -> EnvelopeSetCid {
            let cid = EnvelopeSetCid::parse(&raw_sha256_cid(&bytes).unwrap().to_string()).unwrap();
            self.envelopes
                .lock()
                .unwrap()
                .insert(cid.to_string(), bytes);
            cid
        }
        fn package(&self, cid: &ContentCid) -> EncryptedPackageBytes {
            self.contents
                .lock()
                .unwrap()
                .get(&cid.to_string())
                .cloned()
                .unwrap()
        }
        fn content_count(&self) -> usize {
            self.contents.lock().unwrap().len()
        }
    }
    impl BlobStore for TestBlobs {
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
                let mut stored_chunks = Vec::new();
                for chunk in chunks {
                    let idx = chunk.index();
                    let mut buf = Vec::new();
                    chunk
                        .into_reader()
                        .read_to_end(&mut buf)
                        .await
                        .map_err(|_| StorageError::TransportUnavailable)?;
                    total += buf.len() as u64;
                    stored_chunks.push((idx, buf));
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
                    bytes_written: total,
                    replication: ReplicationReceipt {
                        cid: StorageCid::Content(cid),
                        required_replicas: min_replicas,
                        pinned_peers: vec!["peer-1".into(), "peer-2".into()],
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
                let mut buf = Vec::new();
                reader
                    .read_to_end(&mut buf)
                    .await
                    .map_err(|_| StorageError::TransportUnavailable)?;
                if buf.len() as u64 != byte_length {
                    return Err(StorageError::InvalidPackage);
                }
                let cid = self.insert_envelope(buf);
                Ok(StoredEnvelopeSet {
                    cid: cid.clone(),
                    bytes_written: byte_length,
                    replication: ReplicationReceipt {
                        cid: StorageCid::EnvelopeSet(cid),
                        required_replicas: min_replicas,
                        pinned_peers: vec!["peer-1".into(), "peer-2".into()],
                    },
                })
            })
        }
        fn get_content<'a>(&'a self, cid: &'a ContentCid) -> StorageFuture<'a, StorageReader> {
            Box::pin(async move {
                let pkg = self.package(cid);
                Ok(Box::pin(Cursor::new(pkg.manifest_bytes)) as StorageReader)
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
                Ok(ReplicationReceipt {
                    cid,
                    required_replicas: min_replicas,
                    pinned_peers: vec!["peer-1".into(), "peer-2".into()],
                })
            })
        }
        fn verify_retrievable<'a>(&'a self, _cid: StorageCid) -> StorageFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    #[derive(Clone, Default)]
    struct TestLedger {
        members: Arc<Mutex<BTreeMap<MemberId, PublicMemberIdentity>>>,
        heads: Arc<Mutex<BTreeMap<FileId, HeadState>>>,
        versions: Arc<Mutex<BTreeMap<(FileId, u64), AccessReference>>>,
    }
    impl TestLedger {
        fn register(&self, id: PublicMemberIdentity) {
            self.members.lock().unwrap().insert(id.member_id, id);
        }
    }
    impl LedgerPort for TestLedger {
        fn get_member(&self, member_id: MemberId) -> PortFuture<'_, Option<PublicMemberIdentity>> {
            Box::pin(async move { Ok(self.members.lock().unwrap().get(&member_id).cloned()) })
        }
        fn get_file_head(&self, file_id: FileId) -> PortFuture<'_, Option<HeadState>> {
            Box::pin(async move { Ok(self.heads.lock().unwrap().get(&file_id).cloned()) })
        }
        fn authorize_read<'a>(
            &'a self,
            req: &'a SignedAccessLookupRequest,
        ) -> PortFuture<'a, AccessReference> {
            Box::pin(async move {
                self.versions
                    .lock()
                    .unwrap()
                    .get(&(req.file_id, req.version_number.get()))
                    .cloned()
                    .ok_or(DomainError::Unauthorized)
            })
        }
        fn create_file<'a>(
            &'a self,
            req: &'a SignedCreateFileRequest,
        ) -> PortFuture<'a, TransactionReceipt> {
            Box::pin(async move {
                self.heads.lock().unwrap().insert(
                    req.file_id,
                    HeadState {
                        file_id: req.file_id,
                        status: FileStatus::Active,
                        current_version: req.version_number,
                        current_head_manifest_hash: req.manifest_hash,
                    },
                );
                self.versions.lock().unwrap().insert(
                    (req.file_id, req.version_number.get()),
                    AccessReference {
                        file_id: req.file_id,
                        version_number: req.version_number,
                        manifest_hash: req.manifest_hash,
                        content_cid: req.content_cid.clone(),
                        envelope_set_cid: req.envelope_set_cid.clone(),
                        epoch_id: req.epoch_id,
                        envelope_revision: 1,
                        finalized_block: 10,
                    },
                );
                Ok(TransactionReceipt {
                    transaction_hash: [0x11; 32],
                    block_number: 10,
                    finalized: true,
                    succeeded: true,
                })
            })
        }
        fn append_version<'a>(
            &'a self,
            _req: &'a SignedAppendVersionRequest,
        ) -> PortFuture<'a, TransactionReceipt> {
            Box::pin(async { Err(DomainError::ContractRejected) })
        }
        fn update_envelope_set<'a>(
            &'a self,
            _req: &'a SignedEnvelopeUpdateRequest,
        ) -> PortFuture<'a, TransactionReceipt> {
            Box::pin(async { Err(DomainError::ContractRejected) })
        }
    }

    struct StubAuth;
    impl GatewayAuthPort for StubAuth {
        fn request_challenge(&self, member_id: MemberId) -> PortFuture<'_, LoginChallenge> {
            Box::pin(async move {
                Ok(LoginChallenge {
                    member_id,
                    nonce: OperationNonce::from_bytes([0x55; 32]),
                    issued_at: 1_800_000_000,
                    expires_at: 1_800_000_120,
                    audience: "rrds-test".into(),
                    protocol_version: 1,
                })
            })
        }
        fn exchange_challenge<'a>(
            &'a self,
            challenge: &'a LoginChallenge,
            _signature: &'a EvmSignature,
        ) -> PortFuture<'a, AuthenticatedSession> {
            Box::pin(async move {
                Ok(AuthenticatedSession::new(
                    "0x11".into(),
                    challenge.member_id,
                    challenge.expires_at + 600,
                ))
            })
        }
    }

    async fn make_member(
        seed: u8,
        key_ver: u32,
    ) -> (Arc<DevelopmentKeyCustody>, PublicMemberIdentity) {
        let member_id = MemberId::from_bytes([seed; 32]);
        let custody = Arc::new(
            DevelopmentKeyCustody::generate(
                member_id,
                KeyVersion::new(key_ver).unwrap(),
                KeyVersion::new(key_ver).unwrap(),
            )
            .unwrap(),
        );
        let pub_keys = custody.public_identity().await.unwrap();
        let identity = PublicMemberIdentity {
            member_id,
            organization_id: OrganizationId::from_bytes([0x01; 32]),
            signing_address: pub_keys.signing_address,
            signing_key_version: pub_keys.signing_key_version,
            encryption_key_version: pub_keys.encryption_key_version,
            encryption_public_key: pub_keys
                .encryption_public_key
                .to_bytes()
                .try_into()
                .unwrap(),
            status: MemberStatus::Active,
            finalized_block: 1,
        };
        (custody, identity)
    }

    let (alice_custody, alice) = make_member(1, 1).await;
    let (bob_custody, bob) = make_member(2, 1).await;
    let (mallory_custody, mallory) = make_member(3, 1).await;
    let (alice_stale_custody, _) = make_member(1, 2).await;

    let blobs = TestBlobs::default();
    let ledger = TestLedger::default();
    ledger.register(alice.clone());
    ledger.register(bob.clone());
    ledger.register(mallory.clone());

    let upload_cfg = UploadConfig {
        chain_id: 1337,
        file_registry: EvmAddress::from_bytes([0x11; 20]),
        min_pin_replicas: 2,
        chunk_size_bytes: 64,
        max_file_bytes: 1024 * 1024,
        operation_ttl_seconds: 120,
    };
    let download_cfg = DownloadConfig {
        chain_id: 1337,
        access_governance: EvmAddress::from_bytes([0x22; 20]),
        operation_ttl_seconds: 120,
    };
    let share_cfg = ShareConfig {
        chain_id: 1337,
        access_governance: EvmAddress::from_bytes([0x22; 20]),
        min_pin_replicas: 2,
        operation_ttl_seconds: 120,
    };

    // 1. Stale local signing key is rejected BEFORE pinning any blobs in storage.
    let stale_upload = UploadService::new(
        alice_stale_custody.clone(),
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_000),
        upload_cfg.clone(),
    );
    assert_eq!(
        stale_upload
            .create_file(None, "stale.txt".into(), FolderId::ROOT, b"nope", None, &[])
            .await
            .unwrap_err()
            .domain_error(),
        DomainError::Unauthorized
    );
    assert_eq!(
        blobs.content_count(),
        0,
        "stale signing key must not pin orphaned content blobs"
    );

    // 2. Upload a 3-chunk file (160 bytes with 64-byte chunks) for Alice only.
    let alice_upload = UploadService::new(
        alice_custody.clone(),
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_000),
        upload_cfg.clone(),
    );
    let plaintext: Vec<u8> = (0u8..160).collect();
    let receipt = alice_upload
        .create_file(
            None,
            "tri-chunk.bin".into(),
            FolderId::ROOT,
            &plaintext,
            Some(b"secret-meta"),
            &[],
        )
        .await
        .unwrap();
    let v1_pkg = blobs.package(&receipt.content_cid);
    let v1_access = AccessReference {
        file_id: receipt.file_id,
        version_number: VersionNumber::ONE,
        manifest_hash: receipt.manifest_hash,
        content_cid: receipt.content_cid.clone(),
        envelope_set_cid: receipt.envelope_set_cid.clone(),
        epoch_id: receipt.epoch_id,
        envelope_revision: 1,
        finalized_block: 10,
    };

    // 3. Tampered chunk CID (chunk 2 of 3) MUST fail closed BEFORE invoking custody.unwrap_dek.
    let unwrap_calls = Arc::new(AtomicUsize::new(0));
    let counting_dl = DownloadService::new(
        CountingCustody {
            inner: alice_custody.clone(),
            unwrap_calls: unwrap_calls.clone(),
        },
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_010),
        download_cfg.clone(),
    );
    let mut tampered_chunk2 = v1_pkg.clone();
    tampered_chunk2.chunks[1].1[0] ^= 0x01;
    assert_eq!(
        counting_dl
            .decrypt_authorized_package(
                v1_access.clone(),
                Some(receipt.manifest_hash),
                &tampered_chunk2,
            )
            .await
            .err(),
        Some(DomainError::IntegrityCheckFailed)
    );
    assert_eq!(
        unwrap_calls.load(Ordering::SeqCst),
        0,
        "tampered chunk must fail CID check before calling custody.unwrap_dek"
    );

    // 4. Tampered manifest hash also fails BEFORE invoking custody.unwrap_dek.
    assert_eq!(
        counting_dl
            .decrypt_authorized_package(
                v1_access.clone(),
                Some(ManifestHash::from_bytes([0xee; 32])),
                &v1_pkg,
            )
            .await
            .err(),
        Some(DomainError::IntegrityCheckFailed)
    );
    assert_eq!(
        unwrap_calls.load(Ordering::SeqCst),
        0,
        "manifest hash mismatch must fail before calling custody.unwrap_dek"
    );

    // 5. Legitimate download succeeds and invokes custody.unwrap_dek exactly once.
    let ok_dec = counting_dl
        .decrypt_authorized_package(v1_access.clone(), Some(receipt.manifest_hash), &v1_pkg)
        .await
        .unwrap();
    assert_eq!(ok_dec.plaintext.as_slice(), plaintext.as_slice());
    assert_eq!(unwrap_calls.load(Ordering::SeqCst), 1);

    // 6. Mallory without an envelope entry gets Unauthorized even with stolen ciphertext.
    let mallory_dl = DownloadService::new(
        mallory_custody.clone(),
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_010),
        download_cfg.clone(),
    );
    assert_eq!(
        mallory_dl
            .decrypt_authorized_package(v1_access.clone(), Some(receipt.manifest_hash), &v1_pkg)
            .await
            .err(),
        Some(DomainError::Unauthorized)
    );

    // 7. Transplanted envelope: Alice's wrapped DEK copied under Mallory's memberId fails unwrap.
    let orig_env_bytes = blobs
        .envelopes
        .lock()
        .unwrap()
        .get(&receipt.envelope_set_cid.to_string())
        .unwrap()
        .clone();
    let orig_env_set = KeyEnvelopeSet::parse_canonical(&orig_env_bytes).unwrap();
    let transplanted_set = KeyEnvelopeSet::new(
        receipt.file_id,
        VersionNumber::ONE,
        receipt.epoch_id,
        2,
        vec![KeyEnvelopeEntry::new(
            mallory.member_id,
            mallory.encryption_key_version,
            orig_env_set.envelopes()[0].envelope().clone(),
        )],
    )
    .unwrap();
    let transplanted_cid = blobs.insert_envelope(transplanted_set.canonical_bytes().unwrap());
    let mut mallory_access = v1_access.clone();
    mallory_access.envelope_set_cid = transplanted_cid;
    mallory_access.envelope_revision = 2;
    assert_eq!(
        mallory_dl
            .decrypt_authorized_package(mallory_access, Some(receipt.manifest_hash), &v1_pkg)
            .await
            .err(),
        Some(DomainError::IntegrityCheckFailed)
    );

    // 8. Wrong-DEK envelope: valid HPKE envelope for Bob wrapping a DECOY DEK unwraps cleanly
    //    via HPKE, then fails closed during AES-GCM private-metadata / chunk decryption.
    let decoy_dek = DataEncryptionKey::generate().unwrap();
    let bob_pk = crypto::HpkeRecipientPublicKey::from_bytes(&bob.encryption_public_key).unwrap();
    let bob_ctx = WrapContext::new(
        receipt.file_id,
        VersionNumber::ONE,
        receipt.epoch_id,
        bob.member_id,
        bob.encryption_key_version,
    );
    let decoy_env = KeyEnvelope::wrap(&decoy_dek, &bob_pk, bob_ctx).unwrap();
    let decoy_set = KeyEnvelopeSet::new(
        receipt.file_id,
        VersionNumber::ONE,
        receipt.epoch_id,
        2,
        vec![KeyEnvelopeEntry::new(
            bob.member_id,
            bob.encryption_key_version,
            decoy_env,
        )],
    )
    .unwrap();
    let decoy_cid = blobs.insert_envelope(decoy_set.canonical_bytes().unwrap());
    let mut bob_decoy_access = v1_access.clone();
    bob_decoy_access.envelope_set_cid = decoy_cid;
    bob_decoy_access.envelope_revision = 2;
    let bob_dl = DownloadService::new(
        bob_custody.clone(),
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_010),
        download_cfg.clone(),
    );
    assert_eq!(
        bob_dl
            .decrypt_authorized_package(bob_decoy_access, Some(receipt.manifest_hash), &v1_pkg)
            .await
            .err(),
        Some(DomainError::IntegrityCheckFailed)
    );

    // 9. Multi-chunk AEAD failure on chunk 2 of 3 (even if manifest CIDs were forged to match
    //    the tampered chunk!) fails closed without returning partial plaintext.
    let parsed_manifest = EncryptedFileManifest::parse_canonical(&v1_pkg.manifest_bytes).unwrap();
    let mut forged_chunk2_bytes = v1_pkg.chunks[1].1.clone();
    forged_chunk2_bytes[0] ^= 0x01;
    let mut forged_chunk_refs = parsed_manifest.chunks().to_vec();
    forged_chunk_refs[1] = crypto::EncryptedChunkRef::new(
        2,
        raw_sha256_cid(&forged_chunk2_bytes).unwrap(),
        forged_chunk2_bytes.len() as u64,
    )
    .unwrap();
    let forged_manifest = EncryptedFileManifest::new(
        parsed_manifest.file_id(),
        parsed_manifest.version_number(),
        parsed_manifest.parent_manifest_hash(),
        parsed_manifest.epoch_id(),
        parsed_manifest.nonce_prefix(),
        parsed_manifest.chunk_size_bytes(),
        forged_chunk_refs,
        parsed_manifest.private_metadata().cloned(),
    )
    .unwrap();
    let forged_manifest_hash = forged_manifest.manifest_hash().unwrap();
    let forged_pkg = EncryptedPackageBytes {
        manifest_bytes: forged_manifest.canonical_bytes().unwrap(),
        chunks: vec![
            v1_pkg.chunks[0].clone(),
            (2, forged_chunk2_bytes),
            v1_pkg.chunks[2].clone(),
        ],
    };
    let mut forged_access = v1_access.clone();
    forged_access.manifest_hash = forged_manifest_hash;
    assert_eq!(
        counting_dl
            .decrypt_authorized_package(forged_access, Some(forged_manifest_hash), &forged_pkg)
            .await
            .err(),
        Some(DomainError::IntegrityCheckFailed)
    );

    // 10. Key-version mismatch: rotated Alice (v2) cannot decrypt a v1-only envelope set.
    let alice_v2_dl = DownloadService::new(
        alice_stale_custody,
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_010),
        download_cfg.clone(),
    );
    assert_eq!(
        alice_v2_dl
            .decrypt_authorized_package(v1_access.clone(), Some(receipt.manifest_hash), &v1_pkg)
            .await
            .err(),
        Some(DomainError::Unauthorized)
    );

    // 11. Custody ProviderUnavailable surfaces cleanly as KeyCustodyUnavailable across services.
    let unavail_auth = AuthService::new(
        UnavailableCustody,
        StubAuth,
        FixedClock(1_800_000_010),
        AuthConfig {
            chain_id: 1337,
            access_governance: EvmAddress::from_bytes([0x22; 20]),
            expected_audience: "rrds-test".into(),
            max_challenge_ttl_seconds: 120,
        },
    );
    assert_eq!(
        unavail_auth.login().await.err(),
        Some(DomainError::KeyCustodyUnavailable)
    );

    let unavail_upload = UploadService::new(
        UnavailableCustody,
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_010),
        upload_cfg,
    );
    assert_eq!(
        unavail_upload
            .create_file(None, "x.txt".into(), FolderId::ROOT, b"data", None, &[])
            .await
            .unwrap_err()
            .domain_error(),
        DomainError::KeyCustodyUnavailable
    );

    let unavail_dl = DownloadService::new(
        UnavailableCustody,
        blobs.clone(),
        ledger.clone(),
        FixedClock(1_800_000_010),
        download_cfg,
    );
    assert_eq!(
        unavail_dl
            .decrypt_authorized_package(v1_access.clone(), Some(receipt.manifest_hash), &v1_pkg)
            .await
            .err(),
        Some(DomainError::KeyCustodyUnavailable)
    );

    let unavail_share = ShareService::new(
        UnavailableCustody,
        blobs,
        ledger,
        FixedClock(1_800_000_010),
        share_cfg,
    );
    assert_eq!(
        unavail_share
            .share_version_envelope(&v1_access, bob.member_id, ProposalId::from_bytes([0; 32]))
            .await
            .unwrap_err(),
        application::ShareError::Domain(DomainError::KeyCustodyUnavailable)
    );
}
