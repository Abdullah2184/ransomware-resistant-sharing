use std::{env, io::Cursor, path::Path, time::Duration};

use crypto::{
    ChunkDecryptor, ChunkEncryptor, DEFAULT_CHUNK_SIZE_BYTES, DataEncryptionKey, EncryptedChunkRef,
    EncryptedFileManifest, EncryptionContext, HpkeRecipientKeyPair, KeyEnvelope, KeyEnvelopeEntry,
    KeyEnvelopeSet, NoncePrefix, WrapContext, chunk_count_for_len, decrypt_private_metadata,
    encrypt_private_metadata, extract_verified_car_package, raw_sha256_cid,
};
use domain::{
    AccessReference, DomainError, EpochId, FileId, KeyVersion, ManifestHash, MemberId,
    VersionNumber,
};
use ipfs_adapter::{ClusterCredentials, IpfsClusterStore, IpfsConfig};
use ports::{BlobStore, ContentChunk, ContentPackage, StorageCid, StorageError, StorageReader};
use tokio::io::AsyncReadExt;

struct LiveIpfsEnv {
    kubo_urls: Vec<String>,
    cluster_urls: Vec<String>,
    username: String,
    password: String,
}

fn load_live_ipfs_env() -> LiveIpfsEnv {
    let kubo_urls = env::var("IPFS_API_URLS")
        .or_else(|_| env::var("IPFS_API_URL"))
        .expect("set IPFS_API_URLS (two Kubo peers, e.g. from .env)")
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert!(
        kubo_urls.len() >= 2,
        "live dual-node test requires at least two Kubo endpoints in IPFS_API_URLS"
    );

    let cluster_urls = env::var("IPFS_CLUSTER_API_URLS")
        .or_else(|_| env::var("IPFS_CLUSTER_API_URL"))
        .expect("set IPFS_CLUSTER_API_URLS or IPFS_CLUSTER_API_URL (e.g. from .env)")
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert!(
        !cluster_urls.is_empty(),
        "IPFS_CLUSTER_API_URL(S) must not be empty"
    );

    let username =
        env::var("IPFS_CLUSTER_USERNAME").expect("set IPFS_CLUSTER_USERNAME (e.g. from .env)");
    let raw_password_path = env::var("IPFS_CLUSTER_PASSWORD_FILE")
        .expect("set IPFS_CLUSTER_PASSWORD_FILE (e.g. from .env)");

    let direct_path = Path::new(&raw_password_path);
    let resolved_path = if direct_path.is_file() {
        direct_path.to_path_buf()
    } else if direct_path.is_relative() {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(direct_path)
    } else {
        direct_path.to_path_buf()
    };
    let password = std::fs::read_to_string(&resolved_path)
        .unwrap_or_else(|_| {
            panic!(
                "could not read IPFS_CLUSTER_PASSWORD_FILE at `{}`; run `sh infra/ipfs-cluster/init-secrets.sh` from the repository root",
                resolved_path.display()
            )
        })
        .trim_end()
        .to_owned();

    LiveIpfsEnv {
        kubo_urls,
        cluster_urls,
        username,
        password,
    }
}

fn make_store(env_cfg: &LiveIpfsEnv, kubo_urls: Vec<String>) -> IpfsClusterStore {
    IpfsClusterStore::new(IpfsConfig {
        kubo_api_urls: kubo_urls,
        cluster_api_urls: env_cfg.cluster_urls.clone(),
        cluster_credentials: ClusterCredentials::new(
            env_cfg.username.clone(),
            env_cfg.password.clone(),
        ),
        request_timeout: Duration::from_secs(120),
        replication_timeout: Duration::from_secs(120),
        replication_poll_interval: Duration::from_millis(500),
        max_upload_bytes: 1_073_741_824,
    })
    .expect("valid IPFS configuration")
}

fn build_encrypted_package(
    file_id: FileId,
    version_number: VersionNumber,
    parent_manifest_hash: ManifestHash,
    epoch_id: EpochId,
    dek: &DataEncryptionKey,
    plaintext: &[u8],
    private_metadata: Option<&[u8]>,
) -> (EncryptedFileManifest, ManifestHash, ContentPackage) {
    let nonce_prefix = NoncePrefix::generate().unwrap();
    let total_chunks =
        chunk_count_for_len(plaintext.len() as u64, DEFAULT_CHUNK_SIZE_BYTES).expect("chunk count");
    let ctx = EncryptionContext::new(file_id, version_number, epoch_id);
    let enc_meta = private_metadata
        .map(|meta| encrypt_private_metadata(dek, nonce_prefix, ctx, total_chunks, meta).unwrap());

    let dek_copy = dek.clone_for_test();
    let mut encryptor = ChunkEncryptor::new(
        dek_copy,
        nonce_prefix,
        ctx,
        DEFAULT_CHUNK_SIZE_BYTES,
        total_chunks,
    )
    .unwrap();

    let mut chunk_refs = Vec::with_capacity(total_chunks as usize);
    let mut content_chunks = Vec::with_capacity(total_chunks as usize);
    for slice in plaintext.chunks(DEFAULT_CHUNK_SIZE_BYTES) {
        let encrypted = encryptor.encrypt_next(slice).unwrap();
        let bytes = encrypted.ciphertext_and_tag().to_vec();
        let cid = raw_sha256_cid(&bytes).unwrap();
        let len = bytes.len() as u64;
        chunk_refs.push(EncryptedChunkRef::new(encrypted.index(), cid, len).unwrap());
        content_chunks.push(ContentChunk::new(
            encrypted.index(),
            len,
            Box::pin(Cursor::new(bytes)) as StorageReader,
        ));
    }
    encryptor.finish().unwrap();

    let manifest = EncryptedFileManifest::new(
        file_id,
        version_number,
        parent_manifest_hash,
        epoch_id,
        nonce_prefix,
        DEFAULT_CHUNK_SIZE_BYTES as u32,
        chunk_refs,
        enc_meta,
    )
    .unwrap();
    let manifest_hash = manifest.manifest_hash().unwrap();
    let package = ContentPackage::new(manifest.clone(), content_chunks).unwrap();
    (manifest, manifest_hash, package)
}

trait DekTestExt {
    fn clone_for_test(&self) -> DataEncryptionKey;
}

impl DekTestExt for DataEncryptionKey {
    fn clone_for_test(&self) -> DataEncryptionKey {
        // Re-wrap and unwrap via a local ephemeral key pair so we never rely on internal visibility.
        let pair = HpkeRecipientKeyPair::generate().unwrap();
        let ctx = WrapContext::new(
            FileId::from_bytes([0xee; 32]),
            VersionNumber::ONE,
            EpochId::from_bytes([0xdd; 32]),
            MemberId::from_bytes([0xcc; 32]),
            KeyVersion::new(1).unwrap(),
        );
        let env = KeyEnvelope::wrap(self, pair.public_key(), ctx).unwrap();
        pair.open_dek(&env, ctx).unwrap()
    }
}

async fn fetch_and_verify_decrypt(
    store: &IpfsClusterStore,
    access: &AccessReference,
    dek: &DataEncryptionKey,
) -> (Vec<u8>, Option<Vec<u8>>) {
    let mut car_bytes = Vec::new();
    store
        .get_content(&access.content_cid)
        .await
        .expect("kubo dag/export succeeds")
        .read_to_end(&mut car_bytes)
        .await
        .expect("read full CAR stream");

    let extracted = extract_verified_car_package(&car_bytes, access)
        .expect("real Kubo CARv1 must pass 2-level UnixFS & manifest_hash verification");
    let manifest = EncryptedFileManifest::parse_canonical(&extracted.manifest_bytes).unwrap();
    let ctx = EncryptionContext::new(
        manifest.file_id(),
        manifest.version_number(),
        manifest.epoch_id(),
    );
    let decrypted_meta = manifest.private_metadata().map(|meta| {
        decrypt_private_metadata(
            dek,
            manifest.nonce_prefix(),
            ctx,
            manifest.chunk_count(),
            meta,
        )
        .unwrap()
        .to_vec()
    });
    let dek_copy = dek.clone_for_test();
    let mut decryptor = ChunkDecryptor::new(
        dek_copy,
        manifest.nonce_prefix(),
        ctx,
        manifest.chunk_size_bytes() as usize,
        manifest.chunk_count(),
    )
    .unwrap();
    let mut plaintext = Vec::new();
    for (idx, chunk_bytes) in extracted.chunks {
        let chunk = crypto::EncryptedChunk::from_parts(idx, chunk_bytes);
        plaintext.extend_from_slice(&decryptor.decrypt_next(&chunk).unwrap());
    }
    decryptor.finish().unwrap();
    (plaintext, decrypted_meta)
}

#[tokio::test]
#[ignore = "requires running local Kubo (2 peers) and IPFS Cluster services"]
async fn uploads_retrieves_verifies_and_decrypts_across_both_kubo_nodes_and_rejects_bad_cases() {
    let env_cfg = load_live_ipfs_env();
    let node1 = make_store(&env_cfg, vec![env_cfg.kubo_urls[0].clone()]);
    let node2 = make_store(&env_cfg, vec![env_cfg.kubo_urls[1].clone()]);

    // 1. Multi-chunk (> 1 MiB = 2 AES-256-GCM chunks) + private metadata uploaded to Kubo 1.
    let mut multi_chunk_plaintext = vec![0u8; DEFAULT_CHUNK_SIZE_BYTES + 4096];
    for (i, byte) in multi_chunk_plaintext.iter_mut().enumerate() {
        *byte = ((i * 31 + 17) % 251) as u8;
    }
    let file_id_1 = FileId::from_bytes([0x41; 32]);
    let epoch_id_1 = EpochId::from_bytes([0x51; 32]);
    let dek_1 = DataEncryptionKey::generate().unwrap();
    let (_, manifest_hash_1, pkg_1) = build_encrypted_package(
        file_id_1,
        VersionNumber::ONE,
        ManifestHash::ZERO,
        epoch_id_1,
        &dek_1,
        &multi_chunk_plaintext,
        Some(b"secret-q4-board-deck.pdf"),
    );

    let stored_1 = node1
        .put_content(pkg_1, 2)
        .await
        .expect("upload to Kubo 1 and 2-peer Cluster pin quorum");
    assert!(stored_1.replication.is_satisfied());
    assert_eq!(stored_1.replication.pinned_peers.len(), 2);

    // ensure_replication verifies existing quorum + root block on BOTH nodes without repinning.
    assert_eq!(
        node1
            .ensure_replication(StorageCid::Content(stored_1.cid.clone()), 2)
            .await
            .unwrap()
            .pinned_peers
            .len(),
        2
    );
    assert_eq!(
        node2
            .ensure_replication(StorageCid::Content(stored_1.cid.clone()), 2)
            .await
            .unwrap()
            .pinned_peers
            .len(),
        2
    );

    // Canonical HPKE KeyEnvelopeSet uploaded to Kubo 1, retrieved & unwrapped from Kubo 2.
    let alice_pair = HpkeRecipientKeyPair::generate().unwrap();
    let intruder_pair = HpkeRecipientKeyPair::generate().unwrap();
    let alice_id = MemberId::from_bytes([0xa1; 32]);
    let alice_ctx = WrapContext::new(
        file_id_1,
        VersionNumber::ONE,
        epoch_id_1,
        alice_id,
        KeyVersion::new(1).unwrap(),
    );
    let alice_env = KeyEnvelope::wrap(&dek_1, alice_pair.public_key(), alice_ctx).unwrap();
    let env_set = KeyEnvelopeSet::new(
        file_id_1,
        VersionNumber::ONE,
        epoch_id_1,
        1,
        vec![KeyEnvelopeEntry::new(
            alice_id,
            KeyVersion::new(1).unwrap(),
            alice_env,
        )],
    )
    .unwrap();
    let env_bytes = env_set.canonical_bytes().unwrap();
    let stored_env = node1
        .put_envelope_set(
            Box::pin(Cursor::new(env_bytes.clone())) as StorageReader,
            env_bytes.len() as u64,
            2,
        )
        .await
        .expect("envelope upload to Kubo 1 and 2-peer pin quorum");
    assert_eq!(
        stored_env.cid.to_string(),
        raw_sha256_cid(&env_bytes).unwrap().to_string()
    );

    // Retrieve envelope from Kubo 2 and verify CID + HPKE unwrap (and intruder fails closed).
    let mut env_from_node2 = Vec::new();
    node2
        .get_envelope_set(&stored_env.cid)
        .await
        .expect("envelope retrievable from Kubo 2")
        .read_to_end(&mut env_from_node2)
        .await
        .unwrap();
    assert_eq!(env_from_node2, env_bytes);
    let parsed_env = KeyEnvelopeSet::parse_canonical(&env_from_node2).unwrap();
    let unwrapped_dek = alice_pair
        .open_dek(parsed_env.envelopes()[0].envelope(), alice_ctx)
        .expect("authorized recipient unwraps DEK from Kubo 2 envelope");
    assert!(
        intruder_pair
            .open_dek(parsed_env.envelopes()[0].envelope(), alice_ctx)
            .is_err(),
        "unauthorized key pair must not unwrap DEK"
    );

    let access_1 = AccessReference {
        file_id: file_id_1,
        version_number: VersionNumber::ONE,
        manifest_hash: manifest_hash_1,
        content_cid: stored_1.cid.clone(),
        envelope_set_cid: stored_env.cid.clone(),
        epoch_id: epoch_id_1,
        envelope_revision: 1,
        finalized_block: 100,
    };

    // Retrieve & CAR-verify & decrypt from BOTH Kubo 1 AND Kubo 2!
    let (pt_from_node1, meta_from_node1) =
        fetch_and_verify_decrypt(&node1, &access_1, &unwrapped_dek).await;
    assert_eq!(pt_from_node1, multi_chunk_plaintext);
    assert_eq!(
        meta_from_node1.as_deref(),
        Some(b"secret-q4-board-deck.pdf".as_slice())
    );

    let (pt_from_node2, meta_from_node2) =
        fetch_and_verify_decrypt(&node2, &access_1, &unwrapped_dek).await;
    assert_eq!(pt_from_node2, multi_chunk_plaintext);
    assert_eq!(
        meta_from_node2.as_deref(),
        Some(b"secret-q4-board-deck.pdf".as_slice())
    );

    // 2. Reverse direction: upload to Kubo 2 -> retrieve, CAR-verify, and decrypt from Kubo 1!
    let payload_from_node2 = b"uploaded-via-kubo2-retrieved-via-kubo1-verified".to_vec();
    let file_id_2 = FileId::from_bytes([0x42; 32]);
    let epoch_id_2 = EpochId::from_bytes([0x52; 32]);
    let dek_2 = DataEncryptionKey::generate().unwrap();
    let (_, manifest_hash_2, pkg_2) = build_encrypted_package(
        file_id_2,
        VersionNumber::ONE,
        ManifestHash::ZERO,
        epoch_id_2,
        &dek_2,
        &payload_from_node2,
        None,
    );
    let stored_2 = node2
        .put_content(pkg_2, 2)
        .await
        .expect("upload to Kubo 2 and 2-peer Cluster pin quorum");
    assert_eq!(stored_2.replication.pinned_peers.len(), 2);
    let access_2 = AccessReference {
        file_id: file_id_2,
        version_number: VersionNumber::ONE,
        manifest_hash: manifest_hash_2,
        content_cid: stored_2.cid.clone(),
        envelope_set_cid: stored_env.cid.clone(),
        epoch_id: epoch_id_2,
        envelope_revision: 1,
        finalized_block: 101,
    };
    let (pt_2_from_node1, _) = fetch_and_verify_decrypt(&node1, &access_2, &dek_2).await;
    assert_eq!(pt_2_from_node1, payload_from_node2);

    // 3. 0-byte empty file uploaded to Kubo 1 -> retrieved & CAR-verified from Kubo 2!
    let file_id_empty = FileId::from_bytes([0x43; 32]);
    let epoch_id_empty = EpochId::from_bytes([0x53; 32]);
    let dek_empty = DataEncryptionKey::generate().unwrap();
    let (_, manifest_hash_empty, pkg_empty) = build_encrypted_package(
        file_id_empty,
        VersionNumber::ONE,
        ManifestHash::ZERO,
        epoch_id_empty,
        &dek_empty,
        b"",
        None,
    );
    let stored_empty = node1
        .put_content(pkg_empty, 2)
        .await
        .expect("empty file upload and 2-peer pin quorum");
    let access_empty = AccessReference {
        file_id: file_id_empty,
        version_number: VersionNumber::ONE,
        manifest_hash: manifest_hash_empty,
        content_cid: stored_empty.cid.clone(),
        envelope_set_cid: stored_env.cid.clone(),
        epoch_id: epoch_id_empty,
        envelope_revision: 1,
        finalized_block: 102,
    };
    let (pt_empty_from_node2, _) =
        fetch_and_verify_decrypt(&node2, &access_empty, &dek_empty).await;
    assert!(pt_empty_from_node2.is_empty());

    // 4. Negative & insecure-access cases against the REAL live IPFS/Cluster services:
    // 4a. Unauthenticated and wrong-password requests to Cluster REST API are rejected (401).
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let cluster_pin_url = format!(
        "{}/pins/{}",
        env_cfg.cluster_urls[0].trim_end_matches('/'),
        stored_1.cid
    );
    assert_eq!(
        http.get(&cluster_pin_url).send().await.unwrap().status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        http.get(&cluster_pin_url)
            .basic_auth(&env_cfg.username, Some("wrong-password-attempt"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );

    // 4b. Unpinned random CID fails ensure_replication with ReplicationInsufficient (never blind-pins).
    let unpinned_cid = raw_sha256_cid(b"never-uploaded-or-pinned-in-cluster-987654321").unwrap();
    assert_eq!(
        node1
            .ensure_replication(StorageCid::Content(unpinned_cid), 2)
            .await,
        Err(StorageError::ReplicationInsufficient)
    );

    // 4c. Real Kubo CAR stream with 1-bit tamper or wrong manifest_hash or wrong content_cid fails closed.
    let mut live_car = Vec::new();
    node2
        .get_content(&access_1.content_cid)
        .await
        .unwrap()
        .read_to_end(&mut live_car)
        .await
        .unwrap();
    let mut tampered_car = live_car.clone();
    *tampered_car.last_mut().unwrap() ^= 0x01;
    assert_eq!(
        extract_verified_car_package(&tampered_car, &access_1),
        Err(DomainError::IntegrityCheckFailed)
    );

    let mut wrong_manifest = access_1.clone();
    wrong_manifest.manifest_hash = ManifestHash::from_bytes([0xff; 32]);
    assert_eq!(
        extract_verified_car_package(&live_car, &wrong_manifest),
        Err(DomainError::IntegrityCheckFailed)
    );

    let mut wrong_root = access_1.clone();
    wrong_root.content_cid = stored_2.cid.clone();
    assert_eq!(
        extract_verified_car_package(&live_car, &wrong_root),
        Err(DomainError::IntegrityCheckFailed)
    );
}
