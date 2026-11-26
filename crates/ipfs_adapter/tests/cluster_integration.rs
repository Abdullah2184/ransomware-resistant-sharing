use std::{env, io::Cursor, path::Path};

use crypto::{EncryptedChunkRef, EncryptedFileManifest, NoncePrefix};
use domain::{ContentCid, EpochId, FileId, ManifestHash, VersionNumber};
use ipfs_adapter::{ClusterCredentials, IpfsClusterStore, IpfsConfig};
use ports::{BlobStore, ContentChunk, ContentPackage, StorageCid, StorageReader};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

fn load_integration_ipfs_config() -> IpfsConfig {
    let kubo_api_urls = env::var("IPFS_API_URLS")
        .or_else(|_| env::var("IPFS_API_URL"))
        .expect("set IPFS_API_URLS or IPFS_API_URL (for example from .env)")
        .split(',')
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let cluster_api_url =
        env::var("IPFS_CLUSTER_API_URL").expect("set IPFS_CLUSTER_API_URL (for example from .env)");
    let username = env::var("IPFS_CLUSTER_USERNAME")
        .expect("set IPFS_CLUSTER_USERNAME (for example from .env)");
    let raw_password_path = env::var("IPFS_CLUSTER_PASSWORD_FILE")
        .expect("set IPFS_CLUSTER_PASSWORD_FILE (for example from .env)");

    let direct_path = Path::new(&raw_password_path);
    let resolved_path = if direct_path.is_file() {
        direct_path.to_path_buf()
    } else if direct_path.is_relative() {
        // Cargo executes integration tests with CWD set to the crate directory
        // (`crates/ipfs_adapter`), while `.env` paths are relative to the workspace root.
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(direct_path)
    } else {
        direct_path.to_path_buf()
    };
    let password = std::fs::read_to_string(&resolved_path).unwrap_or_else(|_| {
        panic!(
            "could not read IPFS_CLUSTER_PASSWORD_FILE at `{}`; run `sh infra/ipfs-cluster/init-secrets.sh` from the repository root",
            resolved_path.display()
        )
    });

    IpfsConfig {
        kubo_api_urls,
        cluster_api_url,
        cluster_credentials: ClusterCredentials::new(username, password.trim_end().to_owned()),
        request_timeout: std::time::Duration::from_secs(120),
        replication_timeout: std::time::Duration::from_secs(120),
        replication_poll_interval: std::time::Duration::from_millis(500),
        max_upload_bytes: 1_073_741_824,
    }
}

#[tokio::test]
#[ignore = "requires running local Kubo and Cluster services"]
async fn uploads_retrieves_and_replicates_encrypted_objects_on_two_peers() {
    let store =
        IpfsClusterStore::new(load_integration_ipfs_config()).expect("valid IPFS configuration");
    let ciphertext = vec![0xa5; 17];
    let chunk_cid = raw_chunk_cid(&ciphertext);
    let chunk_reference = EncryptedChunkRef::new(
        1,
        ContentCid::parse(&chunk_cid).unwrap(),
        ciphertext.len() as u64,
    )
    .unwrap();
    let manifest = EncryptedFileManifest::new(
        FileId::from_bytes([1; 32]),
        VersionNumber::ONE,
        ManifestHash::ZERO,
        EpochId::from_bytes([2; 32]),
        NoncePrefix::from_bytes([3; 8]),
        crypto::DEFAULT_CHUNK_SIZE_BYTES as u32,
        vec![chunk_reference],
        None,
    )
    .unwrap();
    let package = ContentPackage::new(
        manifest,
        vec![ContentChunk::new(
            1,
            ciphertext.len() as u64,
            Box::pin(Cursor::new(ciphertext.clone())),
        )],
    )
    .unwrap();

    let content = store
        .put_content(package, 2)
        .await
        .expect("content upload and two-peer pin quorum");
    assert!(content.replication.is_satisfied());
    assert_eq!(content.replication.pinned_peers.len(), 2);
    store
        .verify_retrievable(StorageCid::Content(content.cid.clone()))
        .await
        .expect("content root can be exported");

    let envelope_bytes = br#"{"schema":"rrds.key-envelope-set.v1","integration":"non-sensitive"}"#;
    let envelope = store
        .put_envelope_set(
            Box::pin(Cursor::new(envelope_bytes.to_vec())) as StorageReader,
            envelope_bytes.len() as u64,
            2,
        )
        .await
        .expect("envelope upload and two-peer pin quorum");
    assert!(envelope.replication.is_satisfied());
    let mut downloaded = Vec::new();
    store
        .get_envelope_set(&envelope.cid)
        .await
        .unwrap()
        .read_to_end(&mut downloaded)
        .await
        .unwrap();
    assert_eq!(downloaded, envelope_bytes);
    store
        .verify_retrievable(StorageCid::EnvelopeSet(envelope.cid))
        .await
        .expect("envelope can be retrieved");
}

fn raw_chunk_cid(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    cid::Cid::new_v1(
        0x55,
        cid::multihash::Multihash::<64>::wrap(0x12, &digest).unwrap(),
    )
    .to_string()
}
