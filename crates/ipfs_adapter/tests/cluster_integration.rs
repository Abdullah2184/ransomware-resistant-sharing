use std::io::Cursor;

use crypto::{EncryptedChunkRef, EncryptedFileManifest, NoncePrefix};
use domain::{ContentCid, EpochId, FileId, ManifestHash, VersionNumber};
use ipfs_adapter::{IpfsClusterStore, IpfsConfig};
use ports::{BlobStore, ContentChunk, ContentPackage, StorageCid, StorageReader};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

#[tokio::test]
#[ignore = "requires running local Kubo and Cluster services"]
async fn uploads_retrieves_and_replicates_encrypted_objects_on_two_peers() {
    let store = IpfsClusterStore::new(IpfsConfig::from_env().expect("IPFS test configuration"))
        .expect("valid IPFS configuration");
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
        4 * 1024 * 1024,
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
