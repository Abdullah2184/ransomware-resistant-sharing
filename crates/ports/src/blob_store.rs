use std::{error::Error, fmt, future::Future, io::Cursor, pin::Pin};

use crypto::{EncryptedFileManifest, raw_sha256_cid};
use domain::{ContentCid, DomainError, EnvelopeSetCid};
use tokio::io::{AsyncRead, AsyncReadExt};

const PACKAGE_FRAME_MAGIC: &[u8; 8] = b"RRDSPKG1";
const MAX_MANIFEST_FRAME_BYTES: usize = 512 * 1024;

pub type StorageReader = Pin<Box<dyn AsyncRead + Send + Unpin + 'static>>;
pub type StorageFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StorageError>> + Send + 'a>>;

/// One encrypted ciphertext chunk; plaintext is never accepted at this port.
pub struct ContentChunk {
    index: u32,
    ciphertext_bytes: u64,
    reader: StorageReader,
}

impl ContentChunk {
    pub fn new(index: u32, ciphertext_bytes: u64, reader: StorageReader) -> Self {
        Self {
            index,
            ciphertext_bytes,
            reader,
        }
    }

    pub const fn index(&self) -> u32 {
        self.index
    }

    pub const fn ciphertext_bytes(&self) -> u64 {
        self.ciphertext_bytes
    }

    pub fn into_reader(self) -> StorageReader {
        self.reader
    }
}

/// A manifest and the exact ciphertext chunks committed to by that manifest.
pub struct ContentPackage {
    manifest: EncryptedFileManifest,
    chunks: Vec<ContentChunk>,
}

impl ContentPackage {
    pub fn new(
        manifest: EncryptedFileManifest,
        chunks: Vec<ContentChunk>,
    ) -> Result<Self, StorageError> {
        if chunks.len() != manifest.chunks().len() {
            return Err(StorageError::InvalidPackage);
        }

        for (reference, chunk) in manifest.chunks().iter().zip(&chunks) {
            if reference.index() != chunk.index()
                || reference.ciphertext_bytes() != chunk.ciphertext_bytes()
            {
                return Err(StorageError::InvalidPackage);
            }
        }

        Ok(Self { manifest, chunks })
    }

    pub const fn manifest(&self) -> &EncryptedFileManifest {
        &self.manifest
    }

    pub fn chunks(&self) -> &[ContentChunk] {
        &self.chunks
    }

    pub fn into_parts(self) -> (EncryptedFileManifest, Vec<ContentChunk>) {
        (self.manifest, self.chunks)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StorageCid {
    Content(ContentCid),
    EnvelopeSet(EnvelopeSetCid),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredContent {
    pub cid: ContentCid,
    pub bytes_written: u64,
    pub replication: ReplicationReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredEnvelopeSet {
    pub cid: EnvelopeSetCid,
    pub bytes_written: u64,
    pub replication: ReplicationReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicationReceipt {
    pub cid: StorageCid,
    pub required_replicas: usize,
    pub pinned_peers: Vec<String>,
}

impl ReplicationReceipt {
    pub fn is_satisfied(&self) -> bool {
        self.pinned_peers.len() >= self.required_replicas
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    InvalidPackage,
    InvalidCid,
    InvalidReplicaCount,
    SizeLimitExceeded,
    TransportUnavailable,
    InvalidResponse,
    ReplicationInsufficient,
    IntegrityCheckFailed,
    TimedOut,
}

impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPackage => "invalid encrypted content package",
            Self::InvalidCid => "invalid content identifier",
            Self::InvalidReplicaCount => "invalid replication requirement",
            Self::SizeLimitExceeded => "storage size limit exceeded",
            Self::TransportUnavailable => "storage service unavailable",
            Self::InvalidResponse => "storage service returned an invalid response",
            Self::ReplicationInsufficient => "storage replication requirement not met",
            Self::IntegrityCheckFailed => "stored object integrity check failed",
            Self::TimedOut => "storage operation timed out",
        };
        formatter.write_str(message)
    }
}

impl Error for StorageError {}

impl From<DomainError> for StorageError {
    fn from(error: DomainError) -> Self {
        match error {
            DomainError::InvalidCid => Self::InvalidCid,
            _ => Self::InvalidPackage,
        }
    }
}

/// Storage operations accept encrypted package streams and return only after
/// the requested Cluster replication quorum has been verified.
pub trait BlobStore: Send + Sync {
    fn put_content<'a>(
        &'a self,
        package: ContentPackage,
        min_replicas: usize,
    ) -> StorageFuture<'a, StoredContent>;

    fn put_envelope_set<'a>(
        &'a self,
        reader: StorageReader,
        byte_length: u64,
        min_replicas: usize,
    ) -> StorageFuture<'a, StoredEnvelopeSet>;

    fn get_content<'a>(&'a self, cid: &'a ContentCid) -> StorageFuture<'a, StorageReader>;

    fn get_envelope_set<'a>(&'a self, cid: &'a EnvelopeSetCid) -> StorageFuture<'a, StorageReader>;

    fn ensure_replication<'a>(
        &'a self,
        cid: StorageCid,
        min_replicas: usize,
    ) -> StorageFuture<'a, ReplicationReceipt>;

    fn verify_retrievable<'a>(&'a self, cid: StorageCid) -> StorageFuture<'a, ()>;
}

/// Serializes an encrypted [`ContentPackage`] into the canonical length-prefixed
/// binary frame (`RRDSPKG1`) accepted by the gateway's `POST /v1/blobs/content` route.
pub async fn encode_content_package_frame(
    package: ContentPackage,
    max_total_bytes: usize,
) -> Result<Vec<u8>, StorageError> {
    let (manifest, chunks) = package.into_parts();
    let manifest_bytes = manifest
        .canonical_bytes()
        .map_err(|_| StorageError::InvalidPackage)?;
    if manifest_bytes.len() > MAX_MANIFEST_FRAME_BYTES {
        return Err(StorageError::SizeLimitExceeded);
    }
    let manifest_len =
        u32::try_from(manifest_bytes.len()).map_err(|_| StorageError::InvalidPackage)?;
    let chunk_count = u32::try_from(chunks.len()).map_err(|_| StorageError::InvalidPackage)?;

    let mut out = Vec::new();
    out.extend_from_slice(PACKAGE_FRAME_MAGIC);
    out.extend_from_slice(&manifest_len.to_be_bytes());
    out.extend_from_slice(&manifest_bytes);
    out.extend_from_slice(&chunk_count.to_be_bytes());
    if out.len() > max_total_bytes {
        return Err(StorageError::SizeLimitExceeded);
    }

    for chunk in chunks {
        let index = chunk.index();
        let declared_len = chunk.ciphertext_bytes();
        let declared_usize =
            usize::try_from(declared_len).map_err(|_| StorageError::SizeLimitExceeded)?;
        let next_len = out
            .len()
            .checked_add(12)
            .and_then(|v| v.checked_add(declared_usize))
            .ok_or(StorageError::SizeLimitExceeded)?;
        if next_len > max_total_bytes {
            return Err(StorageError::SizeLimitExceeded);
        }
        let mut bytes = Vec::with_capacity(declared_usize);
        chunk
            .into_reader()
            .take(declared_len.saturating_add(1))
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| StorageError::TransportUnavailable)?;
        if u64::try_from(bytes.len()).ok() != Some(declared_len) {
            return Err(StorageError::InvalidPackage);
        }
        out.extend_from_slice(&index.to_be_bytes());
        out.extend_from_slice(&declared_len.to_be_bytes());
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

/// Validates and decodes an `RRDSPKG1` encrypted package frame into a
/// [`ContentPackage`], verifying canonical manifest structure and every chunk's
/// length and SHA-256 CID before accepting it for storage.
pub fn decode_content_package_frame(frame: &[u8]) -> Result<ContentPackage, StorageError> {
    if frame.len() < 16 || &frame[..8] != PACKAGE_FRAME_MAGIC {
        return Err(StorageError::InvalidPackage);
    }
    let manifest_len = u32::from_be_bytes(
        frame[8..12]
            .try_into()
            .map_err(|_| StorageError::InvalidPackage)?,
    ) as usize;
    if manifest_len == 0 || manifest_len > MAX_MANIFEST_FRAME_BYTES {
        return Err(StorageError::InvalidPackage);
    }
    let manifest_end = 12usize
        .checked_add(manifest_len)
        .ok_or(StorageError::InvalidPackage)?;
    let count_end = manifest_end
        .checked_add(4)
        .ok_or(StorageError::InvalidPackage)?;
    let manifest_bytes = frame
        .get(12..manifest_end)
        .ok_or(StorageError::InvalidPackage)?;
    let manifest = EncryptedFileManifest::parse_canonical(manifest_bytes)
        .map_err(|_| StorageError::InvalidPackage)?;

    let chunk_count = u32::from_be_bytes(
        frame
            .get(manifest_end..count_end)
            .ok_or(StorageError::InvalidPackage)?
            .try_into()
            .map_err(|_| StorageError::InvalidPackage)?,
    ) as usize;
    if chunk_count != manifest.chunks().len() {
        return Err(StorageError::InvalidPackage);
    }

    let mut cursor = count_end;
    let mut chunks = Vec::with_capacity(chunk_count);
    for expected_ref in manifest.chunks() {
        let header_end = cursor.checked_add(12).ok_or(StorageError::InvalidPackage)?;
        let header = frame
            .get(cursor..header_end)
            .ok_or(StorageError::InvalidPackage)?;
        let index = u32::from_be_bytes(
            header[0..4]
                .try_into()
                .map_err(|_| StorageError::InvalidPackage)?,
        );
        let declared_len = u64::from_be_bytes(
            header[4..12]
                .try_into()
                .map_err(|_| StorageError::InvalidPackage)?,
        );
        let byte_len = usize::try_from(declared_len).map_err(|_| StorageError::InvalidPackage)?;
        let data_end = header_end
            .checked_add(byte_len)
            .ok_or(StorageError::InvalidPackage)?;
        let chunk_bytes = frame
            .get(header_end..data_end)
            .ok_or(StorageError::InvalidPackage)?;
        if index != expected_ref.index() || declared_len != expected_ref.ciphertext_bytes() {
            return Err(StorageError::InvalidPackage);
        }
        let actual_cid =
            raw_sha256_cid(chunk_bytes).map_err(|_| StorageError::IntegrityCheckFailed)?;
        if actual_cid != *expected_ref.cid() {
            return Err(StorageError::IntegrityCheckFailed);
        }
        chunks.push(ContentChunk::new(
            index,
            declared_len,
            Box::pin(Cursor::new(chunk_bytes.to_vec())) as StorageReader,
        ));
        cursor = data_end;
    }
    if cursor != frame.len() {
        return Err(StorageError::InvalidPackage);
    }
    ContentPackage::new(manifest, chunks)
}

#[cfg(test)]
mod tests {
    use crypto::{EncryptedChunkRef, NoncePrefix};
    use domain::{EpochId, FileId, ManifestHash, VersionNumber};

    use super::*;

    #[tokio::test]
    async fn content_package_frame_round_trips_and_rejects_tamper_or_trailing_bytes() {
        let chunk_data = vec![0x5a; 48];
        let chunk_cid = raw_sha256_cid(&chunk_data).unwrap();
        let manifest = EncryptedFileManifest::new(
            FileId::from_bytes([0x11; 32]),
            VersionNumber::ONE,
            ManifestHash::ZERO,
            EpochId::from_bytes([0x22; 32]),
            NoncePrefix::from_bytes([0x33; 8]),
            64,
            vec![EncryptedChunkRef::new(1, chunk_cid, chunk_data.len() as u64).unwrap()],
            None,
        )
        .unwrap();
        let pkg = ContentPackage::new(
            manifest.clone(),
            vec![ContentChunk::new(
                1,
                chunk_data.len() as u64,
                Box::pin(Cursor::new(chunk_data.clone())) as StorageReader,
            )],
        )
        .unwrap();

        let frame = encode_content_package_frame(pkg, 1024 * 1024)
            .await
            .unwrap();
        let decoded = decode_content_package_frame(&frame).unwrap();
        assert_eq!(decoded.manifest(), &manifest);
        assert_eq!(decoded.chunks().len(), 1);

        // Tampered chunk fails CID integrity check.
        let mut tampered = frame.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert_eq!(
            decode_content_package_frame(&tampered).err(),
            Some(StorageError::IntegrityCheckFailed)
        );

        // Trailing garbage rejected.
        let mut trailing = frame;
        trailing.push(0x00);
        assert_eq!(
            decode_content_package_frame(&trailing).err(),
            Some(StorageError::InvalidPackage)
        );

        // Plaintext / wrong magic rejected.
        assert_eq!(
            decode_content_package_frame(b"not-an-encrypted-package").err(),
            Some(StorageError::InvalidPackage)
        );
    }

    #[tokio::test]
    async fn content_package_frame_handles_empty_files_and_rejects_size_or_reader_mismatches() {
        // 0-byte file (0 chunks) round-trips cleanly.
        let empty_manifest = EncryptedFileManifest::new(
            FileId::from_bytes([0x11; 32]),
            VersionNumber::ONE,
            ManifestHash::ZERO,
            EpochId::from_bytes([0x22; 32]),
            NoncePrefix::from_bytes([0x33; 8]),
            64,
            Vec::new(),
            None,
        )
        .unwrap();
        let empty_pkg = ContentPackage::new(empty_manifest.clone(), Vec::new()).unwrap();
        let frame = encode_content_package_frame(empty_pkg, 4096).await.unwrap();
        let decoded = decode_content_package_frame(&frame).unwrap();
        assert_eq!(decoded.manifest(), &empty_manifest);
        assert!(decoded.chunks().is_empty());

        // Oversized frame rejected before buffering full chunk.
        let chunk_data = vec![0x77; 48];
        let chunk_cid = raw_sha256_cid(&chunk_data).unwrap();
        let manifest = EncryptedFileManifest::new(
            FileId::from_bytes([0x11; 32]),
            VersionNumber::ONE,
            ManifestHash::ZERO,
            EpochId::from_bytes([0x22; 32]),
            NoncePrefix::from_bytes([0x33; 8]),
            64,
            vec![EncryptedChunkRef::new(1, chunk_cid, 48).unwrap()],
            None,
        )
        .unwrap();
        let too_tight = ContentPackage::new(
            manifest.clone(),
            vec![ContentChunk::new(
                1,
                48,
                Box::pin(Cursor::new(chunk_data.clone())) as StorageReader,
            )],
        )
        .unwrap();
        assert_eq!(
            encode_content_package_frame(too_tight, frame.len() + 10).await,
            Err(StorageError::SizeLimitExceeded)
        );

        // Oversized chunk reader (returns more bytes than declared_len) is bounded and rejected.
        let lying_reader = ContentPackage::new(
            manifest.clone(),
            vec![ContentChunk::new(
                1,
                48,
                Box::pin(Cursor::new(vec![0x77_u8; 200])) as StorageReader,
            )],
        )
        .unwrap();
        assert_eq!(
            encode_content_package_frame(lying_reader, 1024 * 1024).await,
            Err(StorageError::InvalidPackage)
        );

        // Truncated chunk reader rejected.
        let short_reader = ContentPackage::new(
            manifest.clone(),
            vec![ContentChunk::new(
                1,
                48,
                Box::pin(Cursor::new(vec![0x77_u8; 12])) as StorageReader,
            )],
        )
        .unwrap();
        assert_eq!(
            encode_content_package_frame(short_reader, 1024 * 1024).await,
            Err(StorageError::InvalidPackage)
        );

        // ContentPackage::new rejects mismatched chunk count or index.
        assert!(ContentPackage::new(manifest.clone(), Vec::new()).is_err());
        assert!(
            ContentPackage::new(
                manifest,
                vec![ContentChunk::new(
                    2,
                    48,
                    Box::pin(Cursor::new(chunk_data)) as StorageReader,
                )],
            )
            .is_err()
        );
    }

    #[test]
    fn sensitive_port_types_redact_secrets_in_debug_output() {
        let session = crate::AuthenticatedSession::new(
            "super-secret-bearer-token".to_owned(),
            domain::MemberId::from_bytes([0x11; 32]),
            1_800_000_000,
        );
        let session_dbg = format!("{session:?}");
        assert!(session_dbg.contains("[REDACTED]"));
        assert!(!session_dbg.contains("super-secret-bearer-token"));

        let key_id = crate::KeyId::from_bytes([0xab; 32]);
        assert_eq!(format!("{key_id:?}"), "KeyId([REDACTED])");

        let sig = crate::EvmSignature::from_bytes([0xcd; 65]);
        assert!(!format!("{sig:?}").contains("205"));
    }
}
