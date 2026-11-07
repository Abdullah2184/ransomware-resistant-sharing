use std::{error::Error, fmt, future::Future, pin::Pin};

use crypto::EncryptedFileManifest;
use domain::{ContentCid, DomainError, EnvelopeSetCid};
use tokio::io::AsyncRead;

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
