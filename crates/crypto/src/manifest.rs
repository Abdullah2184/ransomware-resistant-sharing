use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use domain::{ContentCid, EpochId, FileId, ManifestHash, VersionNumber};
use serde::{Deserialize, Serialize};

use crate::{CryptoError, NoncePrefix};

const SCHEMA: &str = "rrds.encrypted-content.v1";
const CIPHER: &str = "AES-256-GCM";
const NONCE_SCHEME: &str = "prefix64-index32-v1";
const GCM_TAG_BYTES: usize = 16;
const NONCE_PREFIX_BYTES: usize = 8;
const MAX_CHUNK_SIZE_BYTES: u32 = 4 * 1024 * 1024;

/// A reference to one immutable ciphertext chunk in the encrypted package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedChunkRef {
    index: u32,
    cid: ContentCid,
    ciphertext_bytes: u64,
}

impl EncryptedChunkRef {
    pub fn new(index: u32, cid: ContentCid, ciphertext_bytes: u64) -> Result<Self, CryptoError> {
        if index == 0 {
            return Err(CryptoError::InvalidManifest);
        }
        Ok(Self {
            index,
            cid,
            ciphertext_bytes,
        })
    }

    pub const fn index(&self) -> u32 {
        self.index
    }

    pub const fn cid(&self) -> &ContentCid {
        &self.cid
    }

    pub const fn ciphertext_bytes(&self) -> u64 {
        self.ciphertext_bytes
    }
}

/// Encrypted private metadata uses reserved nonce index zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateMetadataCiphertext(Vec<u8>);

impl PrivateMetadataCiphertext {
    pub fn new(ciphertext_and_tag: Vec<u8>) -> Result<Self, CryptoError> {
        if ciphertext_and_tag.len() < GCM_TAG_BYTES {
            return Err(CryptoError::InvalidManifest);
        }
        Ok(Self(ciphertext_and_tag))
    }

    pub fn ciphertext_and_tag(&self) -> &[u8] {
        &self.0
    }
}

/// Validated, versioned metadata required to safely decrypt an encrypted package.
///
/// `canonical_bytes` uses compact JSON in the field order declared by the v1
/// schema, lowercase `0x` hex identifiers, canonical CIDv1 strings, and
/// unpadded base64url byte strings. Parsing rejects noncanonical encodings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedFileManifest {
    file_id: FileId,
    version_number: VersionNumber,
    parent_manifest_hash: ManifestHash,
    epoch_id: EpochId,
    nonce_prefix: NoncePrefix,
    chunk_size_bytes: u32,
    chunk_count: u32,
    chunks: Vec<EncryptedChunkRef>,
    private_metadata: Option<PrivateMetadataCiphertext>,
}

impl EncryptedFileManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        file_id: FileId,
        version_number: VersionNumber,
        parent_manifest_hash: ManifestHash,
        epoch_id: EpochId,
        nonce_prefix: NoncePrefix,
        chunk_size_bytes: u32,
        chunks: Vec<EncryptedChunkRef>,
        private_metadata: Option<PrivateMetadataCiphertext>,
    ) -> Result<Self, CryptoError> {
        let manifest = Self {
            file_id,
            version_number,
            parent_manifest_hash,
            epoch_id,
            nonce_prefix,
            chunk_size_bytes,
            chunk_count: u32::try_from(chunks.len()).map_err(|_| CryptoError::InvalidManifest)?,
            chunks,
            private_metadata,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub const fn file_id(&self) -> FileId {
        self.file_id
    }

    pub const fn version_number(&self) -> VersionNumber {
        self.version_number
    }

    pub const fn parent_manifest_hash(&self) -> ManifestHash {
        self.parent_manifest_hash
    }

    pub const fn epoch_id(&self) -> EpochId {
        self.epoch_id
    }

    pub const fn nonce_prefix(&self) -> NoncePrefix {
        self.nonce_prefix
    }

    pub const fn chunk_size_bytes(&self) -> u32 {
        self.chunk_size_bytes
    }

    pub const fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    pub fn chunks(&self) -> &[EncryptedChunkRef] {
        &self.chunks
    }

    pub fn private_metadata(&self) -> Option<&PrivateMetadataCiphertext> {
        self.private_metadata.as_ref()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        self.validate()?;
        serde_json::to_vec(&ManifestDto::from(self))
            .map_err(|_| CryptoError::ManifestEncodingFailed)
    }

    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, CryptoError> {
        let dto: ManifestDto =
            serde_json::from_slice(bytes).map_err(|_| CryptoError::InvalidManifest)?;
        let manifest = Self::try_from(dto)?;
        if manifest.canonical_bytes()?.as_slice() != bytes {
            return Err(CryptoError::InvalidManifest);
        }
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.chunk_size_bytes == 0
            || self.chunk_size_bytes > MAX_CHUNK_SIZE_BYTES
            || u32::try_from(self.chunks.len()).ok() != Some(self.chunk_count)
        {
            return Err(CryptoError::InvalidManifest);
        }

        for (offset, chunk) in self.chunks.iter().enumerate() {
            let expected_index =
                u32::try_from(offset + 1).map_err(|_| CryptoError::InvalidManifest)?;
            if chunk.index != expected_index {
                return Err(CryptoError::InvalidManifest);
            }

            let minimum_bytes =
                u64::try_from(GCM_TAG_BYTES + 1).map_err(|_| CryptoError::InvalidManifest)?;
            let maximum_bytes = u64::from(self.chunk_size_bytes)
                .checked_add(
                    u64::try_from(GCM_TAG_BYTES).map_err(|_| CryptoError::InvalidManifest)?,
                )
                .ok_or(CryptoError::InvalidManifest)?;
            if chunk.ciphertext_bytes < minimum_bytes || chunk.ciphertext_bytes > maximum_bytes {
                return Err(CryptoError::InvalidManifest);
            }
            if expected_index < self.chunk_count() && chunk.ciphertext_bytes != maximum_bytes {
                return Err(CryptoError::InvalidManifest);
            }
        }

        Ok(())
    }
}

impl TryFrom<ManifestDto> for EncryptedFileManifest {
    type Error = CryptoError;

    fn try_from(dto: ManifestDto) -> Result<Self, Self::Error> {
        if dto.schema != SCHEMA || dto.cipher != CIPHER || dto.nonce_scheme != NONCE_SCHEME {
            return Err(CryptoError::InvalidManifest);
        }
        if usize::try_from(dto.chunk_count).ok() != Some(dto.chunks.len()) {
            return Err(CryptoError::InvalidManifest);
        }
        let file_id = FileId::from_bytes(parse_bytes32(&dto.file_id)?);
        let parent_manifest_hash =
            ManifestHash::from_bytes(parse_bytes32(&dto.parent_manifest_hash)?);
        let epoch_id = EpochId::from_bytes(parse_bytes32(&dto.epoch_id)?);
        let nonce_prefix = decode_fixed::<NONCE_PREFIX_BYTES>(&dto.nonce_prefix)?;
        let private_metadata = dto
            .private_metadata
            .map(|metadata| {
                if metadata.encoding != CIPHER || metadata.nonce_index != 0 {
                    return Err(CryptoError::InvalidManifest);
                }
                let ciphertext = decode_base64(&metadata.ciphertext)?;
                PrivateMetadataCiphertext::new(ciphertext)
            })
            .transpose()?;
        let chunks = dto
            .chunks
            .into_iter()
            .map(|chunk| {
                if chunk.index == 0 {
                    return Err(CryptoError::InvalidManifest);
                }
                let cid =
                    ContentCid::parse(&chunk.cid).map_err(|_| CryptoError::InvalidManifest)?;
                EncryptedChunkRef::new(chunk.index, cid, chunk.ciphertext_bytes)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Self::new(
            file_id,
            VersionNumber::new(dto.version_number).map_err(|_| CryptoError::InvalidManifest)?,
            parent_manifest_hash,
            epoch_id,
            NoncePrefix::from_bytes(nonce_prefix),
            dto.chunk_size_bytes,
            chunks,
            private_metadata,
        )
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestDto {
    schema: String,
    #[serde(rename = "fileId")]
    file_id: String,
    #[serde(rename = "versionNumber")]
    version_number: u64,
    #[serde(rename = "parentManifestHash")]
    parent_manifest_hash: String,
    #[serde(rename = "epochId")]
    epoch_id: String,
    cipher: String,
    #[serde(rename = "nonceScheme")]
    nonce_scheme: String,
    #[serde(rename = "chunkSizeBytes")]
    chunk_size_bytes: u32,
    #[serde(rename = "chunkCount")]
    chunk_count: u32,
    #[serde(rename = "noncePrefix")]
    nonce_prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "privateMetadata")]
    private_metadata: Option<PrivateMetadataDto>,
    chunks: Vec<ChunkDto>,
}

impl From<&EncryptedFileManifest> for ManifestDto {
    fn from(manifest: &EncryptedFileManifest) -> Self {
        Self {
            schema: SCHEMA.to_owned(),
            file_id: manifest.file_id.to_string(),
            version_number: manifest.version_number.get(),
            parent_manifest_hash: manifest.parent_manifest_hash.to_string(),
            epoch_id: manifest.epoch_id.to_string(),
            cipher: CIPHER.to_owned(),
            nonce_scheme: NONCE_SCHEME.to_owned(),
            chunk_size_bytes: manifest.chunk_size_bytes,
            chunk_count: manifest.chunk_count,
            nonce_prefix: URL_SAFE_NO_PAD.encode(manifest.nonce_prefix.as_bytes()),
            private_metadata: manifest.private_metadata.as_ref().map(|metadata| {
                PrivateMetadataDto {
                    encoding: CIPHER.to_owned(),
                    nonce_index: 0,
                    ciphertext: URL_SAFE_NO_PAD.encode(&metadata.0),
                }
            }),
            chunks: manifest
                .chunks
                .iter()
                .map(|chunk| ChunkDto {
                    index: chunk.index,
                    cid: chunk.cid.to_string(),
                    ciphertext_bytes: chunk.ciphertext_bytes,
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateMetadataDto {
    encoding: String,
    #[serde(rename = "nonceIndex")]
    nonce_index: u32,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkDto {
    index: u32,
    cid: String,
    #[serde(rename = "ciphertextBytes")]
    ciphertext_bytes: u64,
}

fn parse_bytes32(value: &str) -> Result<[u8; 32], CryptoError> {
    let bytes = value
        .strip_prefix("0x")
        .filter(|value| value.len() == 64)
        .ok_or(CryptoError::InvalidManifest)?;
    let mut output = [0; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&bytes[start..start + 2], 16)
            .map_err(|_| CryptoError::InvalidManifest)?;
    }
    Ok(output)
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], CryptoError> {
    let bytes = decode_base64(value)?;
    bytes.try_into().map_err(|_| CryptoError::InvalidManifest)
}

fn decode_base64(value: &str) -> Result<Vec<u8>, CryptoError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CryptoError::InvalidManifest)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(CryptoError::InvalidManifest);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use cid::Cid;

    use super::*;
    use crate::{ChunkEncryptor, DataEncryptionKey, EncryptionContext};

    fn chunk_cid(marker: u8) -> ContentCid {
        let hash = cid::multihash::Multihash::<64>::wrap(0x12, &[marker; 32]).unwrap();
        ContentCid::parse(&Cid::new_v1(0x55, hash).to_string()).unwrap()
    }

    fn manifest() -> EncryptedFileManifest {
        EncryptedFileManifest::new(
            FileId::from_bytes([1; 32]),
            VersionNumber::new(1).unwrap(),
            ManifestHash::ZERO,
            EpochId::from_bytes([2; 32]),
            NoncePrefix::from_bytes([3; 8]),
            4,
            vec![
                EncryptedChunkRef::new(1, chunk_cid(4), 20).unwrap(),
                EncryptedChunkRef::new(2, chunk_cid(5), 18).unwrap(),
            ],
            Some(PrivateMetadataCiphertext::new(vec![6; 24]).unwrap()),
        )
        .unwrap()
    }

    #[test]
    fn canonical_manifest_round_trips_with_typed_cids_and_metadata() {
        let manifest = manifest();
        let bytes = manifest.canonical_bytes().unwrap();
        let parsed = EncryptedFileManifest::parse_canonical(&bytes).unwrap();

        assert_eq!(parsed, manifest);
        assert_eq!(parsed.chunks()[0].index(), 1);
        assert_eq!(parsed.chunks()[1].ciphertext_bytes(), 18);
        assert_eq!(
            parsed
                .private_metadata()
                .unwrap()
                .ciphertext_and_tag()
                .len(),
            24
        );
    }

    #[test]
    fn empty_content_omits_optional_private_metadata() {
        let empty_manifest = EncryptedFileManifest::new(
            FileId::from_bytes([1; 32]),
            VersionNumber::ONE,
            ManifestHash::ZERO,
            EpochId::from_bytes([2; 32]),
            NoncePrefix::from_bytes([3; 8]),
            1,
            Vec::new(),
            None,
        )
        .unwrap();
        let bytes = empty_manifest.canonical_bytes().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();

        assert!(!text.contains("privateMetadata"));
        assert_eq!(
            EncryptedFileManifest::parse_canonical(&bytes).unwrap(),
            empty_manifest
        );
    }

    #[test]
    fn manifest_accepts_chunk_lengths_from_the_aes_gcm_encryptor() {
        let file_id = FileId::from_bytes([1; 32]);
        let epoch_id = EpochId::from_bytes([2; 32]);
        let nonce_prefix = NoncePrefix::from_bytes([3; 8]);
        let mut encryptor = ChunkEncryptor::new(
            DataEncryptionKey::generate().unwrap(),
            nonce_prefix,
            EncryptionContext::new(file_id, VersionNumber::ONE, epoch_id),
            4,
            2,
        )
        .unwrap();
        let first = encryptor.encrypt_next(b"abcd").unwrap();
        let second = encryptor.encrypt_next(b"ef").unwrap();
        encryptor.finish().unwrap();

        let manifest = EncryptedFileManifest::new(
            file_id,
            VersionNumber::ONE,
            ManifestHash::ZERO,
            epoch_id,
            nonce_prefix,
            4,
            vec![
                EncryptedChunkRef::new(
                    first.index(),
                    chunk_cid(6),
                    u64::try_from(first.ciphertext_and_tag().len()).unwrap(),
                )
                .unwrap(),
                EncryptedChunkRef::new(
                    second.index(),
                    chunk_cid(7),
                    u64::try_from(second.ciphertext_and_tag().len()).unwrap(),
                )
                .unwrap(),
            ],
            None,
        )
        .unwrap();

        assert_eq!(manifest.chunk_count(), 2);
        assert_eq!(
            EncryptedFileManifest::parse_canonical(&manifest.canonical_bytes().unwrap()).unwrap(),
            manifest
        );
    }

    #[test]
    fn rejects_noncanonical_json_and_unknown_fields() {
        let bytes = manifest().canonical_bytes().unwrap();
        let with_whitespace = format!(" {}", String::from_utf8(bytes.clone()).unwrap());
        assert_eq!(
            EncryptedFileManifest::parse_canonical(with_whitespace.as_bytes()),
            Err(CryptoError::InvalidManifest)
        );

        let with_unknown_field = String::from_utf8(bytes)
            .unwrap()
            .replace("\"schema\":", "\"unexpected\":true,\"schema\":");
        assert_eq!(
            EncryptedFileManifest::parse_canonical(with_unknown_field.as_bytes()),
            Err(CryptoError::InvalidManifest)
        );
    }

    #[test]
    fn rejects_inconsistent_chunk_indexes_lengths_cids_and_prefixes() {
        let mut dto: ManifestDto =
            serde_json::from_slice(&manifest().canonical_bytes().unwrap()).unwrap();
        dto.chunks[0].index = 2;
        assert!(matches!(
            EncryptedFileManifest::try_from(dto),
            Err(CryptoError::InvalidManifest)
        ));

        let mut dto: ManifestDto =
            serde_json::from_slice(&manifest().canonical_bytes().unwrap()).unwrap();
        dto.chunks[0].ciphertext_bytes = 19;
        assert!(matches!(
            EncryptedFileManifest::try_from(dto),
            Err(CryptoError::InvalidManifest)
        ));

        let mut dto: ManifestDto =
            serde_json::from_slice(&manifest().canonical_bytes().unwrap()).unwrap();
        dto.chunks[0].cid = "not-a-cid".to_owned();
        assert!(matches!(
            EncryptedFileManifest::try_from(dto),
            Err(CryptoError::InvalidManifest)
        ));

        let mut dto: ManifestDto =
            serde_json::from_slice(&manifest().canonical_bytes().unwrap()).unwrap();
        dto.nonce_prefix = "AQIDBA".to_owned();
        assert!(matches!(
            EncryptedFileManifest::try_from(dto),
            Err(CryptoError::InvalidManifest)
        ));
    }

    #[test]
    fn rejects_unsupported_suite_and_invalid_private_metadata() {
        let mut dto: ManifestDto =
            serde_json::from_slice(&manifest().canonical_bytes().unwrap()).unwrap();
        dto.cipher = "unsupported".to_owned();
        assert!(matches!(
            EncryptedFileManifest::try_from(dto),
            Err(CryptoError::InvalidManifest)
        ));

        let mut dto: ManifestDto =
            serde_json::from_slice(&manifest().canonical_bytes().unwrap()).unwrap();
        dto.private_metadata.as_mut().unwrap().nonce_index = 1;
        assert!(matches!(
            EncryptedFileManifest::try_from(dto),
            Err(CryptoError::InvalidManifest)
        ));
    }

    #[test]
    fn rejects_declared_chunk_count_and_version_mismatches() {
        let mut dto: ManifestDto =
            serde_json::from_slice(&manifest().canonical_bytes().unwrap()).unwrap();
        dto.chunk_count -= 1;
        assert!(matches!(
            EncryptedFileManifest::try_from(dto),
            Err(CryptoError::InvalidManifest)
        ));

        let mut dto: ManifestDto =
            serde_json::from_slice(&manifest().canonical_bytes().unwrap()).unwrap();
        dto.version_number = 0;
        assert!(matches!(
            EncryptedFileManifest::try_from(dto),
            Err(CryptoError::InvalidManifest)
        ));
    }
}
