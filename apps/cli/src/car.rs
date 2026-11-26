//! Minimal bounded CARv1 reader (and test encoder) for extracting verified
//! encrypted content packages returned by `GET /v1/files/{id}/versions/{v}/content`.

use std::collections::HashMap;

use application::EncryptedPackageBytes;
use cid::Cid;
use crypto::{EncryptedFileManifest, raw_sha256_cid};
use domain::{AccessReference, DomainError};

const MAX_CAR_HEADER_BYTES: usize = 64 * 1024;
const MAX_CAR_BLOCKS: usize = 65_536;

/// Parses a CARv1 byte stream, verifies every raw (`0x55`) block's SHA-256 CID,
/// locates the canonical `EncryptedFileManifest` matching `access`, and returns
/// the ordered `(chunk_index, ciphertext_bytes)` package for client decryption.
pub fn extract_package_from_car(
    car_bytes: &[u8],
    access: &AccessReference,
) -> Result<EncryptedPackageBytes, DomainError> {
    let mut offset = 0usize;
    let header_len = read_uvarint(car_bytes, &mut offset)?;
    if header_len == 0 || header_len > MAX_CAR_HEADER_BYTES {
        return Err(DomainError::IntegrityCheckFailed);
    }
    offset = offset
        .checked_add(header_len)
        .filter(|end| *end <= car_bytes.len())
        .ok_or(DomainError::IntegrityCheckFailed)?;

    let mut raw_blocks: HashMap<String, Vec<u8>> = HashMap::new();
    let mut block_count = 0usize;
    while offset < car_bytes.len() {
        block_count += 1;
        if block_count > MAX_CAR_BLOCKS {
            return Err(DomainError::IntegrityCheckFailed);
        }
        let section_len = read_uvarint(car_bytes, &mut offset)?;
        if section_len == 0 {
            return Err(DomainError::IntegrityCheckFailed);
        }
        let section_end = offset
            .checked_add(section_len)
            .filter(|end| *end <= car_bytes.len())
            .ok_or(DomainError::IntegrityCheckFailed)?;
        let section = &car_bytes[offset..section_end];
        offset = section_end;

        let (cid, data) = split_car_block(section)?;
        if cid.version() == cid::Version::V1 && cid.codec() == 0x55 {
            let computed = raw_sha256_cid(data).map_err(|_| DomainError::IntegrityCheckFailed)?;
            if computed.to_string() != cid.to_string() {
                return Err(DomainError::IntegrityCheckFailed);
            }
            raw_blocks.insert(cid.to_string(), data.to_vec());
        }
    }

    let mut matched_manifest: Option<(EncryptedFileManifest, Vec<u8>)> = None;
    for bytes in raw_blocks.values() {
        if let Ok(manifest) = EncryptedFileManifest::parse_canonical(bytes)
            && manifest.file_id() == access.file_id
            && manifest.version_number() == access.version_number
            && manifest.epoch_id() == access.epoch_id
        {
            if matched_manifest.is_some() {
                return Err(DomainError::IntegrityCheckFailed);
            }
            matched_manifest = Some((manifest, bytes.clone()));
        }
    }
    let (manifest, manifest_bytes) = matched_manifest.ok_or(DomainError::InvalidManifest)?;

    let mut chunks = Vec::with_capacity(manifest.chunks().len());
    for chunk_ref in manifest.chunks() {
        let cid_str = chunk_ref.cid().to_string();
        let data = raw_blocks
            .get(&cid_str)
            .ok_or(DomainError::IntegrityCheckFailed)?;
        chunks.push((chunk_ref.index(), data.clone()));
    }
    Ok(EncryptedPackageBytes {
        manifest_bytes,
        chunks,
    })
}

fn split_car_block(section: &[u8]) -> Result<(Cid, &[u8]), DomainError> {
    let mut cursor = std::io::Cursor::new(section);
    let cid = Cid::read_bytes(&mut cursor).map_err(|_| DomainError::IntegrityCheckFailed)?;
    let pos = usize::try_from(cursor.position()).map_err(|_| DomainError::IntegrityCheckFailed)?;
    if pos > section.len() {
        return Err(DomainError::IntegrityCheckFailed);
    }
    Ok((cid, &section[pos..]))
}

fn read_uvarint(bytes: &[u8], offset: &mut usize) -> Result<usize, DomainError> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *bytes
            .get(*offset)
            .ok_or(DomainError::IntegrityCheckFailed)?;
        *offset += 1;
        value |= u64::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(DomainError::IntegrityCheckFailed)?;
        if byte & 0x80 == 0 {
            return usize::try_from(value).map_err(|_| DomainError::IntegrityCheckFailed);
        }
        shift += 7;
        if shift >= 63 {
            return Err(DomainError::IntegrityCheckFailed);
        }
    }
}

/// Encodes an [`EncryptedPackageBytes`] into a valid CARv1 byte stream for tests.
#[cfg(test)]
pub fn encode_package_to_car(package: &EncryptedPackageBytes) -> Vec<u8> {
    fn write_uvarint(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push(((value as u8) & 0x7f) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    // Minimal CBOR CARv1 header: { "roots": [], "version": 1 }
    let header: &[u8] = &[
        0xa2, 0x65, b'r', b'o', b'o', b't', b's', 0x80, 0x67, b'v', b'e', b'r', b's', b'i', b'o',
        b'n', 0x01,
    ];
    let mut out = Vec::new();
    write_uvarint(&mut out, header.len() as u64);
    out.extend_from_slice(header);

    let mut append_raw = |data: &[u8]| {
        let cid_str = raw_sha256_cid(data).unwrap().to_string();
        let cid: Cid = cid_str.parse().unwrap();
        let cid_bytes = cid.to_bytes();
        write_uvarint(&mut out, (cid_bytes.len() + data.len()) as u64);
        out.extend_from_slice(&cid_bytes);
        out.extend_from_slice(data);
    };

    append_raw(&package.manifest_bytes);
    for (_, chunk) in &package.chunks {
        append_raw(chunk);
    }
    out
}

#[cfg(test)]
mod tests {
    use crypto::{EncryptedChunkRef, NoncePrefix};
    use domain::{ContentCid, EnvelopeSetCid, EpochId, FileId, ManifestHash, VersionNumber};

    use super::*;

    #[test]
    fn car_round_trip_extracts_verified_manifest_and_chunks_and_rejects_tamper() {
        let file_id = FileId::from_bytes([0x11; 32]);
        let epoch_id = EpochId::from_bytes([0x22; 32]);
        let chunk_bytes = vec![0xaa; 48];
        let chunk_cid = raw_sha256_cid(&chunk_bytes).unwrap();
        let manifest = EncryptedFileManifest::new(
            file_id,
            VersionNumber::ONE,
            ManifestHash::ZERO,
            epoch_id,
            NoncePrefix::from_bytes([0x33; 8]),
            64,
            vec![EncryptedChunkRef::new(1, chunk_cid, chunk_bytes.len() as u64).unwrap()],
            None,
        )
        .unwrap();
        let manifest_bytes = manifest.canonical_bytes().unwrap();
        let content_cid = raw_sha256_cid(&manifest_bytes).unwrap();
        let package = EncryptedPackageBytes {
            manifest_bytes,
            chunks: vec![(1, chunk_bytes)],
        };
        let access = AccessReference {
            file_id,
            version_number: VersionNumber::ONE,
            content_cid: ContentCid::parse(&content_cid.to_string()).unwrap(),
            envelope_set_cid: EnvelopeSetCid::parse(&content_cid.to_string()).unwrap(),
            epoch_id,
            envelope_revision: 1,
            finalized_block: 10,
        };

        let car = encode_package_to_car(&package);
        let extracted = extract_package_from_car(&car, &access).unwrap();
        assert_eq!(extracted, package);

        // Tampering with a single ciphertext byte breaks raw block CID verification.
        let mut tampered = car.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert_eq!(
            extract_package_from_car(&tampered, &access),
            Err(DomainError::IntegrityCheckFailed)
        );
    }
}
