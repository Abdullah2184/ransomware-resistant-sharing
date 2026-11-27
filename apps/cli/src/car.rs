//! Minimal bounded CARv1 reader (and test encoders) for extracting verified
//! encrypted content packages returned by `GET /v1/files/{id}/versions/{v}/content`.
//!
//! Enforces `TECHNICAL_SPECIFICATION.md` §9.3 #5:
//! - Parses the CARv1 DAG-CBOR header (`version == 1` and non-empty `roots`) and
//!   requires `access.content_cid` to be declared as a CAR root.
//! - Verifies the SHA-256 multihash of every block (`raw` `0x55` and `dag-pb` `0x70`)
//!   and rejects duplicate CIDs and non-canonical varints.
//! - Anchors `manifest.json` and every ciphertext chunk to the verified root block
//!   (via `dag-pb` `PBNode.Links` for Kubo UnixFS directories, or directly when the
//!   root itself is a `raw` manifest block) and checks `access.manifest_hash`.

use std::collections::{HashMap, HashSet};

use application::EncryptedPackageBytes;
use cid::Cid;
use crypto::{EncryptedFileManifest, verify_sha256_cid};
use domain::{AccessReference, DomainError, ManifestHash};

const MAX_CAR_HEADER_BYTES: usize = 64 * 1024;
const MAX_CAR_BLOCKS: usize = 65_536;
const MAX_CAR_ROOTS: usize = 64;
const CODEC_RAW: u64 = 0x55;
const CODEC_DAG_PB: u64 = 0x70;

/// Parses a CARv1 byte stream, verifies the CARv1 root header and every block's
/// SHA-256 CID, anchors the canonical `EncryptedFileManifest` and all ciphertext
/// chunks to `access.content_cid`, verifies `access.manifest_hash`, and returns
/// the ordered `(chunk_index, ciphertext_bytes)` package for client decryption.
pub fn extract_package_from_car(
    car_bytes: &[u8],
    access: &AccessReference,
) -> Result<EncryptedPackageBytes, DomainError> {
    if access.manifest_hash == ManifestHash::ZERO {
        return Err(DomainError::IntegrityCheckFailed);
    }
    let expected_root: Cid = access
        .content_cid
        .to_string()
        .parse()
        .map_err(|_| DomainError::InvalidCid)?;

    let mut offset = 0usize;
    let header_len = read_uvarint(car_bytes, &mut offset)?;
    if header_len == 0 || header_len > MAX_CAR_HEADER_BYTES {
        return Err(DomainError::IntegrityCheckFailed);
    }
    let header_end = offset
        .checked_add(header_len)
        .filter(|end| *end <= car_bytes.len())
        .ok_or(DomainError::IntegrityCheckFailed)?;
    let header_roots = parse_car_v1_header(&car_bytes[offset..header_end])?;
    if !header_roots.contains(&expected_root) {
        return Err(DomainError::IntegrityCheckFailed);
    }
    offset = header_end;

    let mut blocks: HashMap<String, (u64, Vec<u8>)> = HashMap::new();
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
        if !matches!(cid.codec(), CODEC_RAW | CODEC_DAG_PB) || !verify_sha256_cid(&cid, data) {
            return Err(DomainError::IntegrityCheckFailed);
        }
        if blocks
            .insert(cid.to_string(), (cid.codec(), data.to_vec()))
            .is_some()
        {
            return Err(DomainError::IntegrityCheckFailed);
        }
    }

    let expected_root_str = expected_root.to_string();
    let (root_codec, root_data) = blocks
        .get(&expected_root_str)
        .ok_or(DomainError::IntegrityCheckFailed)?;

    let (manifest_bytes, allowed_chunk_cids): (Vec<u8>, Option<HashSet<String>>) = match *root_codec
    {
        CODEC_DAG_PB => {
            let links = parse_dag_pb_links(root_data)?;
            let mut manifest_cid: Option<Cid> = None;
            let mut linked_cids = HashSet::with_capacity(links.len());
            for link in links {
                if link.name == "manifest.json" {
                    if manifest_cid.replace(link.cid).is_some() {
                        return Err(DomainError::IntegrityCheckFailed);
                    }
                } else {
                    linked_cids.insert(link.cid.to_string());
                }
            }
            let manifest_cid = manifest_cid.ok_or(DomainError::InvalidManifest)?;
            if manifest_cid.codec() != CODEC_RAW {
                return Err(DomainError::IntegrityCheckFailed);
            }
            let (codec, bytes) = blocks
                .get(&manifest_cid.to_string())
                .ok_or(DomainError::InvalidManifest)?;
            if *codec != CODEC_RAW {
                return Err(DomainError::IntegrityCheckFailed);
            }
            (bytes.clone(), Some(linked_cids))
        }
        CODEC_RAW => (root_data.clone(), None),
        _ => return Err(DomainError::IntegrityCheckFailed),
    };

    let manifest = EncryptedFileManifest::parse_canonical(&manifest_bytes)
        .map_err(|_| DomainError::InvalidManifest)?;
    if manifest.file_id() != access.file_id
        || manifest.version_number() != access.version_number
        || manifest.epoch_id() != access.epoch_id
    {
        return Err(DomainError::IntegrityCheckFailed);
    }
    let manifest_hash = manifest
        .manifest_hash()
        .map_err(|_| DomainError::InvalidManifest)?;
    if manifest_hash != access.manifest_hash {
        return Err(DomainError::IntegrityCheckFailed);
    }

    let mut chunks = Vec::with_capacity(manifest.chunks().len());
    for chunk_ref in manifest.chunks() {
        let cid_str = chunk_ref.cid().to_string();
        if let Some(linked) = &allowed_chunk_cids
            && !linked.contains(&cid_str)
        {
            return Err(DomainError::IntegrityCheckFailed);
        }
        let (codec, data) = blocks
            .get(&cid_str)
            .ok_or(DomainError::IntegrityCheckFailed)?;
        if *codec != CODEC_RAW
            || u64::try_from(data.len()).ok() != Some(chunk_ref.ciphertext_bytes())
        {
            return Err(DomainError::IntegrityCheckFailed);
        }
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

/// Parses a DAG-CBOR CARv1 header `{ "version": 1, "roots": [Cid, ...] }`.
fn parse_car_v1_header(header: &[u8]) -> Result<Vec<Cid>, DomainError> {
    let mut pos = 0usize;
    let (major, map_len) = read_cbor_head(header, &mut pos)?;
    if major != 5 || map_len != 2 {
        return Err(DomainError::IntegrityCheckFailed);
    }

    let mut version: Option<u64> = None;
    let mut roots: Option<Vec<Cid>> = None;

    for _ in 0..map_len {
        let key = read_cbor_text(header, &mut pos)?;
        match key {
            "version" => {
                if version.is_some() {
                    return Err(DomainError::IntegrityCheckFailed);
                }
                let (v_major, v_val) = read_cbor_head(header, &mut pos)?;
                if v_major != 0 {
                    return Err(DomainError::IntegrityCheckFailed);
                }
                version = Some(v_val);
            }
            "roots" => {
                if roots.is_some() {
                    return Err(DomainError::IntegrityCheckFailed);
                }
                let (a_major, arr_len) = read_cbor_head(header, &mut pos)?;
                let arr_len =
                    usize::try_from(arr_len).map_err(|_| DomainError::IntegrityCheckFailed)?;
                if a_major != 4 || arr_len == 0 || arr_len > MAX_CAR_ROOTS {
                    return Err(DomainError::IntegrityCheckFailed);
                }
                let mut parsed_roots = Vec::with_capacity(arr_len);
                for _ in 0..arr_len {
                    let (t_major, tag_num) = read_cbor_head(header, &mut pos)?;
                    if t_major != 6 || tag_num != 42 {
                        return Err(DomainError::IntegrityCheckFailed);
                    }
                    let cid_bytes = read_cbor_bytes(header, &mut pos)?;
                    let Some((&0x00, raw_cid)) = cid_bytes.split_first() else {
                        return Err(DomainError::IntegrityCheckFailed);
                    };
                    let cid =
                        Cid::try_from(raw_cid).map_err(|_| DomainError::IntegrityCheckFailed)?;
                    parsed_roots.push(cid);
                }
                roots = Some(parsed_roots);
            }
            _ => return Err(DomainError::IntegrityCheckFailed),
        }
    }

    if pos != header.len() || version != Some(1) {
        return Err(DomainError::IntegrityCheckFailed);
    }
    roots.ok_or(DomainError::IntegrityCheckFailed)
}

fn read_cbor_head(bytes: &[u8], pos: &mut usize) -> Result<(u8, u64), DomainError> {
    let initial = *bytes.get(*pos).ok_or(DomainError::IntegrityCheckFailed)?;
    *pos += 1;
    let major = initial >> 5;
    let info = initial & 0x1f;
    let val = match info {
        0..=23 => u64::from(info),
        24 => {
            let b = *bytes.get(*pos).ok_or(DomainError::IntegrityCheckFailed)?;
            *pos += 1;
            u64::from(b)
        }
        25 => {
            let slice = bytes
                .get(*pos..*pos + 2)
                .ok_or(DomainError::IntegrityCheckFailed)?;
            *pos += 2;
            u64::from(u16::from_be_bytes([slice[0], slice[1]]))
        }
        26 => {
            let slice = bytes
                .get(*pos..*pos + 4)
                .ok_or(DomainError::IntegrityCheckFailed)?;
            *pos += 4;
            u64::from(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
        }
        27 => {
            let slice = bytes
                .get(*pos..*pos + 8)
                .ok_or(DomainError::IntegrityCheckFailed)?;
            *pos += 8;
            u64::from_be_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ])
        }
        _ => return Err(DomainError::IntegrityCheckFailed),
    };
    Ok((major, val))
}

fn read_cbor_text<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a str, DomainError> {
    let (major, len) = read_cbor_head(bytes, pos)?;
    if major != 3 {
        return Err(DomainError::IntegrityCheckFailed);
    }
    let len = usize::try_from(len).map_err(|_| DomainError::IntegrityCheckFailed)?;
    let end = pos
        .checked_add(len)
        .filter(|e| *e <= bytes.len())
        .ok_or(DomainError::IntegrityCheckFailed)?;
    let text =
        std::str::from_utf8(&bytes[*pos..end]).map_err(|_| DomainError::IntegrityCheckFailed)?;
    *pos = end;
    Ok(text)
}

fn read_cbor_bytes<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a [u8], DomainError> {
    let (major, len) = read_cbor_head(bytes, pos)?;
    if major != 2 {
        return Err(DomainError::IntegrityCheckFailed);
    }
    let len = usize::try_from(len).map_err(|_| DomainError::IntegrityCheckFailed)?;
    let end = pos
        .checked_add(len)
        .filter(|e| *e <= bytes.len())
        .ok_or(DomainError::IntegrityCheckFailed)?;
    let slice = &bytes[*pos..end];
    *pos = end;
    Ok(slice)
}

struct DagPbLink {
    cid: Cid,
    name: String,
}

/// Parses IPLD `dag-pb` `PBNode` protobuf links (field 2 = `Links`, field 1 = `Data`).
fn parse_dag_pb_links(node_bytes: &[u8]) -> Result<Vec<DagPbLink>, DomainError> {
    let mut pos = 0usize;
    let mut links = Vec::new();
    while pos < node_bytes.len() {
        let tag = read_uvarint_u64(node_bytes, &mut pos)?;
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        match (field_num, wire_type) {
            (2, 2) => {
                let len = read_uvarint(node_bytes, &mut pos)?;
                let end = pos
                    .checked_add(len)
                    .filter(|e| *e <= node_bytes.len())
                    .ok_or(DomainError::IntegrityCheckFailed)?;
                links.push(parse_dag_pb_link(&node_bytes[pos..end])?);
                pos = end;
            }
            (1, 2) => {
                // Optional PBNode.Data (e.g. UnixFS directory metadata)
                let len = read_uvarint(node_bytes, &mut pos)?;
                pos = pos
                    .checked_add(len)
                    .filter(|e| *e <= node_bytes.len())
                    .ok_or(DomainError::IntegrityCheckFailed)?;
            }
            _ => return Err(DomainError::IntegrityCheckFailed),
        }
    }
    Ok(links)
}

fn parse_dag_pb_link(link_bytes: &[u8]) -> Result<DagPbLink, DomainError> {
    let mut pos = 0usize;
    let mut cid: Option<Cid> = None;
    let mut name = String::new();
    while pos < link_bytes.len() {
        let tag = read_uvarint_u64(link_bytes, &mut pos)?;
        let field_num = tag >> 3;
        let wire_type = tag & 0x07;
        match (field_num, wire_type) {
            (1, 2) => {
                let len = read_uvarint(link_bytes, &mut pos)?;
                let end = pos
                    .checked_add(len)
                    .filter(|e| *e <= link_bytes.len())
                    .ok_or(DomainError::IntegrityCheckFailed)?;
                if cid.is_some() {
                    return Err(DomainError::IntegrityCheckFailed);
                }
                cid = Some(
                    Cid::try_from(&link_bytes[pos..end])
                        .map_err(|_| DomainError::IntegrityCheckFailed)?,
                );
                pos = end;
            }
            (2, 2) => {
                let len = read_uvarint(link_bytes, &mut pos)?;
                let end = pos
                    .checked_add(len)
                    .filter(|e| *e <= link_bytes.len())
                    .ok_or(DomainError::IntegrityCheckFailed)?;
                name = std::str::from_utf8(&link_bytes[pos..end])
                    .map_err(|_| DomainError::IntegrityCheckFailed)?
                    .to_owned();
                pos = end;
            }
            (3, 0) => {
                let _tsize = read_uvarint_u64(link_bytes, &mut pos)?;
            }
            _ => return Err(DomainError::IntegrityCheckFailed),
        }
    }
    let cid = cid.ok_or(DomainError::IntegrityCheckFailed)?;
    Ok(DagPbLink { cid, name })
}

fn read_uvarint(bytes: &[u8], offset: &mut usize) -> Result<usize, DomainError> {
    let value = read_uvarint_u64(bytes, offset)?;
    usize::try_from(value).map_err(|_| DomainError::IntegrityCheckFailed)
}

/// Decodes a canonical unsigned LEB128 varint, rejecting overlong encodings and u64 overflow.
fn read_uvarint_u64(bytes: &[u8], offset: &mut usize) -> Result<u64, DomainError> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        let byte = *bytes
            .get(*offset)
            .ok_or(DomainError::IntegrityCheckFailed)?;
        *offset += 1;
        if shift > 0 && byte == 0 {
            // Non-canonical overlong varint encoding.
            return Err(DomainError::IntegrityCheckFailed);
        }
        if shift == 63 && byte > 1 {
            return Err(DomainError::IntegrityCheckFailed);
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift > 63 {
            return Err(DomainError::IntegrityCheckFailed);
        }
    }
}

#[cfg(test)]
fn write_uvarint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(((value as u8) & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

#[cfg(test)]
fn encode_cbor_header(roots: &[Cid]) -> Vec<u8> {
    fn write_cbor_uint(out: &mut Vec<u8>, major: u8, value: usize) {
        let prefix = major << 5;
        if value < 24 {
            out.push(prefix | (value as u8));
        } else if value <= u8::MAX as usize {
            out.push(prefix | 24);
            out.push(value as u8);
        } else if value <= u16::MAX as usize {
            out.push(prefix | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        } else {
            out.push(prefix | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
    }

    let mut header = Vec::new();
    header.push(0xa2); // map(2)
    // "roots"
    write_cbor_uint(&mut header, 3, 5);
    header.extend_from_slice(b"roots");
    write_cbor_uint(&mut header, 4, roots.len());
    for root in roots {
        let raw = root.to_bytes();
        // tag(42)
        header.push(0xd8);
        header.push(42);
        // bytes(0x00 || raw)
        write_cbor_uint(&mut header, 2, raw.len() + 1);
        header.push(0x00);
        header.extend_from_slice(&raw);
    }
    // "version": 1
    write_cbor_uint(&mut header, 3, 7);
    header.extend_from_slice(b"version");
    header.push(0x01);
    header
}

/// Encodes an [`EncryptedPackageBytes`] into a valid CARv1 byte stream with the
/// raw manifest CID as the CARv1 root (used in unit & mock-gateway tests).
#[cfg(test)]
pub fn encode_package_to_car(package: &EncryptedPackageBytes) -> Vec<u8> {
    let root_cid: Cid = crypto::raw_sha256_cid(&package.manifest_bytes)
        .unwrap()
        .to_string()
        .parse()
        .unwrap();
    let header = encode_cbor_header(&[root_cid]);
    let mut out = Vec::new();
    write_uvarint(&mut out, header.len() as u64);
    out.extend_from_slice(&header);

    let mut append_raw = |data: &[u8]| {
        let cid_str = crypto::raw_sha256_cid(data).unwrap().to_string();
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

/// Encodes an [`EncryptedPackageBytes`] into a Kubo-compatible UnixFS `dag-pb` (`0x70`)
/// directory-rooted CARv1 stream with `manifest.json` and chunk links.
#[cfg(test)]
pub fn encode_unixfs_package_to_car(
    package: &EncryptedPackageBytes,
) -> (domain::ContentCid, Vec<u8>) {
    fn encode_pb_link(cid: &Cid, name: &str, size: u64) -> Vec<u8> {
        let cid_bytes = cid.to_bytes();
        let mut link = Vec::new();
        // Field 1: Hash (bytes)
        link.push(0x0a);
        write_uvarint(&mut link, cid_bytes.len() as u64);
        link.extend_from_slice(&cid_bytes);
        // Field 2: Name (string)
        link.push(0x12);
        write_uvarint(&mut link, name.len() as u64);
        link.extend_from_slice(name.as_bytes());
        // Field 3: Tsize (uint64)
        link.push(0x18);
        write_uvarint(&mut link, size);
        link
    }

    let manifest_cid: Cid = crypto::raw_sha256_cid(&package.manifest_bytes)
        .unwrap()
        .to_string()
        .parse()
        .unwrap();

    let mut pb_node = Vec::new();
    let manifest_link = encode_pb_link(
        &manifest_cid,
        "manifest.json",
        package.manifest_bytes.len() as u64,
    );
    pb_node.push(0x12);
    write_uvarint(&mut pb_node, manifest_link.len() as u64);
    pb_node.extend_from_slice(&manifest_link);

    for (idx, chunk) in &package.chunks {
        let chunk_cid: Cid = crypto::raw_sha256_cid(chunk)
            .unwrap()
            .to_string()
            .parse()
            .unwrap();
        let name = format!("chunk-{idx:08}.bin");
        let link = encode_pb_link(&chunk_cid, &name, chunk.len() as u64);
        pb_node.push(0x12);
        write_uvarint(&mut pb_node, link.len() as u64);
        pb_node.extend_from_slice(&link);
    }
    // Field 1: UnixFS Directory Data (`Type = Directory (1)` => 0x08 0x01)
    pb_node.push(0x0a);
    pb_node.push(0x02);
    pb_node.push(0x08);
    pb_node.push(0x01);

    let root_raw_cid = crypto::raw_sha256_cid(&pb_node).unwrap();
    let parsed_raw: Cid = root_raw_cid.to_string().parse().unwrap();
    let root_cid = Cid::new_v1(CODEC_DAG_PB, *parsed_raw.hash());
    let content_cid = domain::ContentCid::parse(&root_cid.to_string()).unwrap();

    let header = encode_cbor_header(&[root_cid]);
    let mut out = Vec::new();
    write_uvarint(&mut out, header.len() as u64);
    out.extend_from_slice(&header);

    let append_block = |out: &mut Vec<u8>, cid: &Cid, data: &[u8]| {
        let cid_bytes = cid.to_bytes();
        write_uvarint(out, (cid_bytes.len() + data.len()) as u64);
        out.extend_from_slice(&cid_bytes);
        out.extend_from_slice(data);
    };

    append_block(&mut out, &root_cid, &pb_node);
    append_block(&mut out, &manifest_cid, &package.manifest_bytes);
    for (_, chunk) in &package.chunks {
        let chunk_cid: Cid = crypto::raw_sha256_cid(chunk)
            .unwrap()
            .to_string()
            .parse()
            .unwrap();
        append_block(&mut out, &chunk_cid, chunk);
    }

    (content_cid, out)
}

#[cfg(test)]
mod tests {
    use crypto::{EncryptedChunkRef, NoncePrefix, raw_sha256_cid};
    use domain::{ContentCid, EnvelopeSetCid, EpochId, FileId, ManifestHash, VersionNumber};

    use super::*;

    fn sample_package() -> (
        EncryptedFileManifest,
        EncryptedPackageBytes,
        AccessReference,
    ) {
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
        let manifest_hash = manifest.manifest_hash().unwrap();
        let content_cid = raw_sha256_cid(&manifest_bytes).unwrap();
        let package = EncryptedPackageBytes {
            manifest_bytes,
            chunks: vec![(1, chunk_bytes)],
        };
        let access = AccessReference {
            file_id,
            version_number: VersionNumber::ONE,
            manifest_hash,
            content_cid: ContentCid::parse(&content_cid.to_string()).unwrap(),
            envelope_set_cid: EnvelopeSetCid::parse(&content_cid.to_string()).unwrap(),
            epoch_id,
            envelope_revision: 1,
            finalized_block: 10,
        };
        (manifest, package, access)
    }

    #[test]
    fn car_round_trip_extracts_verified_raw_root_and_rejects_tamper() {
        let (_, package, access) = sample_package();
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

    #[test]
    fn unixfs_dag_pb_root_round_trips_and_rejects_mismatched_root_or_unlinked_blocks() {
        let (_, package, mut access) = sample_package();
        let (dag_pb_cid, car) = encode_unixfs_package_to_car(&package);
        access.content_cid = dag_pb_cid;

        let extracted = extract_package_from_car(&car, &access).unwrap();
        assert_eq!(extracted, package);

        // Wrong content_cid (root mismatch) fails closed even if manifest & chunks are valid.
        let mut wrong_root_access = access.clone();
        wrong_root_access.content_cid = raw_sha256_cid(b"other-root").unwrap();
        assert_eq!(
            extract_package_from_car(&car, &wrong_root_access),
            Err(DomainError::IntegrityCheckFailed)
        );

        // Wrong manifest_hash fails closed even if root CID matches.
        let mut wrong_hash_access = access.clone();
        wrong_hash_access.manifest_hash = ManifestHash::from_bytes([0xee; 32]);
        assert_eq!(
            extract_package_from_car(&car, &wrong_hash_access),
            Err(DomainError::IntegrityCheckFailed)
        );

        // Zero manifest_hash fails closed.
        let mut zero_hash_access = access.clone();
        zero_hash_access.manifest_hash = ManifestHash::ZERO;
        assert_eq!(
            extract_package_from_car(&car, &zero_hash_access),
            Err(DomainError::IntegrityCheckFailed)
        );

        // Tampering inside the dag-pb root block breaks SHA-256 verification.
        let mut tampered_root = car.clone();
        // Flip a byte right after header + first section length + CID bytes (~100 bytes in).
        let header_len_byte = tampered_root[0] as usize;
        let root_data_offset = 1 + header_len_byte + 2 + 36 + 5;
        tampered_root[root_data_offset] ^= 0x01;
        assert_eq!(
            extract_package_from_car(&tampered_root, &access),
            Err(DomainError::IntegrityCheckFailed)
        );
    }

    #[test]
    fn rejects_malformed_headers_noncanonical_varints_duplicates_and_missing_chunks() {
        let (_, package, access) = sample_package();
        let car = encode_package_to_car(&package);

        // Empty or truncated stream.
        assert_eq!(
            extract_package_from_car(&[], &access),
            Err(DomainError::IntegrityCheckFailed)
        );
        assert_eq!(
            extract_package_from_car(&car[..car.len() - 5], &access),
            Err(DomainError::IntegrityCheckFailed)
        );

        // Non-canonical overlong varint for header length (0x81 0x00 encodes 1 non-canonically).
        let overlong = [0x81u8, 0x00, 0x01];
        assert_eq!(
            extract_package_from_car(&overlong, &access),
            Err(DomainError::IntegrityCheckFailed)
        );

        // Oversized header length (> 64 KiB).
        let mut oversized = Vec::new();
        write_uvarint(&mut oversized, (MAX_CAR_HEADER_BYTES + 1) as u64);
        assert_eq!(
            extract_package_from_car(&oversized, &access),
            Err(DomainError::IntegrityCheckFailed)
        );

        // Duplicate block in CAR stream is rejected.
        let mut with_dup = car.clone();
        let chunk_data = &package.chunks[0].1;
        let chunk_cid: Cid = raw_sha256_cid(chunk_data)
            .unwrap()
            .to_string()
            .parse()
            .unwrap();
        let cid_bytes = chunk_cid.to_bytes();
        write_uvarint(&mut with_dup, (cid_bytes.len() + chunk_data.len()) as u64);
        with_dup.extend_from_slice(&cid_bytes);
        with_dup.extend_from_slice(chunk_data);
        assert_eq!(
            extract_package_from_car(&with_dup, &access),
            Err(DomainError::IntegrityCheckFailed)
        );

        // Missing chunk block is rejected.
        let only_manifest = EncryptedPackageBytes {
            manifest_bytes: package.manifest_bytes.clone(),
            chunks: Vec::new(),
        };
        let missing_chunk_car = encode_package_to_car(&only_manifest);
        assert_eq!(
            extract_package_from_car(&missing_chunk_car, &access),
            Err(DomainError::IntegrityCheckFailed)
        );
    }
}
