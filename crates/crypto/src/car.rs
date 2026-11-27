//! Minimal bounded CARv1 reader for extracting verified encrypted content packages
//! exported by Kubo `api/v0/dag/export` (`TECHNICAL_SPECIFICATION.md` §9.3 #5 and
//! `docs/adr/content-package-unixfs-profile.md`).
//!
//! Enforces:
//! - Strict DAG-CBOR CARv1 header (`version == 1`, non-empty `roots`) declaring
//!   `access.content_cid` as a root.
//! - Canonical unsigned LEB128 varints (rejects overlong encodings and overflow).
//! - SHA-256 multihash verification for every `raw` (`0x55`) and `dag-pb` (`0x70`)
//!   block, rejecting duplicate CIDs and unsupported codecs.
//! - Two-level UnixFS directory layout anchoring:
//!   - Root `dag-pb` (`access.content_cid`) links `manifest.json` (`raw` `0x55`)
//!     and, when `chunk_count > 0`, a nested `chunks` `dag-pb` (`0x70`) directory
//!     whose links `00000001`..`{N:08}` match every chunk CID in the manifest.
//!   - For 0-byte files (`chunk_count == 0`), root links only `manifest.json`.
//!   - Compact `raw` (`0x55`) manifest-rooted CAR streams remain supported for
//!     synthetic unit tests.
//! - Authoritative `access.manifest_hash` verification before returning bytes.

use std::collections::HashMap;

use cid::Cid;
use domain::{AccessReference, ContentCid, DomainError, ManifestHash};

use crate::{EncryptedFileManifest, raw_sha256_cid, verify_sha256_cid};

const MAX_CAR_HEADER_BYTES: usize = 64 * 1024;
const MAX_CAR_BLOCKS: usize = 65_536;
const MAX_CAR_ROOTS: usize = 64;
const CODEC_RAW: u64 = 0x55;
const CODEC_DAG_PB: u64 = 0x70;

/// Verified manifest bytes and ordered `(chunk_index, ciphertext_bytes)` extracted
/// from a CARv1 stream before client-side decryption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCarPackage {
    pub manifest_bytes: Vec<u8>,
    pub chunks: Vec<(u32, Vec<u8>)>,
}

/// Parses a CARv1 byte stream, verifies its root header, block SHA-256 multihashes,
/// two-level UnixFS directory links (`manifest.json` + `chunks/00000001..N`), and
/// `access.manifest_hash`, returning the verified manifest and ordered chunks.
pub fn extract_verified_car_package(
    car_bytes: &[u8],
    access: &AccessReference,
) -> Result<VerifiedCarPackage, DomainError> {
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

    let (manifest_bytes, named_chunk_links): (Vec<u8>, Option<HashMap<String, Cid>>) =
        match *root_codec {
            CODEC_DAG_PB => {
                let root_links = parse_dag_pb_links(root_data)?;
                let mut manifest_cid: Option<Cid> = None;
                let mut chunks_dir_cid: Option<Cid> = None;
                for link in root_links {
                    match link.name.as_str() {
                        "manifest.json" => {
                            if manifest_cid.replace(link.cid).is_some() {
                                return Err(DomainError::IntegrityCheckFailed);
                            }
                        }
                        "chunks" => {
                            if chunks_dir_cid.replace(link.cid).is_some() {
                                return Err(DomainError::IntegrityCheckFailed);
                            }
                        }
                        _ => return Err(DomainError::IntegrityCheckFailed),
                    }
                }
                let manifest_cid = manifest_cid.ok_or(DomainError::InvalidManifest)?;
                if manifest_cid.codec() != CODEC_RAW {
                    return Err(DomainError::IntegrityCheckFailed);
                }
                let (m_codec, m_bytes) = blocks
                    .get(&manifest_cid.to_string())
                    .ok_or(DomainError::InvalidManifest)?;
                if *m_codec != CODEC_RAW {
                    return Err(DomainError::IntegrityCheckFailed);
                }

                let mut chunk_links_map = HashMap::new();
                if let Some(dir_cid) = chunks_dir_cid {
                    if dir_cid.codec() != CODEC_DAG_PB {
                        return Err(DomainError::IntegrityCheckFailed);
                    }
                    let (dir_codec, dir_bytes) = blocks
                        .get(&dir_cid.to_string())
                        .ok_or(DomainError::IntegrityCheckFailed)?;
                    if *dir_codec != CODEC_DAG_PB {
                        return Err(DomainError::IntegrityCheckFailed);
                    }
                    for link in parse_dag_pb_links(dir_bytes)? {
                        if link.cid.codec() != CODEC_RAW
                            || chunk_links_map.insert(link.name, link.cid).is_some()
                        {
                            return Err(DomainError::IntegrityCheckFailed);
                        }
                    }
                }
                (m_bytes.clone(), Some(chunk_links_map))
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

    if let Some(chunk_links) = &named_chunk_links
        && chunk_links.len() != manifest.chunks().len()
    {
        return Err(DomainError::IntegrityCheckFailed);
    }

    let mut chunks = Vec::with_capacity(manifest.chunks().len());
    for chunk_ref in manifest.chunks() {
        let cid_str = chunk_ref.cid().to_string();
        if let Some(chunk_links) = &named_chunk_links {
            let expected_name = format!("{:08}", chunk_ref.index());
            let linked_cid = chunk_links
                .get(&expected_name)
                .ok_or(DomainError::IntegrityCheckFailed)?;
            if linked_cid.to_string() != cid_str {
                return Err(DomainError::IntegrityCheckFailed);
            }
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
    Ok(VerifiedCarPackage {
        manifest_bytes,
        chunks,
    })
}

/// Encodes a canonical manifest and ciphertext chunks into a Kubo-compatible
/// two-level UnixFS `dag-pb` (`0x70`) directory CARv1 stream (`manifest.json` +
/// `chunks/00000001..N`) and returns `(root_content_cid, car_bytes)`.
pub fn encode_unixfs_car_package(
    manifest_bytes: &[u8],
    chunks: &[(u32, Vec<u8>)],
) -> Result<(ContentCid, Vec<u8>), DomainError> {
    let manifest_cid: Cid = raw_sha256_cid(manifest_bytes)
        .map_err(|_| DomainError::InvalidManifest)?
        .to_string()
        .parse()
        .map_err(|_| DomainError::InvalidCid)?;

    let mut root_links: Vec<(&str, Cid, u64)> = Vec::new();
    let mut chunks_dir_block: Option<(Cid, Vec<u8>)> = None;

    if !chunks.is_empty() {
        let mut dir_links: Vec<(String, Cid, u64)> = Vec::with_capacity(chunks.len());
        for (idx, chunk) in chunks {
            let chunk_cid: Cid = raw_sha256_cid(chunk)
                .map_err(|_| DomainError::InvalidManifest)?
                .to_string()
                .parse()
                .map_err(|_| DomainError::InvalidCid)?;
            dir_links.push((format!("{idx:08}"), chunk_cid, chunk.len() as u64));
        }
        dir_links.sort_by(|a, b| a.0.cmp(&b.0));
        let dir_refs: Vec<(&str, Cid, u64)> = dir_links
            .iter()
            .map(|(name, cid, size)| (name.as_str(), *cid, *size))
            .collect();
        let chunks_pb = encode_unixfs_dir_pb_node(&dir_refs);
        let chunks_dir_cid = dag_pb_sha256_cid(&chunks_pb)?;
        let chunks_cumulative = chunks_pb.len() as u64
            + chunks
                .iter()
                .map(|(_, data)| data.len() as u64)
                .sum::<u64>();
        root_links.push(("chunks", chunks_dir_cid, chunks_cumulative));
        chunks_dir_block = Some((chunks_dir_cid, chunks_pb));
    }

    root_links.push(("manifest.json", manifest_cid, manifest_bytes.len() as u64));
    root_links.sort_by(|a, b| a.0.cmp(b.0));
    let root_pb = encode_unixfs_dir_pb_node(&root_links);
    let root_cid = dag_pb_sha256_cid(&root_pb)?;
    let content_cid = ContentCid::parse(&root_cid.to_string())?;

    let header = encode_cbor_header(&[root_cid]);
    let mut out = Vec::new();
    write_uvarint(&mut out, header.len() as u64);
    out.extend_from_slice(&header);

    append_car_block(&mut out, &root_cid, &root_pb);
    append_car_block(&mut out, &manifest_cid, manifest_bytes);
    if let Some((dir_cid, dir_pb)) = chunks_dir_block {
        append_car_block(&mut out, &dir_cid, &dir_pb);
    }
    for (_, chunk) in chunks {
        let chunk_cid: Cid = raw_sha256_cid(chunk)
            .map_err(|_| DomainError::InvalidManifest)?
            .to_string()
            .parse()
            .map_err(|_| DomainError::InvalidCid)?;
        append_car_block(&mut out, &chunk_cid, chunk);
    }
    Ok((content_cid, out))
}

fn dag_pb_sha256_cid(pb_bytes: &[u8]) -> Result<Cid, DomainError> {
    let raw = raw_sha256_cid(pb_bytes).map_err(|_| DomainError::InvalidManifest)?;
    let parsed_raw: Cid = raw
        .to_string()
        .parse()
        .map_err(|_| DomainError::InvalidCid)?;
    Ok(Cid::new_v1(CODEC_DAG_PB, *parsed_raw.hash()))
}

fn encode_unixfs_dir_pb_node(links: &[(&str, Cid, u64)]) -> Vec<u8> {
    let mut pb_node = Vec::new();
    for (name, cid, size) in links {
        let cid_bytes = cid.to_bytes();
        let mut link = Vec::new();
        link.push(0x0a);
        write_uvarint(&mut link, cid_bytes.len() as u64);
        link.extend_from_slice(&cid_bytes);
        link.push(0x12);
        write_uvarint(&mut link, name.len() as u64);
        link.extend_from_slice(name.as_bytes());
        link.push(0x18);
        write_uvarint(&mut link, *size);

        pb_node.push(0x12);
        write_uvarint(&mut pb_node, link.len() as u64);
        pb_node.extend_from_slice(&link);
    }
    // Field 1: UnixFS Directory Data (`Type = Directory (1)` => 0x08 0x01)
    pb_node.push(0x0a);
    pb_node.push(0x02);
    pb_node.push(0x08);
    pb_node.push(0x01);
    pb_node
}

fn append_car_block(out: &mut Vec<u8>, cid: &Cid, data: &[u8]) {
    let cid_bytes = cid.to_bytes();
    write_uvarint(out, (cid_bytes.len() + data.len()) as u64);
    out.extend_from_slice(&cid_bytes);
    out.extend_from_slice(data);
}

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
    write_cbor_uint(&mut header, 3, 5);
    header.extend_from_slice(b"roots");
    write_cbor_uint(&mut header, 4, roots.len());
    for root in roots {
        let raw = root.to_bytes();
        header.push(0xd8);
        header.push(42);
        write_cbor_uint(&mut header, 2, raw.len() + 1);
        header.push(0x00);
        header.extend_from_slice(&raw);
    }
    write_cbor_uint(&mut header, 3, 7);
    header.extend_from_slice(b"version");
    header.push(0x01);
    header
}

fn write_uvarint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(((value as u8) & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
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
mod tests {
    use domain::{EnvelopeSetCid, EpochId, FileId, VersionNumber};

    use super::*;
    use crate::{EncryptedChunkRef, NoncePrefix};

    fn sample_package(chunks: Vec<(u32, Vec<u8>)>) -> (VerifiedCarPackage, AccessReference) {
        let file_id = FileId::from_bytes([0x11; 32]);
        let epoch_id = EpochId::from_bytes([0x22; 32]);
        let chunk_refs = chunks
            .iter()
            .map(|(index, data)| {
                EncryptedChunkRef::new(*index, raw_sha256_cid(data).unwrap(), data.len() as u64)
                    .unwrap()
            })
            .collect();
        let manifest = EncryptedFileManifest::new(
            file_id,
            VersionNumber::ONE,
            ManifestHash::ZERO,
            epoch_id,
            NoncePrefix::from_bytes([0x33; 8]),
            64,
            chunk_refs,
            None,
        )
        .unwrap();
        let manifest_bytes = manifest.canonical_bytes().unwrap();
        let manifest_hash = manifest.manifest_hash().unwrap();
        let (content_cid, _) = encode_unixfs_car_package(&manifest_bytes, &chunks).unwrap();
        let env_cid = EnvelopeSetCid::parse(&raw_sha256_cid(b"env").unwrap().to_string()).unwrap();
        let access = AccessReference {
            file_id,
            version_number: VersionNumber::ONE,
            manifest_hash,
            content_cid,
            envelope_set_cid: env_cid,
            epoch_id,
            envelope_revision: 1,
            finalized_block: 10,
        };
        (
            VerifiedCarPackage {
                manifest_bytes,
                chunks,
            },
            access,
        )
    }

    #[test]
    fn two_level_unixfs_car_round_trips_multi_chunk_and_empty_packages() {
        // Multi-chunk (chunk 1 full 64 + 16 = 80 bytes, chunk 2 partial 20 bytes).
        let (pkg, access) = sample_package(vec![(1, vec![0xaa; 80]), (2, vec![0xbb; 20])]);
        let (cid, car) = encode_unixfs_car_package(&pkg.manifest_bytes, &pkg.chunks).unwrap();
        assert_eq!(cid, access.content_cid);
        assert_eq!(extract_verified_car_package(&car, &access).unwrap(), pkg);

        // 0-byte empty file (manifest.json only, no chunks subdirectory).
        let (empty_pkg, empty_access) = sample_package(Vec::new());
        let (empty_cid, empty_car) =
            encode_unixfs_car_package(&empty_pkg.manifest_bytes, &empty_pkg.chunks).unwrap();
        assert_eq!(empty_cid, empty_access.content_cid);
        assert_eq!(
            extract_verified_car_package(&empty_car, &empty_access).unwrap(),
            empty_pkg
        );
    }

    #[test]
    fn rejects_wrong_root_wrong_manifest_hash_noncanonical_varint_duplicates_and_tamper() {
        let (pkg, access) = sample_package(vec![(1, vec![0xaa; 48])]);
        let (_, car) = encode_unixfs_car_package(&pkg.manifest_bytes, &pkg.chunks).unwrap();

        // Wrong content_cid
        let mut wrong_root = access.clone();
        wrong_root.content_cid = raw_sha256_cid(b"other").unwrap();
        assert_eq!(
            extract_verified_car_package(&car, &wrong_root),
            Err(DomainError::IntegrityCheckFailed)
        );

        // Wrong manifest_hash
        let mut wrong_hash = access.clone();
        wrong_hash.manifest_hash = ManifestHash::from_bytes([0xee; 32]);
        assert_eq!(
            extract_verified_car_package(&car, &wrong_hash),
            Err(DomainError::IntegrityCheckFailed)
        );

        // Tampered trailing chunk byte
        let mut tampered = car.clone();
        *tampered.last_mut().unwrap() ^= 0xff;
        assert_eq!(
            extract_verified_car_package(&tampered, &access),
            Err(DomainError::IntegrityCheckFailed)
        );

        // Non-canonical overlong varint
        assert_eq!(
            extract_verified_car_package(&[0x81, 0x00, 0x01], &access),
            Err(DomainError::IntegrityCheckFailed)
        );

        // Duplicate block appended
        let mut dup = car.clone();
        let chunk_cid: Cid = raw_sha256_cid(&pkg.chunks[0].1)
            .unwrap()
            .to_string()
            .parse()
            .unwrap();
        append_car_block(&mut dup, &chunk_cid, &pkg.chunks[0].1);
        assert_eq!(
            extract_verified_car_package(&dup, &access),
            Err(DomainError::IntegrityCheckFailed)
        );
    }
}
