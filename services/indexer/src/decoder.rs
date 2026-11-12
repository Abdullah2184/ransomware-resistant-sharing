use chain_adapter::{ChainError, ChainLog, decode_hex};
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    InvalidLog,
    InvalidAbiData,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidLog => "invalid contract event log",
            Self::InvalidAbiData => "invalid contract event data",
        };
        formatter.write_str(message)
    }
}

impl Error for DecodeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedEvent {
    pub name: String,
    pub fields: Value,
}

const EVENTS: &[&str] = &[
    "OrganizationRegistered(bytes32,address)",
    "OrganizationAuthorityChanged(bytes32,address,address)",
    "MemberRegistered(bytes32,bytes32,address)",
    "MemberStatusChanged(bytes32,uint8,uint8)",
    "MemberKeyRegistered(bytes32,uint32,bool,bytes32)",
    "MemberKeySuperseded(bytes32,uint32,uint32)",
    "MemberKeyStatusChanged(bytes32,uint32,bool,uint8,uint8)",
    "FilePolicyAuthorityChanged(bytes32,bytes32,address)",
    "FilePolicyRegistered(bytes32,bytes32)",
    "ReadAccessGranted(bytes32,bytes32,address,bytes32)",
    "ReadAccessRevoked(bytes32,bytes32,address,bytes32)",
    "WriteAccessGranted(bytes32,bytes32,address,bytes32)",
    "WriteAccessRevoked(bytes32,bytes32,address,bytes32)",
    "HistoricalReadAccessGranted(bytes32,uint64,bytes32,address,bytes32)",
    "HistoricalReadAccessRevoked(bytes32,uint64,bytes32,address,bytes32)",
    "EnvelopeSetInitialized(bytes32,uint64,bytes32,string)",
    "EnvelopeSetUpdated(bytes32,uint64,bytes32,bytes32,bytes32,string,string,uint32,uint256)",
    "FileCreated(bytes32,bytes32,bytes32,string,bytes32)",
    "FileMetadataChanged(bytes32,string,bytes32,address)",
    "FileStatusChanged(bytes32,uint8,uint8)",
    "VersionAppended(bytes32,uint64,bytes32,bytes32,bytes32,bytes32,address,string,string)",
    "CurrentHeadAdvanced(bytes32,uint64,bytes32)",
    "FolderCreated(bytes32,bytes32,bytes32,string,address)",
    "FolderRenamed(bytes32,string,address)",
];

pub fn decode(log: &ChainLog) -> Result<DecodedEvent, DecodeError> {
    let topic0 = log.topics.first().ok_or(DecodeError::InvalidLog)?;
    let event = EVENTS
        .iter()
        .find(|signature| event_topic(signature) == *topic0);
    let Some(event) = event else {
        return Ok(DecodedEvent {
            name: "Unknown".to_owned(),
            fields: json!({}),
        });
    };

    let topics = log
        .topics
        .iter()
        .skip(1)
        .map(|topic| topic.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let data = decode_hex(&log.data).map_err(map_chain_error)?;
    let fields = match *event {
        "OrganizationRegistered(bytes32,address)" => {
            json!({"organization_id": indexed(&topics, 0)?, "authority": indexed_address(&topics, 1)?})
        }
        "OrganizationAuthorityChanged(bytes32,address,address)" => json!({
            "organization_id": indexed(&topics, 0)?,
            "old_authority": indexed_address(&topics, 1)?,
            "new_authority": indexed_address(&topics, 2)?
        }),
        "MemberRegistered(bytes32,bytes32,address)" => json!({
            "member_id": indexed(&topics, 0)?,
            "organization_id": indexed(&topics, 1)?,
            "signing_address": address_word(&data, 0)?
        }),
        "MemberStatusChanged(bytes32,uint8,uint8)" => json!({
            "member_id": indexed(&topics, 0)?,
            "old_status": number_word(&data, 0)?,
            "new_status": number_word(&data, 1)?
        }),
        "MemberKeyRegistered(bytes32,uint32,bool,bytes32)" => json!({
            "member_id": indexed(&topics, 0)?,
            "key_version": number_topic(&topics, 1)?,
            "encryption_key": bool_word(&data, 0)?,
            "public_key": word_hex(&data, 1)?
        }),
        "MemberKeySuperseded(bytes32,uint32,uint32)" => json!({
            "member_id": indexed(&topics, 0)?,
            "signing_key_version": number_word(&data, 0)?,
            "encryption_key_version": number_word(&data, 1)?
        }),
        "MemberKeyStatusChanged(bytes32,uint32,bool,uint8,uint8)" => json!({
            "member_id": indexed(&topics, 0)?,
            "key_version": number_topic(&topics, 1)?,
            "encryption_key": bool_word(&data, 0)?,
            "old_status": number_word(&data, 1)?,
            "new_status": number_word(&data, 2)?
        }),
        "FilePolicyAuthorityChanged(bytes32,bytes32,address)" => json!({
            "file_id": indexed(&topics, 0)?,
            "policy": indexed(&topics, 1)?,
            "authority": address_word(&data, 0)?
        }),
        "FilePolicyRegistered(bytes32,bytes32)" => json!({
            "file_id": indexed(&topics, 0)?,
            "organization_id": indexed(&topics, 1)?
        }),
        "ReadAccessGranted(bytes32,bytes32,address,bytes32)"
        | "ReadAccessRevoked(bytes32,bytes32,address,bytes32)"
        | "WriteAccessGranted(bytes32,bytes32,address,bytes32)"
        | "WriteAccessRevoked(bytes32,bytes32,address,bytes32)" => json!({
            "file_id": indexed(&topics, 0)?,
            "member_id": indexed(&topics, 1)?,
            "actor": indexed_address(&topics, 2)?,
            "proposal_id": word_hex(&data, 0)?
        }),
        "HistoricalReadAccessGranted(bytes32,uint64,bytes32,address,bytes32)"
        | "HistoricalReadAccessRevoked(bytes32,uint64,bytes32,address,bytes32)" => json!({
            "file_id": indexed(&topics, 0)?,
            "version_number": number_topic(&topics, 1)?,
            "member_id": indexed(&topics, 2)?,
            "actor": address_word(&data, 0)?,
            "proposal_id": word_hex(&data, 1)?
        }),
        "EnvelopeSetInitialized(bytes32,uint64,bytes32,string)" => json!({
            "file_id": indexed(&topics, 0)?,
            "version_number": number_topic(&topics, 1)?,
            "epoch_id": indexed(&topics, 2)?,
            "envelope_set_cid": string_word(&data, 0)?
        }),
        "EnvelopeSetUpdated(bytes32,uint64,bytes32,bytes32,bytes32,string,string,uint32,uint256)" =>
        {
            json!({
                "file_id": indexed(&topics, 0)?,
                "version_number": number_topic(&topics, 1)?,
                "epoch_id": indexed(&topics, 2)?,
                "actor_member_id": word_hex(&data, 0)?,
                "proposal_id": word_hex(&data, 1)?,
                "old_cid": string_word(&data, 2)?,
                "new_cid": string_word(&data, 3)?,
                "revision": number_word(&data, 4)?,
                "timestamp": number_word(&data, 5)?
            })
        }
        "FileCreated(bytes32,bytes32,bytes32,string,bytes32)" => json!({
            "file_id": indexed(&topics, 0)?,
            "organization_id": indexed(&topics, 1)?,
            "creator_member_id": indexed(&topics, 2)?,
            "display_name": string_word(&data, 0)?,
            "parent_folder_id": word_hex(&data, 1)?
        }),
        "FileMetadataChanged(bytes32,string,bytes32,address)" => json!({
            "file_id": indexed(&topics, 0)?,
            "display_name": string_word(&data, 0)?,
            "parent_folder_id": word_hex(&data, 1)?,
            "actor": indexed_address(&topics, 1)?
        }),
        "FileStatusChanged(bytes32,uint8,uint8)" => json!({
            "file_id": indexed(&topics, 0)?,
            "old_status": number_word(&data, 0)?,
            "new_status": number_word(&data, 1)?
        }),
        "VersionAppended(bytes32,uint64,bytes32,bytes32,bytes32,bytes32,address,string,string)" => {
            json!({
                "file_id": indexed(&topics, 0)?,
                "version_number": number_topic(&topics, 1)?,
                "manifest_hash": indexed(&topics, 2)?,
                "parent_manifest_hash": word_hex(&data, 0)?,
                "epoch_id": word_hex(&data, 1)?,
                "author_member_id": word_hex(&data, 2)?,
                "author_signing_address": address_word(&data, 3)?,
                "content_cid": string_word(&data, 4)?,
                "initial_envelope_set_cid": string_word(&data, 5)?
            })
        }
        "CurrentHeadAdvanced(bytes32,uint64,bytes32)" => json!({
            "file_id": indexed(&topics, 0)?,
            "version_number": number_word(&data, 0)?,
            "manifest_hash": word_hex(&data, 1)?
        }),
        "FolderCreated(bytes32,bytes32,bytes32,string,address)" => json!({
            "folder_id": indexed(&topics, 0)?,
            "organization_id": indexed(&topics, 1)?,
            "parent_folder_id": indexed(&topics, 2)?,
            "display_name": string_word(&data, 0)?,
            "actor": address_word(&data, 1)?
        }),
        "FolderRenamed(bytes32,string,address)" => json!({
            "folder_id": indexed(&topics, 0)?,
            "display_name": string_word(&data, 0)?,
            "actor": indexed_address(&topics, 1)?
        }),
        _ => return Err(DecodeError::InvalidLog),
    };

    Ok(DecodedEvent {
        name: event_name(event),
        fields,
    })
}

pub fn event_topic(signature: &str) -> String {
    let digest = Keccak256::digest(signature.as_bytes());
    format!("0x{}", encode_hex(&digest))
}

fn event_name(signature: &str) -> String {
    signature
        .split_once('(')
        .map_or_else(|| "Unknown".to_owned(), |(name, _)| name.to_owned())
}

fn indexed(topics: &[String], index: usize) -> Result<String, DecodeError> {
    let value = topics.get(index).ok_or(DecodeError::InvalidLog)?;
    if decode_hex(value).map_err(map_chain_error)?.len() != 32 {
        return Err(DecodeError::InvalidLog);
    }
    Ok(value.to_ascii_lowercase())
}

fn indexed_address(topics: &[String], index: usize) -> Result<String, DecodeError> {
    let bytes = decode_hex(&indexed(topics, index)?).map_err(map_chain_error)?;
    address_string(&bytes)
}

fn number_topic(topics: &[String], index: usize) -> Result<u64, DecodeError> {
    let bytes = decode_hex(&indexed(topics, index)?).map_err(map_chain_error)?;
    small_integer(&bytes)
}

fn word(data: &[u8], index: usize) -> Result<&[u8], DecodeError> {
    let start = index.checked_mul(32).ok_or(DecodeError::InvalidAbiData)?;
    let end = start.checked_add(32).ok_or(DecodeError::InvalidAbiData)?;
    data.get(start..end).ok_or(DecodeError::InvalidAbiData)
}

fn word_hex(data: &[u8], index: usize) -> Result<String, DecodeError> {
    Ok(format!("0x{}", encode_hex(word(data, index)?)))
}

fn number_word(data: &[u8], index: usize) -> Result<u64, DecodeError> {
    small_integer(word(data, index)?)
}

fn bool_word(data: &[u8], index: usize) -> Result<bool, DecodeError> {
    match number_word(data, index)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DecodeError::InvalidAbiData),
    }
}

fn address_word(data: &[u8], index: usize) -> Result<String, DecodeError> {
    address_string(word(data, index)?)
}

fn address_string(word: &[u8]) -> Result<String, DecodeError> {
    if word.len() != 32 || word[..12].iter().any(|byte| *byte != 0) {
        return Err(DecodeError::InvalidAbiData);
    }
    Ok(format!("0x{}", encode_hex(&word[12..])))
}

fn small_integer(word: &[u8]) -> Result<u64, DecodeError> {
    if word.len() != 32 || word[..24].iter().any(|byte| *byte != 0) {
        return Err(DecodeError::InvalidAbiData);
    }
    let mut value = [0; 8];
    value.copy_from_slice(&word[24..]);
    Ok(u64::from_be_bytes(value))
}

fn string_word(data: &[u8], offset_word: usize) -> Result<String, DecodeError> {
    let offset = usize::try_from(small_integer(word(data, offset_word)?)?)
        .map_err(|_| DecodeError::InvalidAbiData)?;
    let head_end = offset_word
        .checked_add(1)
        .and_then(|words| words.checked_mul(32))
        .ok_or(DecodeError::InvalidAbiData)?;
    if offset % 32 != 0 || offset < head_end {
        return Err(DecodeError::InvalidAbiData);
    }
    let length_end = offset.checked_add(32).ok_or(DecodeError::InvalidAbiData)?;
    let length_word = data
        .get(offset..length_end)
        .ok_or(DecodeError::InvalidAbiData)?;
    let length =
        usize::try_from(small_integer(length_word)?).map_err(|_| DecodeError::InvalidAbiData)?;
    let start = offset.checked_add(32).ok_or(DecodeError::InvalidAbiData)?;
    let end = start
        .checked_add(length)
        .ok_or(DecodeError::InvalidAbiData)?;
    let text = data.get(start..end).ok_or(DecodeError::InvalidAbiData)?;
    std::str::from_utf8(text)
        .map(str::to_owned)
        .map_err(|_| DecodeError::InvalidAbiData)
}

fn map_chain_error(_error: ChainError) -> DecodeError {
    DecodeError::InvalidLog
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word_hex_u64(value: u64) -> String {
        format!("{value:064x}")
    }

    fn topic(value: &str) -> String {
        format!("0x{value}")
    }

    fn log(signature: &str, topics: Vec<String>, data: String) -> ChainLog {
        ChainLog {
            address: format!("0x{}", "11".repeat(20)),
            topics: std::iter::once(event_topic(signature))
                .chain(topics)
                .collect(),
            data,
            block_number: "0x1".to_owned(),
            block_hash: format!("0x{}", "22".repeat(32)),
            transaction_hash: format!("0x{}", "33".repeat(32)),
            transaction_index: "0x0".to_owned(),
            log_index: "0x0".to_owned(),
            removed: false,
        }
    }

    #[test]
    fn decodes_file_creation_with_dynamic_name() {
        let display_name = "Quarterly report";
        let mut data = format!("{}{}", word_hex_u64(64), "00".repeat(32));
        data.push_str(&abi_string_tail(display_name));
        let event = decode(&log(
            "FileCreated(bytes32,bytes32,bytes32,string,bytes32)",
            vec![
                topic(&"aa".repeat(32)),
                topic(&"bb".repeat(32)),
                topic(&"cc".repeat(32)),
            ],
            format!("0x{data}"),
        ))
        .unwrap();

        assert_eq!(event.name, "FileCreated");
        assert_eq!(event.fields["display_name"], display_name);
        assert_eq!(event.fields["file_id"], topic(&"aa".repeat(32)));
    }

    #[test]
    fn decodes_version_append_cids_and_addresses() {
        let content = "bafy-content";
        let envelope = "bafy-envelope";
        let content_tail = abi_string_tail(content);
        let envelope_offset = 192 + content_tail.len() / 2;
        let mut data = String::new();
        data.push_str(&"44".repeat(32));
        data.push_str(&"55".repeat(32));
        data.push_str(&"66".repeat(32));
        data.push_str(&format!("{}{}", "00".repeat(12), "77".repeat(20)));
        data.push_str(&word_hex_u64(192));
        data.push_str(&word_hex_u64(envelope_offset as u64));
        data.push_str(&content_tail);
        data.push_str(&abi_string_tail(envelope));

        let event = decode(&log(
            "VersionAppended(bytes32,uint64,bytes32,bytes32,bytes32,bytes32,address,string,string)",
            vec![
                topic(&"aa".repeat(32)),
                topic(&word_hex_u64(7)),
                topic(&"bb".repeat(32)),
            ],
            format!("0x{data}"),
        ))
        .unwrap();

        assert_eq!(event.fields["version_number"], 7);
        assert_eq!(event.fields["content_cid"], content);
        assert_eq!(event.fields["initial_envelope_set_cid"], envelope);
    }

    #[test]
    fn decodes_registered_key_version_kind_and_public_material() {
        let public_key = format!("0x{}", "ab".repeat(32));
        let event = decode(&log(
            "MemberKeyRegistered(bytes32,uint32,bool,bytes32)",
            vec![topic(&"aa".repeat(32)), topic(&word_hex_u64(3))],
            format!("0x{}{}", word_hex_u64(1), &public_key[2..]),
        ))
        .unwrap();

        assert_eq!(event.name, "MemberKeyRegistered");
        assert_eq!(event.fields["key_version"], 3);
        assert_eq!(event.fields["encryption_key"], true);
        assert_eq!(event.fields["public_key"], public_key);
    }

    fn abi_string_tail(value: &str) -> String {
        let mut tail = word_hex_u64(value.len() as u64);
        for byte in value.as_bytes() {
            tail.push_str(&format!("{byte:02x}"));
        }
        while !tail.len().is_multiple_of(64) {
            tail.push('0');
        }
        tail
    }

    #[test]
    fn rejects_malformed_abi_offsets_and_unknown_events_without_panicking() {
        let malformed = log(
            "FileCreated(bytes32,bytes32,bytes32,string,bytes32)",
            vec![
                topic(&"aa".repeat(32)),
                topic(&"bb".repeat(32)),
                topic(&"cc".repeat(32)),
            ],
            format!("0x{}", "ff".repeat(64)),
        );
        assert_eq!(decode(&malformed), Err(DecodeError::InvalidAbiData));

        let unknown = log(
            "UnknownEvent(bytes32)",
            vec![topic(&"dd".repeat(32))],
            "0x".into(),
        );
        assert_eq!(decode(&unknown).unwrap().name, "Unknown");
    }

    #[test]
    fn decodes_version_scoped_historical_read_events() {
        let signature = "HistoricalReadAccessGranted(bytes32,uint64,bytes32,address,bytes32)";
        let data = format!(
            "0x{}{}{}",
            "00".repeat(12),
            "33".repeat(20),
            "44".repeat(32)
        );
        let decoded = decode(&log(
            signature,
            vec![
                topic(&"11".repeat(32)),
                topic(&word_hex_u64(7)),
                topic(&"22".repeat(32)),
            ],
            data,
        ))
        .unwrap();
        assert_eq!(decoded.name, "HistoricalReadAccessGranted");
        assert_eq!(decoded.fields["file_id"], format!("0x{}", "11".repeat(32)));
        assert_eq!(decoded.fields["version_number"], 7);
        assert_eq!(
            decoded.fields["member_id"],
            format!("0x{}", "22".repeat(32))
        );
        assert_eq!(decoded.fields["actor"], format!("0x{}", "33".repeat(20)));
        assert_eq!(
            decoded.fields["proposal_id"],
            format!("0x{}", "44".repeat(32))
        );
    }
}
