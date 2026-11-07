//! Besu JSON-RPC client for finalized event indexing.

use std::{
    error::Error,
    fmt,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use domain::EvmAddress;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};

const RPC_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainError {
    InvalidEndpoint,
    TransportUnavailable,
    InvalidResponse,
    RpcRejected(i64),
    InvalidQuantity,
    RemovedLog,
}

impl fmt::Display for ChainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint => formatter.write_str("invalid Besu RPC endpoint"),
            Self::TransportUnavailable => formatter.write_str("Besu RPC unavailable"),
            Self::InvalidResponse => formatter.write_str("invalid Besu RPC response"),
            Self::RpcRejected(code) => write!(formatter, "Besu RPC rejected request ({code})"),
            Self::InvalidQuantity => formatter.write_str("invalid RPC quantity"),
            Self::RemovedLog => formatter.write_str("RPC returned a removed log"),
        }
    }
}

impl Error for ChainError {}

/// JSON-RPC event log. Quantities remain canonical RPC hex until validated.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ChainLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    pub block_number: String,
    pub block_hash: String,
    pub transaction_hash: String,
    pub transaction_index: String,
    pub log_index: String,
    #[serde(default)]
    pub removed: bool,
}

impl ChainLog {
    pub fn block_number(&self) -> Result<u64, ChainError> {
        parse_quantity(&self.block_number)
    }

    pub fn log_index(&self) -> Result<u64, ChainError> {
        parse_quantity(&self.log_index)
    }

    pub fn transaction_index(&self) -> Result<u64, ChainError> {
        parse_quantity(&self.transaction_index)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
struct BlockHeader {
    number: String,
    hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizedBlock {
    pub number: u64,
    pub hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileHeadState {
    pub status: u64,
    pub version_number: u64,
    pub manifest_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberIdentityState {
    pub signing_address: EvmAddress,
    pub encryption_key_version: u32,
    pub active: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileVersionState {
    pub content_cid: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeSetState {
    pub cid: String,
    pub epoch_id: [u8; 32],
    pub revision: u32,
}

/// JSON-RPC client that never falls back from the node's `finalized` tag to a
/// guessed confirmation count.
pub struct BesuClient {
    client: Client,
    endpoint: Url,
    next_id: AtomicU64,
}

impl fmt::Debug for BesuClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BesuClient")
            .field("endpoint", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl BesuClient {
    pub fn new(endpoint: &str) -> Result<Self, ChainError> {
        let endpoint = Url::parse(endpoint).map_err(|_| ChainError::InvalidEndpoint)?;
        if !matches!(endpoint.scheme(), "http" | "https") || endpoint.host_str().is_none() {
            return Err(ChainError::InvalidEndpoint);
        }
        let client = Client::builder()
            .timeout(RPC_TIMEOUT)
            .build()
            .map_err(|_| ChainError::TransportUnavailable)?;
        Ok(Self {
            client,
            endpoint,
            next_id: AtomicU64::new(1),
        })
    }

    pub async fn chain_id(&self) -> Result<u64, ChainError> {
        let quantity: String = self.rpc("eth_chainId", json!([])).await?;
        parse_quantity(&quantity)
    }

    pub async fn finalized_block(&self) -> Result<FinalizedBlock, ChainError> {
        let header: Option<BlockHeader> = self
            .rpc("eth_getBlockByNumber", json!(["finalized", false]))
            .await?;
        let header = header.ok_or(ChainError::InvalidResponse)?;
        let number = parse_quantity(&header.number)?;
        validate_hash(&header.hash)?;
        Ok(FinalizedBlock {
            number,
            hash: header.hash.to_ascii_lowercase(),
        })
    }

    pub async fn block_hash(&self, number: u64) -> Result<String, ChainError> {
        let tag = quantity(number);
        let header: Option<BlockHeader> = self
            .rpc("eth_getBlockByNumber", json!([tag, false]))
            .await?;
        let header = header.ok_or(ChainError::InvalidResponse)?;
        if parse_quantity(&header.number)? != number {
            return Err(ChainError::InvalidResponse);
        }
        validate_hash(&header.hash)?;
        Ok(header.hash.to_ascii_lowercase())
    }

    pub async fn logs(
        &self,
        from_block: u64,
        to_block: u64,
        contracts: &[EvmAddress],
    ) -> Result<Vec<ChainLog>, ChainError> {
        if from_block > to_block || contracts.is_empty() {
            return Err(ChainError::InvalidResponse);
        }
        let addresses: Vec<_> = contracts.iter().map(format_address).collect();
        let logs: Vec<ChainLog> = self
            .rpc(
                "eth_getLogs",
                json!([{
                    "fromBlock": quantity(from_block),
                    "toBlock": quantity(to_block),
                    "address": addresses,
                }]),
            )
            .await?;
        for log in &logs {
            if log.removed {
                return Err(ChainError::RemovedLog);
            }
            if log.block_number()? < from_block || log.block_number()? > to_block {
                return Err(ChainError::InvalidResponse);
            }
            validate_hash(&log.block_hash)?;
            validate_hash(&log.transaction_hash)?;
            let address_bytes = decode_hex(&log.address)?;
            if address_bytes.len() != 20
                || !addresses.contains(&format!("0x{}", encode_hex(&address_bytes)))
            {
                return Err(ChainError::InvalidResponse);
            }
            log.transaction_index()?;
            log.log_index()?;
            validate_hash(log.topics.first().ok_or(ChainError::InvalidResponse)?)?;
            if log.topics.len() > 4 || log.topics.iter().any(|topic| validate_hash(topic).is_err())
            {
                return Err(ChainError::InvalidResponse);
            }
            decode_hex(&log.data)?;
        }
        Ok(logs)
    }

    /// Reads the authoritative file head from the RPC node's finalized state.
    pub async fn file_head(
        &self,
        file_registry: &EvmAddress,
        file_id: &[u8; 32],
    ) -> Result<Option<FileHeadState>, ChainError> {
        let selector = Keccak256::digest(b"getFile(bytes32)");
        let mut call_data = Vec::with_capacity(36);
        call_data.extend_from_slice(&selector[..4]);
        call_data.extend_from_slice(file_id);
        let result: String = self
            .rpc(
                "eth_call",
                json!([{
                    "to": format_address(file_registry),
                    "data": format!("0x{}", encode_hex(&call_data)),
                }, "finalized"]),
            )
            .await?;
        let bytes = decode_hex(&result)?;
        let tuple_offset =
            usize::try_from(read_word_u64(&bytes, 0)?).map_err(|_| ChainError::InvalidResponse)?;
        if tuple_offset < 32 || tuple_offset % 32 != 0 {
            return Err(ChainError::InvalidResponse);
        }
        let status = read_word_u64(&bytes, tuple_word_offset(tuple_offset, 5)?)?;
        if status > 2 {
            return Err(ChainError::InvalidResponse);
        }
        if status == 0 {
            return Ok(None);
        }
        let version_number = read_word_u64(&bytes, tuple_word_offset(tuple_offset, 6)?)?;
        let manifest_start = tuple_word_offset(tuple_offset, 7)?;
        let manifest_end = manifest_start
            .checked_add(32)
            .ok_or(ChainError::InvalidResponse)?;
        let manifest_hash = bytes
            .get(manifest_start..manifest_end)
            .ok_or(ChainError::InvalidResponse)?;
        Ok(Some(FileHeadState {
            status,
            version_number,
            manifest_hash: format!("0x{}", encode_hex(manifest_hash)),
        }))
    }

    pub async fn file_head_at(
        &self,
        file_registry: &EvmAddress,
        file_id: &[u8; 32],
        block_number: u64,
    ) -> Result<Option<FileHeadState>, ChainError> {
        let selector = Keccak256::digest(b"getFile(bytes32)");
        let mut call_data = Vec::with_capacity(36);
        call_data.extend_from_slice(&selector[..4]);
        call_data.extend_from_slice(file_id);
        let result: String = self
            .rpc(
                "eth_call",
                json!([{
                    "to": format_address(file_registry),
                    "data": format!("0x{}", encode_hex(&call_data)),
                }, quantity(block_number)]),
            )
            .await?;
        let bytes = decode_hex(&result)?;
        let tuple_offset =
            usize::try_from(read_word_u64(&bytes, 0)?).map_err(|_| ChainError::InvalidResponse)?;
        if tuple_offset < 32 || tuple_offset % 32 != 0 {
            return Err(ChainError::InvalidResponse);
        }
        let status = read_word_u64(&bytes, tuple_word_offset(tuple_offset, 5)?)?;
        if status > 2 {
            return Err(ChainError::InvalidResponse);
        }
        if status == 0 {
            return Ok(None);
        }
        let version_number = read_word_u64(&bytes, tuple_word_offset(tuple_offset, 6)?)?;
        let manifest_start = tuple_word_offset(tuple_offset, 7)?;
        let manifest_end = manifest_start
            .checked_add(32)
            .ok_or(ChainError::InvalidResponse)?;
        let manifest_hash = bytes
            .get(manifest_start..manifest_end)
            .ok_or(ChainError::InvalidResponse)?;
        Ok(Some(FileHeadState {
            status,
            version_number,
            manifest_hash: format!("0x{}", encode_hex(manifest_hash)),
        }))
    }

    /// Returns the active member's signing address from finalized contract state.
    ///
    /// Inactive or unregistered identities return `None`; malformed contract
    /// responses fail closed.
    pub async fn active_member_signer(
        &self,
        access_governance: &EvmAddress,
        member_id: &[u8; 32],
    ) -> Result<Option<EvmAddress>, ChainError> {
        let selector = Keccak256::digest(b"memberIdentity(bytes32)");
        let mut call_data = Vec::with_capacity(36);
        call_data.extend_from_slice(&selector[..4]);
        call_data.extend_from_slice(member_id);
        let result: String = self
            .rpc(
                "eth_call",
                json!([{
                    "to": format_address(access_governance),
                    "data": format!("0x{}", encode_hex(&call_data)),
                }, "finalized"]),
            )
            .await?;
        let words = decode_hex(&result)?;
        if words.len() != 6 * 32 {
            return Err(ChainError::InvalidResponse);
        }

        let status = parse_abi_u64(&words[5 * 32..6 * 32])?;
        if status != 1 {
            return Ok(None);
        }
        let address_word = &words[32..64];
        if address_word[..12].iter().any(|byte| *byte != 0) {
            return Err(ChainError::InvalidResponse);
        }
        let mut address = [0; 20];
        address.copy_from_slice(&address_word[12..]);
        if address == [0; 20] {
            return Err(ChainError::InvalidResponse);
        }
        Ok(Some(EvmAddress::from_bytes(address)))
    }

    pub async fn member_identity(
        &self,
        access_governance: &EvmAddress,
        member_id: &[u8; 32],
        block_number: u64,
    ) -> Result<Option<MemberIdentityState>, ChainError> {
        let selector = Keccak256::digest(b"memberIdentity(bytes32)");
        let mut call_data = Vec::with_capacity(36);
        call_data.extend_from_slice(&selector[..4]);
        call_data.extend_from_slice(member_id);
        let encoded: String = self
            .rpc(
                "eth_call",
                json!([{
                    "to": format_address(access_governance),
                    "data": format!("0x{}", encode_hex(&call_data)),
                }, quantity(block_number)]),
            )
            .await?;
        let result = decode_hex(&encoded)?;
        if result.len() != 6 * 32 {
            return Err(ChainError::InvalidResponse);
        }
        let organization = &result[..32];
        let mut signer = [0; 20];
        let signer_word = &result[32..64];
        if signer_word[..12].iter().any(|byte| *byte != 0) {
            return Err(ChainError::InvalidResponse);
        }
        signer.copy_from_slice(&signer_word[12..]);
        let signing_key_version = parse_abi_u32(&result[64..96])?;
        let encryption_key_version = parse_abi_u32(&result[96..128])?;
        let encryption_key = &result[128..160];
        let status = parse_abi_u64(&result[160..192])?;
        if status > 3 {
            return Err(ChainError::InvalidResponse);
        }
        if status == 0 {
            if organization.iter().any(|byte| *byte != 0)
                || signer != [0; 20]
                || signing_key_version != 0
                || encryption_key_version != 0
                || encryption_key.iter().any(|byte| *byte != 0)
            {
                return Err(ChainError::InvalidResponse);
            }
            return Ok(None);
        }
        if organization.iter().all(|byte| *byte == 0)
            || signer == [0; 20]
            || signing_key_version == 0
            || encryption_key_version == 0
            || encryption_key.iter().all(|byte| *byte == 0)
        {
            return Err(ChainError::InvalidResponse);
        }
        Ok(Some(MemberIdentityState {
            signing_address: EvmAddress::from_bytes(signer),
            encryption_key_version,
            active: status == 1,
        }))
    }

    pub async fn has_read_access(
        &self,
        access_governance: &EvmAddress,
        member_id: &[u8; 32],
        file_id: &[u8; 32],
        block_number: u64,
    ) -> Result<bool, ChainError> {
        let selector = Keccak256::digest(b"hasReadAccess(bytes32,bytes32)");
        let mut call_data = Vec::with_capacity(68);
        call_data.extend_from_slice(&selector[..4]);
        call_data.extend_from_slice(member_id);
        call_data.extend_from_slice(file_id);
        let result: String = self
            .rpc(
                "eth_call",
                json!([{
                    "to": format_address(access_governance),
                    "data": format!("0x{}", encode_hex(&call_data)),
                }, quantity(block_number)]),
            )
            .await?;
        let result = decode_hex(&result)?;
        if result.len() != 32 || result[..31].iter().any(|byte| *byte != 0) || result[31] > 1 {
            return Err(ChainError::InvalidResponse);
        }
        Ok(result[31] == 1)
    }

    pub async fn file_version(
        &self,
        file_registry: &EvmAddress,
        file_id: &[u8; 32],
        version_number: u64,
        block_number: u64,
    ) -> Result<Option<FileVersionState>, ChainError> {
        let selector = Keccak256::digest(b"getVersion(bytes32,uint64)");
        let mut call_data = Vec::with_capacity(68);
        call_data.extend_from_slice(&selector[..4]);
        call_data.extend_from_slice(file_id);
        call_data.extend_from_slice(&abi_word_u64(version_number));
        let encoded = match self
            .rpc::<String>(
                "eth_call",
                json!([{
                    "to": format_address(file_registry),
                    "data": format!("0x{}", encode_hex(&call_data)),
                }, quantity(block_number)]),
            )
            .await
        {
            Ok(encoded) => decode_hex(&encoded)?,
            Err(ChainError::RpcRejected(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let tuple_offset = usize::try_from(read_word_u64(&encoded, 0)?)
            .map_err(|_| ChainError::InvalidResponse)?;
        if tuple_offset < 32 || tuple_offset % 32 != 0 {
            return Err(ChainError::InvalidResponse);
        }
        let tuple_end = tuple_offset.checked_add(9 * 32).ok_or(ChainError::InvalidResponse)?;
        if encoded.get(tuple_offset..tuple_end).is_none() {
            return Err(ChainError::InvalidResponse);
        }
        let returned_version = read_word_u64(&encoded, tuple_offset + 32)?;
        if returned_version != version_number {
            return Err(ChainError::InvalidResponse);
        }
        let content_offset = usize::try_from(read_word_u64(&encoded, tuple_offset + 3 * 32)?)
            .map_err(|_| ChainError::InvalidResponse)?;
        let content_cid = decode_abi_string(&encoded, tuple_offset, content_offset)?;
        let cid = domain::ContentCid::parse(&content_cid)
            .map_err(|_| ChainError::InvalidResponse)?;
        Ok(Some(FileVersionState {
            content_cid: cid.to_string(),
        }))
    }

    pub async fn current_envelope_set(
        &self,
        access_governance: &EvmAddress,
        file_id: &[u8; 32],
        version_number: u64,
        block_number: u64,
    ) -> Result<Option<EnvelopeSetState>, ChainError> {
        let selector = Keccak256::digest(b"currentEnvelopeSet(bytes32,uint64)");
        let mut call_data = Vec::with_capacity(68);
        call_data.extend_from_slice(&selector[..4]);
        call_data.extend_from_slice(file_id);
        call_data.extend_from_slice(&abi_word_u64(version_number));
        let encoded = match self
            .rpc::<String>(
                "eth_call",
                json!([{
                    "to": format_address(access_governance),
                    "data": format!("0x{}", encode_hex(&call_data)),
                }, quantity(block_number)]),
            )
            .await
        {
            Ok(encoded) => decode_hex(&encoded)?,
            Err(ChainError::RpcRejected(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let offset = usize::try_from(read_word_u64(&encoded, 0)?)
            .map_err(|_| ChainError::InvalidResponse)?;
        if offset < 96 || offset % 32 != 0 {
            return Err(ChainError::InvalidResponse);
        }
        let epoch_start = encoded.get(32..64).ok_or(ChainError::InvalidResponse)?;
        let mut epoch_id = [0; 32];
        epoch_id.copy_from_slice(epoch_start);
        let revision = parse_abi_u32(encoded.get(64..96).ok_or(ChainError::InvalidResponse)?)?;
        if epoch_id == [0; 32] || revision == 0 {
            return Err(ChainError::InvalidResponse);
        }
        let cid = decode_abi_string(&encoded, 0, offset)?;
        let cid = domain::EnvelopeSetCid::parse(&cid)
            .map_err(|_| ChainError::InvalidResponse)?;
        Ok(Some(EnvelopeSetState {
            cid: cid.to_string(),
            epoch_id,
            revision,
        }))
    }

    async fn eth_call(
        &self,
        contract: &EvmAddress,
        signature: &str,
        bytes32_argument: &[u8; 32],
    ) -> Result<Vec<u8>, ChainError> {
        let selector = Keccak256::digest(signature.as_bytes());
        let mut call_data = Vec::with_capacity(36);
        call_data.extend_from_slice(&selector[..4]);
        call_data.extend_from_slice(bytes32_argument);
        let result: String = self
            .rpc(
                "eth_call",
                json!([{
                    "to": format_address(contract),
                    "data": format!("0x{}", encode_hex(&call_data)),
                }, "finalized"]),
            )
            .await?;
        decode_hex(&result)
    }

    async fn rpc<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T, ChainError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let response = self
            .client
            .post(self.endpoint.clone())
            .json(&RpcRequest {
                jsonrpc: "2.0",
                method,
                params,
                id,
            })
            .send()
            .await
            .map_err(|_| ChainError::TransportUnavailable)?;
        if !response.status().is_success() {
            return Err(ChainError::TransportUnavailable);
        }
        let body: RpcResponse<T> = response
            .json()
            .await
            .map_err(|_| ChainError::InvalidResponse)?;
        if body.jsonrpc != "2.0" || body.id != id {
            return Err(ChainError::InvalidResponse);
        }
        if let Some(error) = body.error {
            return Err(ChainError::RpcRejected(error.code));
        }
        body.result.ok_or(ChainError::InvalidResponse)
    }
}

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'static str,
    method: &'a str,
    params: Value,
    id: u64,
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    jsonrpc: String,
    id: u64,
    result: Option<T>,
    error: Option<RpcErrorObject>,
}

#[derive(Deserialize)]
struct RpcErrorObject {
    code: i64,
}

fn parse_abi_u64(word: &[u8]) -> Result<u64, ChainError> {
    if word.len() != 32 || word[..24].iter().any(|byte| *byte != 0) {
        return Err(ChainError::InvalidResponse);
    }
    let mut value = [0; 8];
    value.copy_from_slice(&word[24..]);
    Ok(u64::from_be_bytes(value))
}

fn parse_abi_u32(word: &[u8]) -> Result<u32, ChainError> {
    if word.len() != 32 || word[..28].iter().any(|byte| *byte != 0) {
        return Err(ChainError::InvalidResponse);
    }
    let mut value = [0; 4];
    value.copy_from_slice(&word[28..]);
    Ok(u32::from_be_bytes(value))
}

fn abi_word_u64(value: u64) -> [u8; 32] {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn decode_abi_string(encoded: &[u8], tuple_start: usize, offset: usize) -> Result<String, ChainError> {
    if offset % 32 != 0 {
        return Err(ChainError::InvalidResponse);
    }
    let start = tuple_start
        .checked_add(offset)
        .ok_or(ChainError::InvalidResponse)?;
    let length_end = start.checked_add(32).ok_or(ChainError::InvalidResponse)?;
    let length = usize::try_from(read_word_u64(encoded, start)?)
        .map_err(|_| ChainError::InvalidResponse)?;
    if length == 0 || length > 256 {
        return Err(ChainError::InvalidResponse);
    }
    let end = length_end
        .checked_add(length)
        .ok_or(ChainError::InvalidResponse)?;
    let bytes = encoded
        .get(length_end..end)
        .ok_or(ChainError::InvalidResponse)?;
    let padding_end = length_end
        .checked_add(length.div_ceil(32) * 32)
        .ok_or(ChainError::InvalidResponse)?;
    let padding = encoded
        .get(end..padding_end)
        .ok_or(ChainError::InvalidResponse)?;
    if padding.iter().any(|byte| *byte != 0) {
        return Err(ChainError::InvalidResponse);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| ChainError::InvalidResponse)
}

fn format_address(address: &EvmAddress) -> String {
    format!("0x{}", encode_hex(address.as_bytes()))
}

fn quantity(value: u64) -> String {
    format!("0x{value:x}")
}

fn parse_quantity(value: &str) -> Result<u64, ChainError> {
    let digits = value
        .strip_prefix("0x")
        .ok_or(ChainError::InvalidQuantity)?;
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        return Err(ChainError::InvalidQuantity);
    }
    u64::from_str_radix(digits, 16).map_err(|_| ChainError::InvalidQuantity)
}

fn validate_hash(value: &str) -> Result<(), ChainError> {
    let bytes = decode_hex(value)?;
    if bytes.len() != 32 {
        return Err(ChainError::InvalidResponse);
    }
    Ok(())
}

fn read_word_u64(data: &[u8], offset: usize) -> Result<u64, ChainError> {
    let end = offset.checked_add(32).ok_or(ChainError::InvalidResponse)?;
    let word = data.get(offset..end).ok_or(ChainError::InvalidResponse)?;
    if word[..24].iter().any(|byte| *byte != 0) {
        return Err(ChainError::InvalidResponse);
    }
    let mut value = [0; 8];
    value.copy_from_slice(&word[24..]);
    Ok(u64::from_be_bytes(value))
}

fn tuple_word_offset(base: usize, index: usize) -> Result<usize, ChainError> {
    index
        .checked_mul(32)
        .and_then(|offset| base.checked_add(offset))
        .ok_or(ChainError::InvalidResponse)
}

pub fn decode_hex(value: &str) -> Result<Vec<u8>, ChainError> {
    let digits = value
        .strip_prefix("0x")
        .ok_or(ChainError::InvalidResponse)?;
    if digits.len() % 2 != 0 {
        return Err(ChainError::InvalidResponse);
    }
    let mut output = Vec::with_capacity(digits.len() / 2);
    for pair in digits.as_bytes().as_chunks::<2>().0 {
        let high = hex_nibble(pair[0]).ok_or(ChainError::InvalidResponse)?;
        let low = hex_nibble(pair[1]).ok_or(ChainError::InvalidResponse)?;
        output.push((high << 4) | low);
    }
    Ok(output)
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

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn parses_only_canonical_rpc_quantities() {
        assert_eq!(parse_quantity("0x0"), Ok(0));
        assert_eq!(parse_quantity("0x10"), Ok(16));
        assert_eq!(parse_quantity("0x00"), Err(ChainError::InvalidQuantity));
        assert_eq!(parse_quantity("10"), Err(ChainError::InvalidQuantity));
        assert_eq!(parse_quantity("0xzz"), Err(ChainError::InvalidQuantity));
    }

    #[test]
    fn decodes_hex_without_accepting_malformed_data() {
        assert_eq!(decode_hex("0x00abFF"), Ok(vec![0, 0xab, 0xff]));
        assert_eq!(decode_hex("0x0"), Err(ChainError::InvalidResponse));
        assert_eq!(decode_hex("00"), Err(ChainError::InvalidResponse));
    }

    #[test]
    fn hides_rpc_endpoint_from_debug_output() {
        let client = BesuClient::new("http://user:password@example.invalid:8545").unwrap();
        assert!(!format!("{client:?}").contains("password"));
        assert!(!format!("{client:?}").contains("example.invalid"));
    }

    #[tokio::test]
    async fn queries_file_head_at_finalized_state() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = stream.read(&mut request).await.unwrap();
            let request_text = String::from_utf8_lossy(&request[..read]);
            assert!(request_text.contains("\"eth_call\""));
            assert!(request_text.contains("\"finalized\""));

            let mut output = String::new();
            output.push_str(&format!("{:064x}", 32));
            output.push_str(&format!("{:064x}", 64));
            output.push_str(&"00".repeat(32));
            output.push_str(&"00".repeat(32));
            output.push_str(&"00".repeat(32));
            output.push_str(&"00".repeat(32));
            output.push_str(&format!("{:064x}", 1));
            output.push_str(&format!("{:064x}", 3));
            output.push_str(&"ab".repeat(32));
            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": format!("0x{output}")
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let client = BesuClient::new(&format!("http://{address}")).unwrap();
        let result = client
            .file_head(&EvmAddress::from_bytes([0x11; 20]), &[0x22; 32])
            .await
            .unwrap();
        assert_eq!(
            result,
            Some(FileHeadState {
                status: 1,
                version_number: 3,
                manifest_hash: format!("0x{}", "ab".repeat(32)),
            })
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn queries_active_member_signer_at_finalized_state() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = stream.read(&mut request).await.unwrap();
            let request_text = String::from_utf8_lossy(&request[..read]);
            assert!(request_text.contains("\"eth_call\""));
            assert!(request_text.contains("\"finalized\""));

            let mut output = String::new();
            output.push_str(&"00".repeat(32));
            output.push_str(&format!("{}{}", "00".repeat(12), "11".repeat(20)));
            output.push_str(&format!("{:064x}", 1));
            output.push_str(&format!("{:064x}", 1));
            output.push_str(&"22".repeat(32));
            output.push_str(&format!("{:064x}", 1));
            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": format!("0x{output}")
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let client = BesuClient::new(&format!("http://{address}")).unwrap();
        assert_eq!(
            client
                .active_member_signer(&EvmAddress::from_bytes([0x33; 20]), &[0x44; 32])
                .await
                .unwrap(),
            Some(EvmAddress::from_bytes([0x11; 20]))
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn filters_logs_to_configured_contracts_and_rejects_mismatched_results() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for response_address in ["11", "22"] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 1024];
                let body_start;
                loop {
                    let read = stream.read(&mut buffer).await.unwrap();
                    request.extend_from_slice(&buffer[..read]);
                    if let Some(position) =
                        request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                    {
                        body_start = position + 4;
                        break;
                    }
                }
                let headers = String::from_utf8_lossy(&request[..body_start]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap();
                while request.len() < body_start + content_length {
                    let read = stream.read(&mut buffer).await.unwrap();
                    request.extend_from_slice(&buffer[..read]);
                }
                let body: Value = serde_json::from_slice(&request[body_start..]).unwrap();
                assert_eq!(body["method"], "eth_getLogs");
                assert_eq!(body["params"][0]["fromBlock"], "0x5");
                assert_eq!(
                    body["params"][0]["address"][0],
                    format!("0x{}", "11".repeat(20))
                );
                let log = json!({
                    "address": format!("0x{}", response_address.repeat(20)),
                    "topics": [format!("0x{}", "aa".repeat(32))],
                    "data": "0x",
                    "blockNumber": "0x5",
                    "blockHash": format!("0x{}", "bb".repeat(32)),
                    "transactionHash": format!("0x{}", "cc".repeat(32)),
                    "transactionIndex": "0x0",
                    "logIndex": "0x0",
                    "removed": false
                });
                let response_body = json!({
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": [log]
                })
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let client = BesuClient::new(&format!("http://{address}")).unwrap();
        let configured_address = EvmAddress::from_bytes([0x11; 20]);
        let accepted = client
            .logs(5, 5, &[configured_address])
            .await
            .expect("matching contract log");
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].block_number().unwrap(), 5);

        let rejected = client.logs(5, 5, &[configured_address]).await;
        assert_eq!(rejected, Err(ChainError::InvalidResponse));
        server.await.unwrap();
    }
}
