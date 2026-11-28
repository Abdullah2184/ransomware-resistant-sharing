//! Besu JSON-RPC client for QBFT-committed event indexing, contract queries,
//! and Type-2 transaction relaying.

pub mod relayer;

use std::{
    error::Error,
    fmt,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use domain::EvmAddress;
pub use relayer::{
    DevelopmentRelayerSigner, EnvelopeSetUpdateCall, RelayError, RelayOutcome, RelayerConfig,
    RelayerSigner, RelayerStartupPolicy, TransactionRelayer, TxSignature, VersionAppendCall,
    encode_append_version_calldata, encode_create_file_calldata, encode_eip1559_signed_tx,
    encode_eip1559_unsigned_tx, encode_update_envelope_set_calldata,
};
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
    ExecutionReverted(Option<[u8; 4]>),
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
            Self::ExecutionReverted(_) => formatter.write_str("Besu contract call reverted"),
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
    pub organization_id: [u8; 32],
    pub signing_address: EvmAddress,
    pub signing_key_version: u32,
    pub encryption_key_version: u32,
    pub encryption_public_key: [u8; 32],
    pub status: u64,
}

impl MemberIdentityState {
    pub const fn active(&self) -> bool {
        self.status == 1
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileVersionState {
    pub content_cid: String,
    pub manifest_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeSetState {
    pub cid: String,
    pub epoch_id: [u8; 32],
    pub revision: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmTransactionReceipt {
    pub transaction_hash: [u8; 32],
    pub block_number: u64,
    pub block_hash: String,
    pub status: bool,
    pub gas_used: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RpcTransactionReceipt {
    transaction_hash: String,
    block_number: String,
    block_hash: String,
    status: String,
    gas_used: String,
}

/// JSON-RPC client for QBFT, where the latest committed head is final. This
/// deliberately does not use the proof-of-stake `finalized` block tag.
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
            .rpc_nullable("eth_getBlockByNumber", json!(["latest", false]))
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
            .rpc_nullable("eth_getBlockByNumber", json!([tag, false]))
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

    /// Reads the authoritative file head from the QBFT-committed head state.
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
                }, "latest"]),
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

    /// Returns the active member's signing address from QBFT-committed state.
    ///
    /// Inactive or unregistered identities return `None`; malformed contract
    /// responses fail closed.
    pub async fn active_member_signer(
        &self,
        access_governance: &EvmAddress,
        member_id: &[u8; 32],
    ) -> Result<Option<EvmAddress>, ChainError> {
        let words = self
            .eth_call(access_governance, "memberIdentity(bytes32)", member_id)
            .await?;
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
        let mut organization_id = [0; 32];
        organization_id.copy_from_slice(organization);
        let mut encryption_public_key = [0; 32];
        encryption_public_key.copy_from_slice(encryption_key);
        Ok(Some(MemberIdentityState {
            organization_id,
            signing_address: EvmAddress::from_bytes(signer),
            signing_key_version,
            encryption_key_version,
            encryption_public_key,
            status,
        }))
    }

    async fn eth_call_bool(
        &self,
        contract: &EvmAddress,
        call_data: &[u8],
        block_number: u64,
    ) -> Result<bool, ChainError> {
        let result: String = self
            .rpc(
                "eth_call",
                json!([{
                    "to": format_address(contract),
                    "data": format!("0x{}", encode_hex(call_data)),
                }, quantity(block_number)]),
            )
            .await?;
        let result = decode_hex(&result)?;
        if result.len() != 32 || result[..31].iter().any(|byte| *byte != 0) || result[31] > 1 {
            return Err(ChainError::InvalidResponse);
        }
        Ok(result[31] == 1)
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
        self.eth_call_bool(access_governance, &call_data, block_number)
            .await
    }

    pub async fn has_write_access(
        &self,
        access_governance: &EvmAddress,
        member_id: &[u8; 32],
        file_id: &[u8; 32],
        block_number: u64,
    ) -> Result<bool, ChainError> {
        let selector = Keccak256::digest(b"hasWriteAccess(bytes32,bytes32)");
        let mut call_data = Vec::with_capacity(68);
        call_data.extend_from_slice(&selector[..4]);
        call_data.extend_from_slice(member_id);
        call_data.extend_from_slice(file_id);
        self.eth_call_bool(access_governance, &call_data, block_number)
            .await
    }

    pub async fn has_historical_read_access(
        &self,
        access_governance: &EvmAddress,
        member_id: &[u8; 32],
        file_id: &[u8; 32],
        version_number: u64,
        block_number: u64,
    ) -> Result<bool, ChainError> {
        let selector = Keccak256::digest(b"hasHistoricalReadAccess(bytes32,bytes32,uint64)");
        let mut call_data = Vec::with_capacity(100);
        call_data.extend_from_slice(&selector[..4]);
        call_data.extend_from_slice(member_id);
        call_data.extend_from_slice(file_id);
        call_data.extend_from_slice(&abi_word_u64(version_number));
        self.eth_call_bool(access_governance, &call_data, block_number)
            .await
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
            Err(ChainError::ExecutionReverted(selector))
                if selector.is_none()
                    || selector == Some(selector4("FileNotFound()"))
                    || selector == Some(selector4("InvalidVersionNumber()")) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let tuple_offset = usize::try_from(read_word_u64(&encoded, 0)?)
            .map_err(|_| ChainError::InvalidResponse)?;
        if tuple_offset < 32 || tuple_offset % 32 != 0 {
            return Err(ChainError::InvalidResponse);
        }
        let tuple_end = tuple_offset
            .checked_add(9 * 32)
            .ok_or(ChainError::InvalidResponse)?;
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
        let cid =
            domain::ContentCid::parse(&content_cid).map_err(|_| ChainError::InvalidResponse)?;
        let manifest_hash = read_word_bytes32(&encoded, tuple_offset + 6 * 32)?;
        if manifest_hash == [0; 32] {
            return Err(ChainError::InvalidResponse);
        }
        Ok(Some(FileVersionState {
            content_cid: cid.to_string(),
            manifest_hash,
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
            Err(ChainError::ExecutionReverted(selector))
                if selector.is_none()
                    || selector == Some(selector4("InvalidEnvelopeReference()")) =>
            {
                return Ok(None);
            }
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
        let cid = domain::EnvelopeSetCid::parse(&cid).map_err(|_| ChainError::InvalidResponse)?;
        Ok(Some(EnvelopeSetState {
            cid: cid.to_string(),
            epoch_id,
            revision,
        }))
    }

    pub async fn pending_nonce(&self, address: &EvmAddress) -> Result<u64, ChainError> {
        let quantity: String = self
            .rpc(
                "eth_getTransactionCount",
                json!([format_address(address), "pending"]),
            )
            .await?;
        parse_quantity(&quantity)
    }

    pub async fn estimate_gas(
        &self,
        from: &EvmAddress,
        to: &EvmAddress,
        data: &[u8],
    ) -> Result<u64, ChainError> {
        let quantity: String = self
            .rpc(
                "eth_estimateGas",
                json!([{
                    "from": format_address(from),
                    "to": format_address(to),
                    "data": format!("0x{}", encode_hex(data)),
                }]),
            )
            .await?;
        parse_quantity(&quantity)
    }

    pub async fn send_raw_transaction(&self, raw_tx: &[u8]) -> Result<[u8; 32], ChainError> {
        let hash_hex: String = self
            .rpc(
                "eth_sendRawTransaction",
                json!([format!("0x{}", encode_hex(raw_tx))]),
            )
            .await?;
        let bytes = decode_hex(&hash_hex)?;
        let hash: [u8; 32] = bytes.try_into().map_err(|_| ChainError::InvalidResponse)?;
        Ok(hash)
    }

    pub async fn transaction_receipt(
        &self,
        tx_hash: &[u8; 32],
    ) -> Result<Option<EvmTransactionReceipt>, ChainError> {
        let receipt: Option<RpcTransactionReceipt> = self
            .rpc_nullable(
                "eth_getTransactionReceipt",
                json!([format!("0x{}", encode_hex(tx_hash))]),
            )
            .await?;
        let Some(receipt) = receipt else {
            return Ok(None);
        };
        let returned_hash_bytes = decode_hex(&receipt.transaction_hash)?;
        let returned_hash: [u8; 32] = returned_hash_bytes
            .try_into()
            .map_err(|_| ChainError::InvalidResponse)?;
        if returned_hash != *tx_hash {
            return Err(ChainError::InvalidResponse);
        }
        let block_number = parse_quantity(&receipt.block_number)?;
        validate_hash(&receipt.block_hash)?;
        let status_quantity = parse_quantity(&receipt.status)?;
        let status = match status_quantity {
            0 => false,
            1 => true,
            _ => return Err(ChainError::InvalidResponse),
        };
        let gas_used = parse_quantity(&receipt.gas_used)?;
        Ok(Some(EvmTransactionReceipt {
            transaction_hash: returned_hash,
            block_number,
            block_hash: receipt.block_hash.to_ascii_lowercase(),
            status,
            gas_used,
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
                }, "latest"]),
            )
            .await?;
        decode_hex(&result)
    }

    async fn rpc<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T, ChainError> {
        let value = self.rpc_raw(method, params).await?;
        serde_json::from_value(value).map_err(|_| ChainError::InvalidResponse)
    }

    async fn rpc_nullable<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<Option<T>, ChainError> {
        let value = self.rpc_raw(method, params).await?;
        if value.is_null() {
            return Ok(None);
        }
        serde_json::from_value(value)
            .map(Some)
            .map_err(|_| ChainError::InvalidResponse)
    }

    async fn rpc_raw(&self, method: &str, params: Value) -> Result<Value, ChainError> {
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
        let body: RpcResponse = response
            .json()
            .await
            .map_err(|_| ChainError::InvalidResponse)?;
        if body.jsonrpc != "2.0" || body.id != id {
            return Err(ChainError::InvalidResponse);
        }
        if let Some(error) = body.error {
            if error.code == 3 {
                let selector = error
                    .data
                    .as_deref()
                    .and_then(|value| decode_hex(value).ok())
                    .filter(|bytes| bytes.len() >= 4)
                    .map(|bytes| [bytes[0], bytes[1], bytes[2], bytes[3]]);
                return Err(ChainError::ExecutionReverted(selector));
            }
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
struct RpcResponse {
    jsonrpc: String,
    id: u64,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    result: Option<Value>,
    error: Option<RpcErrorObject>,
}

fn deserialize_present_value<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
struct RpcErrorObject {
    code: i64,
    #[serde(default)]
    data: Option<String>,
}

fn selector4(signature: &str) -> [u8; 4] {
    let digest = Keccak256::digest(signature.as_bytes());
    [digest[0], digest[1], digest[2], digest[3]]
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

fn decode_abi_string(
    encoded: &[u8],
    tuple_start: usize,
    offset: usize,
) -> Result<String, ChainError> {
    if !offset.is_multiple_of(32) {
        return Err(ChainError::InvalidResponse);
    }
    let start = tuple_start
        .checked_add(offset)
        .ok_or(ChainError::InvalidResponse)?;
    let length_end = start.checked_add(32).ok_or(ChainError::InvalidResponse)?;
    let length =
        usize::try_from(read_word_u64(encoded, start)?).map_err(|_| ChainError::InvalidResponse)?;
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

fn read_word_bytes32(data: &[u8], offset: usize) -> Result<[u8; 32], ChainError> {
    let end = offset.checked_add(32).ok_or(ChainError::InvalidResponse)?;
    let word = data.get(offset..end).ok_or(ChainError::InvalidResponse)?;
    let mut value = [0u8; 32];
    value.copy_from_slice(word);
    Ok(value)
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
    domain::hex::decode_prefixed_hex(value).ok_or(ChainError::InvalidResponse)
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    domain::hex::encode_hex(bytes)
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
    async fn queries_latest_qbft_committed_block_as_finalized_head() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = stream.read(&mut request).await.unwrap();
            let request_text = String::from_utf8_lossy(&request[..read]);
            assert!(request_text.contains("eth_getBlockByNumber"));
            assert!(request_text.contains("\"latest\""));

            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "number": "0x2a",
                    "hash": format!("0x{}", "ab".repeat(32))
                }
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
            client.finalized_block().await.unwrap(),
            FinalizedBlock {
                number: 42,
                hash: format!("0x{}", "ab".repeat(32)),
            }
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn queries_file_head_at_qbft_committed_state() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = stream.read(&mut request).await.unwrap();
            let request_text = String::from_utf8_lossy(&request[..read]);
            assert!(request_text.contains("\"eth_call\""));
            assert!(request_text.contains("\"latest\""));

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
    async fn queries_active_member_signer_at_qbft_committed_state() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = stream.read(&mut request).await.unwrap();
            let request_text = String::from_utf8_lossy(&request[..read]);
            assert!(request_text.contains("\"eth_call\""));
            assert!(request_text.contains("\"latest\""));

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
    async fn queries_public_member_identity_at_the_requested_block() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = stream.read(&mut request).await.unwrap();
            let request_text = String::from_utf8_lossy(&request[..read]);
            assert!(request_text.contains("\"eth_call\""));
            assert!(request_text.contains("\"0x7\""));

            let mut output = String::new();
            output.push_str(&"11".repeat(32));
            output.push_str(&format!("{}{}", "00".repeat(12), "22".repeat(20)));
            output.push_str(&format!("{:064x}", 3));
            output.push_str(&format!("{:064x}", 4));
            output.push_str(&"33".repeat(32));
            output.push_str(&format!("{:064x}", 2));
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
                .member_identity(&EvmAddress::from_bytes([0x44; 20]), &[0x55; 32], 7)
                .await
                .unwrap(),
            Some(MemberIdentityState {
                organization_id: [0x11; 32],
                signing_address: EvmAddress::from_bytes([0x22; 20]),
                signing_key_version: 3,
                encryption_key_version: 4,
                encryption_public_key: [0x33; 32],
                status: 2,
            })
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn queries_version_scoped_historical_read_at_requested_block() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = stream.read(&mut request).await.unwrap();
            let request_text = String::from_utf8_lossy(&request[..read]);
            assert!(request_text.contains("\"eth_call\""));
            assert!(request_text.contains("\"0x7\""));

            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": format!("0x{:064x}", 1)
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
        assert!(
            client
                .has_historical_read_access(
                    &EvmAddress::from_bytes([0x33; 20]),
                    &[0x44; 32],
                    &[0x55; 32],
                    2,
                    7,
                )
                .await
                .unwrap()
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

    #[tokio::test]
    async fn queries_write_access_at_requested_block() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let read = stream.read(&mut request).await.unwrap();
            let request_text = String::from_utf8_lossy(&request[..read]);
            assert!(request_text.contains("\"eth_call\""));
            assert!(request_text.contains("\"0x9\""));
            let selector = Keccak256::digest(b"hasWriteAccess(bytes32,bytes32)");
            assert!(request_text.contains(&encode_hex(&selector[..4])));

            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": format!("0x{:064x}", 1)
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
        assert!(
            client
                .has_write_access(
                    &EvmAddress::from_bytes([0x33; 20]),
                    &[0x44; 32],
                    &[0x55; 32],
                    9,
                )
                .await
                .unwrap()
        );
        server.await.unwrap();
    }

    fn abi_encode_string(value: &str) -> Vec<u8> {
        let bytes = value.as_bytes();
        let padded_len = bytes.len().div_ceil(32) * 32;
        let mut out = Vec::with_capacity(32 + padded_len);
        out.extend_from_slice(&abi_word_u64(bytes.len() as u64));
        out.extend_from_slice(bytes);
        out.resize(32 + padded_len, 0);
        out
    }

    async fn spawn_rpc_sequence(
        responses: Vec<Value>,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            for response_payload in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let body_start;
                loop {
                    let n = stream.read(&mut chunk).await.unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        body_start = pos + 4;
                        break;
                    }
                }
                let headers = String::from_utf8_lossy(&buf[..body_start]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                while buf.len() < body_start + content_length {
                    let n = stream.read(&mut chunk).await.unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                }
                let body = response_payload.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn queries_file_head_at_explicit_block_and_handles_unregistered_files() {
        let mut active_words = Vec::new();
        active_words.extend_from_slice(&abi_word_u64(32)); // tuple offset
        active_words.extend_from_slice(&abi_word_u64(8 * 32)); // displayName offset
        active_words.extend_from_slice(&[0u8; 32]); // parentFolderId
        active_words.extend_from_slice(&[0x11; 32]); // creatorMemberId
        active_words.extend_from_slice(&[0x22; 32]); // organizationId
        active_words.extend_from_slice(&abi_word_u64(1_800_000_000)); // createdAt
        active_words.extend_from_slice(&abi_word_u64(1)); // status = Active
        active_words.extend_from_slice(&abi_word_u64(4)); // currentVersionNumber
        active_words.extend_from_slice(&[0xab; 32]); // currentHeadManifestHash
        active_words.extend_from_slice(&abi_encode_string("report.pdf"));

        let mut unregistered_words = Vec::new();
        unregistered_words.extend_from_slice(&abi_word_u64(32));
        for _ in 0..8 {
            unregistered_words.extend_from_slice(&[0u8; 32]);
        }

        let (addr, server) = spawn_rpc_sequence(vec![
            json!({ "jsonrpc": "2.0", "id": 1, "result": format!("0x{}", encode_hex(&active_words)) }),
            json!({ "jsonrpc": "2.0", "id": 2, "result": format!("0x{}", encode_hex(&unregistered_words)) }),
        ])
        .await;

        let client = BesuClient::new(&format!("http://{addr}")).unwrap();
        let registry = EvmAddress::from_bytes([0x10; 20]);
        let head = client
            .file_head_at(&registry, &[0x99; 32], 42)
            .await
            .unwrap()
            .expect("active head");
        assert_eq!(head.status, 1);
        assert_eq!(head.version_number, 4);
        assert_eq!(head.manifest_hash, format!("0x{}", "ab".repeat(32)));

        assert_eq!(
            client
                .file_head_at(&registry, &[0x88; 32], 42)
                .await
                .unwrap(),
            None
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn queries_read_access_and_rejects_malformed_boolean_words() {
        let (addr, server) = spawn_rpc_sequence(vec![
            json!({ "jsonrpc": "2.0", "id": 1, "result": format!("0x{:064x}", 1) }),
            json!({ "jsonrpc": "2.0", "id": 2, "result": format!("0x{:064x}", 0) }),
            json!({ "jsonrpc": "2.0", "id": 3, "result": format!("0x{:064x}", 2) }),
        ])
        .await;

        let client = BesuClient::new(&format!("http://{addr}")).unwrap();
        let gov = EvmAddress::from_bytes([0x20; 20]);
        assert!(
            client
                .has_read_access(&gov, &[1; 32], &[2; 32], 12)
                .await
                .unwrap()
        );
        assert!(
            !client
                .has_read_access(&gov, &[1; 32], &[2; 32], 12)
                .await
                .unwrap()
        );
        assert_eq!(
            client.has_read_access(&gov, &[1; 32], &[2; 32], 12).await,
            Err(ChainError::InvalidResponse)
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn queries_file_version_and_handles_missing_or_mismatched_versions() {
        let content_cid = "bafkreiewgvgk44czrxzm3u42r3ypxj76o6uebclaabcq7wsnlgaotpvcx4";
        let build_version_tuple = |returned_version: u64| {
            let mut out = Vec::new();
            out.extend_from_slice(&abi_word_u64(32)); // tuple offset
            out.extend_from_slice(&[0x77; 32]); // fileId
            out.extend_from_slice(&abi_word_u64(returned_version)); // versionNumber
            out.extend_from_slice(&[0u8; 32]); // parentManifestHash
            out.extend_from_slice(&abi_word_u64(9 * 32)); // contentCid offset within tuple
            out.extend_from_slice(&abi_word_u64(12 * 32)); // initialEnvelopeSetCid offset
            out.extend_from_slice(&[0x33; 32]); // epochId
            out.extend_from_slice(&[0x44; 32]); // manifestHash
            out.extend_from_slice(&[0x55; 32]); // authorMemberId
            out.extend_from_slice(&[0x66; 32]); // authorSigningAddress
            out.extend_from_slice(&abi_encode_string(content_cid));
            out
        };

        let file_not_found_selector = format!("0x{}", encode_hex(&selector4("FileNotFound()")));
        let invalid_version_selector =
            format!("0x{}", encode_hex(&selector4("InvalidVersionNumber()")));
        let (addr, server) = spawn_rpc_sequence(vec![
            json!({ "jsonrpc": "2.0", "id": 1, "result": format!("0x{}", encode_hex(&build_version_tuple(3))) }),
            json!({ "jsonrpc": "2.0", "id": 2, "error": { "code": 3, "message": "Execution reverted", "data": file_not_found_selector } }),
            json!({ "jsonrpc": "2.0", "id": 3, "error": { "code": 3, "message": "Execution reverted", "data": invalid_version_selector } }),
            json!({ "jsonrpc": "2.0", "id": 4, "error": { "code": -32603, "message": "Internal error" } }),
            json!({ "jsonrpc": "2.0", "id": 5, "error": { "code": 3, "message": "Execution reverted", "data": "0xdeadbeef" } }),
            json!({ "jsonrpc": "2.0", "id": 6, "result": format!("0x{}", encode_hex(&build_version_tuple(99))) }),
        ])
        .await;

        let client = BesuClient::new(&format!("http://{addr}")).unwrap();
        let registry = EvmAddress::from_bytes([0x10; 20]);
        let found = client
            .file_version(&registry, &[0x77; 32], 3, 20)
            .await
            .unwrap()
            .expect("version 3");
        assert_eq!(found.content_cid, content_cid);
        assert_eq!(found.manifest_hash, [0x44; 32]);
        assert_eq!(
            client
                .file_version(&registry, &[0x77; 32], 4, 20)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            client
                .file_version(&registry, &[0x77; 32], 5, 20)
                .await
                .unwrap(),
            None
        );
        // Non-revert RPC errors (e.g. pruned historical state -32603) must surface as Err, never Ok(None).
        assert_eq!(
            client.file_version(&registry, &[0x77; 32], 3, 20).await,
            Err(ChainError::RpcRejected(-32603))
        );
        // Unexpected revert selectors must fail closed rather than looking like a missing version.
        assert_eq!(
            client.file_version(&registry, &[0x77; 32], 3, 20).await,
            Err(ChainError::ExecutionReverted(Some([
                0xde, 0xad, 0xbe, 0xef
            ])))
        );
        assert_eq!(
            client.file_version(&registry, &[0x77; 32], 3, 20).await,
            Err(ChainError::InvalidResponse)
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn queries_current_envelope_set_and_rejects_zero_revision() {
        let envelope_cid = "bafkreiewgvgk44czrxzm3u42r3ypxj76o6uebclaabcq7wsnlgaotpvcx4";
        let build_envelope_return = |revision: u64| {
            let mut out = Vec::new();
            out.extend_from_slice(&abi_word_u64(96)); // string offset
            out.extend_from_slice(&[0xee; 32]); // epochId
            out.extend_from_slice(&abi_word_u64(revision)); // revision
            out.extend_from_slice(&abi_encode_string(envelope_cid));
            out
        };

        let invalid_env_selector =
            format!("0x{}", encode_hex(&selector4("InvalidEnvelopeReference()")));
        let (addr, server) = spawn_rpc_sequence(vec![
            json!({ "jsonrpc": "2.0", "id": 1, "result": format!("0x{}", encode_hex(&build_envelope_return(2))) }),
            json!({ "jsonrpc": "2.0", "id": 2, "error": { "code": 3, "message": "Execution reverted", "data": invalid_env_selector } }),
            json!({ "jsonrpc": "2.0", "id": 3, "error": { "code": -32603, "message": "Internal error" } }),
            json!({ "jsonrpc": "2.0", "id": 4, "error": { "code": 3, "message": "Execution reverted", "data": "0xbadc0ffe" } }),
            json!({ "jsonrpc": "2.0", "id": 5, "result": format!("0x{}", encode_hex(&build_envelope_return(0))) }),
        ])
        .await;

        let client = BesuClient::new(&format!("http://{addr}")).unwrap();
        let gov = EvmAddress::from_bytes([0x20; 20]);
        let env = client
            .current_envelope_set(&gov, &[0x77; 32], 1, 25)
            .await
            .unwrap()
            .expect("envelope set");
        assert_eq!(env.cid, envelope_cid);
        assert_eq!(env.epoch_id, [0xee; 32]);
        assert_eq!(env.revision, 2);

        assert_eq!(
            client
                .current_envelope_set(&gov, &[0x77; 32], 2, 25)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            client.current_envelope_set(&gov, &[0x77; 32], 1, 25).await,
            Err(ChainError::RpcRejected(-32603))
        );
        assert_eq!(
            client.current_envelope_set(&gov, &[0x77; 32], 1, 25).await,
            Err(ChainError::ExecutionReverted(Some([
                0xba, 0xdc, 0x0f, 0xfe
            ])))
        );
        assert_eq!(
            client.current_envelope_set(&gov, &[0x77; 32], 1, 25).await,
            Err(ChainError::InvalidResponse)
        );
        server.await.unwrap();
    }
}
