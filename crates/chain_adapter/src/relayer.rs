//! Solidity ABI calldata encoding, EIP-2718 Type-2 transaction signing, and
//! Besu QBFT transaction relaying.

use std::{
    error::Error,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use domain::EvmAddress;
use k256::ecdsa::{SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::{BesuClient, ChainError, EvmTransactionReceipt};

const CREATE_FILE_SIGNATURE: &str = "createFile((bytes32,uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,address,bytes32,uint256),string,string,string,bytes32,bytes)";
const APPEND_VERSION_SIGNATURE: &str = "appendVersion((bytes32,uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,address,bytes32,uint256),string,string,bytes)";
const UPDATE_ENVELOPE_SET_SIGNATURE: &str = "updateEnvelopeSet((bytes32,uint64,bytes32,string,string,bytes32,bytes32,bytes32,uint256),bytes)";

/// Parameters for `FileRegistry.createFile` and `FileRegistry.appendVersion`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionAppendCall {
    pub file_id: [u8; 32],
    pub version_number: u64,
    pub parent_manifest_hash: [u8; 32],
    pub content_cid: String,
    pub envelope_set_cid: String,
    pub epoch_id: [u8; 32],
    pub manifest_hash: [u8; 32],
    pub member_id: [u8; 32],
    pub signer_address: EvmAddress,
    pub operation_nonce: [u8; 32],
    pub deadline: u64,
}

/// Parameters for `AccessGovernance.updateEnvelopeSet`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeSetUpdateCall {
    pub file_id: [u8; 32],
    pub version_number: u64,
    pub epoch_id: [u8; 32],
    pub old_envelope_set_cid: String,
    pub new_envelope_set_cid: String,
    pub actor_member_id: [u8; 32],
    pub proposal_id: [u8; 32],
    pub operation_nonce: [u8; 32],
    pub deadline: u64,
}

/// Low-`s` canonical secp256k1 transaction signature for EIP-2718 Type-2 transactions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxSignature {
    pub y_parity: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
}

/// Startup enforcement policy for relayer key custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayerStartupPolicy {
    Production,
    UnsafeDevelopment,
}

/// Relayer configuration for zero-gas-price London Besu QBFT transactions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayerConfig {
    pub chain_id: u64,
    pub default_gas_limit: u64,
    pub max_gas_limit: u64,
    pub confirmation_timeout: Duration,
    pub poll_interval: Duration,
}

impl RelayerConfig {
    pub fn local_default(chain_id: u64) -> Self {
        Self {
            chain_id,
            default_gas_limit: 2_000_000,
            max_gas_limit: 10_000_000,
            confirmation_timeout: Duration::from_secs(30),
            poll_interval: Duration::from_millis(250),
        }
    }
}

/// Final outcome of a relayed contract transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayOutcome {
    Committed(EvmTransactionReceipt),
    Reverted(EvmTransactionReceipt),
}

/// Stable errors returned by the transaction relayer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayError {
    InvalidConfig,
    UnsafeSignerInProduction,
    GasLimitExceeded,
    SigningFailed,
    HashMismatch,
    Chain(ChainError),
    ConfirmationTimedOut { tx_hash: [u8; 32] },
}

impl fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => formatter.write_str("invalid transaction relayer configuration"),
            Self::UnsafeSignerInProduction => {
                formatter.write_str("development relayer signer rejected by production policy")
            }
            Self::GasLimitExceeded => {
                formatter.write_str("requested transaction gas limit exceeds configured maximum")
            }
            Self::SigningFailed => formatter.write_str("transaction relayer signing failed"),
            Self::HashMismatch => {
                formatter.write_str("Besu RPC returned a mismatched transaction hash")
            }
            Self::Chain(error) => write!(formatter, "chain RPC error: {error}"),
            Self::ConfirmationTimedOut { .. } => {
                formatter.write_str("transaction confirmation timed out; reconciliation required")
            }
        }
    }
}

impl Error for RelayError {}

impl From<ChainError> for RelayError {
    fn from(error: ChainError) -> Self {
        Self::Chain(error)
    }
}

/// Signer boundary for dedicated relayer accounts.
///
/// Implementations MUST keep relayer keys isolated from member signing keys and
/// QBFT validator keys.
pub trait RelayerSigner: Send + Sync {
    fn address(&self) -> EvmAddress;
    fn is_test_only(&self) -> bool;
    fn sign_tx_hash(&self, tx_hash: &[u8; 32]) -> Result<TxSignature, RelayError>;
}

/// In-memory software secp256k1 relayer signer for local development and tests.
///
/// Rejected by [`RelayerStartupPolicy::Production`].
pub struct DevelopmentRelayerSigner {
    key_bytes: Zeroizing<[u8; 32]>,
    address: EvmAddress,
}

impl fmt::Debug for DevelopmentRelayerSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevelopmentRelayerSigner")
            .field("address", &self.address)
            .field("test_only", &true)
            .finish()
    }
}

impl DevelopmentRelayerSigner {
    pub fn generate() -> Result<Self, RelayError> {
        let mut raw = Zeroizing::new([0u8; 32]);
        getrandom::fill(raw.as_mut()).map_err(|_| RelayError::SigningFailed)?;
        Self::from_secret_bytes(*raw)
    }

    pub fn from_secret_bytes(secret: [u8; 32]) -> Result<Self, RelayError> {
        let key_bytes = Zeroizing::new(secret);
        let signing_key = SigningKey::from_bytes(key_bytes.as_slice().into())
            .map_err(|_| RelayError::SigningFailed)?;
        let address = evm_address_from_verifying_key(signing_key.verifying_key());
        Ok(Self { key_bytes, address })
    }

    /// Parses a `0x`-prefixed 32-byte hex private key for unsafe local
    /// development only. Never use in production deployments.
    pub fn from_hex_secret(hex_key: &str) -> Result<Self, RelayError> {
        let raw = crate::decode_hex(hex_key).map_err(|_| RelayError::SigningFailed)?;
        let mut secret = Zeroizing::new([0u8; 32]);
        if raw.len() != 32 {
            return Err(RelayError::SigningFailed);
        }
        secret.copy_from_slice(&raw);
        Self::from_secret_bytes(*secret)
    }
}

impl RelayerSigner for DevelopmentRelayerSigner {
    fn address(&self) -> EvmAddress {
        self.address
    }

    fn is_test_only(&self) -> bool {
        true
    }

    fn sign_tx_hash(&self, tx_hash: &[u8; 32]) -> Result<TxSignature, RelayError> {
        let signing_key = SigningKey::from_bytes(self.key_bytes.as_slice().into())
            .map_err(|_| RelayError::SigningFailed)?;
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(tx_hash)
            .map_err(|_| RelayError::SigningFailed)?;
        let (normalized, y_parity) = match signature.normalize_s() {
            Some(low_s) => (low_s, u8::from(recovery_id) ^ 1),
            None => (signature, u8::from(recovery_id)),
        };
        if y_parity > 1 {
            return Err(RelayError::SigningFailed);
        }
        let bytes = normalized.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        Ok(TxSignature { y_parity, r, s })
    }
}

/// Sequential Type-2 transaction relayer targeting Besu QBFT.
pub struct TransactionRelayer {
    client: BesuClient,
    signer: Arc<dyn RelayerSigner>,
    config: RelayerConfig,
    next_nonce: Mutex<Option<u64>>,
}

impl fmt::Debug for TransactionRelayer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransactionRelayer")
            .field("relayer_address", &self.signer.address())
            .field("chain_id", &self.config.chain_id)
            .finish_non_exhaustive()
    }
}

impl TransactionRelayer {
    pub fn new(
        client: BesuClient,
        signer: Arc<dyn RelayerSigner>,
        policy: RelayerStartupPolicy,
        config: RelayerConfig,
    ) -> Result<Self, RelayError> {
        if config.chain_id == 0
            || config.default_gas_limit == 0
            || config.default_gas_limit > config.max_gas_limit
            || config.confirmation_timeout.is_zero()
            || config.poll_interval.is_zero()
        {
            return Err(RelayError::InvalidConfig);
        }
        if matches!(policy, RelayerStartupPolicy::Production) && signer.is_test_only() {
            return Err(RelayError::UnsafeSignerInProduction);
        }
        Ok(Self {
            client,
            signer,
            config,
            next_nonce: Mutex::new(None),
        })
    }

    pub fn relayer_address(&self) -> EvmAddress {
        self.signer.address()
    }

    /// Submits one signed Type-2 contract call and polls until the receipt is
    /// included in a QBFT-committed block or the confirmation deadline elapses.
    ///
    /// On timeout this returns [`RelayError::ConfirmationTimedOut`] with the
    /// submitted transaction hash and never automatically resubmits.
    pub async fn submit_and_confirm(
        &self,
        to: EvmAddress,
        calldata: Vec<u8>,
        gas_limit: Option<u64>,
    ) -> Result<RelayOutcome, RelayError> {
        let gas_limit = gas_limit.unwrap_or(self.config.default_gas_limit);
        if gas_limit == 0 || gas_limit > self.config.max_gas_limit {
            return Err(RelayError::GasLimitExceeded);
        }

        let tx_hash = {
            let mut nonce_guard = self.next_nonce.lock().await;
            let nonce = match *nonce_guard {
                Some(cached) => cached,
                None => self.client.pending_nonce(&self.signer.address()).await?,
            };
            let unsigned =
                encode_eip1559_unsigned_tx(self.config.chain_id, nonce, gas_limit, to, &calldata);
            let signing_hash = keccak256(&unsigned);
            let signature = self.signer.sign_tx_hash(&signing_hash)?;
            let signed = encode_eip1559_signed_tx(
                self.config.chain_id,
                nonce,
                gas_limit,
                to,
                &calldata,
                signature,
            );
            let expected_hash = keccak256(&signed);
            match self.client.send_raw_transaction(&signed).await {
                Ok(submitted_hash) => {
                    if submitted_hash != expected_hash {
                        *nonce_guard = None;
                        return Err(RelayError::HashMismatch);
                    }
                    *nonce_guard = nonce.checked_add(1);
                    submitted_hash
                }
                Err(error) => {
                    *nonce_guard = None;
                    return Err(RelayError::Chain(error));
                }
            }
        };

        let deadline = Instant::now() + self.config.confirmation_timeout;
        loop {
            if let Some(outcome) = self.reconcile_transaction(tx_hash).await? {
                return Ok(outcome);
            }
            if Instant::now() >= deadline {
                return Err(RelayError::ConfirmationTimedOut { tx_hash });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            tokio::time::sleep(self.config.poll_interval.min(remaining)).await;
        }
    }

    /// Queries the current QBFT-committed receipt for a previously submitted
    /// transaction hash. Returns `Ok(None)` while the transaction is still
    /// pending or not yet at/below the committed head.
    pub async fn reconcile_transaction(
        &self,
        tx_hash: [u8; 32],
    ) -> Result<Option<RelayOutcome>, RelayError> {
        let Some(receipt) = self.client.transaction_receipt(&tx_hash).await? else {
            return Ok(None);
        };
        let finalized = self.client.finalized_block().await?;
        if receipt.block_number > finalized.number {
            return Ok(None);
        }
        if receipt.status {
            Ok(Some(RelayOutcome::Committed(receipt)))
        } else {
            Ok(Some(RelayOutcome::Reverted(receipt)))
        }
    }
}

/// Encodes ABI calldata for `FileRegistry.createFile`.
pub fn encode_create_file_calldata(
    call: &VersionAppendCall,
    display_name: &str,
    parent_folder_id: [u8; 32],
    signature: &[u8],
) -> Vec<u8> {
    let selector = function_selector(CREATE_FILE_SIGNATURE);
    let content_encoded = encode_abi_dynamic_bytes(call.content_cid.as_bytes());
    let envelope_encoded = encode_abi_dynamic_bytes(call.envelope_set_cid.as_bytes());
    let display_name_encoded = encode_abi_dynamic_bytes(display_name.as_bytes());
    let signature_encoded = encode_abi_dynamic_bytes(signature);

    // Head: 11-word static VersionAppend tuple + 3 dynamic offsets + 1 static bytes32 + 1 dynamic offset = 16 words.
    let head_size = 16 * 32;
    let content_offset = head_size;
    let envelope_offset = content_offset + content_encoded.len();
    let display_name_offset = envelope_offset + envelope_encoded.len();
    let signature_offset = display_name_offset + display_name_encoded.len();

    let mut out = Vec::with_capacity(4 + signature_offset + signature_encoded.len());
    out.extend_from_slice(&selector);
    write_version_append_tuple(&mut out, call);
    out.extend_from_slice(&abi_word_usize(content_offset));
    out.extend_from_slice(&abi_word_usize(envelope_offset));
    out.extend_from_slice(&abi_word_usize(display_name_offset));
    out.extend_from_slice(&parent_folder_id);
    out.extend_from_slice(&abi_word_usize(signature_offset));
    out.extend_from_slice(&content_encoded);
    out.extend_from_slice(&envelope_encoded);
    out.extend_from_slice(&display_name_encoded);
    out.extend_from_slice(&signature_encoded);
    out
}

/// Encodes ABI calldata for `FileRegistry.appendVersion`.
pub fn encode_append_version_calldata(call: &VersionAppendCall, signature: &[u8]) -> Vec<u8> {
    let selector = function_selector(APPEND_VERSION_SIGNATURE);
    let content_encoded = encode_abi_dynamic_bytes(call.content_cid.as_bytes());
    let envelope_encoded = encode_abi_dynamic_bytes(call.envelope_set_cid.as_bytes());
    let signature_encoded = encode_abi_dynamic_bytes(signature);

    // Head: 11-word static VersionAppend tuple + 3 dynamic offsets = 14 words.
    let head_size = 14 * 32;
    let content_offset = head_size;
    let envelope_offset = content_offset + content_encoded.len();
    let signature_offset = envelope_offset + envelope_encoded.len();

    let mut out = Vec::with_capacity(4 + signature_offset + signature_encoded.len());
    out.extend_from_slice(&selector);
    write_version_append_tuple(&mut out, call);
    out.extend_from_slice(&abi_word_usize(content_offset));
    out.extend_from_slice(&abi_word_usize(envelope_offset));
    out.extend_from_slice(&abi_word_usize(signature_offset));
    out.extend_from_slice(&content_encoded);
    out.extend_from_slice(&envelope_encoded);
    out.extend_from_slice(&signature_encoded);
    out
}

/// Encodes ABI calldata for `AccessGovernance.updateEnvelopeSet`.
pub fn encode_update_envelope_set_calldata(
    call: &EnvelopeSetUpdateCall,
    signature: &[u8],
) -> Vec<u8> {
    let selector = function_selector(UPDATE_ENVELOPE_SET_SIGNATURE);

    let old_cid_encoded = encode_abi_dynamic_bytes(call.old_envelope_set_cid.as_bytes());
    let new_cid_encoded = encode_abi_dynamic_bytes(call.new_envelope_set_cid.as_bytes());

    // Inner dynamic EnvelopeSetUpdate tuple head: 9 words = 288 bytes.
    let tuple_head_size = 9 * 32;
    let old_cid_offset = tuple_head_size;
    let new_cid_offset = old_cid_offset + old_cid_encoded.len();
    let mut tuple_encoded = Vec::with_capacity(new_cid_offset + new_cid_encoded.len());
    tuple_encoded.extend_from_slice(&call.file_id);
    tuple_encoded.extend_from_slice(&abi_word_u64(call.version_number));
    tuple_encoded.extend_from_slice(&call.epoch_id);
    tuple_encoded.extend_from_slice(&abi_word_usize(old_cid_offset));
    tuple_encoded.extend_from_slice(&abi_word_usize(new_cid_offset));
    tuple_encoded.extend_from_slice(&call.actor_member_id);
    tuple_encoded.extend_from_slice(&call.proposal_id);
    tuple_encoded.extend_from_slice(&call.operation_nonce);
    tuple_encoded.extend_from_slice(&abi_word_u64(call.deadline));
    tuple_encoded.extend_from_slice(&old_cid_encoded);
    tuple_encoded.extend_from_slice(&new_cid_encoded);

    let signature_encoded = encode_abi_dynamic_bytes(signature);

    // Outer head: 2 dynamic offsets (request tuple + signature) = 64 bytes.
    let tuple_offset = 2 * 32;
    let signature_offset = tuple_offset + tuple_encoded.len();

    let mut out = Vec::with_capacity(4 + signature_offset + signature_encoded.len());
    out.extend_from_slice(&selector);
    out.extend_from_slice(&abi_word_usize(tuple_offset));
    out.extend_from_slice(&abi_word_usize(signature_offset));
    out.extend_from_slice(&tuple_encoded);
    out.extend_from_slice(&signature_encoded);
    out
}

/// Encodes the unsigned EIP-2718 Type-2 (EIP-1559) signing payload with zero
/// gas fees for private London Besu QBFT networks.
pub fn encode_eip1559_unsigned_tx(
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    to: EvmAddress,
    data: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&rlp_u64(chain_id));
    payload.extend_from_slice(&rlp_u64(nonce));
    payload.extend_from_slice(&rlp_u64(0)); // maxPriorityFeePerGas
    payload.extend_from_slice(&rlp_u64(0)); // maxFeePerGas
    payload.extend_from_slice(&rlp_u64(gas_limit));
    payload.extend_from_slice(&rlp_bytes(to.as_bytes()));
    payload.extend_from_slice(&rlp_u64(0)); // value
    payload.extend_from_slice(&rlp_bytes(data));
    payload.extend_from_slice(&rlp_list(&[])); // empty accessList

    let list = rlp_list(&payload);
    let mut out = Vec::with_capacity(1 + list.len());
    out.push(0x02);
    out.extend_from_slice(&list);
    out
}

/// Encodes a signed EIP-2718 Type-2 (EIP-1559) raw transaction for
/// `eth_sendRawTransaction`.
pub fn encode_eip1559_signed_tx(
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    to: EvmAddress,
    data: &[u8],
    signature: TxSignature,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&rlp_u64(chain_id));
    payload.extend_from_slice(&rlp_u64(nonce));
    payload.extend_from_slice(&rlp_u64(0)); // maxPriorityFeePerGas
    payload.extend_from_slice(&rlp_u64(0)); // maxFeePerGas
    payload.extend_from_slice(&rlp_u64(gas_limit));
    payload.extend_from_slice(&rlp_bytes(to.as_bytes()));
    payload.extend_from_slice(&rlp_u64(0)); // value
    payload.extend_from_slice(&rlp_bytes(data));
    payload.extend_from_slice(&rlp_list(&[])); // empty accessList
    payload.extend_from_slice(&rlp_u64(u64::from(signature.y_parity)));
    payload.extend_from_slice(&rlp_bytes(strip_leading_zeros(&signature.r)));
    payload.extend_from_slice(&rlp_bytes(strip_leading_zeros(&signature.s)));

    let list = rlp_list(&payload);
    let mut out = Vec::with_capacity(1 + list.len());
    out.push(0x02);
    out.extend_from_slice(&list);
    out
}

fn write_version_append_tuple(out: &mut Vec<u8>, call: &VersionAppendCall) {
    let content_cid_hash = keccak256(call.content_cid.as_bytes());
    let envelope_set_cid_hash = keccak256(call.envelope_set_cid.as_bytes());
    out.extend_from_slice(&call.file_id);
    out.extend_from_slice(&abi_word_u64(call.version_number));
    out.extend_from_slice(&call.parent_manifest_hash);
    out.extend_from_slice(&content_cid_hash);
    out.extend_from_slice(&envelope_set_cid_hash);
    out.extend_from_slice(&call.epoch_id);
    out.extend_from_slice(&call.manifest_hash);
    out.extend_from_slice(&call.member_id);
    out.extend_from_slice(&abi_word_address(call.signer_address));
    out.extend_from_slice(&call.operation_nonce);
    out.extend_from_slice(&abi_word_u64(call.deadline));
}

fn encode_abi_dynamic_bytes(bytes: &[u8]) -> Vec<u8> {
    let padded_len = bytes.len().div_ceil(32) * 32;
    let mut out = Vec::with_capacity(32 + padded_len);
    out.extend_from_slice(&abi_word_usize(bytes.len()));
    out.extend_from_slice(bytes);
    out.resize(32 + padded_len, 0);
    out
}

fn function_selector(signature: &str) -> [u8; 4] {
    let hash = keccak256(signature.as_bytes());
    [hash[0], hash[1], hash[2], hash[3]]
}

fn abi_word_u64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn abi_word_usize(value: usize) -> [u8; 32] {
    abi_word_u64(u64::try_from(value).expect("ABI length fits in u64"))
}

fn abi_word_address(address: EvmAddress) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address.as_bytes());
    word
}

fn rlp_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    let bytes = value.to_be_bytes();
    rlp_bytes(strip_leading_zeros(&bytes))
}

fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] <= 0x7f {
        return vec![bytes[0]];
    }
    if bytes.len() <= 55 {
        let mut out = Vec::with_capacity(1 + bytes.len());
        out.push(0x80 + bytes.len() as u8);
        out.extend_from_slice(bytes);
        return out;
    }
    let len_bytes = (bytes.len() as u64).to_be_bytes();
    let len_trimmed = strip_leading_zeros(&len_bytes);
    let mut out = Vec::with_capacity(1 + len_trimmed.len() + bytes.len());
    out.push(0xb7 + len_trimmed.len() as u8);
    out.extend_from_slice(len_trimmed);
    out.extend_from_slice(bytes);
    out
}

fn rlp_list(encoded_items: &[u8]) -> Vec<u8> {
    if encoded_items.len() <= 55 {
        let mut out = Vec::with_capacity(1 + encoded_items.len());
        out.push(0xc0 + encoded_items.len() as u8);
        out.extend_from_slice(encoded_items);
        return out;
    }
    let len_bytes = (encoded_items.len() as u64).to_be_bytes();
    let len_trimmed = strip_leading_zeros(&len_bytes);
    let mut out = Vec::with_capacity(1 + len_trimmed.len() + encoded_items.len());
    out.push(0xf7 + len_trimmed.len() as u8);
    out.extend_from_slice(len_trimmed);
    out.extend_from_slice(encoded_items);
    out
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    &bytes[first_non_zero..]
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let digest = Keccak256::digest(bytes);
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn evm_address_from_verifying_key(verifying_key: &VerifyingKey) -> EvmAddress {
    let encoded = verifying_key.to_encoded_point(false);
    let hash = keccak256(&encoded.as_bytes()[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    EvmAddress::from_bytes(address)
}

/// Recovers the sender EVM address from a Type-2 signing hash and signature.
#[cfg(test)]
fn recover_tx_signer(signing_hash: &[u8; 32], sig: TxSignature) -> EvmAddress {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&sig.r);
    bytes[32..].copy_from_slice(&sig.s);
    let signature = k256::ecdsa::Signature::from_slice(&bytes).expect("valid signature");
    let recovery_id = k256::ecdsa::RecoveryId::from_byte(sig.y_parity).expect("valid parity");
    let key =
        VerifyingKey::recover_from_prehash(signing_hash, &signature, recovery_id).expect("recover");
    evm_address_from_verifying_key(&key)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use serde_json::{Value, json};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;
    use crate::{decode_hex, encode_hex};

    fn sample_version_append() -> VersionAppendCall {
        VersionAppendCall {
            file_id: [0x01; 32],
            version_number: 1,
            parent_manifest_hash: [0x00; 32],
            content_cid: "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku".to_owned(),
            envelope_set_cid: "bafkreifjjcie6lypi6ny7amxnfftagclbuxndqonfipmb64f2uf2nuiuqa"
                .to_owned(),
            epoch_id: [0x06; 32],
            manifest_hash: [0x03; 32],
            member_id: [0x07; 32],
            signer_address: EvmAddress::from_bytes([0x10; 20]),
            operation_nonce: [0x99; 32],
            deadline: 1_800_000_000,
        }
    }

    fn read_abi_word_u64(data: &[u8], word_index: usize) -> u64 {
        let start = word_index * 32;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[start + 24..start + 32]);
        u64::from_be_bytes(bytes)
    }

    #[test]
    fn encodes_create_file_and_append_version_calldata_matching_solidity_abi() {
        let call = sample_version_append();
        let signature = vec![0xab; 65];
        let parent_folder = [0x44; 32];

        let create_data =
            encode_create_file_calldata(&call, "quarterly-report.pdf", parent_folder, &signature);
        assert_eq!(
            &create_data[..4],
            &keccak256(CREATE_FILE_SIGNATURE.as_bytes())[..4]
        );
        let args = &create_data[4..];
        // Static tuple fields
        assert_eq!(&args[0..32], &call.file_id);
        assert_eq!(read_abi_word_u64(args, 1), 1);
        assert_eq!(&args[2 * 32..3 * 32], &call.parent_manifest_hash);
        assert_eq!(
            &args[3 * 32..4 * 32],
            &keccak256(call.content_cid.as_bytes())
        );
        assert_eq!(
            &args[4 * 32..5 * 32],
            &keccak256(call.envelope_set_cid.as_bytes())
        );
        assert_eq!(&args[8 * 32 + 12..9 * 32], call.signer_address.as_bytes());
        assert_eq!(read_abi_word_u64(args, 10), 1_800_000_000);
        // Dynamic offsets + static parentFolderId
        assert_eq!(read_abi_word_u64(args, 11), 512);
        assert_eq!(&args[14 * 32..15 * 32], &parent_folder);
        let sig_offset = read_abi_word_u64(args, 15) as usize;
        assert_eq!(read_abi_word_u64(&args[sig_offset..], 0), 65);
        assert_eq!(&args[sig_offset + 32..sig_offset + 32 + 65], &signature[..]);

        let append_data = encode_append_version_calldata(&call, &signature);
        assert_eq!(
            &append_data[..4],
            &keccak256(APPEND_VERSION_SIGNATURE.as_bytes())[..4]
        );
        let append_args = &append_data[4..];
        assert_eq!(read_abi_word_u64(append_args, 11), 448);
        let append_sig_offset = read_abi_word_u64(append_args, 13) as usize;
        assert_eq!(read_abi_word_u64(&append_args[append_sig_offset..], 0), 65);
    }

    #[test]
    fn encodes_update_envelope_set_calldata_with_dynamic_tuple_offsets() {
        let call = EnvelopeSetUpdateCall {
            file_id: [0x0a; 32],
            version_number: 3,
            epoch_id: [0x0b; 32],
            old_envelope_set_cid: "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
                .to_owned(),
            new_envelope_set_cid: "bafkreifjjcie6lypi6ny7amxnfftagclbuxndqonfipmb64f2uf2nuiuqa"
                .to_owned(),
            actor_member_id: [0x0e; 32],
            proposal_id: [0x0f; 32],
            operation_nonce: [0x99; 32],
            deadline: 1_800_000_000,
        };
        let signature = vec![0xcd; 65];
        let encoded = encode_update_envelope_set_calldata(&call, &signature);
        assert_eq!(
            &encoded[..4],
            &keccak256(UPDATE_ENVELOPE_SET_SIGNATURE.as_bytes())[..4]
        );
        let args = &encoded[4..];
        assert_eq!(read_abi_word_u64(args, 0), 64);
        let sig_offset = read_abi_word_u64(args, 1) as usize;
        let tuple = &args[64..sig_offset];
        assert_eq!(&tuple[0..32], &call.file_id);
        assert_eq!(read_abi_word_u64(tuple, 1), 3);
        assert_eq!(read_abi_word_u64(tuple, 3), 288);
        let old_len = read_abi_word_u64(&tuple[288..], 0) as usize;
        assert_eq!(old_len, call.old_envelope_set_cid.len());
        assert_eq!(
            &tuple[288 + 32..288 + 32 + old_len],
            call.old_envelope_set_cid.as_bytes()
        );
        let new_offset = read_abi_word_u64(tuple, 4) as usize;
        let new_len = read_abi_word_u64(&tuple[new_offset..], 0) as usize;
        assert_eq!(
            &tuple[new_offset + 32..new_offset + 32 + new_len],
            call.new_envelope_set_cid.as_bytes()
        );
        assert_eq!(read_abi_word_u64(&args[sig_offset..], 0), 65);
        assert_eq!(&args[sig_offset + 32..sig_offset + 32 + 65], &signature[..]);
    }

    #[test]
    fn encodes_canonical_rlp_and_recovers_type2_tx_signer() {
        assert_eq!(rlp_u64(0), vec![0x80]);
        assert_eq!(rlp_u64(1), vec![0x01]);
        assert_eq!(rlp_u64(127), vec![0x7f]);
        assert_eq!(rlp_u64(128), vec![0x81, 0x80]);
        assert_eq!(rlp_u64(1337), vec![0x82, 0x05, 0x39]);
        assert_eq!(rlp_bytes(&[]), vec![0x80]);
        assert_eq!(rlp_list(&[]), vec![0xc0]);
        let long = vec![0xaa; 60];
        let encoded_long = rlp_bytes(&long);
        assert_eq!(encoded_long[0], 0xb8);
        assert_eq!(encoded_long[1], 60);
        assert_eq!(&encoded_long[2..], &long[..]);

        let signer = DevelopmentRelayerSigner::from_secret_bytes([0x42; 32]).unwrap();
        let unsigned = encode_eip1559_unsigned_tx(
            1337,
            7,
            500_000,
            EvmAddress::from_bytes([0x22; 20]),
            b"calldata-bytes",
        );
        assert_eq!(unsigned[0], 0x02);
        let hash = keccak256(&unsigned);
        let sig = signer.sign_tx_hash(&hash).unwrap();
        assert_eq!(recover_tx_signer(&hash, sig), signer.address());
        let signed = encode_eip1559_signed_tx(
            1337,
            7,
            500_000,
            EvmAddress::from_bytes([0x22; 20]),
            b"calldata-bytes",
            sig,
        );
        assert_eq!(signed[0], 0x02);
        assert!(signed.len() > unsigned.len());
    }

    #[test]
    fn production_policy_rejects_development_relayer_signer() {
        let client = BesuClient::new("http://127.0.0.1:8545").unwrap();
        let signer = Arc::new(DevelopmentRelayerSigner::from_secret_bytes([0x11; 32]).unwrap());
        assert_eq!(
            TransactionRelayer::new(
                client,
                signer,
                RelayerStartupPolicy::Production,
                RelayerConfig::local_default(1337),
            )
            .unwrap_err(),
            RelayError::UnsafeSignerInProduction
        );
    }

    async fn read_rpc_request(stream: &mut tokio::net::TcpStream) -> Value {
        let mut request = Vec::new();
        let mut buffer = [0u8; 2048];
        let body_start;
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(read > 0, "unexpected EOF reading mock RPC request");
            request.extend_from_slice(&buffer[..read]);
            if let Some(pos) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                body_start = pos + 4;
                break;
            }
        }
        let headers = String::from_utf8_lossy(&request[..body_start]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|v| v.trim().parse::<usize>().ok())
            })
            .unwrap();
        while request.len() < body_start + content_length {
            let read = stream.read(&mut buffer).await.unwrap();
            request.extend_from_slice(&buffer[..read]);
        }
        serde_json::from_slice(&request[body_start..]).unwrap()
    }

    async fn write_rpc_response(stream: &mut tokio::net::TcpStream, id: &Value, result: Value) {
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    }

    #[tokio::test]
    async fn relays_sequential_transactions_handles_revert_and_reconciles_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let submitted_hashes = Arc::new(Mutex::new(Vec::<String>::new()));
        let receipt_polls = Arc::new(AtomicUsize::new(0));
        let release_tx3 = Arc::new(AtomicBool::new(false));
        let hashes_clone = submitted_hashes.clone();
        let polls_clone = receipt_polls.clone();
        let release_tx3_clone = release_tx3.clone();

        let server = tokio::spawn(async move {
            // Serve 3 relay flows:
            // tx 1 (nonce 5): pending once, then committed at block 10
            // tx 2 (nonce 6): reverted at block 11
            // tx 3 (nonce 7): pending past timeout, then committed on explicit reconcile
            for _ in 0..32 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let body = read_rpc_request(&mut stream).await;
                let method = body["method"].as_str().unwrap();
                let result = match method {
                    "eth_getTransactionCount" => json!("0x5"),
                    "eth_sendRawTransaction" => {
                        let raw_hex = body["params"][0].as_str().unwrap();
                        let raw = decode_hex(raw_hex).unwrap();
                        assert_eq!(raw[0], 0x02, "must submit EIP-2718 Type-2 tx");
                        let tx_hash = format!("0x{}", encode_hex(&keccak256(&raw)));
                        hashes_clone.lock().await.push(tx_hash.clone());
                        json!(tx_hash)
                    }
                    "eth_getTransactionReceipt" => {
                        let queried = body["params"][0].as_str().unwrap().to_owned();
                        let hashes = hashes_clone.lock().await;
                        if hashes.first().is_some_and(|h| h == &queried) {
                            let poll = polls_clone.fetch_add(1, Ordering::SeqCst);
                            if poll == 0 {
                                Value::Null
                            } else {
                                json!({
                                    "transactionHash": queried,
                                    "blockNumber": "0xa",
                                    "blockHash": format!("0x{}", "11".repeat(32)),
                                    "status": "0x1",
                                    "gasUsed": "0x5208"
                                })
                            }
                        } else if hashes.get(1).is_some_and(|h| h == &queried) {
                            json!({
                                "transactionHash": queried,
                                "blockNumber": "0xb",
                                "blockHash": format!("0x{}", "22".repeat(32)),
                                "status": "0x0",
                                "gasUsed": "0x7530"
                            })
                        } else {
                            // tx 3: return Null until explicitly released for reconcile
                            if !release_tx3_clone.load(Ordering::SeqCst) {
                                Value::Null
                            } else {
                                json!({
                                    "transactionHash": queried,
                                    "blockNumber": "0xc",
                                    "blockHash": format!("0x{}", "33".repeat(32)),
                                    "status": "0x1",
                                    "gasUsed": "0x61a8"
                                })
                            }
                        }
                    }
                    "eth_getBlockByNumber" => json!({
                        "number": "0xc",
                        "hash": format!("0x{}", "33".repeat(32))
                    }),
                    other => panic!("unexpected RPC method: {other}"),
                };
                write_rpc_response(&mut stream, &body["id"], result).await;
            }
        });

        let client = BesuClient::new(&format!("http://{address}")).unwrap();
        let signer = Arc::new(DevelopmentRelayerSigner::from_secret_bytes([0x55; 32]).unwrap());
        let relayer = TransactionRelayer::new(
            client,
            signer,
            RelayerStartupPolicy::UnsafeDevelopment,
            RelayerConfig {
                chain_id: 1337,
                default_gas_limit: 500_000,
                max_gas_limit: 1_000_000,
                confirmation_timeout: Duration::from_millis(60),
                poll_interval: Duration::from_millis(15),
            },
        )
        .unwrap();

        // Gas limit guard
        assert_eq!(
            relayer
                .submit_and_confirm(EvmAddress::from_bytes([0xaa; 20]), vec![1], Some(2_000_000))
                .await,
            Err(RelayError::GasLimitExceeded)
        );

        // Tx 1: commits after one pending poll
        let outcome1 = relayer
            .submit_and_confirm(EvmAddress::from_bytes([0xaa; 20]), vec![1, 2, 3], None)
            .await
            .unwrap();
        match outcome1 {
            RelayOutcome::Committed(receipt) => {
                assert_eq!(receipt.block_number, 10);
                assert!(receipt.status);
                assert_eq!(receipt.gas_used, 21_000);
            }
            other => panic!("expected Committed, got {other:?}"),
        }

        // Tx 2: uses sequential nonce 6 and reports Reverted (never Committed)
        let outcome2 = relayer
            .submit_and_confirm(EvmAddress::from_bytes([0xaa; 20]), vec![4, 5, 6], None)
            .await
            .unwrap();
        match outcome2 {
            RelayOutcome::Reverted(receipt) => {
                assert_eq!(receipt.block_number, 11);
                assert!(!receipt.status);
            }
            other => panic!("expected Reverted, got {other:?}"),
        }

        // Tx 3: times out while pending, then explicit reconcile resolves to Committed without resubmitting
        let timeout_err = relayer
            .submit_and_confirm(EvmAddress::from_bytes([0xaa; 20]), vec![7, 8, 9], None)
            .await
            .unwrap_err();
        let tx3_hash = match timeout_err {
            RelayError::ConfirmationTimedOut { tx_hash } => tx_hash,
            other => panic!("expected ConfirmationTimedOut, got {other:?}"),
        };
        assert_eq!(
            submitted_hashes.lock().await.len(),
            3,
            "timeout must not auto-resubmit"
        );
        // Release mock receipt so explicit reconcile resolves tx 3
        release_tx3.store(true, Ordering::SeqCst);
        let reconciled = relayer
            .reconcile_transaction(tx3_hash)
            .await
            .unwrap()
            .expect("reconciled receipt");
        match reconciled {
            RelayOutcome::Committed(receipt) => {
                assert_eq!(receipt.transaction_hash, tx3_hash);
                assert_eq!(receipt.block_number, 12);
            }
            other => panic!("expected Committed on reconcile, got {other:?}"),
        }

        server.abort();
    }
}
