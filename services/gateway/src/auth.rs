use std::fmt;

use domain::{EvmAddress, MemberId};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const LOGIN_CHALLENGE_TYPE: &str = "LoginChallenge(bytes32 memberId,bytes32 nonce,uint64 issuedAt,uint64 expiresAt,string audience,uint32 protocolVersion)";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct LoginChallenge {
    pub member_id: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub audience: String,
    pub protocol_version: u32,
}

#[derive(Debug)]
pub enum AuthInputError {
    MemberId,
    Nonce,
    Signature,
}

impl fmt::Display for AuthInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::MemberId => "invalid member identifier",
            Self::Nonce => "invalid challenge nonce",
            Self::Signature => "invalid challenge signature",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AuthInputError {}

pub fn parse_member_id(value: &str) -> Result<MemberId, AuthInputError> {
    let bytes = parse_fixed_hex::<32>(value).ok_or(AuthInputError::MemberId)?;
    if bytes == [0; 32] || value != value.to_ascii_lowercase() {
        return Err(AuthInputError::MemberId);
    }
    Ok(MemberId::from_bytes(bytes))
}

pub fn parse_nonce(value: &str) -> Result<[u8; 32], AuthInputError> {
    let nonce = parse_fixed_hex(value).ok_or(AuthInputError::Nonce)?;
    if nonce == [0; 32] {
        return Err(AuthInputError::Nonce);
    }
    Ok(nonce)
}

pub fn challenge_digest(
    challenge: &LoginChallenge,
    chain_id: u64,
    verifying_contract: EvmAddress,
) -> Result<[u8; 32], AuthInputError> {
    let member_id = parse_member_id(&challenge.member_id)?;
    let nonce = parse_nonce(&challenge.nonce)?;

    let domain_separator = struct_hash(
        DOMAIN_TYPE,
        &[
            keccak(b"RRDS Gateway"),
            keccak(b"1"),
            uint_word_u64(chain_id),
            address_word(verifying_contract),
        ],
    );
    let challenge_hash = struct_hash(
        LOGIN_CHALLENGE_TYPE,
        &[
            member_id.into_bytes(),
            nonce,
            uint_word_u64(challenge.issued_at),
            uint_word_u64(challenge.expires_at),
            keccak(challenge.audience.as_bytes()),
            uint_word_u32(challenge.protocol_version),
        ],
    );
    let mut encoded = Vec::with_capacity(66);
    encoded.extend_from_slice(b"\x19\x01");
    encoded.extend_from_slice(&domain_separator);
    encoded.extend_from_slice(&challenge_hash);
    Ok(keccak(&encoded))
}

pub fn recover_signer(digest: &[u8; 32], signature: &str) -> Result<EvmAddress, AuthInputError> {
    let bytes = parse_fixed_hex::<65>(signature).ok_or(AuthInputError::Signature)?;
    if !matches!(bytes[64], 27 | 28) {
        return Err(AuthInputError::Signature);
    }
    let signature = Signature::from_slice(&bytes[..64]).map_err(|_| AuthInputError::Signature)?;
    if signature.normalize_s().is_some() {
        return Err(AuthInputError::Signature);
    }
    let recovery_id = RecoveryId::from_byte(bytes[64] - 27).ok_or(AuthInputError::Signature)?;
    let verifying_key = VerifyingKey::recover_from_prehash(digest, &signature, recovery_id)
        .map_err(|_| AuthInputError::Signature)?;
    let encoded = verifying_key.to_encoded_point(false);
    let public_key = encoded.as_bytes();
    let hash = keccak(&public_key[1..]);
    let mut address = [0; 20];
    address.copy_from_slice(&hash[12..]);
    Ok(EvmAddress::from_bytes(address))
}

pub fn parse_fixed_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    let value = value.strip_prefix("0x")?;
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut output = [0; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16).ok()?;
    }
    Some(output)
}

fn struct_hash(type_name: &str, fields: &[[u8; 32]]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(32 * (fields.len() + 1));
    encoded.extend_from_slice(&keccak(type_name.as_bytes()));
    for field in fields {
        encoded.extend_from_slice(field);
    }
    keccak(&encoded)
}

fn uint_word_u64(value: u64) -> [u8; 32] {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn uint_word_u32(value: u32) -> [u8; 32] {
    let mut word = [0; 32];
    word[28..].copy_from_slice(&value.to_be_bytes());
    word
}

fn address_word(address: EvmAddress) -> [u8; 32] {
    let mut word = [0; 32];
    word[12..].copy_from_slice(address.as_bytes());
    word
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    let digest = Keccak256::digest(bytes);
    let mut output = [0; 32];
    output.copy_from_slice(&digest);
    output
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::SigningKey;

    use super::*;

    fn challenge() -> LoginChallenge {
        LoginChallenge {
            member_id: format!("0x{}", "11".repeat(32)),
            nonce: format!("0x{}", "22".repeat(32)),
            issued_at: 1_800_000_000,
            expires_at: 1_800_000_120,
            audience: "rrds-local".to_owned(),
            protocol_version: 1,
        }
    }

    #[test]
    fn challenge_signature_recovers_the_signing_address() {
        let signing_key = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
        let contract = EvmAddress::from_bytes([0x33; 20]);
        let digest = challenge_digest(&challenge(), 1337, contract).unwrap();
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
        let mut bytes = [0; 65];
        bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
        bytes[64] = u8::from(recovery_id) + 27;
        let signature = format!("0x{}", encode_hex(&bytes));

        assert_eq!(
            recover_signer(&digest, &signature).unwrap(),
            address_from_key(&signing_key)
        );
    }

    #[test]
    fn challenge_digest_binds_audience_chain_contract_and_nonce() {
        let challenge = challenge();
        let contract = EvmAddress::from_bytes([0x33; 20]);
        let digest = challenge_digest(&challenge, 1337, contract).unwrap();
        let mut other_audience = challenge.clone();
        other_audience.audience.push_str("-other");
        let mut other_nonce = challenge.clone();
        other_nonce.nonce = format!("0x{}", "23".repeat(32));

        assert_ne!(
            digest,
            challenge_digest(&other_audience, 1337, contract).unwrap()
        );
        assert_ne!(
            digest,
            challenge_digest(&challenge, 1338, contract).unwrap()
        );
        assert_ne!(
            digest,
            challenge_digest(&challenge, 1337, EvmAddress::from_bytes([0x34; 20])).unwrap()
        );
        assert_ne!(
            digest,
            challenge_digest(&other_nonce, 1337, contract).unwrap()
        );
    }

    #[test]
    fn challenge_digest_matches_the_shared_typed_data_fixture() {
        let digest =
            challenge_digest(&challenge(), 1337, EvmAddress::from_bytes([0x33; 20])).unwrap();
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/eip712-v1.json")).unwrap();
        assert_eq!(
            format!("0x{}", encode_hex(&digest)),
            fixture["loginChallenge"].as_str().unwrap()
        );
    }

    #[test]
    fn rejects_noncanonical_identifiers_and_malleable_signatures() {
        assert!(parse_member_id(&format!("0X{}", "11".repeat(32))).is_err());
        assert!(parse_member_id(&format!("0x{}", "00".repeat(32))).is_err());
        assert!(parse_nonce("0x00").is_err());
        assert!(recover_signer(&[0; 32], "0x0000").is_err());
    }

    fn address_from_key(key: &SigningKey) -> EvmAddress {
        let point = key.verifying_key().to_encoded_point(false);
        let hash = keccak(&point.as_bytes()[1..]);
        let mut address = [0; 20];
        address.copy_from_slice(&hash[12..]);
        EvmAddress::from_bytes(address)
    }

    fn encode_hex(bytes: &[u8]) -> String {
        let mut value = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(value, "{byte:02x}").unwrap();
        }
        value
    }
}
