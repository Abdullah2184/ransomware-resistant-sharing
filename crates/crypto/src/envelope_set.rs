use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use domain::{EpochId, FileId, KeyVersion, MemberId, VersionNumber};
use serde::{Deserialize, Serialize};

use crate::{CryptoError, KeyEnvelope};

const SCHEMA: &str = "rrds.key-envelope-set.v1";
const WRAPPING_SUITE: &str = "HPKE-X25519-HKDF-SHA256-AES256GCM";
const ENCAPSULATED_KEY_BYTES: usize = 32;
const WRAPPED_DEK_BYTES: usize = 48;

/// Maximum number of distinct members represented in one immutable set.
pub const MAX_ENVELOPE_SET_ENTRIES: usize = 1024;

/// One recipient's wrapped DEK for a particular registered encryption-key version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyEnvelopeEntry {
    member_id: MemberId,
    encryption_key_version: KeyVersion,
    envelope: KeyEnvelope,
}

impl KeyEnvelopeEntry {
    pub fn new(
        member_id: MemberId,
        encryption_key_version: KeyVersion,
        envelope: KeyEnvelope,
    ) -> Self {
        Self {
            member_id,
            encryption_key_version,
            envelope,
        }
    }

    pub const fn member_id(&self) -> MemberId {
        self.member_id
    }

    pub const fn encryption_key_version(&self) -> KeyVersion {
        self.encryption_key_version
    }

    pub const fn envelope(&self) -> &KeyEnvelope {
        &self.envelope
    }
}

/// Canonical immutable envelope set for one file version and key epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyEnvelopeSet {
    file_id: FileId,
    version_number: VersionNumber,
    epoch_id: EpochId,
    revision: u32,
    envelopes: Vec<KeyEnvelopeEntry>,
}

impl KeyEnvelopeSet {
    pub fn new(
        file_id: FileId,
        version_number: VersionNumber,
        epoch_id: EpochId,
        revision: u32,
        envelopes: Vec<KeyEnvelopeEntry>,
    ) -> Result<Self, CryptoError> {
        let set = Self {
            file_id,
            version_number,
            epoch_id,
            revision,
            envelopes,
        };
        set.validate()?;
        Ok(set)
    }

    pub const fn file_id(&self) -> FileId {
        self.file_id
    }

    pub const fn version_number(&self) -> VersionNumber {
        self.version_number
    }

    pub const fn epoch_id(&self) -> EpochId {
        self.epoch_id
    }

    pub const fn revision(&self) -> u32 {
        self.revision
    }

    pub fn envelopes(&self) -> &[KeyEnvelopeEntry] {
        &self.envelopes
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        self.validate()?;
        serde_json::to_vec(&EnvelopeSetDto::from(self))
            .map_err(|_| CryptoError::EnvelopeSetEncodingFailed)
    }

    pub fn parse_canonical(bytes: &[u8]) -> Result<Self, CryptoError> {
        let dto: EnvelopeSetDto =
            serde_json::from_slice(bytes).map_err(|_| CryptoError::InvalidEnvelopeSet)?;
        let set = Self::try_from(dto)?;
        if set.canonical_bytes()?.as_slice() != bytes {
            return Err(CryptoError::InvalidEnvelopeSet);
        }
        Ok(set)
    }

    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.revision == 0 || self.envelopes.len() > MAX_ENVELOPE_SET_ENTRIES {
            return Err(CryptoError::InvalidEnvelopeSet);
        }

        let mut previous_member = None;
        for entry in &self.envelopes {
            if previous_member.is_some_and(|previous| previous >= entry.member_id) {
                return Err(CryptoError::InvalidEnvelopeSet);
            }
            if entry.envelope.encapsulated_key().len() != ENCAPSULATED_KEY_BYTES
                || entry.envelope.ciphertext().len() != WRAPPED_DEK_BYTES
            {
                return Err(CryptoError::InvalidEnvelopeSet);
            }
            previous_member = Some(entry.member_id);
        }

        Ok(())
    }
}

impl TryFrom<EnvelopeSetDto> for KeyEnvelopeSet {
    type Error = CryptoError;

    fn try_from(dto: EnvelopeSetDto) -> Result<Self, Self::Error> {
        if dto.schema != SCHEMA || dto.wrapping_suite != WRAPPING_SUITE {
            return Err(CryptoError::InvalidEnvelopeSet);
        }
        if dto.envelopes.len() > MAX_ENVELOPE_SET_ENTRIES {
            return Err(CryptoError::InvalidEnvelopeSet);
        }
        let envelopes = dto
            .envelopes
            .into_iter()
            .map(|entry| {
                let member_id = MemberId::from_bytes(parse_bytes32(&entry.member_id)?);
                let encryption_key_version = KeyVersion::new(entry.encryption_key_version)
                    .map_err(|_| CryptoError::InvalidEnvelopeSet)?;
                let encapsulated_key =
                    decode_fixed::<ENCAPSULATED_KEY_BYTES>(&entry.encapsulated_key)?;
                let wrapped_dek = decode_fixed::<WRAPPED_DEK_BYTES>(&entry.wrapped_dek)?;
                let envelope = KeyEnvelope::from_parts(encapsulated_key, wrapped_dek)?;
                Ok(KeyEnvelopeEntry::new(
                    member_id,
                    encryption_key_version,
                    envelope,
                ))
            })
            .collect::<Result<Vec<_>, CryptoError>>()?;

        Self::new(
            FileId::from_bytes(parse_bytes32(&dto.file_id)?),
            VersionNumber::new(dto.version_number).map_err(|_| CryptoError::InvalidEnvelopeSet)?,
            EpochId::from_bytes(parse_bytes32(&dto.epoch_id)?),
            dto.revision,
            envelopes,
        )
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeSetDto {
    schema: String,
    #[serde(rename = "fileId")]
    file_id: String,
    #[serde(rename = "versionNumber")]
    version_number: u64,
    #[serde(rename = "epochId")]
    epoch_id: String,
    #[serde(rename = "wrappingSuite")]
    wrapping_suite: String,
    revision: u32,
    envelopes: Vec<EnvelopeEntryDto>,
}

impl From<&KeyEnvelopeSet> for EnvelopeSetDto {
    fn from(set: &KeyEnvelopeSet) -> Self {
        Self {
            schema: SCHEMA.to_owned(),
            file_id: set.file_id.to_string(),
            version_number: set.version_number.get(),
            epoch_id: set.epoch_id.to_string(),
            wrapping_suite: WRAPPING_SUITE.to_owned(),
            revision: set.revision,
            envelopes: set
                .envelopes
                .iter()
                .map(|entry| EnvelopeEntryDto {
                    member_id: entry.member_id.to_string(),
                    encryption_key_version: entry.encryption_key_version.get(),
                    encapsulated_key: URL_SAFE_NO_PAD.encode(entry.envelope.encapsulated_key()),
                    wrapped_dek: URL_SAFE_NO_PAD.encode(entry.envelope.ciphertext()),
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeEntryDto {
    #[serde(rename = "memberId")]
    member_id: String,
    #[serde(rename = "encryptionKeyVersion")]
    encryption_key_version: u32,
    #[serde(rename = "encapsulatedKey")]
    encapsulated_key: String,
    #[serde(rename = "wrappedDek")]
    wrapped_dek: String,
}

fn parse_bytes32(value: &str) -> Result<[u8; 32], CryptoError> {
    let bytes = value
        .strip_prefix("0x")
        .filter(|value| value.len() == 64)
        .ok_or(CryptoError::InvalidEnvelopeSet)?;
    let mut output = [0; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&bytes[start..start + 2], 16)
            .map_err(|_| CryptoError::InvalidEnvelopeSet)?;
    }
    Ok(output)
}

fn decode_fixed<const N: usize>(value: &str) -> Result<Vec<u8>, CryptoError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CryptoError::InvalidEnvelopeSet)?;
    if bytes.len() != N || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(CryptoError::InvalidEnvelopeSet);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DataEncryptionKey, HpkeRecipientKeyPair, WrapContext};

    fn envelope(fill: u8) -> KeyEnvelope {
        KeyEnvelope::from_parts(
            vec![fill; ENCAPSULATED_KEY_BYTES],
            vec![fill; WRAPPED_DEK_BYTES],
        )
        .unwrap()
    }

    fn entry(member: u8) -> KeyEnvelopeEntry {
        KeyEnvelopeEntry::new(
            MemberId::from_bytes([member; 32]),
            KeyVersion::new(1).unwrap(),
            envelope(member),
        )
    }

    fn set(entries: Vec<KeyEnvelopeEntry>) -> Result<KeyEnvelopeSet, CryptoError> {
        KeyEnvelopeSet::new(
            FileId::from_bytes([1; 32]),
            VersionNumber::new(3).unwrap(),
            EpochId::from_bytes([2; 32]),
            1,
            entries,
        )
    }

    #[test]
    fn canonical_envelope_set_round_trips_without_plaintext_key_fields() {
        let set = set(vec![entry(1), entry(2)]).unwrap();
        let bytes = set.canonical_bytes().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();

        assert_eq!(KeyEnvelopeSet::parse_canonical(&bytes).unwrap(), set);
        assert!(text.contains("\"wrappingSuite\":\"HPKE-X25519-HKDF-SHA256-AES256GCM\""));
        assert!(text.contains("\"encryptionKeyVersion\":1"));
        assert!(!text.contains("privateKey"));
        assert!(!text.contains("\"dek\""));
    }

    #[test]
    fn serialized_recipient_envelope_can_be_unwrapped_after_parse() {
        let recipient = HpkeRecipientKeyPair::generate().unwrap();
        let member_id = MemberId::from_bytes([7; 32]);
        let key_version = KeyVersion::new(2).unwrap();
        let file_id = FileId::from_bytes([1; 32]);
        let version_number = VersionNumber::new(3).unwrap();
        let epoch_id = EpochId::from_bytes([2; 32]);
        let context = WrapContext::new(file_id, version_number, epoch_id, member_id, key_version);
        let dek = DataEncryptionKey::from_secret(zeroize::Zeroizing::new([0x42; 32]));
        let wrapped = KeyEnvelope::wrap(&dek, recipient.public_key(), context).unwrap();
        let set = KeyEnvelopeSet::new(
            file_id,
            version_number,
            epoch_id,
            1,
            vec![KeyEnvelopeEntry::new(member_id, key_version, wrapped)],
        )
        .unwrap();
        let bytes = set.canonical_bytes().unwrap();
        let parsed = KeyEnvelopeSet::parse_canonical(&bytes).unwrap();

        let unwrapped = recipient
            .open_dek(parsed.envelopes()[0].envelope(), context)
            .unwrap();
        assert_eq!(unwrapped.expose_bytes(), &[0x42; 32]);
    }

    #[test]
    fn rejects_unsorted_or_duplicate_member_entries() {
        assert_eq!(
            set(vec![entry(2), entry(1)]),
            Err(CryptoError::InvalidEnvelopeSet)
        );
        assert_eq!(
            set(vec![entry(1), entry(1)]),
            Err(CryptoError::InvalidEnvelopeSet)
        );
    }

    #[test]
    fn accepts_the_approved_maximum_and_rejects_one_more_entry() {
        let maximum_entries = (1..=u8::MAX)
            .chain(std::iter::repeat_n(0, MAX_ENVELOPE_SET_ENTRIES - 255))
            .enumerate()
            .map(|(index, _)| {
                let mut member_id = [0; 32];
                member_id[30..].copy_from_slice(&u16::try_from(index + 1).unwrap().to_be_bytes());
                KeyEnvelopeEntry::new(
                    MemberId::from_bytes(member_id),
                    KeyVersion::new(1).unwrap(),
                    envelope(u8::try_from(index % 255 + 1).unwrap()),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(maximum_entries.len(), MAX_ENVELOPE_SET_ENTRIES);
        assert!(set(maximum_entries.clone()).is_ok());

        let mut too_many = maximum_entries;
        let mut last_member = [0; 32];
        last_member[30..].copy_from_slice(
            &u16::try_from(MAX_ENVELOPE_SET_ENTRIES + 1)
                .unwrap()
                .to_be_bytes(),
        );
        too_many.push(KeyEnvelopeEntry::new(
            MemberId::from_bytes(last_member),
            KeyVersion::new(1).unwrap(),
            envelope(1),
        ));
        assert_eq!(set(too_many), Err(CryptoError::InvalidEnvelopeSet));
    }

    #[test]
    fn rejects_noncanonical_json_wrong_suite_revision_and_malformed_bytes() {
        let canonical = set(vec![entry(1)]).unwrap().canonical_bytes().unwrap();
        let with_whitespace = [b" ".as_slice(), canonical.as_slice()].concat();
        assert_eq!(
            KeyEnvelopeSet::parse_canonical(&with_whitespace),
            Err(CryptoError::InvalidEnvelopeSet)
        );

        let mut dto: EnvelopeSetDto = serde_json::from_slice(&canonical).unwrap();
        dto.wrapping_suite = "unsupported".to_owned();
        assert_eq!(
            KeyEnvelopeSet::try_from(dto),
            Err(CryptoError::InvalidEnvelopeSet)
        );

        let mut dto: EnvelopeSetDto = serde_json::from_slice(&canonical).unwrap();
        dto.revision = 0;
        assert_eq!(
            KeyEnvelopeSet::try_from(dto),
            Err(CryptoError::InvalidEnvelopeSet)
        );

        let mut dto: EnvelopeSetDto = serde_json::from_slice(&canonical).unwrap();
        dto.envelopes[0].wrapped_dek.push('=');
        assert_eq!(
            KeyEnvelopeSet::try_from(dto),
            Err(CryptoError::InvalidEnvelopeSet)
        );
    }
}
