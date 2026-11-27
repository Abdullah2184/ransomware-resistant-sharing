use std::{convert::Infallible, fmt};

use domain::{EpochId, FileId, KeyVersion, MemberId, VersionNumber};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    rand_core::{TryCryptoRng, TryRng},
};
use zeroize::{Zeroize, Zeroizing};

use crate::{CryptoError, DataEncryptionKey};

const HPKE_INFO: &[u8] = b"rrds/key-wrap/v1";
const HPKE_CONTEXT_DOMAIN: &[u8] = b"rrds/key-wrap-context/v1";
const RANDOM_SEED_BYTES: usize = 32;
const ENCAPSULATED_KEY_BYTES: usize = 32;
const DEK_CIPHERTEXT_BYTES: usize = 32 + 16;

/// Canonical masked (bit 255 cleared) representations of RFC 7748 §6.1
/// low-order Curve25519 points that produce an all-zero DH shared secret.
const X25519_LOW_ORDER_MASKED: [[u8; 32]; 7] = [
    [0x00; 32],
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

fn is_low_order_x25519(bytes: &[u8; 32]) -> bool {
    let mut masked = *bytes;
    masked[31] &= 0x7f;
    X25519_LOW_ORDER_MASKED.contains(&masked)
}

type RecipientKem = X25519HkdfSha256;
type RecipientPublicKey = <RecipientKem as KemTrait>::PublicKey;
type RecipientPrivateKey = <RecipientKem as KemTrait>::PrivateKey;
type RecipientEncappedKey = <RecipientKem as KemTrait>::EncappedKey;
type HpkeAead = AesGcm256;
type HpkeKdf = HkdfSha256;

/// Authenticated context for wrapping one version key to one recipient key version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WrapContext {
    file_id: FileId,
    version_number: VersionNumber,
    epoch_id: EpochId,
    recipient_member_id: MemberId,
    recipient_key_version: KeyVersion,
}

impl WrapContext {
    pub const fn new(
        file_id: FileId,
        version_number: VersionNumber,
        epoch_id: EpochId,
        recipient_member_id: MemberId,
        recipient_key_version: KeyVersion,
    ) -> Self {
        Self {
            file_id,
            version_number,
            epoch_id,
            recipient_member_id,
            recipient_key_version,
        }
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

    pub const fn recipient_member_id(&self) -> MemberId {
        self.recipient_member_id
    }

    pub const fn recipient_key_version(&self) -> KeyVersion {
        self.recipient_key_version
    }

    fn validate(&self) -> Result<(), CryptoError> {
        if self.file_id.as_bytes() == &[0; 32]
            || self.epoch_id.as_bytes() == &[0; 32]
            || self.recipient_member_id.as_bytes() == &[0; 32]
        {
            return Err(CryptoError::InvalidEnvelope);
        }
        Ok(())
    }

    fn associated_data(self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(HPKE_CONTEXT_DOMAIN.len() + 32 + 8 + 32 + 32 + 4);
        aad.extend_from_slice(HPKE_CONTEXT_DOMAIN);
        aad.extend_from_slice(self.file_id.as_bytes());
        aad.extend_from_slice(&self.version_number.get().to_be_bytes());
        aad.extend_from_slice(self.epoch_id.as_bytes());
        aad.extend_from_slice(self.recipient_member_id.as_bytes());
        aad.extend_from_slice(&self.recipient_key_version.get().to_be_bytes());
        aad
    }
}

/// Public X25519 key used for HPKE recipient encryption.
#[derive(Clone, Eq, PartialEq)]
pub struct HpkeRecipientPublicKey(RecipientPublicKey);

impl HpkeRecipientPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let raw: &[u8; 32] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidRecipientPublicKey)?;
        if is_low_order_x25519(raw) {
            return Err(CryptoError::InvalidRecipientPublicKey);
        }
        RecipientPublicKey::from_bytes(raw)
            .map(Self)
            .map_err(|_| CryptoError::InvalidRecipientPublicKey)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}

impl fmt::Debug for HpkeRecipientPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("HpkeRecipientPublicKey")
            .field(&"X25519 public key")
            .finish()
    }
}

/// Local HPKE recipient keypair.
///
/// This concrete software key type is suitable for tests and development only.
/// Production decryption should be delegated to `KeyCustodyProvider` rather
/// than loading long-term private key bytes into application code.
pub struct HpkeRecipientKeyPair {
    private_key: RecipientPrivateKey,
    public_key: HpkeRecipientPublicKey,
}

impl HpkeRecipientKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut rng = SystemEntropyRng::new()?;
        let (private_key, public_key) = RecipientKem::gen_keypair_with_rng(&mut rng);
        Ok(Self {
            private_key,
            public_key: HpkeRecipientPublicKey(public_key),
        })
    }

    /// Deterministically derives an X25519 keypair from a 32-byte seed for
    /// local development and testing only. Never use in production.
    pub fn derive_from_seed(seed: &[u8; 32]) -> Result<Self, CryptoError> {
        if seed == &[0u8; 32] {
            return Err(CryptoError::InvalidRecipientPublicKey);
        }
        let (private_key, public_key) = RecipientKem::derive_keypair(seed);
        Ok(Self {
            private_key,
            public_key: HpkeRecipientPublicKey(public_key),
        })
    }

    pub const fn public_key(&self) -> &HpkeRecipientPublicKey {
        &self.public_key
    }

    pub fn open_dek(
        &self,
        envelope: &KeyEnvelope,
        context: WrapContext,
    ) -> Result<DataEncryptionKey, CryptoError> {
        context.validate()?;
        let enc_bytes: &[u8; 32] = envelope
            .encapsulated_key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        if is_low_order_x25519(enc_bytes) {
            return Err(CryptoError::InvalidEnvelope);
        }
        let encapped_key = RecipientEncappedKey::from_bytes(enc_bytes)
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        let mut receiver_context = hpke::setup_receiver::<HpkeAead, HpkeKdf, RecipientKem>(
            &OpModeR::Base,
            &self.private_key,
            &encapped_key,
            HPKE_INFO,
        )
        .map_err(|_| CryptoError::InvalidEnvelope)?;
        let plaintext = Zeroizing::new(
            receiver_context
                .open(&envelope.ciphertext, &context.associated_data())
                .map_err(|_| CryptoError::AuthenticationFailed)?,
        );
        if plaintext.len() != 32 {
            return Err(CryptoError::InvalidEnvelope);
        }
        let mut dek_bytes = Zeroizing::new([0u8; 32]);
        dek_bytes.copy_from_slice(&plaintext);
        Ok(DataEncryptionKey::from_secret(dek_bytes))
    }
}

impl fmt::Debug for HpkeRecipientKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HpkeRecipientKeyPair")
            .field("private_key", &"[REDACTED]")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// The encapsulated key and ciphertext components for a 32-byte DEK envelope.
#[derive(Clone, Eq, PartialEq)]
pub struct KeyEnvelope {
    encapsulated_key: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl KeyEnvelope {
    pub fn from_parts(encapsulated_key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Self, CryptoError> {
        if encapsulated_key.len() != ENCAPSULATED_KEY_BYTES
            || ciphertext.len() != DEK_CIPHERTEXT_BYTES
        {
            return Err(CryptoError::InvalidEnvelope);
        }
        Ok(Self {
            encapsulated_key,
            ciphertext,
        })
    }

    pub fn wrap(
        dek: &DataEncryptionKey,
        recipient: &HpkeRecipientPublicKey,
        context: WrapContext,
    ) -> Result<Self, CryptoError> {
        context.validate()?;
        let mut rng = SystemEntropyRng::new()?;
        let (encapped_key, mut sender_context) =
            hpke::setup_sender_with_rng::<HpkeAead, HpkeKdf, RecipientKem>(
                &OpModeS::Base,
                &recipient.0,
                HPKE_INFO,
                &mut rng,
            )
            .map_err(|_| CryptoError::HpkeOperationFailed)?;
        let ciphertext = sender_context
            .seal(dek.expose_bytes(), &context.associated_data())
            .map_err(|_| CryptoError::HpkeOperationFailed)?;

        Self::from_parts(encapped_key.to_bytes().to_vec(), ciphertext)
    }

    pub fn encapsulated_key(&self) -> &[u8] {
        &self.encapsulated_key
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl fmt::Debug for KeyEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyEnvelope")
            .field("encapsulated_key_bytes", &self.encapsulated_key.len())
            .field("ciphertext_bytes", &self.ciphertext.len())
            .finish()
    }
}

/// One-operation entropy source for HPKE's X25519 key generation.
///
/// The pinned X25519 KEM requests exactly one 32-byte seed. Any incompatible
/// future change fails loudly rather than falling back to predictable bytes.
struct SystemEntropyRng {
    seed: Zeroizing<[u8; RANDOM_SEED_BYTES]>,
    offset: usize,
}

impl SystemEntropyRng {
    fn new() -> Result<Self, CryptoError> {
        let mut seed = Zeroizing::new([0; RANDOM_SEED_BYTES]);
        getrandom::fill(&mut seed[..]).map_err(|_| CryptoError::RandomnessUnavailable)?;
        Ok(Self { seed, offset: 0 })
    }

    fn fill_from_seed(&mut self, destination: &mut [u8]) {
        let end = self
            .offset
            .checked_add(destination.len())
            .filter(|end| *end <= self.seed.len())
            .expect("pinned HPKE X25519 KEM requested unexpected random bytes");
        destination.copy_from_slice(&self.seed[self.offset..end]);
        self.seed[self.offset..end].zeroize();
        self.offset = end;
    }
}

impl TryRng for SystemEntropyRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0; 4];
        self.fill_from_seed(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0; 8];
        self.fill_from_seed(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        self.fill_from_seed(destination);
        Ok(())
    }
}

impl TryCryptoRng for SystemEntropyRng {}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(file: u8, version: u64, epoch: u8, member: u8, key_version: u32) -> WrapContext {
        WrapContext::new(
            FileId::from_bytes([file; 32]),
            VersionNumber::new(version).unwrap(),
            EpochId::from_bytes([epoch; 32]),
            MemberId::from_bytes([member; 32]),
            KeyVersion::new(key_version).unwrap(),
        )
    }

    fn dek() -> DataEncryptionKey {
        DataEncryptionKey::from_secret(Zeroizing::new([0x42; 32]))
    }

    #[test]
    fn hpke_wrap_unwrap_round_trip_uses_a_32_byte_dek() {
        let recipient = HpkeRecipientKeyPair::generate().unwrap();
        let context = context(1, 3, 5, 7, 2);
        let envelope = KeyEnvelope::wrap(&dek(), recipient.public_key(), context).unwrap();
        let unwrapped = recipient.open_dek(&envelope, context).unwrap();

        assert_eq!(unwrapped.expose_bytes(), &[0x42; 32]);
        assert_eq!(envelope.encapsulated_key().len(), ENCAPSULATED_KEY_BYTES);
        assert_eq!(envelope.ciphertext().len(), DEK_CIPHERTEXT_BYTES);
    }

    #[test]
    fn rejects_wrong_recipient_and_modified_ciphertext() {
        let recipient = HpkeRecipientKeyPair::generate().unwrap();
        let other_recipient = HpkeRecipientKeyPair::generate().unwrap();
        let context = context(1, 3, 5, 7, 2);
        let envelope = KeyEnvelope::wrap(&dek(), recipient.public_key(), context).unwrap();

        assert!(matches!(
            other_recipient.open_dek(&envelope, context),
            Err(CryptoError::AuthenticationFailed)
        ));

        let mut altered = envelope.clone();
        altered.ciphertext[0] ^= 1;
        assert!(matches!(
            recipient.open_dek(&altered, context),
            Err(CryptoError::AuthenticationFailed)
        ));

        let mut altered = envelope;
        altered.encapsulated_key[0] ^= 1;
        assert!(matches!(
            recipient.open_dek(&altered, context),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn rejects_context_changes_to_file_version_epoch_member_or_key_version() {
        let recipient = HpkeRecipientKeyPair::generate().unwrap();
        let original = context(1, 3, 5, 7, 2);
        let envelope = KeyEnvelope::wrap(&dek(), recipient.public_key(), original).unwrap();

        for altered in [
            context(8, 3, 5, 7, 2),
            context(1, 4, 5, 7, 2),
            context(1, 3, 6, 7, 2),
            context(1, 3, 5, 8, 2),
            context(1, 3, 5, 7, 3),
        ] {
            assert!(matches!(
                recipient.open_dek(&envelope, altered),
                Err(CryptoError::AuthenticationFailed)
            ));
        }
    }

    #[test]
    fn rejects_malformed_recipient_keys_and_envelopes() {
        assert_eq!(
            HpkeRecipientPublicKey::from_bytes(&[0; 31]).unwrap_err(),
            CryptoError::InvalidRecipientPublicKey
        );
        assert_eq!(
            KeyEnvelope::from_parts(vec![0; 31], vec![0; DEK_CIPHERTEXT_BYTES]),
            Err(CryptoError::InvalidEnvelope)
        );
        assert_eq!(
            KeyEnvelope::from_parts(
                vec![0; ENCAPSULATED_KEY_BYTES],
                vec![0; DEK_CIPHERTEXT_BYTES - 1]
            ),
            Err(CryptoError::InvalidEnvelope)
        );

        // All RFC 7748 §6.1 low-order X25519 points (both bit-255=0 and bit-255=1)
        // must be rejected at key parsing and as encapsulated keys during unwrap.
        let recipient = HpkeRecipientKeyPair::generate().unwrap();
        let valid_ctx = context(1, 1, 2, 3, 1);
        for low_order in X25519_LOW_ORDER_MASKED {
            assert_eq!(
                HpkeRecipientPublicKey::from_bytes(&low_order).unwrap_err(),
                CryptoError::InvalidRecipientPublicKey
            );
            let mut high_bit = low_order;
            high_bit[31] |= 0x80;
            assert_eq!(
                HpkeRecipientPublicKey::from_bytes(&high_bit).unwrap_err(),
                CryptoError::InvalidRecipientPublicKey
            );

            let forged_env =
                KeyEnvelope::from_parts(low_order.to_vec(), vec![0xaa; DEK_CIPHERTEXT_BYTES])
                    .unwrap();
            assert_eq!(
                recipient.open_dek(&forged_env, valid_ctx).err(),
                Some(CryptoError::InvalidEnvelope)
            );
        }

        // Zero file_id, epoch_id, or recipient_member_id rejected on wrap and open.
        let valid_env = KeyEnvelope::wrap(&dek(), recipient.public_key(), valid_ctx).unwrap();
        for bad_ctx in [
            context(0, 1, 2, 3, 1),
            context(1, 1, 0, 3, 1),
            context(1, 1, 2, 0, 1),
        ] {
            assert_eq!(
                KeyEnvelope::wrap(&dek(), recipient.public_key(), bad_ctx),
                Err(CryptoError::InvalidEnvelope)
            );
            assert_eq!(
                recipient.open_dek(&valid_env, bad_ctx).err(),
                Some(CryptoError::InvalidEnvelope)
            );
        }

        // 1-bit flip in the trailing GCM tag byte of wrappedDek fails authentication.
        let mut bad_tag = valid_env;
        *bad_tag.ciphertext.last_mut().unwrap() ^= 0x01;
        assert_eq!(
            recipient.open_dek(&bad_tag, valid_ctx).err(),
            Some(CryptoError::AuthenticationFailed)
        );
    }

    fn decode_hex_str(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0);
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn matches_rfc9180_and_cross_implementation_openssl_hpke_vectors() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/hpke-rfc9180-v1.json"))
                .unwrap();

        // 1. Official RFC 9180 Base mode (X25519 / HKDF-SHA256 / AES-256-GCM) vector
        let rfc = &fixture["rfc9180BaseVector"];
        let ikm_r: [u8; 32] = decode_hex_str(rfc["ikmR"].as_str().unwrap())
            .try_into()
            .unwrap();
        let expected_pk_r = decode_hex_str(rfc["pkRm"].as_str().unwrap());
        let recipient = HpkeRecipientKeyPair::derive_from_seed(&ikm_r).unwrap();
        assert_eq!(recipient.public_key().to_bytes(), expected_pk_r);

        let enc = RecipientEncappedKey::from_bytes(&decode_hex_str(rfc["enc"].as_str().unwrap()))
            .unwrap();
        let mut receiver = hpke::setup_receiver::<HpkeAead, HpkeKdf, RecipientKem>(
            &OpModeR::Base,
            &recipient.private_key,
            &enc,
            rfc["info"].as_str().unwrap().as_bytes(),
        )
        .unwrap();
        let opened = receiver
            .open(
                &decode_hex_str(rfc["ciphertext"].as_str().unwrap()),
                rfc["aad"].as_str().unwrap().as_bytes(),
            )
            .unwrap();
        assert_eq!(opened, rfc["plaintext"].as_str().unwrap().as_bytes());

        // 2. Cross-implementation OpenSSL -> Rust RRDS KeyEnvelope vector
        let rrds = &fixture["rrdsDekWrapCrossImplVector"];
        let rrds_ikm_r: [u8; 32] = decode_hex_str(rrds["ikmR"].as_str().unwrap())
            .try_into()
            .unwrap();
        let rrds_recipient = HpkeRecipientKeyPair::derive_from_seed(&rrds_ikm_r).unwrap();
        assert_eq!(
            rrds_recipient.public_key().to_bytes(),
            decode_hex_str(rrds["pkRm"].as_str().unwrap())
        );

        let envelope = KeyEnvelope::from_parts(
            decode_hex_str(rrds["enc"].as_str().unwrap()),
            decode_hex_str(rrds["ciphertext"].as_str().unwrap()),
        )
        .unwrap();
        let wrap_ctx = WrapContext::new(
            FileId::from_bytes([rrds["fileIdByte"].as_u64().unwrap() as u8; 32]),
            VersionNumber::new(rrds["versionNumber"].as_u64().unwrap()).unwrap(),
            EpochId::from_bytes([rrds["epochIdByte"].as_u64().unwrap() as u8; 32]),
            MemberId::from_bytes([rrds["memberIdByte"].as_u64().unwrap() as u8; 32]),
            KeyVersion::new(rrds["keyVersion"].as_u64().unwrap() as u32).unwrap(),
        );
        let unwrapped_dek = rrds_recipient.open_dek(&envelope, wrap_ctx).unwrap();
        assert_eq!(
            unwrapped_dek.expose_bytes(),
            &[rrds["dekByte"].as_u64().unwrap() as u8; 32]
        );
    }
}
