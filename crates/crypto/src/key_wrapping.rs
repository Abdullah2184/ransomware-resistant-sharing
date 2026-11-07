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
        RecipientPublicKey::from_bytes(bytes)
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

    pub const fn public_key(&self) -> &HpkeRecipientPublicKey {
        &self.public_key
    }

    pub fn open_dek(
        &self,
        envelope: &KeyEnvelope,
        context: WrapContext,
    ) -> Result<DataEncryptionKey, CryptoError> {
        let encapped_key = RecipientEncappedKey::from_bytes(&envelope.encapsulated_key)
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
        let dek_bytes: [u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        Ok(DataEncryptionKey::from_secret(Zeroizing::new(dek_bytes)))
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
    }
}
