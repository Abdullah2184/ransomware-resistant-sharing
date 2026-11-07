//! Key custody adapters. The development adapter is not suitable for production.

use std::fmt;

use crypto::{HpkeRecipientKeyPair, TypedDigest};
use domain::{EvmAddress, KeyVersion, MemberId};
use k256::ecdsa::{SigningKey, VerifyingKey};
use ports::{
    CustodyCapabilities, CustodyError, CustodyFuture, CustodyHealth, EvmSignature,
    KeyCustodyProvider, KeyId, PublicIdentityKeys,
};
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

/// Software-held ECDSA and HPKE keys for local development and tests only.
///
/// The private keys reside in process memory and are not protected by an HSM.
/// The capability report marks this provider `test_only` and reports that
/// private keys are exportable. Production startup must reject this provider.
pub struct DevelopmentKeyCustody {
    identity: PublicIdentityKeys,
    signing_key: SigningKey,
    encryption_key: HpkeRecipientKeyPair,
}

impl DevelopmentKeyCustody {
    pub fn generate(
        member_id: MemberId,
        signing_key_version: KeyVersion,
        encryption_key_version: KeyVersion,
    ) -> Result<Self, CustodyError> {
        let signing_key = generate_signing_key()?;
        let signing_key_id = generate_key_id()?;
        let mut encryption_key_id = generate_key_id()?;
        while encryption_key_id == signing_key_id {
            encryption_key_id = generate_key_id()?;
        }
        let encryption_key =
            HpkeRecipientKeyPair::generate().map_err(|_| CustodyError::KeyGenerationFailed)?;
        let signing_address = evm_address(signing_key.verifying_key());

        let identity = PublicIdentityKeys {
            member_id,
            signing_key_id,
            signing_key_version,
            signing_address,
            encryption_key_id,
            encryption_key_version,
            encryption_public_key: encryption_key.public_key().clone(),
        };

        Ok(Self {
            identity,
            signing_key,
            encryption_key,
        })
    }

    fn sign(&self, digest: &TypedDigest) -> Result<EvmSignature, CustodyError> {
        let (signature, recovery_id) = self
            .signing_key
            .sign_prehash_recoverable(digest.as_bytes())
            .map_err(|_| CustodyError::SigningFailed)?;
        let recovery_id = u8::from(recovery_id);
        if recovery_id > 1 {
            return Err(CustodyError::SigningFailed);
        }
        let signature_bytes = signature.to_bytes();
        let mut evm_bytes = [0; 65];
        evm_bytes[..64].copy_from_slice(signature_bytes.as_ref());
        evm_bytes[64] = recovery_id + 27;
        Ok(EvmSignature::from_bytes(evm_bytes))
    }
}

impl fmt::Debug for DevelopmentKeyCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevelopmentKeyCustody")
            .field("identity", &self.identity)
            .field("private_keys", &"[REDACTED]")
            .finish()
    }
}

impl KeyCustodyProvider for DevelopmentKeyCustody {
    fn public_identity(&self) -> CustodyFuture<'_, PublicIdentityKeys> {
        Box::pin(async { Ok(self.identity.clone()) })
    }

    fn sign_typed_digest<'a>(
        &'a self,
        key_id: &'a KeyId,
        digest: &'a TypedDigest,
    ) -> CustodyFuture<'a, EvmSignature> {
        Box::pin(async move {
            if key_id != &self.identity.signing_key_id {
                return Err(CustodyError::KeyNotFound);
            }
            self.sign(digest)
        })
    }

    fn unwrap_dek<'a>(
        &'a self,
        key_id: &'a KeyId,
        envelope: &'a crypto::KeyEnvelope,
        context: crypto::WrapContext,
    ) -> CustodyFuture<'a, Zeroizing<[u8; 32]>> {
        Box::pin(async move {
            if key_id != &self.identity.encryption_key_id {
                return Err(CustodyError::KeyNotFound);
            }
            self.encryption_key
                .open_dek(envelope, context)
                .map(|dek| dek.into_zeroizing_bytes())
                .map_err(|_| CustodyError::UnwrapFailed)
        })
    }

    fn health_check(&self) -> CustodyFuture<'_, CustodyHealth> {
        Box::pin(async {
            Ok(CustodyHealth {
                healthy: true,
                capabilities: CustodyCapabilities {
                    secp256k1_signing: true,
                    hpke_x25519_unwrap: true,
                    private_keys_non_exportable: false,
                    test_only: true,
                },
            })
        })
    }
}

fn generate_signing_key() -> Result<SigningKey, CustodyError> {
    loop {
        let mut secret = Zeroizing::new([0; 32]);
        getrandom::fill(&mut secret[..]).map_err(|_| CustodyError::RandomnessUnavailable)?;
        if let Ok(signing_key) = SigningKey::from_bytes((&*secret).into()) {
            return Ok(signing_key);
        }
    }
}

fn generate_key_id() -> Result<KeyId, CustodyError> {
    loop {
        let mut key_id = [0; 32];
        getrandom::fill(&mut key_id).map_err(|_| CustodyError::RandomnessUnavailable)?;
        if key_id != [0; 32] {
            return Ok(KeyId::from_bytes(key_id));
        }
    }
}

fn evm_address(verifying_key: &VerifyingKey) -> EvmAddress {
    let public_key = verifying_key.to_encoded_point(false);
    let hash = Keccak256::digest(&public_key.as_bytes()[1..]);
    let mut address = [0; 20];
    address.copy_from_slice(&hash[12..]);
    EvmAddress::from_bytes(address)
}

#[cfg(test)]
mod tests {
    use crypto::{
        AccessLookup, ChainId, DataEncryptionKey, Eip712Domain, KeyEnvelope, UnixDeadline,
        WrapContext,
    };
    use domain::{EpochId, FileId, KeyVersion, MemberId, VersionNumber};
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use ports::{CustodyError, KeyCustodyProvider};
    use zeroize::Zeroizing;

    use super::*;

    fn provider() -> DevelopmentKeyCustody {
        DevelopmentKeyCustody::generate(
            MemberId::from_bytes([1; 32]),
            KeyVersion::new(1).unwrap(),
            KeyVersion::new(1).unwrap(),
        )
        .unwrap()
    }

    fn digest() -> TypedDigest {
        let domain = Eip712Domain::access_governance(
            ChainId::from_u64(1337),
            EvmAddress::from_bytes([0x22; 20]),
        );
        AccessLookup::new(
            MemberId::from_bytes([1; 32]),
            FileId::from_bytes([2; 32]),
            VersionNumber::ONE,
            KeyVersion::new(1).unwrap(),
            domain_nonce(),
            UnixDeadline::from_unix_seconds(1_800_000_000).unwrap(),
        )
        .unwrap()
        .digest(&domain)
        .unwrap()
    }

    fn domain_nonce() -> domain::OperationNonce {
        domain::OperationNonce::from_bytes([3; 32])
    }

    fn wrap_context() -> WrapContext {
        WrapContext::new(
            FileId::from_bytes([4; 32]),
            VersionNumber::ONE,
            EpochId::from_bytes([5; 32]),
            MemberId::from_bytes([1; 32]),
            KeyVersion::new(1).unwrap(),
        )
    }

    #[tokio::test]
    async fn reports_its_test_only_capabilities_and_public_identity() {
        let provider = provider();
        let provider_port: &dyn KeyCustodyProvider = &provider;
        let identity = provider_port.public_identity().await.unwrap();
        let health = provider_port.health_check().await.unwrap();

        assert_eq!(identity.member_id, MemberId::from_bytes([1; 32]));
        assert_eq!(identity.signing_key_version, KeyVersion::new(1).unwrap());
        assert_eq!(identity.encryption_key_version, KeyVersion::new(1).unwrap());
        assert_ne!(identity.signing_key_id, identity.encryption_key_id);
        assert!(health.healthy);
        assert!(health.capabilities.secp256k1_signing);
        assert!(health.capabilities.hpke_x25519_unwrap);
        assert!(!health.capabilities.private_keys_non_exportable);
        assert!(health.capabilities.test_only);
        assert!(format!("{provider:?}").contains("private_keys: \"[REDACTED]\""));
    }

    #[tokio::test]
    async fn produces_recoverable_evm_signature_for_registered_signing_key() {
        let provider = provider();
        let identity = provider.public_identity().await.unwrap();
        let digest = digest();
        let signature = provider
            .sign_typed_digest(&identity.signing_key_id, &digest)
            .await
            .unwrap();
        let bytes = signature.as_bytes();
        assert!(matches!(bytes[64], 27 | 28));

        let parsed_signature = Signature::try_from(&bytes[..64]).unwrap();
        let recovery_id = RecoveryId::try_from(bytes[64] - 27).unwrap();
        let recovered =
            VerifyingKey::recover_from_prehash(digest.as_bytes(), &parsed_signature, recovery_id)
                .unwrap();

        assert_eq!(evm_address(&recovered), identity.signing_address);
    }

    #[tokio::test]
    async fn refuses_unknown_signing_and_encryption_key_ids() {
        let provider = provider();
        let unknown_key_id = KeyId::from_bytes([0xff; 32]);

        assert!(matches!(
            provider.sign_typed_digest(&unknown_key_id, &digest()).await,
            Err(CustodyError::KeyNotFound)
        ));
        assert!(matches!(
            provider
                .unwrap_dek(&unknown_key_id, &empty_envelope(), wrap_context())
                .await,
            Err(CustodyError::KeyNotFound)
        ));
    }

    #[tokio::test]
    async fn unwraps_only_for_the_registered_encryption_key_and_context() {
        let provider = provider();
        let identity = provider.public_identity().await.unwrap();
        let dek = DataEncryptionKey::from_secret(Zeroizing::new([0x42; 32]));
        let envelope =
            KeyEnvelope::wrap(&dek, &identity.encryption_public_key, wrap_context()).unwrap();

        let unwrapped = provider
            .unwrap_dek(&identity.encryption_key_id, &envelope, wrap_context())
            .await
            .unwrap();
        assert_eq!(&*unwrapped, &[0x42; 32]);

        let incorrect_context = WrapContext::new(
            FileId::from_bytes([9; 32]),
            VersionNumber::ONE,
            EpochId::from_bytes([5; 32]),
            MemberId::from_bytes([1; 32]),
            KeyVersion::new(1).unwrap(),
        );
        assert!(matches!(
            provider
                .unwrap_dek(&identity.encryption_key_id, &envelope, incorrect_context)
                .await,
            Err(CustodyError::UnwrapFailed)
        ));
    }

    fn empty_envelope() -> KeyEnvelope {
        KeyEnvelope::from_parts(vec![0; 32], vec![0; 48]).unwrap()
    }
}
