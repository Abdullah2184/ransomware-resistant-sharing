//! Security invariant and negative test suite (`TECHNICAL_SPECIFICATION.md` §§14, 15).

use std::sync::Arc;

use chain_adapter::{
    BesuClient, DevelopmentRelayerSigner, RelayError, RelayerConfig, RelayerStartupPolicy,
    TransactionRelayer,
};
use crypto::{
    ChainId, ChunkDecryptor, ChunkEncryptor, DataEncryptionKey, Eip712Domain, EncryptedChunk,
    EncryptionContext, HpkeRecipientKeyPair, KeyEnvelope, NoncePrefix, UnixDeadline, VersionAppend,
    WrapContext, chunk_count_for_len,
};
use domain::{
    ContentCid, EnvelopeSetCid, EpochId, EvmAddress, FileId, KeyVersion, ManifestHash, MemberId,
    OperationNonce, VersionNumber,
};
use key_custody::{
    CustodyPolicyError, CustodyStartupPolicy, DevelopmentKeyCustody, verify_provider_policy,
};
use ports::{
    PreUploadScanner, ScanOutcome, ScanVerdict, ScannerMode, StorageError,
    decode_content_package_frame,
};
use scanner::DisabledScanner;

#[test]
fn ciphertext_tamper_chunk_swap_and_context_transplant_all_fail_closed() {
    let dek_bytes = DataEncryptionKey::generate()
        .unwrap()
        .into_zeroizing_bytes();
    let nonce_prefix = NoncePrefix::generate().unwrap();
    let file_id = FileId::from_bytes([0x11; 32]);
    let epoch_id = EpochId::from_bytes([0x22; 32]);
    let context = EncryptionContext::new(file_id, VersionNumber::ONE, epoch_id);
    let total_chunks = chunk_count_for_len(128, 64).unwrap();

    let mut enc = ChunkEncryptor::new(
        DataEncryptionKey::from_secret(dek_bytes.clone()),
        nonce_prefix,
        context,
        64,
        total_chunks,
    )
    .unwrap();
    let c1 = enc.encrypt_next(&[0x41; 64]).unwrap();
    let c2 = enc.encrypt_next(&[0x42; 64]).unwrap();
    enc.finish().unwrap();

    // 1. Single-bit ciphertext mutation fails AEAD verification.
    let mut bad_bytes = c1.ciphertext_and_tag().to_vec();
    bad_bytes[0] ^= 0x01;
    let mut dec = ChunkDecryptor::new(
        DataEncryptionKey::from_secret(dek_bytes.clone()),
        nonce_prefix,
        context,
        64,
        total_chunks,
    )
    .unwrap();
    assert!(
        dec.decrypt_next(&EncryptedChunk::from_parts(1, bad_bytes))
            .is_err()
    );

    // 2. Chunk swap (passing c2 as index 1) fails AAD index binding.
    let mut dec_swap = ChunkDecryptor::new(
        DataEncryptionKey::from_secret(dek_bytes.clone()),
        nonce_prefix,
        context,
        64,
        total_chunks,
    )
    .unwrap();
    assert!(
        dec_swap
            .decrypt_next(&EncryptedChunk::from_parts(
                1,
                c2.ciphertext_and_tag().to_vec()
            ))
            .is_err()
    );

    // 3. Context transplant (different fileId or versionNumber) fails AAD binding.
    let wrong_ctx =
        EncryptionContext::new(FileId::from_bytes([0x99; 32]), VersionNumber::ONE, epoch_id);
    let mut dec_ctx = ChunkDecryptor::new(
        DataEncryptionKey::from_secret(dek_bytes),
        nonce_prefix,
        wrong_ctx,
        64,
        total_chunks,
    )
    .unwrap();
    assert!(dec_ctx.decrypt_next(&c1).is_err());
}

#[test]
fn hpke_envelope_rejects_wrong_recipient_and_context_substitution() {
    let dek = DataEncryptionKey::generate().unwrap();
    let alice = HpkeRecipientKeyPair::generate().unwrap();
    let mallory = HpkeRecipientKeyPair::generate().unwrap();
    let ctx = WrapContext::new(
        FileId::from_bytes([0x01; 32]),
        VersionNumber::ONE,
        EpochId::from_bytes([0x02; 32]),
        MemberId::from_bytes([0x03; 32]),
        KeyVersion::new(1).unwrap(),
    );
    let envelope = KeyEnvelope::wrap(&dek, alice.public_key(), ctx).unwrap();

    // Wrong recipient key fails.
    assert!(mallory.open_dek(&envelope, ctx).is_err());

    // Wrong key version in AAD context fails even for the legitimate recipient key.
    let wrong_ver_ctx = WrapContext::new(
        FileId::from_bytes([0x01; 32]),
        VersionNumber::ONE,
        EpochId::from_bytes([0x02; 32]),
        MemberId::from_bytes([0x03; 32]),
        KeyVersion::new(2).unwrap(),
    );
    assert!(alice.open_dek(&envelope, wrong_ver_ctx).is_err());
}

#[test]
fn eip712_domain_separation_rejects_cross_contract_and_cross_chain_reuse() {
    let cid =
        ContentCid::parse("bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku").unwrap();
    let env_cid =
        EnvelopeSetCid::parse("bafkreifjjcie6lypi6ny7amxnfftagclbuxndqonfipmb64f2uf2nuiuqa")
            .unwrap();
    let append = VersionAppend::new(
        FileId::from_bytes([0x11; 32]),
        VersionNumber::ONE,
        ManifestHash::ZERO,
        ManifestHash::from_bytes([0x22; 32]),
        cid,
        env_cid,
        EpochId::from_bytes([0x33; 32]),
        MemberId::from_bytes([0x44; 32]),
        EvmAddress::from_bytes([0x55; 20]),
        OperationNonce::from_bytes([0x66; 32]),
        UnixDeadline::from_unix_seconds(1_800_000_000).unwrap(),
    )
    .unwrap();

    let file_domain =
        Eip712Domain::file_registry(ChainId::from_u64(1337), EvmAddress::from_bytes([0xaa; 20]));
    let other_chain =
        Eip712Domain::file_registry(ChainId::from_u64(1338), EvmAddress::from_bytes([0xaa; 20]));
    let wrong_contract_kind = Eip712Domain::access_governance(
        ChainId::from_u64(1337),
        EvmAddress::from_bytes([0xaa; 20]),
    );

    assert_ne!(
        append.digest(&file_domain).unwrap(),
        append.digest(&other_chain).unwrap()
    );
    assert!(append.digest(&wrong_contract_kind).is_err());
}

#[tokio::test]
async fn production_startup_policies_reject_software_custody_and_relayer_keys() {
    let custody = DevelopmentKeyCustody::generate(
        MemberId::from_bytes([1; 32]),
        KeyVersion::new(1).unwrap(),
        KeyVersion::new(1).unwrap(),
    )
    .unwrap();
    assert_eq!(
        verify_provider_policy(&custody, CustodyStartupPolicy::Production).await,
        Err(CustodyPolicyError::TestProviderRejectedInProduction)
    );

    let client = BesuClient::new("http://127.0.0.1:8545").unwrap();
    let relayer_signer = Arc::new(DevelopmentRelayerSigner::from_secret_bytes([0x33; 32]).unwrap());
    assert_eq!(
        TransactionRelayer::new(
            client,
            relayer_signer,
            RelayerStartupPolicy::Production,
            RelayerConfig::local_default(1337),
        )
        .unwrap_err(),
        RelayError::UnsafeSignerInProduction
    );
}

#[tokio::test]
async fn plaintext_package_frame_rejected_and_default_scanner_stays_disabled() {
    assert_eq!(
        decode_content_package_frame(b"PLAINTEXT_NOT_ENCRYPTED").err(),
        Some(StorageError::InvalidPackage)
    );
    let scanner = DisabledScanner;
    assert_eq!(scanner.mode(), ScannerMode::Disabled);
    assert_eq!(
        scanner.scan_plaintext("doc.txt", b"hello").await.unwrap(),
        ScanOutcome::Skipped
    );
    assert_eq!(
        scanner.evaluate("doc.txt", b"hello").await.unwrap(),
        ScanVerdict::Allow
    );
}
