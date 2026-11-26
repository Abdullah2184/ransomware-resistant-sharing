//! Cross-component integration test verifying `application` signed requests
//! flow cleanly through `chain_adapter` ABI calldata encoding and Type-2
//! `TransactionRelayer` submission against a mock Besu JSON-RPC endpoint.

use std::{sync::Arc, time::Duration};

use chain_adapter::{
    BesuClient, DevelopmentRelayerSigner, EnvelopeSetUpdateCall, RelayOutcome, RelayerConfig,
    RelayerStartupPolicy, TransactionRelayer, VersionAppendCall, encode_create_file_calldata,
    encode_update_envelope_set_calldata,
};
use crypto::{ChainId, Eip712Domain, EnvelopeSetUpdate, UnixDeadline, VersionAppend};
use domain::{
    ContentCid, EnvelopeSetCid, EpochId, EvmAddress, FileId, KeyVersion, ManifestHash, MemberId,
    OperationNonce, ProposalId, VersionNumber,
};
use key_custody::DevelopmentKeyCustody;
use ports::KeyCustodyProvider;
use serde_json::{Value, json};
use sha3::{Digest, Keccak256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
async fn signed_application_operations_encode_and_relay_as_type2_transactions() {
    let member_id = MemberId::from_bytes([0x11; 32]);
    let custody = DevelopmentKeyCustody::from_dev_secrets(
        member_id,
        KeyVersion::new(1).unwrap(),
        KeyVersion::new(1).unwrap(),
        [0x44; 32],
        [0x55; 32],
    )
    .unwrap();
    let identity = custody.public_identity().await.unwrap();

    let file_registry = EvmAddress::from_bytes([0xaa; 20]);
    let access_governance = EvmAddress::from_bytes([0xbb; 20]);
    let file_id = FileId::from_bytes([0x01; 32]);
    let epoch_id = EpochId::from_bytes([0x02; 32]);
    let manifest_hash = ManifestHash::from_bytes([0x03; 32]);
    let content_cid =
        ContentCid::parse("bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku").unwrap();
    let env_v1_cid =
        EnvelopeSetCid::parse("bafkreifjjcie6lypi6ny7amxnfftagclbuxndqonfipmb64f2uf2nuiuqa")
            .unwrap();
    let env_v2_cid =
        EnvelopeSetCid::parse("bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku")
            .unwrap();

    // Sign VersionAppend via KeyCustodyProvider -> encode createFile calldata.
    let append_digest = VersionAppend::new(
        file_id,
        VersionNumber::ONE,
        ManifestHash::ZERO,
        manifest_hash,
        content_cid.clone(),
        env_v1_cid.clone(),
        epoch_id,
        member_id,
        identity.signing_address,
        OperationNonce::from_bytes([0x71; 32]),
        UnixDeadline::from_unix_seconds(1_800_000_120).unwrap(),
    )
    .unwrap()
    .digest(&Eip712Domain::file_registry(
        ChainId::from_u64(1337),
        file_registry,
    ))
    .unwrap();
    let append_sig = custody
        .sign_typed_digest(&identity.signing_key_id, &append_digest)
        .await
        .unwrap();
    let create_calldata = encode_create_file_calldata(
        &VersionAppendCall {
            file_id: *file_id.as_bytes(),
            version_number: 1,
            parent_manifest_hash: [0; 32],
            content_cid: content_cid.to_string(),
            envelope_set_cid: env_v1_cid.to_string(),
            epoch_id: *epoch_id.as_bytes(),
            manifest_hash: *manifest_hash.as_bytes(),
            member_id: *member_id.as_bytes(),
            signer_address: identity.signing_address,
            operation_nonce: [0x71; 32],
            deadline: 1_800_000_120,
        },
        "quarterly-audit.pdf",
        [0; 32],
        append_sig.as_bytes(),
    );

    // Sign EnvelopeSetUpdate via KeyCustodyProvider -> encode updateEnvelopeSet calldata.
    let env_digest = EnvelopeSetUpdate::new(
        file_id,
        VersionNumber::ONE,
        epoch_id,
        env_v1_cid.clone(),
        env_v2_cid.clone(),
        member_id,
        ProposalId::from_bytes([0; 32]),
        OperationNonce::from_bytes([0x72; 32]),
        UnixDeadline::from_unix_seconds(1_800_000_120).unwrap(),
    )
    .unwrap()
    .digest(&Eip712Domain::access_governance(
        ChainId::from_u64(1337),
        access_governance,
    ))
    .unwrap();
    let env_sig = custody
        .sign_typed_digest(&identity.signing_key_id, &env_digest)
        .await
        .unwrap();
    let update_calldata = encode_update_envelope_set_calldata(
        &EnvelopeSetUpdateCall {
            file_id: *file_id.as_bytes(),
            version_number: 1,
            epoch_id: *epoch_id.as_bytes(),
            old_envelope_set_cid: env_v1_cid.to_string(),
            new_envelope_set_cid: env_v2_cid.to_string(),
            actor_member_id: *member_id.as_bytes(),
            proposal_id: [0; 32],
            operation_nonce: [0x72; 32],
            deadline: 1_800_000_120,
        },
        env_sig.as_bytes(),
    );

    // Relay both signed operations sequentially over mock Besu JSON-RPC.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut block = 100u64;
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            let body_start;
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                req.extend_from_slice(&buf[..n]);
                if let Some(pos) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                    body_start = pos + 4;
                    break;
                }
            }
            let headers = String::from_utf8_lossy(&req[..body_start]);
            let len = headers
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .and_then(|v| v.trim().parse::<usize>().ok())
                })
                .unwrap();
            while req.len() < body_start + len {
                let n = stream.read(&mut buf).await.unwrap();
                req.extend_from_slice(&buf[..n]);
            }
            let body: Value = serde_json::from_slice(&req[body_start..]).unwrap();
            let result = match body["method"].as_str().unwrap() {
                "eth_getTransactionCount" => json!("0x0"),
                "eth_sendRawTransaction" => {
                    let raw =
                        chain_adapter::decode_hex(body["params"][0].as_str().unwrap()).unwrap();
                    assert_eq!(raw[0], 0x02, "expected EIP-2718 Type-2 signed transaction");
                    let digest = Keccak256::digest(&raw);
                    let mut tx_hash = String::from("0x");
                    for byte in digest {
                        use std::fmt::Write as _;
                        let _ = write!(tx_hash, "{byte:02x}");
                    }
                    block += 1;
                    json!(tx_hash)
                }
                "eth_getTransactionReceipt" => {
                    let tx_hash = body["params"][0].as_str().unwrap();
                    json!({
                        "transactionHash": tx_hash,
                        "blockNumber": format!("0x{block:x}"),
                        "blockHash": format!("0x{}", "cc".repeat(32)),
                        "status": "0x1",
                        "gasUsed": "0x30d40",
                    })
                }
                "eth_getBlockByNumber" => json!({
                    "number": format!("0x{block:x}"),
                    "hash": format!("0x{}", "cc".repeat(32)),
                }),
                other => panic!("unexpected JSON-RPC method: {other}"),
            };
            let resp_body = json!({
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": result,
            })
            .to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                resp_body.len(),
                resp_body
            );
            stream.write_all(resp.as_bytes()).await.unwrap();
        }
    });

    let client = BesuClient::new(&format!("http://{addr}")).unwrap();
    let relayer_signer = Arc::new(DevelopmentRelayerSigner::from_secret_bytes([0x66; 32]).unwrap());
    let relayer = TransactionRelayer::new(
        client,
        relayer_signer,
        RelayerStartupPolicy::UnsafeDevelopment,
        RelayerConfig {
            chain_id: 1337,
            default_gas_limit: 2_000_000,
            max_gas_limit: 5_000_000,
            confirmation_timeout: Duration::from_secs(2),
            poll_interval: Duration::from_millis(20),
        },
    )
    .unwrap();

    let create_outcome = relayer
        .submit_and_confirm(file_registry, create_calldata, None)
        .await
        .unwrap();
    match create_outcome {
        RelayOutcome::Committed(receipt) => {
            assert_eq!(receipt.block_number, 101);
            assert!(receipt.status);
        }
        other => panic!("expected Committed for createFile, got {other:?}"),
    }

    let update_outcome = relayer
        .submit_and_confirm(access_governance, update_calldata, None)
        .await
        .unwrap();
    match update_outcome {
        RelayOutcome::Committed(receipt) => {
            assert_eq!(receipt.block_number, 102);
            assert!(receipt.status);
        }
        other => panic!("expected Committed for updateEnvelopeSet, got {other:?}"),
    }
    server.abort();
}
