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

async fn read_http_req(stream: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
    let mut req = Vec::new();
    let mut buf = [0u8; 4096];
    let body_start;
    loop {
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n > 0);
        req.extend_from_slice(&buf[..n]);
        if let Some(pos) = req.windows(4).position(|w| w == b"\r\n\r\n") {
            body_start = pos + 4;
            break;
        }
    }
    let headers = String::from_utf8_lossy(&req[..body_start]).into_owned();
    let content_length = headers
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .and_then(|v| v.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    while req.len() < body_start + content_length {
        let n = stream.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        req.extend_from_slice(&buf[..n]);
    }
    (headers, req[body_start..].to_vec())
}

#[tokio::test]
async fn upload_service_integrates_scanner_kubo_failover_and_relayed_type2_ledger_commit() {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use application::{UploadConfig, UploadError, UploadService};
    use domain::{
        AccessReference, DomainError, FolderId, MemberStatus, OrganizationId, PublicMemberIdentity,
        TransactionReceipt,
    };
    use ipfs_adapter::{ClusterCredentials, IpfsClusterStore, IpfsConfig};
    use ports::{
        HeadState, LedgerPort, PortFuture, PreUploadScanner, ScanOutcome, ScannerMode,
        SignedAccessLookupRequest, SignedAppendVersionRequest, SignedCreateFileRequest,
        SignedEnvelopeUpdateRequest, SystemClock,
    };

    struct BlockingScanner;
    impl PreUploadScanner for BlockingScanner {
        fn mode(&self) -> ScannerMode {
            ScannerMode::Enforce
        }
        fn scan_plaintext<'a>(
            &'a self,
            _display_name: &'a str,
            plaintext: &'a [u8],
        ) -> PortFuture<'a, ScanOutcome> {
            let blocked = plaintext.windows(7).any(|w| w == b"BLOCKME");
            Box::pin(async move {
                if blocked {
                    Ok(ScanOutcome::Suspicious {
                        reason: "blocked test pattern".to_owned(),
                    })
                } else {
                    Ok(ScanOutcome::Clean)
                }
            })
        }
    }

    #[derive(Clone)]
    struct RelayerBackedLedger {
        member: PublicMemberIdentity,
        file_registry: EvmAddress,
        relayer: Arc<TransactionRelayer>,
    }

    impl LedgerPort for RelayerBackedLedger {
        fn get_member(&self, member_id: MemberId) -> PortFuture<'_, Option<PublicMemberIdentity>> {
            let member = (member_id == self.member.member_id).then(|| self.member.clone());
            Box::pin(async move { Ok(member) })
        }

        fn get_file_head(&self, _file_id: FileId) -> PortFuture<'_, Option<HeadState>> {
            Box::pin(async { Ok(None) })
        }

        fn create_file<'a>(
            &'a self,
            request: &'a SignedCreateFileRequest,
        ) -> PortFuture<'a, TransactionReceipt> {
            Box::pin(async move {
                let calldata = encode_create_file_calldata(
                    &VersionAppendCall {
                        file_id: *request.file_id.as_bytes(),
                        version_number: request.version_number.get(),
                        parent_manifest_hash: *request.parent_manifest_hash.as_bytes(),
                        content_cid: request.content_cid.to_string(),
                        envelope_set_cid: request.envelope_set_cid.to_string(),
                        epoch_id: *request.epoch_id.as_bytes(),
                        manifest_hash: *request.manifest_hash.as_bytes(),
                        member_id: *request.author_member_id.as_bytes(),
                        signer_address: request.signer_address,
                        operation_nonce: *request.operation_nonce.as_bytes(),
                        deadline: request.deadline,
                    },
                    &request.display_name,
                    *request.parent_folder_id.as_bytes(),
                    request.signature.as_bytes(),
                );
                match self
                    .relayer
                    .submit_and_confirm(self.file_registry, calldata, None)
                    .await
                {
                    Ok(RelayOutcome::Committed(receipt)) => Ok(TransactionReceipt {
                        transaction_hash: receipt.transaction_hash,
                        block_number: receipt.block_number,
                        finalized: true,
                        succeeded: receipt.status,
                    }),
                    _ => Err(DomainError::ContractRejected),
                }
            })
        }

        fn append_version<'a>(
            &'a self,
            _request: &'a SignedAppendVersionRequest,
        ) -> PortFuture<'a, TransactionReceipt> {
            Box::pin(async { Err(DomainError::Internal) })
        }

        fn authorize_read<'a>(
            &'a self,
            _request: &'a SignedAccessLookupRequest,
        ) -> PortFuture<'a, AccessReference> {
            Box::pin(async { Err(DomainError::Internal) })
        }

        fn update_envelope_set<'a>(
            &'a self,
            _request: &'a SignedEnvelopeUpdateRequest,
        ) -> PortFuture<'a, TransactionReceipt> {
            Box::pin(async { Err(DomainError::Internal) })
        }
    }

    // 1. Mock unhealthy Kubo peer 1 (always 503) + healthy Kubo peer 2 + mock Cluster + mock Besu RPC.
    let bad_kubo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_kubo_addr = bad_kubo.local_addr().unwrap();
    let bad_kubo_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = bad_kubo.accept().await else {
                break;
            };
            let _ = read_http_req(&mut stream).await;
            let _ = stream
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
        }
    });

    let blocks: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let good_kubo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let good_kubo_addr = good_kubo.local_addr().unwrap();
    let good_blocks = blocks.clone();
    let good_kubo_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = good_kubo.accept().await else {
                break;
            };
            let (headers, body) = read_http_req(&mut stream).await;
            let first_line = headers.lines().next().unwrap_or("");
            if first_line.starts_with("POST /api/v0/id") {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{\"ID\":\"k2\"}\r\n",
                    )
                    .await;
            } else if first_line.starts_with("POST /api/v0/add?") {
                // Parse multipart parts by finding boundary from Content-Type header.
                let boundary = headers
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .starts_with("content-type:")
                            .then(|| l.split("boundary=").nth(1).map(|b| b.trim().to_owned()))
                            .flatten()
                    })
                    .unwrap();
                let delim = format!("--{boundary}");
                let mut lines = String::new();
                let mut root_parts = Vec::new();
                let mut is_dir = first_line.contains("wrap-with-directory=true");
                let mut cursor = body.as_slice();
                while let Some(pos) = cursor
                    .windows(delim.len())
                    .position(|w| w == delim.as_bytes())
                {
                    cursor = &cursor[pos + delim.len()..];
                    if cursor.starts_with(b"--") {
                        break;
                    }
                    if let Some(hdr_end) = cursor.windows(4).position(|w| w == b"\r\n\r\n") {
                        let part_hdr = String::from_utf8_lossy(&cursor[..hdr_end]).into_owned();
                        let data_start = hdr_end + 4;
                        let next_pos = cursor[data_start..]
                            .windows(delim.len())
                            .position(|w| w == delim.as_bytes())
                            .unwrap();
                        let part_bytes = cursor[data_start..data_start + next_pos]
                            .strip_suffix(b"\r\n")
                            .unwrap_or(&cursor[data_start..data_start + next_pos]);
                        let fname = part_hdr
                            .split("filename=\"")
                            .nth(1)
                            .and_then(|s| s.split('"').next())
                            .unwrap_or("file");
                        let cid = crypto::raw_sha256_cid(part_bytes).unwrap().to_string();
                        good_blocks
                            .lock()
                            .unwrap()
                            .insert(cid.clone(), part_bytes.to_vec());
                        root_parts.extend_from_slice(cid.as_bytes());
                        lines.push_str(&format!("{{\"Name\":\"{fname}\",\"Hash\":\"{cid}\"}}\n"));
                        if !is_dir {
                            is_dir = false;
                        }
                    }
                }
                if is_dir {
                    let root_cid = crypto::raw_sha256_cid(&root_parts).unwrap().to_string();
                    good_blocks
                        .lock()
                        .unwrap()
                        .insert(root_cid.clone(), root_parts);
                    lines.push_str(&format!("{{\"Name\":\"\",\"Hash\":\"{root_cid}\"}}\n"));
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    lines.len(),
                    lines
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            } else if first_line.starts_with("POST /api/v0/block/get?arg=") {
                let cid = first_line
                    .split("arg=")
                    .nth(1)
                    .and_then(|s| s.split_whitespace().next())
                    .unwrap();
                let block = good_blocks.lock().unwrap().get(cid).cloned().unwrap();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    block.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.write_all(&block).await;
            }
        }
    });

    let cluster = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cluster_addr = cluster.local_addr().unwrap();
    let cluster_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = cluster.accept().await else {
                break;
            };
            let (headers, _) = read_http_req(&mut stream).await;
            let first_line = headers.lines().next().unwrap_or("");
            if first_line.starts_with("POST /pins/") {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            } else if first_line.starts_with("GET /pins/") {
                let cid = first_line
                    .trim_start_matches("GET /pins/")
                    .split_whitespace()
                    .next()
                    .unwrap();
                let body = json!({
                    "cid": cid,
                    "peer_map": {
                        "peer-1": { "status": "pinned" },
                        "peer-2": { "status": "pinned" }
                    }
                })
                .to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
            }
        }
    });

    let besu = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let besu_addr = besu.local_addr().unwrap();
    let besu_task = tokio::spawn(async move {
        let mut block = 500u64;
        loop {
            let Ok((mut stream, _)) = besu.accept().await else {
                break;
            };
            let (_, body_bytes) = read_http_req(&mut stream).await;
            let body: Value = serde_json::from_slice(&body_bytes).unwrap();
            let result = match body["method"].as_str().unwrap() {
                "eth_getTransactionCount" => json!("0x0"),
                "eth_sendRawTransaction" => {
                    let raw =
                        chain_adapter::decode_hex(body["params"][0].as_str().unwrap()).unwrap();
                    assert_eq!(raw[0], 0x02);
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
                        "blockHash": format!("0x{}", "dd".repeat(32)),
                        "status": "0x1",
                        "gasUsed": "0x493e0"
                    })
                }
                "eth_getBlockByNumber" => json!({
                    "number": format!("0x{block:x}"),
                    "hash": format!("0x{}", "dd".repeat(32))
                }),
                other => panic!("unexpected RPC method: {other}"),
            };
            let resp_body = json!({
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": result
            })
            .to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                resp_body.len(),
                resp_body
            );
            let _ = stream.write_all(resp.as_bytes()).await;
        }
    });

    // 2. Wire all 6 real crates together: domain + crypto + key_custody + application + ipfs_adapter + chain_adapter.
    let member_id = MemberId::from_bytes([0x91; 32]);
    let custody = DevelopmentKeyCustody::from_dev_secrets(
        member_id,
        KeyVersion::new(1).unwrap(),
        KeyVersion::new(1).unwrap(),
        [0x81; 32],
        [0x82; 32],
    )
    .unwrap();
    let pub_id = custody.public_identity().await.unwrap();
    let member = PublicMemberIdentity {
        member_id,
        organization_id: OrganizationId::from_bytes([0x01; 32]),
        signing_address: pub_id.signing_address,
        encryption_public_key: pub_id.encryption_public_key.to_bytes().try_into().unwrap(),
        signing_key_version: pub_id.signing_key_version,
        encryption_key_version: pub_id.encryption_key_version,
        status: MemberStatus::Active,
        finalized_block: 500,
    };

    let ipfs = IpfsClusterStore::new(IpfsConfig {
        kubo_api_urls: vec![
            format!("http://{bad_kubo_addr}"),
            format!("http://{good_kubo_addr}"),
        ],
        cluster_api_url: format!("http://{cluster_addr}"),
        cluster_credentials: ClusterCredentials::new("rrfs-admin", "test-secret"),
        request_timeout: Duration::from_secs(3),
        replication_timeout: Duration::from_secs(3),
        replication_poll_interval: Duration::from_millis(10),
        max_upload_bytes: 8 * 1024 * 1024,
    })
    .unwrap();

    let file_registry = EvmAddress::from_bytes([0xef; 20]);
    let relayer = Arc::new(
        TransactionRelayer::new(
            BesuClient::new(&format!("http://{besu_addr}")).unwrap(),
            Arc::new(DevelopmentRelayerSigner::from_secret_bytes([0x77; 32]).unwrap()),
            RelayerStartupPolicy::UnsafeDevelopment,
            RelayerConfig {
                chain_id: 1337,
                default_gas_limit: 2_000_000,
                max_gas_limit: 5_000_000,
                confirmation_timeout: Duration::from_secs(3),
                poll_interval: Duration::from_millis(10),
            },
        )
        .unwrap(),
    );
    let ledger = RelayerBackedLedger {
        member,
        file_registry,
        relayer,
    };

    let uploader = UploadService::new(
        custody,
        ipfs,
        ledger,
        SystemClock,
        UploadConfig {
            chain_id: 1337,
            file_registry,
            min_pin_replicas: 2,
            chunk_size_bytes: crypto::DEFAULT_CHUNK_SIZE_BYTES,
            max_file_bytes: 4 * 1024 * 1024,
            operation_ttl_seconds: 120,
        },
    )
    .with_scanner(Arc::new(BlockingScanner));

    // Enforcing scanner blocks before any Kubo/Cluster/Besu I/O.
    let blocked = uploader
        .create_file(
            None,
            "suspect.bin".to_owned(),
            FolderId::ROOT,
            b"prefix-BLOCKME-suffix",
            None,
            &[],
        )
        .await
        .unwrap_err();
    assert!(matches!(blocked, UploadError::BlockedByScanner { .. }));
    assert!(blocks.lock().unwrap().is_empty());

    // Clean payload fails over to Kubo peer 2, pins on 2 Cluster peers, and commits Type-2 tx.
    let receipt = uploader
        .create_file(
            None,
            "cross-system-report.txt".to_owned(),
            FolderId::ROOT,
            b"verified cross-system encrypted payload",
            None,
            &[],
        )
        .await
        .unwrap();
    assert_eq!(receipt.version_number, VersionNumber::ONE);
    assert_eq!(receipt.content_replication.pinned_peers.len(), 2);
    assert_eq!(receipt.envelope_replication.pinned_peers.len(), 2);
    assert_eq!(receipt.transaction.block_number, 501);
    assert!(receipt.transaction.finalized && receipt.transaction.succeeded);
    assert_eq!(receipt.scan_warning, None);

    bad_kubo_task.abort();
    good_kubo_task.abort();
    cluster_task.abort();
    besu_task.abort();
}

#[test]
fn schemas_and_cross_language_crypto_fixtures_enforce_strict_contracts() {
    for (name, raw) in [
        (
            "encrypted-file-manifest-v1.json",
            include_str!("../../schemas/encrypted-file-manifest-v1.json"),
        ),
        (
            "key-envelope-set-v1.json",
            include_str!("../../schemas/key-envelope-set-v1.json"),
        ),
        (
            "access-request-v1.json",
            include_str!("../../schemas/access-request-v1.json"),
        ),
        (
            "version-manifest-v1.json",
            include_str!("../../schemas/version-manifest-v1.json"),
        ),
    ] {
        let schema: Value =
            serde_json::from_str(raw).unwrap_or_else(|e| panic!("invalid JSON in {name}: {e}"));
        assert_eq!(
            schema["$schema"], "https://json-schema.org/draft/2020-12/schema",
            "{name} must declare JSON Schema Draft 2020-12"
        );
        assert_eq!(
            schema["additionalProperties"], false,
            "{name} must reject unknown fields"
        );
        assert!(
            schema["required"]
                .as_array()
                .is_some_and(|arr| !arr.is_empty()),
            "{name} must list required fields"
        );
    }

    let eip712: Value = serde_json::from_str(include_str!("../fixtures/eip712-v1.json")).unwrap();
    for key in [
        "versionAppend",
        "accessLookup",
        "envelopeSetUpdate",
        "memberKeyProof",
        "loginChallenge",
    ] {
        assert!(
            eip712[key]
                .as_str()
                .is_some_and(|v| v.starts_with("0x") && v.len() == 66),
            "missing 32-byte digest fixture {key}"
        );
    }

    let hpke: Value =
        serde_json::from_str(include_str!("../fixtures/hpke-rfc9180-v1.json")).unwrap();
    assert_eq!(hpke["suite"]["kemId"], 32);
    assert_eq!(hpke["suite"]["kdfId"], 1);
    assert_eq!(hpke["suite"]["aeadId"], 2);
}
