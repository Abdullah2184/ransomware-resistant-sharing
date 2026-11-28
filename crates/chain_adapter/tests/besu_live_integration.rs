//! Live Hyperledger Besu QBFT integration tests (`TECHNICAL_SPECIFICATION.md` §§7.6–7.12).
//!
//! Run against the local 4-validator + non-validator RPC Besu network with:
//! `BESU_RPC_URL=http://127.0.0.1:8545 cargo test -p chain-adapter --test besu_live_integration -- --ignored`

use std::env;

use chain_adapter::{BesuClient, ChainError};
use domain::EvmAddress;

const DEFAULT_BESU_RPC_URL: &str = "http://127.0.0.1:8545";
const DEFAULT_CHAIN_ID: u64 = 1337;
const DEFAULT_TIMELOCK: &str = "0xc4647d02e8ba1c922d5c4fc22e04b3d1bcd75568";
const DEFAULT_ACCESS_GOVERNANCE: &str = "0x1efe4b8d6076a0ca115241346f8d7da516ce4055";
const DEFAULT_FILE_REGISTRY: &str = "0x7ba5ef0f4c923942554c8b5788578280f7451f2d";
const DEFAULT_BOOTSTRAP_FROM_BLOCK: u64 = 60_840;
const DEFAULT_BOOTSTRAP_TO_BLOCK: u64 = 60_855;

fn parse_env_address(name: &str, default: &str) -> EvmAddress {
    let raw = env::var(name).unwrap_or_else(|_| default.to_owned());
    let bytes = domain::hex::parse_fixed_hex::<20>(&raw)
        .unwrap_or_else(|| panic!("{name} must be a valid 20-byte hex address"));
    EvmAddress::from_bytes(bytes)
}

#[tokio::test]
#[ignore = "requires live Besu QBFT RPC (BESU_RPC_URL)"]
async fn besu_qbft_live_rpc_reads_revert_classification_and_log_bounds() {
    let rpc_url = env::var("BESU_RPC_URL").unwrap_or_else(|_| DEFAULT_BESU_RPC_URL.to_owned());
    let expected_chain_id: u64 = env::var("BESU_CHAIN_ID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CHAIN_ID);
    let timelock = parse_env_address("CONTRACT_TIMELOCK_ADDRESS", DEFAULT_TIMELOCK);
    let access_governance = parse_env_address(
        "CONTRACT_ACCESS_GOVERNANCE_ADDRESS",
        DEFAULT_ACCESS_GOVERNANCE,
    );
    let file_registry = parse_env_address("CONTRACT_FILE_REGISTRY_ADDRESS", DEFAULT_FILE_REGISTRY);

    let client = BesuClient::new(&rpc_url).expect("valid Besu RPC URL");

    // 1. Chain ID and QBFT committed head parity.
    assert_eq!(
        client.chain_id().await.expect("eth_chainId"),
        expected_chain_id
    );
    let head = client
        .finalized_block()
        .await
        .expect("QBFT latest committed head");
    assert!(head.number > 0, "live QBFT chain must be advancing");
    assert_eq!(
        client
            .block_hash(head.number)
            .await
            .expect("block hash at finalized height"),
        head.hash
    );

    // 2. Pinned-block eth_call reads against deployed AccessGovernance & FileRegistry.
    let unknown_member = [0x9a; 32];
    let unknown_file = [0x9b; 32];
    assert_eq!(
        client
            .member_identity(&access_governance, &unknown_member, head.number)
            .await
            .expect("memberIdentity eth_call"),
        None
    );
    assert_eq!(
        client
            .file_head_at(&file_registry, &unknown_file, head.number)
            .await
            .expect("getFile eth_call"),
        None
    );
    assert!(
        !client
            .has_read_access(
                &access_governance,
                &unknown_member,
                &unknown_file,
                head.number
            )
            .await
            .expect("hasReadAccess eth_call")
    );
    assert!(
        !client
            .has_write_access(
                &access_governance,
                &unknown_member,
                &unknown_file,
                head.number
            )
            .await
            .expect("hasWriteAccess eth_call")
    );
    assert!(
        !client
            .has_historical_read_access(
                &access_governance,
                &unknown_member,
                &unknown_file,
                1,
                head.number,
            )
            .await
            .expect("hasHistoricalReadAccess eth_call")
    );

    // 3. Real Besu EIP-1474 execution reverts (code 3 + FileNotFound / InvalidEnvelopeReference)
    //    return Ok(None), while Bonsai pruned-state RPC errors (-32603) MUST surface as Err!
    assert_eq!(
        client
            .file_version(&file_registry, &unknown_file, 1, head.number)
            .await
            .expect("getVersion FileNotFound revert maps to None"),
        None
    );
    assert_eq!(
        client
            .current_envelope_set(&access_governance, &unknown_file, 1, head.number)
            .await
            .expect("currentEnvelopeSet InvalidEnvelopeReference revert maps to None"),
        None
    );
    if head.number > 1_000 {
        let pruned_block = head.number - 1_000;
        let pruned_err = client
            .file_version(&file_registry, &unknown_file, 1, pruned_block)
            .await
            .expect_err("pruned Bonsai historical state must fail closed, not return Ok(None)");
        assert!(
            matches!(pruned_err, ChainError::RpcRejected(_)),
            "expected RpcRejected for pruned historical state, got {pruned_err:?}"
        );
    }

    // 4. Real eth_getLogs verification: fetch deployed contract logs and confirm range-limit rejection.
    let from_block = env::var("BESU_BOOTSTRAP_FROM_BLOCK")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_BOOTSTRAP_FROM_BLOCK);
    let to_block = env::var("BESU_BOOTSTRAP_TO_BLOCK")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_BOOTSTRAP_TO_BLOCK);
    let deploy_logs = client
        .logs(from_block, to_block, &[access_governance, timelock])
        .await
        .expect("fetch real Besu deployment & timelock logs");
    assert!(
        deploy_logs.len() >= 10,
        "expected >= 10 AccessGovernance + RrdsTimelockController bootstrap logs, got {}",
        deploy_logs.len()
    );
    if head.number > 6_000 {
        let range_err = client
            .logs(0, head.number, &[access_governance])
            .await
            .expect_err("Besu must reject eth_getLogs exceeding 5000-block RPC limit");
        assert_eq!(range_err, ChainError::RpcRejected(-32005));
    }

    // 5. Pending nonce query on fresh unused address returns 0.
    let fresh_addr = EvmAddress::from_bytes([0xef; 20]);
    assert_eq!(
        client
            .pending_nonce(&fresh_addr)
            .await
            .expect("eth_getTransactionCount pending"),
        0
    );
}
