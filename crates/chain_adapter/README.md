# Chain Adapter (`crates/chain_adapter`)

`chain-adapter` encapsulates all Besu QBFT JSON-RPC transport, Solidity ABI
encoding/decoding, EIP-2718 Type-2 transaction construction, and relayer
submission/reconciliation logic so `domain`, `ports`, `application`, and
service route handlers never depend on raw EVM encodings.

See [`docs/adr/chain-adapter-rpc-and-relayer.md`](../../docs/adr/chain-adapter-rpc-and-relayer.md)
for the architectural decision record.

## Responsibilities

- **QBFT finality reads (`BesuClient`):** Queries `eth_getBlockByNumber("latest")`
  as the QBFT-committed head (never the PoS `finalized` tag), retrieves event
  logs (`eth_getLogs`) strictly filtered to configured contracts, distinguishes
  EIP-1474 execution reverts (`code == 3` with expected custom error selectors)
  from non-revert RPC failures (such as Bonsai pruned-state `-32603`), and
  executes pinned-block `eth_call` reads for `memberIdentity`, `hasReadAccess`,
  `hasWriteAccess`, `hasHistoricalReadAccess`, `getFile`, `getVersion`, and
  `currentEnvelopeSet`.
- **ABI calldata encoding (`relayer.rs`):** Encodes canonical Solidity calldata
  matching compiled `solc 0.8.34` ABIs for:
  - `FileRegistry.createFile`
  - `FileRegistry.appendVersion`
  - `AccessGovernance.updateEnvelopeSet`
- **Type-2 transaction relayer (`TransactionRelayer`):**
  - Isolates relayer signing behind `RelayerSigner`; `RelayerStartupPolicy::Production`
    rejects `DevelopmentRelayerSigner`, and dev secret env loading uses
    `Zeroizing` buffers.
  - Serializes nonce allocation per relayer account against `eth_getTransactionCount(..., "pending")`
    (resetting cached nonce on send errors or confirmation timeouts so a dropped
    mempool tx cannot wedge subsequent relays) and provides bounded gas
    estimation (`estimate_bounded_gas`).
  - Constructs canonical zero-gas-price EIP-2718 Type-2 transactions (`0x02 || rlp(...)`)
    compatible with London Besu QBFT (`min-gas-price = 0`, `baseFeePerGas = 0`).
  - Distinguishes `RelayOutcome::Committed`, `RelayOutcome::Reverted`, and
    `RelayError::ConfirmationTimedOut { tx_hash }` without auto-resubmitting on
    timeout, and exposes `reconcile_transaction(tx_hash)`.

## Verification

```shell
cargo test -p chain-adapter --locked --offline
```
