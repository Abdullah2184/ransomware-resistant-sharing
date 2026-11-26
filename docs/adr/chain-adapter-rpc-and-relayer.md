# ADR: Lightweight EVM JSON-RPC client and transaction relayer

**Status:** Accepted for prototype  
**Decision scope:** `crates/chain_adapter` EVM transport, ABI encoding, Type-2
transaction signing, and gateway transaction relayer architecture

## Context

`TECHNICAL_SPECIFICATION.md` §3 lists the Alloy Rust ecosystem for EVM RPC,
contract bindings, and EIP-712 typed data, and requires keeping all RPC and ABI
details behind `crates/chain_adapter` so domain and application crates never
depend on EVM encoding details.

During Phases 3 and 4, `crates/chain_adapter` was implemented using the
workspace's already-pinned `reqwest`, `serde_json`, `sha3`, and `k256` crates
without pulling in the Alloy dependency tree. The repository builds and tests
strictly offline (`--locked --offline`), and EIP-712 typed-data hashing is
already implemented in `crates/crypto` and cross-verified against `solc 0.8.34`
and `viem` fixtures in `tests/fixtures/eip712-v1.json`.

Phase 4/P3 now requires relaying signed `FileRegistry.createFile`,
`FileRegistry.appendVersion`, and `AccessGovernance.updateEnvelopeSet`
transactions to the local London-EVM Besu QBFT network (`chainId = 1337`,
`min-gas-price = 0`, `baseFeePerGas = 0`).

## Decision

1. **Retain the lightweight `chain_adapter` stack for the prototype:**
   Keep `crates/chain_adapter` built on the workspace's pinned `reqwest`,
   `serde_json`, `sha3`, and `k256` crates rather than adding the Alloy crate
   tree during MVP development. Isolate all ABI calldata encoding, RLP
   serialization, EIP-2718 Type-2 transaction signing, and JSON-RPC transport
   strictly inside `crates/chain_adapter`.
2. **Use EIP-2718 Type-2 (EIP-1559) zero-gas-price transactions:**
   Construct canonical Type-2 transactions (`0x02 || rlp([chainId, nonce, 0, 0,
   gasLimit, to, 0, data, [], yParity, r, s])`) compatible with London Besu
   QBFT (`baseFeePerGas = 0`, `--min-gas-price=0`) while preserving gas
   metering and bounded per-transaction gas limits.
3. **Strict relayer key separation:**
   Abstract relayer signing behind a `RelayerSigner` trait. A relayer key must
   never be reused as a member signing key or QBFT validator key. Provide an
   explicitly labelled `DevelopmentRelayerSigner` for tests and local
   development; non-development startup must reject software relayer keys
   unless explicitly configured in unsafe development mode.
4. **Sequential nonce management and finality/timeout reconciliation:**
   Serialize relayer nonce assignment per relayer account, reconcile with
   `eth_getTransactionCount(address, "pending")`, submit via
   `eth_sendRawTransaction`, and poll `eth_getTransactionReceipt` until the
   receipt is included in a QBFT-committed block (`blockNumber <= latest`).
   - Distinguish `Committed` (`status == 1`), `Reverted` (`status == 0`), and
     `ConfirmationTimedOut { tx_hash }`.
   - Never report a reverted or pending transaction as committed.
   - Never automatically resubmit after a timeout without first querying
     `reconcile_transaction(tx_hash)`.
5. **Cross-check ABI encodings:**
   Verify every function selector and calldata encoding in `crates/chain_adapter`
   against the compiled `solc 0.8.34` contract ABIs (`FileRegistry.json` and
   `AccessGovernance.json`).

## Consequences

- **Pros:** Zero new external dependencies; offline `--locked` builds remain
  fast and reproducible; small, auditable cryptographic surface; clean boundary
  allows a future migration to Alloy inside `crates/chain_adapter` without
  changing `domain`, `ports`, `application`, or `services/gateway` routes.
- **Cons / Limitations:** New contract write functions require explicit ABI
  encoders and selector tests in `crates/chain_adapter`. Any future move to
  complex multi-contract governance calls or non-zero dynamic fee markets
  should revisit adopting Alloy.

## Specification references

- `TECHNICAL_SPECIFICATION.md` §§3, 7.6–7.13, 8.1, 10.4.4, and 12.1.
