# Design Decisions, Justifications, and Explicit Limitations

This document summarizes the engineering rationale behind the RRDS technology
stack, cryptographic choices, and architectural trade-offs defined in
[`TECHNICAL_SPECIFICATION.md`](../specifications/TECHNICAL_SPECIFICATION.md) and the
detailed ADRs in [`docs/adr/`](../adr/).

## 1. Language and Toolchain Choices

| Layer | Technology | Rationale | Trade-offs / Limitations |
| --- | --- | --- | --- |
| **Client Core, Gateway & Indexer** | **Rust (`1.99.1`, `edition = 2024`)** | Memory safety without GC pauses, strong static typing for domain/crypto invariants (preventing key/nonce misuse at compile time), native `zeroize` support for key/plaintext buffers, single-binary services, and strict offline `--locked` builds. | Longer compile times than Go/TypeScript; explicit async trait boxing (`Pin<Box<dyn Future>>`) at port boundaries. |
| **Smart Contracts** | **Solidity `0.8.34` + Hardhat `3.21.2` + OpenZeppelin `5.6.1` + Safe `1.4.1`** | Mature EVM tooling, native `ECDSA` / EIP-712 support, `TimelockController`, and audited `@safe-global/safe-contracts` `1.4.1` `2-of-3` threshold Safe proxies verified on Hardhat and Besu QBFT. | Contract bytecode subject to 24 KiB EIP-170 ceiling (`AccessGovernance` is 17,475 bytes); on-chain storage remains minimal (CIDs/hashes only, never file bytes). |

## 2. Cryptographic Standards

| Primitive | Choice | Rationale | Trade-offs / Limitations |
| --- | --- | --- | --- |
| **File Content Encryption** | **AES-256-GCM** (1 MiB chunks, 64-bit random `NoncePrefix` + 32-bit chunk index, context-bound AAD) | Standard AEAD with hardware AES-NI acceleration, per-chunk integrity verification, and chunk-0 reserved for encrypted private metadata. Fresh 256-bit DEK per file version provides forward secrecy after revocation. | 1 MiB chunk size (`1,048,576` B plaintext / `1,048,592` B ciphertext) was amended from 4 MiB to stay under Kubo `0.43.1`'s `2,096,896`-byte chunker limit ([ADR](../adr/content-package-unixfs-profile.md)). |
| **Per-Recipient Key Wrapping** | **RFC 9180 HPKE (`X25519 / HKDF-SHA256 / AES-256-GCM`)** | Standardized asymmetric encapsulation binding `(fileId, versionNumber, epochId, memberId, encryptionKeyVersion)` into HPKE `info`/AAD. Separates encryption keys from secp256k1 signing keys and enables sharing without re-encrypting file ciphertext. | Verified against official RFC 9180 Base mode and cross-implementation OpenSSL vectors (`tests/fixtures/hpke-rfc9180-v1.json`); max 1,024 recipients per envelope set ([ADR](../adr/envelope-set-limits.md)). |
| **Operation & Login Signing** | **secp256k1 + EIP-712 Typed Data** | Native EVM `ecrecover` compatibility (`FileRegistry`, `AccessGovernance`, `Gateway`), strict domain separation (`name`, `version`, `chainId`, `verifyingContract`), low-`s` canonicalization, and per-operation nonces + deadlines. | Requires dedicated hardware/HSM signing custody in production; software `DevelopmentKeyCustody` is gated behind `CustodyStartupPolicy::UnsafeDevelopment`. |

## 3. Infrastructure Choices

- **Hyperledger Besu QBFT (Permissioned EVM):** Deterministic immediate block
  finality (zero probabilistic reorgs once committed by 3-of-4 validators),
  zero-gas-price private operation (`min-gas-price = 0`, `baseFeePerGas = 0`),
  and native EVM contract/Safe ecosystem. *Limitation:* Besu QBFT does not
  support the PoS `finalized` RPC tag — all adapters use `latest` as the
  committed head and pin multi-call reads to an explicit block number.
- **Private Kubo + IPFS Cluster:** Content-addressed immutability (CIDv1
  `raw` / `dag-pb` with `sha2-256`) plus CRDT-coordinated multi-peer pinning
  (`MIN_PIN_REPLICAS`) across independent consortium storage hosts. *Limitation:*
  Local development runs two peers on one Docker host (single failure domain);
  Kubo `0.43.1` requires private LAN DHT + legacy provider settings for local
  discovery ([ADR](../adr/local-integration-verification.md)).
- **PostgreSQL (`metadata_store` + `indexer` + `gateway`):** Atomic ACID
  transactions for single-use login challenges, one-time access nonces,
  multi-replica token-bucket rate limits, append-only hash-chained audit logs,
  and fast SQL file/history projections. *Limitation:* Projections are strictly
  non-authoritative (`authoritative: false`) and can lag the committed block
  head; all authorization decisions hit Besu directly.

## 4. Explicit System Limitations (MVP Scope)

1. **No retroactive cryptographic erasure:** Revoking a member or suspending an
   endpoint stops future authorized access and excludes them from future DEKs,
   but cannot erase plaintext or DEKs already copied prior to revocation.
2. **No `trustedVersion` flag on-chain:** Cryptographic signatures prove author
   identity and immutability, not that uploaded bytes are malware-free. Clean
   version selection during recovery requires human/operational review.
3. **Display names and folder hierarchy visibility:** File display names and
   folder structure are stored on-chain in `FileRegistry` for consortium
   browsing; confidential metadata must be placed in chunk-0 encrypted private
   metadata.
4. **MVP software key custody (HSM deferred post-MVP):** The MVP runs with
   `DevelopmentKeyCustody` (CLI) and `DevelopmentRelayerSigner` (gateway),
   explicitly gated behind `RRDS_ALLOW_UNSAFE_DEV_CUSTODY=true` /
   `GATEWAY_ALLOW_UNSAFE_DEV_RELAYER=true` and refused by
   `CustodyStartupPolicy::Production`, `RelayerStartupPolicy::Production`, and
   `RRDS_ENV=production`. Production PKCS#11 / vendor HSM adapters remain
   deferred post-MVP behind the existing `KeyCustodyProvider` and
   `RelayerSigner` traits (see
   [`docs/operations/consortium-policies.md`](../operations/consortium-policies.md)).
5. **Audit stream vs. full client receipt:** Gateway content-streaming audits
   prove authorized stream start, not full client reception or decryption.
