
# Blockchain-Based Ransomware-Resistant Data Sharing

A consortium-based encrypted file-sharing and recovery system using
permissioned blockchain, IPFS and hardware-backed key custody.

## Project Overview

The system provides:
- Client-side file encryption.
- Distributed encrypted file storage through IPFS.
- File versioning and immutable audit history.
- Identity-based Read and Write access control.
- Multisignature governance.
- Historical file recovery.

## Technical Specification

See [TECHNICAL_SPECIFICATION.md](TECHNICAL_SPECIFICATION.md)
for the architecture, technology stack, module responsibilities,
cryptographic protocols, functional requirements and implementation plan.

## Technology Stack

- Rust — application core and off-chain services.
- Solidity — smart contracts.
- Hardhat — contract development and testing.
- Hyperledger Besu / QBFT — permissioned blockchain.
- IPFS / IPFS Cluster — encrypted file storage.
- PostgreSQL — indexer and gateway operational data.
- HSM — protected key custody.

## Development setup

The verified local toolchain is pinned to Rust `1.99.1`, Node.js `26.13.0`,
pnpm `12.18.0`, Hardhat `3.21.2`, Solidity `0.8.34`, SQLx `0.9.0`, Tokio
`1.54.1`, PostgreSQL `18.6`, Kubo `0.43.1`, and IPFS Cluster `1.1.6`.
Rust and JavaScript dependency selections are locked in `Cargo.lock` and
`contracts/pnpm-lock.yaml`.
The first Rust feature increment pins `aes-gcm` `0.11.1`, `cid` `0.11.3`,
`getrandom` `0.3.4`, and `zeroize` `1.8.2`; their resolved dependency graph is
locked in `Cargo.lock`.

The existing `.env` is local-only and must not be copied, printed, committed,
or replaced. Create/update local values yourself from `.env.example` and keep
private keys in the Hardhat keystore or an approved key-custody provider.

Initialize local IPFS Cluster secrets once, then start the services:

```shell
sh infra/ipfs-cluster/init-secrets.sh
docker compose -f infra/compose.yaml up -d
```

The script generates private-network and Cluster credentials into an ignored
local secrets directory and never prints their values. Both Kubo APIs and
gateways remain private to the Compose network. Only the authenticated
Cluster management API is published on loopback at `127.0.0.1:9094`.

The two local peers are a development replication test only. They share one
host, Docker daemon, and failure domain; this does not demonstrate
two-organization independence. Current Kubo/Cluster status and the remaining
replication verification failure are recorded in
[infra/ipfs-cluster/README.md](infra/ipfs-cluster/README.md).

## Implementation status

The domain foundation now provides typed identifiers, validated CIDv1 types,
the stable domain error taxonomy, and an append-only version graph. The crypto
crate provides stateful AES-256-GCM chunk encryption/decryption with
zeroizing key/plaintext buffers and context-bound authentication. It now also
provides RFC 9180 base-mode HPKE wrapping using the specified
X25519/HKDF-SHA256/AES-256-GCM suite, with file/version/epoch/member/key-version
context binding and negative tests for recipient, encapsulation, ciphertext,
and context changes. It validates and canonically serializes versioned
encrypted-content manifests from specification §6.1, including
chunk order/count/lengths, supported suite identifiers, canonical CIDv1 and
base64url encodings, and nonce-index-zero encrypted metadata. The JSON Schema
is `schemas/encrypted-file-manifest-v1.json`. It also validates and
canonically serializes §6.2 envelope sets, enforcing the approved maximum of
1,024 sorted, unique members and structurally checking HPKE envelope bytes;
the JSON Schema is `schemas/key-envelope-set-v1.json`. A round-trip test
confirms a serialized envelope can be unwrapped by its recipient.

The `ports` crate now defines the asynchronous key-custody boundary.
`key-custody` provides a software-only development provider with recoverable
secp256k1 signing and HPKE unwrap tests. There is not yet a hardware adapter or
a production-startup guard against the test-only provider. Published and
cross-implementation HPKE vectors remain incomplete.

The crypto signing module now builds EIP-712 digests for version append,
access lookup and envelope-set update under the approved schemas in
[`docs/adr/eip712-operation-schemas.md`](docs/adr/eip712-operation-schemas.md).
Rust digests match shared `viem` vectors. These tests establish digest
encoding. Solidity hashing and the Rust/`viem` vectors now agree, and
contract-side signature recovery and authorization are exercised by tests.

The Phase 2 contract increment implements `AccessGovernance` and
`FileRegistry`: organization/member lifecycle and key state, signing-key
proof-of-possession, separate per-file Read/Write ACLs, policy authorities,
emergency suspension, signed envelope pointer updates, signed file creation
and version appends, immutable version history, stale-head and nonce/deadline
rejection, canonical CIDv1 validation, and organization-scoped folders with
stable IDs and immutable parents. Signing and encryption public-key versions
remain queryable after supersession, while prior key versions have explicit
statuses. New ACL grants require an active member, and envelope updates
require an active Read-ACL actor. File metadata changes follow the configured
file metadata policy Safe instead of granting the timelock an implicit bypass.
File creation atomically initializes the signed creator's Read and Write
grants, file policy, first version and initial envelope pointer, as approved
and documented in the governance ADR and §7.1.1. The Hardhat suite passes all
35 tests (29 Solidity, 6 TypeScript). The optimized
`AccessGovernance` runtime is 15,820 bytes, below the 24,576-byte EIP-170
limit; local Besu deployment and actual Safe integration remain unverified.

The deployment increment now includes an OpenZeppelin `TimelockController`
module with a 24-hour consortium-Safe proposal delay, permissionless execution,
and no deployer admin bypass. It deliberately withholds `FILE_REGISTRY_ROLE`;
file creation remains disabled until the Safe schedules and executes that role
grant after the delay. Solidity tests exercise the delay and activation path.
They do not establish an actual Safe deployment or Besu QBFT compatibility.

Phase 3 now has an asynchronous encrypted-content `BlobStore` port, an initial
Kubo/Cluster adapter, a Besu JSON-RPC client that requires finalized state, an
additive PostgreSQL projection migration, and an event decoder/indexer with
transactional event insertion, checkpointing, and file-head reconciliation.
The approved UnixFS package profile is recorded in
[`docs/adr/content-package-unixfs-profile.md`](docs/adr/content-package-unixfs-profile.md).
The adapter checks manifest and chunk CIDs returned by Kubo and waits for the
requested number of distinct Cluster peers before reporting a successful
write. Its live two-peer integration test is ignored by default; local
replication remains unverified because Cluster peer 2 reports `PIN_ERROR`.
See [infra/ipfs-cluster/README.md](infra/ipfs-cluster/README.md); Kubo/Cluster
configuration is intentionally left for manual follow-up.

Phase 3 is **in progress, not complete**. The indexer does not yet implement a
full projection rebuild or reorg recovery, member-key projection initialization
is incomplete because current registration events omit key versions, and the
reconciliation currently checks file heads only. The PostgreSQL audit service,
gateway, full governance proposal workflows, production key custody, and
cross-component acceptance tests remain outstanding. The PostgreSQL
connection test and domain/crypto/decoder/adapter unit tests are useful
component checks, not evidence that the system meets all security or
functional acceptance criteria in `TECHNICAL_SPECIFICATION.md`.

Rust verification for this increment:

```shell
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

All commands passed: 51 Rust tests passed and the live two-peer IPFS
integration test was ignored because the Cluster replication issue remains.
The PostgreSQL integration test applied the additive indexer migration and
confirmed that rerunning it is a no-op; it did not reset or delete database
data.
