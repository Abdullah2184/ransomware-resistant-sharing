
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
pnpm `12.18.0`, Hardhat `3.21.2`, Solidity `0.8.34`, Axum `0.8.9`, SQLx
`0.9.0`, Tokio `1.54.1`, PostgreSQL `18.6`, Kubo `0.43.1`, and IPFS Cluster
`1.1.6`.
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
and documented in the governance ADR and §7.1.1. The current Hardhat suite
passes 37 tests (30 Solidity, 7 TypeScript). The optimized
`AccessGovernance` runtime is 15,820 bytes, below the 24,576-byte EIP-170
limit; local Besu deployment and actual Safe integration remain unverified.

The deployment increment now includes an OpenZeppelin `TimelockController`
module with a 24-hour consortium-Safe proposal delay, permissionless execution,
and no deployer admin bypass. It deliberately withholds `FILE_REGISTRY_ROLE`;
file creation remains disabled until the Safe schedules and executes that role
grant after the delay. Solidity tests exercise the delay and activation path.
They do not establish an actual Safe deployment or Besu QBFT compatibility.

Phase 3 implements an asynchronous encrypted-content `BlobStore` port, the
Kubo/Cluster adapter, a Besu JSON-RPC client that requires finalized state, and
a PostgreSQL projection/indexer pipeline with transactional event insertion,
checkpoints, event replay, identity/ACL/file/version/envelope projections, and
file-head reconciliation against finalized contract state.
The approved UnixFS package profile is recorded in
[`docs/adr/content-package-unixfs-profile.md`](docs/adr/content-package-unixfs-profile.md).
The storage adapter verifies imported manifest/chunk CIDs, hashes the retrieved
root block against its CID, supports bounded retries over configured Kubo
endpoints, and waits for authenticated status from the required number of
distinct Cluster peers before returning write success. The live two-peer
integration test is ignored by default: local replication remains unverified
because Cluster peer 2 reported `PIN_ERROR`. See
[infra/ipfs-cluster/README.md](infra/ipfs-cluster/README.md); further Kubo/
Cluster configuration work is deferred for manual follow-up.

The indexer stores raw decoded finalized events and checkpoints atomically,
rejects chain/checkpoint mismatches, and prevents database projections from
authorizing access. Key-version events are included in the contract and
decoded to rebuild member signing/encryption key history. Operator recovery
modes are available: `indexer --rebuild-projections` reconstructs projections
from persisted finalized events; `indexer --reindex-from-chain` clears only
derived index data for the configured chain and replays from
`INDEXER_START_BLOCK`. The latter requires the Besu node to retain that event
history. Required indexer values are listed in `.env.example`.

The first Phase 4 gateway increment adds one-time, audience-bound EIP-712
login challenges, signature verification against the active member signing
key at finalized Besu state, short-lived sessions, PostgreSQL-backed
single-use challenge/session state, shared source-address token buckets, and
an append-only hash-chained authentication audit stream. Session tokens are
returned once and stored only as hashes; session inspection audits before
returning the authenticated member ID. Challenge consumption, session
creation, and successful-login audit append are one database transaction.
The listener verifies its configured chain ID against Besu at startup,
defaults to loopback, and refuses non-loopback binds until TLS termination is
configured. Rust and `viem` share a passing EIP-712 challenge digest fixture.
See [services/gateway/README.md](services/gateway/README.md),
[docs/api.md](docs/api.md), and the
[gateway authentication ADR](docs/adr/gateway-authentication-and-audit.md).

Protected file/content routes, authoritative per-file ACL checks,
audit-before-CID/ciphertext release, PostgreSQL role separation, audit-query
controls, session revocation, full governance proposal workflows, production
key custody, and end-to-end acceptance tests remain outstanding. Auth route
errors are rate-limited and audited, but malformed HTTP requests rejected
before routing are not. The PostgreSQL audit service currently covers only
gateway authentication.
Phase 3 functionality has component and PostgreSQL integration coverage, but
live two-peer replication and the full storage/indexer application workflow
are **not verified**. Do not treat this as overall MVP acceptance.

Rust verification for this increment:

```shell
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The full Rust workspace passed with 67 tests and one ignored live-Cluster test;
strict Clippy with warnings denied, formatting, and `git diff --check` also
passed. Gateway tests cover typed-data signature recovery and domain binding,
request JSON shape, challenge replay rejection, session token hashing,
transactional audit-chain integrity, and shared rate-limit buckets. The
focused run also verified the new PostgreSQL migration and finalized-state
member lookup. The live two-peer IPFS test remains ignored pending a verified
Cluster quorum. The Hardhat suite passed 37 tests (30 Solidity, 7 TypeScript),
including a shared Rust/`viem` login-challenge digest vector. PostgreSQL
integration tests applied additive migrations; rollback-only feature tests do
not reset or delete persistent database data.
