
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
docker compose --env-file .env -f infra/compose.yaml up -d
```

The script generates private-network and Cluster credentials into an ignored
local secrets directory and never prints their values. Kubo APIs are published
only on host loopback ports `127.0.0.1:15001` and `127.0.0.1:15002` for the
host-run gateway; the Kubo gateways and swarm ports remain unpublished. Only
the authenticated Cluster management API is published at `127.0.0.1:9094`.
See [the local Kubo API ADR](docs/adr/host-loopback-kubo-api-for-development.md).

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
passes 39 tests (32 Solidity, 7 TypeScript). The optimized
`AccessGovernance` runtime is 17,229 bytes, below the 24,576-byte EIP-170
limit; local Besu deployment and actual Safe integration remain unverified.

The deployment increment now includes an OpenZeppelin `TimelockController`
module with a 24-hour consortium-Safe proposal delay, permissionless execution,
and no deployer admin bypass. It deliberately withholds `FILE_REGISTRY_ROLE`;
file creation remains disabled until the Safe schedules and executes that role
grant after the delay. Solidity tests exercise the delay and activation path.
They do not establish an actual Safe deployment or Besu QBFT compatibility.

Phase 3 implements an asynchronous encrypted-content `BlobStore` port, the
Kubo/Cluster adapter, a Besu JSON-RPC client that reads the QBFT committed
head, and
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

The indexer stores raw decoded QBFT-finalized events and checkpoints atomically,
rejects chain/checkpoint mismatches, and prevents database projections from
authorizing access. Key-version events are included in the contract and
decoded to rebuild member signing/encryption key history. Operator recovery
modes are available: `indexer --rebuild-projections` reconstructs projections
from persisted finalized events; `indexer --reindex-from-chain` clears only
derived index data for the configured chain and replays from
`INDEXER_START_BLOCK`. The latter requires the Besu node to retain that event
history. Required indexer values are listed in `.env.example`.

Phase 4 includes one-time, audience-bound EIP-712 login challenges, signature
verification against the active member signing key at QBFT-committed Besu state,
short-lived sessions, PostgreSQL-backed single-use challenge/session state,
shared source-address token buckets, and an append-only hash-chained
authentication audit stream. It also provides signed access lookup with
finalized member, file Read ACL, head, version and envelope-pointer checks;
successful and failed lookups are durably audited before any CID is returned.
Historical versions require explicit version-scoped grants. Contract
grant/revoke state, finalized chain queries, gateway enforcement and indexer
projection are implemented; a Read-ACL epoch prevents old grants from
resurfacing after revoke/regrant. Session tokens are returned once and stored
only as hashes. The listener verifies its configured chain ID at startup,
defaults to loopback, and refuses non-loopback binds until TLS termination is
configured. See [services/gateway/README.md](services/gateway/README.md),
[docs/api.md](docs/api.md),
[the authentication ADR](docs/adr/gateway-authentication-and-audit.md), and
[the historical-access ADR](docs/adr/version-scoped-historical-read-access.md).

The gateway access-lookup route permits current-head versions under the file
Read ACL and requires an explicit historical grant for older versions. It
checks these conditions at one finalized block and durably audits before
returning CIDs. The ciphertext route repeats those checks, audits before
streaming the encrypted IPFS CAR, and never handles plaintext. Client-side
manifest validation, envelope construction and recipient-membership checks,
decryption, identity-directory/file/history listings, PostgreSQL role
separation, audit-query controls, session revocation, full governance proposal
workflows, production key custody, and end-to-end acceptance tests remain
outstanding. The PostgreSQL audit service records authorization before
streaming, not successful full receipt by the client.

The gateway now also exposes `GET /v1/identities/{memberId}`. It reads public
member identity and key status from `AccessGovernance.memberIdentity` at one
QBFT-committed block and returns that block's number and hash. It is
source-rate-limited and does not rely on the identity projection for
authoritative values. File/folder listings, version history, audit queries,
and state-changing routes remain outstanding.

## Takeover progress (12 November 2026)

The initial review found the Rust workspace could not compile: the access
lookup route passed a typed-digest wrapper to a recovery helper expecting its
32-byte digest. This is fixed by passing the wrapper's bytes without changing
the EIP-712 operation. The missing gateway `crypto` dependency is now reflected
in `Cargo.lock`. A finalized-state chain helper was connected to its member
lookup, and strict Clippy findings were addressed.

Verification after these changes: Rust workspace tests pass (69 passed, one
live-Cluster test ignored); Hardhat passes 39 tests (32 Solidity, 7 TypeScript);
formatting, strict Clippy, and `git diff --check` pass. PostgreSQL-backed tests
were also run with the URL from the ignored local `.env`, but the database
connection timed out. Compose resolved `.env` when passed explicitly, then
reported that the Docker Desktop Engine named pipe is absent. Manual action:
start Docker Desktop with its Linux Engine, then run
`docker compose --env-file .env -f infra/compose.yaml up -d` and rerun
PostgreSQL/Cluster integration checks. No credential edits are currently
needed. The IPFS/PostgreSQL Compose project does not provision Besu; the
separate `infra/besu-qbft/compose.yaml` provides the local QBFT network. Full
gateway startup also requires deployed contract addresses in `.env`. The live
two-peer Cluster test remains unverified as documented above.
Phase 3 functionality has component and PostgreSQL integration coverage, but
live two-peer replication and the full storage/indexer application workflow
are **not verified**. Do not treat this as overall MVP acceptance.

Rust verification for this increment:

```shell
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The full Rust workspace previously passed with 67 tests and one ignored live-Cluster test;
strict Clippy with warnings denied, formatting, and `git diff --check` also
passed. Gateway tests cover typed-data signature recovery and domain binding,
request JSON shape, challenge replay rejection, session token hashing,
transactional audit-chain integrity, and shared rate-limit buckets. The
focused run also verified the new PostgreSQL migration and finalized-state
member lookup. The live two-peer IPFS test remains ignored pending a verified
Cluster quorum. The Hardhat suite previously passed 37 tests (30 Solidity, 7 TypeScript),
including a shared Rust/`viem` login-challenge digest vector. PostgreSQL
integration tests applied additive migrations; rollback-only feature tests do
not reset or delete persistent database data.

## Verification follow-up (12 November 2026)

The local Docker stack is now running. Compose recreated Kubo, Kubo 2, and
PostgreSQL without removing named volumes; all five services reported healthy.
Both Kubo daemons report version `0.43.1`. Authenticated Cluster peer listing
shows two distinct peers seeing one another. The documented replication
verifier added one non-sensitive test object and waited for its two-peer pin:
Cluster 1 reported `PINNED`, while Cluster 2 ended in `PIN_ERROR: context
canceled`. Two-replica storage is still **not verified**. The failed object is
left pinned as the verifier documents; no content or volume was deleted.

The current Compose configuration includes loopback bindings for Kubo APIs on
`127.0.0.1:15001` and `127.0.0.1:15002`. Docker reports those bindings in the
container configuration, but requests from this coding environment to those
host ports are refused. PostgreSQL tests similarly cannot connect from this
shell after the containers were recreated. This is a host-to-Docker transport
limitation under investigation; service health inside Docker does not establish
host application connectivity.

The previous `rrfs_dev` database has SQLx migration versions 1–3 recorded.
Its version 3 checksum differs from the checked-in immutable migration file.
After rebuilding the stale metadata-store artifact, the test correctly
reported `VersionMismatch(3)`. We have not altered the database or its
migration history. A dedicated empty database, `rrfs_indexer_test`, was
created for safe integration verification, but this shell could not reach its
published PostgreSQL port. Running the Rust test binary inside the PostgreSQL
container was not viable because the host-built executable requires a newer
glibc than that container provides. The attempted Rust test-runner image pull
was stopped before completion.

The infrastructure investigation is paused at this point rather than changing
persistent data or migration checksums. Next actions when resumed: run tests
from a Docker-networked Rust runner; inspect and reconcile the pre-existing
`rrfs_dev` migration history through an additive, reviewed path; and diagnose
Cluster 2's pin failure from its Kubo/Cluster logs and peer allocations. See
[`docs/adr/local-integration-verification.md`](docs/adr/local-integration-verification.md)
and [the local Cluster status](infra/ipfs-cluster/README.md).

The separate Besu network setup is running. Its pinned image is Besu 26.11.0;
the Compose definition has four validators plus a non-validator RPC node, with
the RPC API bound to loopback. Genesis and validator keys are generated locally
by the preparation script and are ignored by Git. Validators are producing
blocks and the RPC node has four peers. The RPC endpoint is published only to
host loopback. Verification confirmed chain ID 1337, four connected validator
peers, four configured validators, and QBFT-committed block 969. Docker's
generic `finalized` tag does not apply to this QBFT chain; the chain adapter
uses the latest committed QBFT head and contract reads use its explicit block
number. The initial Docker `internal: true` setting also prevented port
publication and has been removed while leaving validator ports unpublished.
See
[`infra/besu-qbft/README.md`](infra/besu-qbft/README.md) and
[`docs/adr/local-besu-qbft-network.md`](docs/adr/local-besu-qbft-network.md).

The Rust workspace all-target tests pass after the QBFT finality correction.
Database tests skip unless `DATABASE_URL` is explicitly configured; it was
unset in this run. The live Kubo replication test remains ignored because the
earlier two-peer verification reported a Cluster pin error. Contract
deployment and gateway end-to-end verification remain outstanding.

Phase 5 CLI work has started with a credential-free `rrds health [gateway-url]`
command that checks the existing `/healthz` route. Its two configuration tests
pass offline. This checks only the HTTP health route, not dependencies such as
PostgreSQL, Besu, or IPFS. The specification's remaining CLI use cases
(identity registration/display, listings, upload, download, modify, history,
sharing, revocation, and recovery) are not available end-to-end: the gateway
currently lacks those routes and the `application` crate has no use-case
services. See [the CLI README](apps/cli/README.md) and
[the Phase 5 CLI ADR](docs/adr/phase-5-cli-incremental-scope.md).

**Integration verification update (12 November 2026):** the workspace test
suite passes offline when allowed to open the local TCP listeners required by
chain-adapter tests. The live Cluster check still fails replication: Kubo 2
sees the CID in its Bitswap wantlist but has zero Bitswap partners, and a
provider lookup finds none, while Kubo and Cluster membership are connected.
The cause remains under investigation. PostgreSQL contains the isolated
`rrfs_indexer_test` database, but the current shell cannot reach the published
port; `rrfs_dev` and persistent volumes were left unchanged. The indexer README
now correctly describes the QBFT committed head rather than Besu's generic
`finalized` tag. See [`progress_report.md`](progress_report.md) and
[`docs/adr/local-integration-verification.md`](docs/adr/local-integration-verification.md).

**Replication verification update (12 November 2026):** the two-peer Cluster
check now passes after configuring Kubo 0.43.1 with a private LAN DHT and its
legacy provider for custom DHT routing. Both Cluster peers report the test CID
`PINNED` with zero attempts, and Kubo 2 retrieves it from Kubo 1. The nodes
remain on one host and do not demonstrate independent replica administration.
PostgreSQL integration and host-side port checks remain open.
