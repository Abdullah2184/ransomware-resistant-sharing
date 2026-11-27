# RRDS System Architecture

This directory documents the system architecture, trust boundaries, deployment
placement, and core security workflows defined by
[`TECHNICAL_SPECIFICATION.md`](../specifications/TECHNICAL_SPECIFICATION.md) and the
accepted ADRs under [`docs/adr/`](../adr/).

## Architecture Subdocuments

- [Deployment Placement, Crate Boundaries & Data Isolation](deployment-and-boundaries.md)
  — Allowed crate/service dependency graph, prohibited cross-system paths,
  plaintext/key isolation rules, PostgreSQL role separation, and authoritative
  vs. projected data access.
- [Cryptography, Key Custody & Encrypted Storage Pipeline](cryptography-custody-and-storage.md)
  — AES-256-GCM 1 MiB chunked encryption, RFC 9180 HPKE key wrapping &
  canonical envelope sets, `KeyCustodyProvider` invariants, `RRDSPKG1` staging,
  multi-peer Kubo/Cluster replication, and CARv1 pre-unwrap verification.
- [Authentication and Challenge-Response Login](authentication-and-challenge.md)
  — One-time EIP-712 login challenges, session token handling and revocation,
  multi-budget rate limiting, per-operation EIP-712 authorization signatures,
  and append-only audit chaining.
- [Historical Access Model](historical-access.md) — Current-head vs.
  version-scoped historical read access, Read-ACL revocation epochs, and
  envelope-set requirements.
- [Data Recovery and Key Revocation](recovery-and-revocation.md) — Ransomware
  and endpoint compromise response, append-only restore/revert, Read/Write
  revocation, emergency suspension, key supersession, and cryptographic limits.

## System Topology and Deployment Placement

In production, components are separated across distinct hosts and trust domains.
Development Compose files co-locate infrastructure for convenience only and do
not represent production isolation (see [`infra/compose/`](../../infra/compose/README.md)
for production-separated per-role templates).

| Deployment System / Host | Repository Modules | Trust Boundary & Responsibilities |
| --- | --- | --- |
| **User / Client Endpoint** | `apps/cli`, `crates/application`, `crates/crypto`, `crates/key_custody`, `crates/scanner` | Local plaintext encryption/decryption (AES-256-GCM), RFC 9180 HPKE DEK wrapping, CARv1 verification, pre-upload scanning (`DisabledScanner` default), and EIP-712 signing via key custody (`KeyCustodyProvider`). Plaintext and unwrapped DEKs exist transiently here only; communicates exclusively over HTTPS with the gateway. |
| **Organization Gateway Server** | `services/gateway` (`routes/{mod,middleware,auth,reads,writes,blobs}`), `crates/ipfs_adapter`, `crates/chain_adapter`, `crates/metadata_store` | Authenticated HTTPS API, `X-Request-Id` & structured JSON logging, multi-budget PostgreSQL rate limiting (`src:*`, `member:*`, `invalid_sig_src:*`), authoritative `eth_call` authorization at a single QBFT-committed block, append-only hash-chained PostgreSQL audit logging (`rrfs_gateway` role), ACL-checked ciphertext staging/streaming, and Type-2 transaction relay (`RelayerSigner`). Never handles plaintext or unwrapped DEKs. |
| **Organization Indexer & Database Server** | `services/indexer`, `crates/metadata_store` (`MigrationMode::Verify` default, migrations `0001`–`0006`), `infra/postgres/` | Consumes finalized Besu QBFT contract events into rebuildable PostgreSQL read projections under the least-privilege `rrfs_indexer` role (`rrfs_migrator` owns DDL). Never serves as the authorization authority and has zero access to `gateway_*` tables. |
| **Consortium IPFS / Cluster Storage Peers** | `infra/ipfs-cluster/` (Kubo `0.43.1` + IPFS Cluster `1.1.6`) | Private-swarm encrypted content packages (2-level UnixFS directories) and immutable envelope sets replicated across independent consortium peers with Kubo's public HTTP gateway disabled (`Addresses.Gateway ""`). Kubo/Cluster APIs are never exposed to client endpoints. |
| **Consortium Blockchain Validators & RPC Nodes** | `contracts/`, `infra/besu-qbft/` (`AccessGovernance`, `FileRegistry`, `RrdsTimelockController`) | Permissioned Hyperledger Besu QBFT network (at least 4 independent validators, 3-of-4 quorum) plus non-validator RPC nodes. Authoritative source of truth for identities, key versions, ACLs, file/version history, current heads, and envelope-set pointers. |

### Indexing Placement Note

Canonical event indexing runs on the **organization server** (`services/indexer`
co-located with PostgreSQL and a trusted Besu RPC node), not on user endpoints.
Endpoint-side indexing would require exposing Besu JSON-RPC directly to
untrusted endpoints, syncing all consortium on-chain events to every user
machine, and maintaining local checkpoint databases on endpoints. Server-side
indexing keeps RPC and PostgreSQL inside the organization boundary while serving
file/folder and history queries over local SQL; endpoints may optionally cache
non-authoritative listings keyed by `finalizedBlock` cursors.
