# RRDS System Architecture

This directory documents the system architecture, trust boundaries, deployment
placement, and core security workflows defined by
[`TECHNICAL_SPECIFICATION.md`](../specifications/TECHNICAL_SPECIFICATION.md) and the
accepted ADRs under [`docs/adr/`](../adr/).

## Architecture Subdocuments

- [Deployment Placement, Crate Boundaries & Data Isolation](deployment-and-boundaries.md)
  — Allowed crate/service dependency graph, prohibited cross-system paths,
  plaintext/key isolation rules, and authoritative vs. projected data access.
- [Authentication and Challenge-Response Login](authentication-and-challenge.md)
  — One-time EIP-712 login challenges, session token handling, and per-operation
  EIP-712 authorization signatures.
- [Historical Access Model](historical-access.md) — Current-head vs.
  version-scoped historical read access, Read-ACL revocation epochs, and
  envelope-set requirements.
- [Data Recovery and Key Revocation](recovery-and-revocation.md) — Ransomware
  and endpoint compromise response, append-only restore/revert, Read/Write
  revocation, emergency suspension, key supersession, and cryptographic limits.

## System Topology and Deployment Placement

In production, components are separated across distinct hosts and trust domains.
Development Compose files co-locate infrastructure for convenience only and do
not represent production isolation.

| Deployment System / Host | Repository Modules | Trust Boundary & Responsibilities |
| --- | --- | --- |
| **User / Client Endpoint** | `apps/cli`, `crates/application`, `crates/crypto`, `crates/key_custody`, `crates/scanner` | Local plaintext encryption/decryption (AES-256-GCM), HPKE DEK wrapping, EIP-712 signing via hardware key custody (`KeyCustodyProvider`). Plaintext and unwrapped DEKs exist transiently here only. |
| **Organization Gateway Server** | `services/gateway`, `crates/ipfs_adapter`, `crates/chain_adapter`, `crates/metadata_store` | Authenticated HTTPS API, multi-replica rate limiting, authoritative `eth_call` authorization at a single QBFT-committed block, append-only hash-chained PostgreSQL audit logging, ciphertext streaming, and Ethereum transaction relay. Never handles plaintext or unwrapped DEKs. |
| **Organization Indexer & Database Server** | `services/indexer`, `crates/metadata_store` (PostgreSQL) | Consumes finalized Besu QBFT contract events into rebuildable PostgreSQL read projections for browsing/history. Never serves as the authorization authority. |
| **Consortium IPFS / Cluster Storage Peers** | `infra/ipfs-cluster/` (Kubo + IPFS Cluster) | Private-swarm encrypted content packages and immutable envelope sets replicated across independent consortium peers. Kubo/Cluster admin APIs are never exposed to client endpoints. |
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
