# RRDS Threat Model & Security Boundaries

This document consolidates the system threat model, adversary assumptions,
enforced mitigations, and explicit non-goals derived from
[`TECHNICAL_SPECIFICATION.md`](specifications/TECHNICAL_SPECIFICATION.md)
(§§1, 4, 5, 8, 10.4, 14) and the architecture records under [`docs/adr/`](adr/).

---

## 1. Security Goals

1. **Confidentiality:** Plaintext file bytes and unwrapped Data Encryption Keys
   (DEKs) exist transiently only inside the authorized client process. Gateways,
   indexers, PostgreSQL databases, Kubo/Cluster storage peers, and Besu
   validators never see plaintext or raw DEKs.
2. **Integrity & Ransomware Resilience:** File versions are immutable,
   linearly chained (`V1 -> V2 -> ...`), and cryptographically authenticated
   (CIDv1 content addressing + AES-256-GCM chunk AAD/tags). Ransomware with
   write access cannot erase or rewrite prior clean versions.
3. **Authoritative Access Control:** Smart contracts (`AccessGovernance` and
   `FileRegistry`) are the sole source of truth for identity status, Read/Write
   ACLs, historical version grants, and current envelope pointers. Off-chain
   projections never authorize access.
4. **Accountability & Non-Repudiation:** All state-changing operations require
   EIP-712 member signatures; routine reads require signed `AccessLookup`
   requests (atomic nonce consumption in PostgreSQL) and fail-closed
   hash-chained PostgreSQL audit commits prior to releasing CIDs or ciphertext.

---

## 2. Adversaries & Mitigations

| Adversary / Failure Mode | Capabilities | Enforced Mitigations | Explicit Residual Risk / Limit |
| --- | --- | --- | --- |
| **Compromised user endpoint (ransomware / malware)** | Can encrypt local files, read plaintext actively opened on the endpoint, invoke local CLI with the user's session/HSM while unlocked. | Append-only versioning (`FileRegistry` never deletes/overwrites prior versions); separate signing vs encryption keys; per-version fresh DEKs; emergency suspension via `EMERGENCY_SUSPENDER_ROLE`; optional client-side `PreUploadScanner` (defense-in-depth, disabled by default); append-only `rrds restore` from a clean machine. | Cannot prevent an active endpoint compromise from exfiltrating plaintext currently open in memory or submitting a malicious *new* version while the member has Write ACL (there is intentionally no on-chain `trustedVersion` flag). |
| **Compromised or bypassed Organization Gateway / Relayer** | Controls HTTP API, relayer Ethereum private key, and PostgreSQL gateway role. | Gateway never receives plaintext or unwrapped DEKs (client-first encryption; `POST /v1/blobs/*` accepts ciphertext/envelopes only). Contracts ignore `msg.sender` for author identity and recover EIP-712 member signatures; a compromised relayer cannot forge member signatures or bypass ACLs/timelock. Least-privilege PostgreSQL roles prevent `rrfs_gateway` from updating/deleting audit rows. | Can deny service, drop/delay relayed transactions, or observe traffic metadata (timing, sizes, member IDs). Routine read audit relies on gateway honesty; direct peer-level IPFS access bypassing the gateway is outside gateway audit visibility. |
| **Compromised Storage Peer (Kubo / IPFS Cluster)** | Can read any pinned block, serve corrupted bytes, or go offline. | All content packages are AES-256-GCM encrypted with per-version DEKs and context-bound AAD (`fileId`, `versionNumber`, `epochId`, `chunkIndex`, `totalChunks`); envelope sets use RFC 9180 HPKE (`X25519 / HKDF-SHA256 / AES-256-GCM`). Clients verify raw-block SHA-256 CIDs (CARv1) and every GCM tag before atomic `0600` output. Pin-before-commit quorum (`MIN_PIN_REPLICAS`) + multi-peer Kubo failover tolerate single-peer outage. | Can cause availability degradation if enough independent peers fail simultaneously; CIDs and ciphertext lengths are visible to consortium storage operators. |
| **Compromised / Lagging PostgreSQL or Indexer** | Serves stale or altered file listings / version history. | Indexer is strictly non-authoritative (`authoritative: false` with `finalizedBlock`/`indexedBlock` cursors). Gateway verifies ACLs, member status, version existence, and current envelope pointers directly via Besu `eth_call` at a recorded QBFT-committed block. Projections are fully rebuildable (`--rebuild-projections`, `--reindex-from-chain`). | Stale indexer data can temporarily degrade discovery/UI browsing availability, but never grants unauthorized access. |
| **Revoked / Departed Consortium Member** | Retains previously downloaded ciphertext, old wrapped DEKs, or cached plaintext. | Revoking Read ACL removes future-version envelopes (fresh DEK per version), atomically increments `readPermissionEpochs` to invalidate all prior version-scoped historical grants, and blocks gateway retrieval. Revoking Write ACL immediately rejects future appends on-chain. | **Cryptographic limit (§9.6):** Cannot erase plaintext or DEKs a revoked member already legitimately obtained for prior versions. |
| **Replay, Cross-Domain, or DoS Attacker** | Replays captured challenges/signatures across endpoints, contracts, or chains; floods unauthenticated endpoints or spoofs victim member IDs. | EIP-712 domain separation (`chainId` + `verifyingContract` + domain name/version); one-time nonces + deadlines consumed atomically on-chain (writes) or in PostgreSQL (challenges & `AccessLookup`); low-`s` canonical ECDSA; multi-budget PostgreSQL token-bucket rate limiting (`src:*`, `member:*`, separate `invalid_sig_src:*` preventing victim lockout); `DELETE /v1/auth/session` revocation. | Single-gateway instances still require network-layer DDoS protection and TLS termination in production. |
| **Rogue Deployer or Single Admin Compromise** | Attempts to silently grant roles, alter org authorities, or reinstate a suspended member. | Deployer holds zero admin roles after construction. `RrdsTimelockController` (24-hour `86,400`s delay) is sole `DEFAULT_ADMIN_ROLE` on `AccessGovernance`; `EMERGENCY_SUSPENDER_ROLE` is suspend-only; consortium & org authorities are external Safe threshold accounts. | Local smoke tests use dev-only EOA placeholders until real Safe smart accounts are deployed on Besu (documented in `contracts/README.md`). |

---

## 3. Metadata Visibility Policy (MVP)

Per [`TECHNICAL_SPECIFICATION.md`](specifications/TECHNICAL_SPECIFICATION.md) §2 #14 and §17 #7:
- **Visible to consortium participants on-chain:** `fileId`, `displayName`, `parentFolderId`, `organizationId`, `creatorMemberId`, `versionNumber`, `contentCid`, `envelopeSetCid`, `epochId`, `manifestHash`, and ACL/governance events.
- **Encrypted off-chain only:** file content chunks (`index 1..N`) and optional sensitive descriptions/metadata (`privateMetadata`, reserved chunk `index 0`).
- **Never stored on-chain, in IPFS, in PostgreSQL, or in logs:** plaintext file bytes, raw DEKs, private signing/decryption keys, bearer session tokens, or RPC/Cluster passwords.

---

## 4. Startup & Key-Custody Safety Invariants

- Both `crates/key_custody` (`CustodyStartupPolicy::Production`) and `crates/chain_adapter` (`RelayerStartupPolicy::Production`) refuse software/development keys by default unless an explicit unsafe-development opt-in is configured.
- `apps/cli` enforces regular-file input validation (rejecting symlinks/directories/oversized inputs) and atomic `0600` + `fsync` + `rename` writes on download so partially decrypted files are never exposed.
- See [`docs/runbooks/ransomware-recovery.md`](runbooks/ransomware-recovery.md) for incident containment and recovery procedures.
