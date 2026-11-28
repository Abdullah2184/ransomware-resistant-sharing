# RRDS Consortium Operational & Governance Policies

**Canonical Reference:** [`docs/specifications/TECHNICAL_SPECIFICATION.md`](../specifications/TECHNICAL_SPECIFICATION.md) §17  
**Status:** Baseline consortium policy specification for MVP & multi-organization rollout

This document establishes concrete baseline policies for each deployment decision
identified in `TECHNICAL_SPECIFICATION.md` §17 so no security-critical behavior
is left implicit or silently guessed by application code.

---

## 1. Key Custody & HSM Boundary (§5.2, §5.5, §17 #1)

- **MVP baseline (current):** Local and prototype deployments run with the
  software `DevelopmentKeyCustody` (`crates/key_custody`) and
  `DevelopmentRelayerSigner` (`crates/chain_adapter`). Both providers explicitly
  report `test_only = true` and `private_keys_non_exportable = false`.
- **Mandatory refusal guard:** `CustodyStartupPolicy::Production`,
  `RelayerStartupPolicy::Production`, and `RRDS_ENV=production` refuse to start
  with software keys. Dev custody requires explicit local opt-in
  (`RRDS_ALLOW_UNSAFE_DEV_CUSTODY=true` for CLI; `GATEWAY_ALLOW_UNSAFE_DEV_RELAYER=true`
  with `RRDS_ENV=development` for gateway).
- **Post-MVP production requirement:** Production deployments MUST replace dev
  providers with hardware-backed `KeyCustodyProvider` (PKCS#11 / vendor HSM
  supporting secp256k1 EIP-712 signing + X25519/HPKE unwrap, or an ADR-approved
  RSA-OAEP alternative if hardware lacks X25519) and HSM/KMS-backed
  `RelayerSigner`.

## 2. Governance Authorities, Safe Thresholds & Timelocks (§7.5, §8.1, §17 #2)

- **Real threshold Safe smart accounts:** All three governance authorities MUST
  be audited Safe threshold proxy contracts (`@safe-global/safe-contracts`
  `Safe` + `SafeProxyFactory`), never single-key EOAs:
  - **Consortium Safe:** minimum `2-of-3` (prototype) / `ceil(2/3 * orgs)`
    (production) controlling `RrdsTimelockController` (`minDelay = 86,400s`,
    24 hours) for `registerOrganization`, `changeOrganizationAuthority`,
    `reinstateMember`, and `FILE_REGISTRY_ROLE` activation.
  - **Emergency Safe:** minimum `2-of-3` (or dedicated incident-response quorum)
    holding `EMERGENCY_SUSPENDER_ROLE` only (`emergencySuspendMember`). Cannot
    grant ACLs, modify files, or reinstate members.
  - **Organization Safe:** per-organization threshold (`2-of-3` minimum)
    governing `registerMember`, `setMemberStatus`, `supersedeMemberKeys`,
    `setFilePermission`, `setHistoricalReadAccess`, `setFilePolicyAuthority`,
    and `FileRegistry` folder/metadata administration (`createFolder`,
    `renameFolder`, `updateFileMetadata`, `setFileStatus`).
- **Gateway boundary (§8.1 deviation note):** ACL mutations and membership
  lifecycle transitions execute directly through the relevant Safe multisig
  against Besu rather than via an unguarded gateway relayer endpoint.
  `POST /v1/files/{fileId}/versions/{version}/envelopes` relays only Option B
  member-signed `EnvelopeSetUpdate` payloads after the Organization Safe has
  finalized the underlying Read ACL grant (see
  [`docs/adr/governance-authority-and-timelock.md`](../adr/governance-authority-and-timelock.md)).

## 3. Organization Onboarding & Member Identity Proofing (§9.1, §17 #3)

1. **Out-of-band identity verification:** Before calling `registerOrganization`
   (Consortium Safe + 24h timelock) or `registerMember` (Organization Safe),
   administrators verify legal entity / employee identity through enterprise
   directory / PKI / HR controls out-of-band.
2. **Cryptographic proof of possession:** Member enrollment requires a valid
   EIP-712 `MemberKeyProof` signed by the member's `secp256k1` signing key
   binding `(memberId, organizationId, signingAddress, encryptionPublicKey,
   signingKeyVersion, encryptionKeyVersion, nonce, deadline)`.
3. **Key rotation & compromise:** Key changes MUST use `supersedeMemberKeys`
   (incrementing key versions monotonically and preserving historical key audit
   records) rather than out-of-band overwrite. Suspected compromise triggers
   immediate `emergencySuspendMember`, forensic audit review, and governed key
   supersession before `reinstateMember`.

## 4. Multi-Organization Storage Replication Policy (§9.2 #6, §10.4.3, §17 #4)

- **Replica independence:** Local development uses `MIN_PIN_REPLICAS=2` on one
  host solely for functional verification. Production deployments MUST set
  `MIN_PIN_REPLICAS >= 3` across **separate organizational hosts and failure
  domains** using [`infra/compose/ipfs-peer.yaml`](../../infra/compose/ipfs-peer.yaml).
- **Network isolation:** Kubo (`/api/v0/*`) and IPFS Cluster (`/pins/*`) admin
  APIs MUST be bound to private/internal networks or loopback behind TLS and
  authenticated Cluster credentials; endpoints MUST retrieve ciphertext solely
  through the organization gateway.
- **Health monitoring:** Each gateway runs a continuous `StorageHealthMonitor`
  (`GATEWAY_STORAGE_HEALTH_INTERVAL_SECONDS`, default `30`s) alerting operators
  whenever healthy Kubo or Cluster peer counts fall below total configured peers.

## 5. File Size, Retention & Safe Orphan Cleanup Policy (§7.13, §9.2 #10, §17 #5)

- **Upload & chunk bounds:** Default maximum ciphertext package upload size is
  `64 MiB` (`GATEWAY_MAX_BLOB_UPLOAD_BYTES=67108864`, configurable up to
  `512 MiB` with `1 MiB` AES-256-GCM chunks per
  [`docs/adr/content-package-unixfs-profile.md`](../adr/content-package-unixfs-profile.md)).
- **Historical version retention:** Finalized file versions and active envelope
  sets are **never unpinned** automatically; any future archival/pruning requires
  an explicit consortium governance policy.
- **Safe orphan cleanup:** Blobs staged via `POST /v1/blobs/{content,envelopes}`
  or left unreferenced after a reverted/failed transaction are recorded in
  `gateway_orphan_blobs` as `candidate` and become `referenced` immediately on
  chain commit (or transaction reconciliation). `OrphanBlobCleaner` only unpins
  candidates older than `ORPHAN_RETENTION_SECONDS` (default `3600`s) **after**
  verifying the CID is absent from BOTH PostgreSQL projections AND authoritative
  Besu on-chain state (`FileRegistry.getVersion` / `AccessGovernance.currentEnvelopeSet`).
  Any Besu RPC failure fails closed and skips unpinning.

## 6. Historical Sharing & Metadata Visibility Policy (§6.3, §17 #6, #7)

- **Historical sharing default:** Granting file-level `Read` covers the current
  head version and future versions only. Access to older versions requires an
  explicit version-scoped `setHistoricalReadAccess` grant by the Organization
  Safe plus a corresponding key-envelope update for each selected historical
  version; revoking file-level `Read` automatically invalidates historical read
  access.
- **Metadata visibility:** Visible `displayName` and `parentFolderId` are stored
  on-chain in `FileRegistry` for consortium browsing. Any confidential title,
  notes, or classification metadata MUST be encrypted inside chunk-0 private
  metadata (`AES-256-GCM`), never placed in on-chain display names or events.

## 7. Emergency Access Recovery Governance (§9.7, §17 #8)

- **No undocumented admin bypass:** Neither gateway operators, database admins,
  nor Besu validators can decrypt files or grant themselves Read ACL access.
- **Escrow / multi-reader continuity:** Organizations requiring business-continuity
  recovery if an individual member loses key custody MUST include a governed
  organization recovery identity (held under threshold/offline custody) in the
  file's authorized Read ACL and envelope sets at upload/share time, or have an
  already-authorized co-reader re-wrap the version DEK via Option B after
  Organization Safe approval.
- **Append-only incident recovery:** Restoring a clean version after ransomware
  follows [`docs/runbooks/ransomware-recovery.md`](../runbooks/ransomware-recovery.md),
  re-encrypts verified plaintext under a fresh DEK, appends a new head version
  recording `restoredFromVersion` in the hash-chained `file.version_restore`
  audit stream, and preserves all corrupted versions for forensic audit.
