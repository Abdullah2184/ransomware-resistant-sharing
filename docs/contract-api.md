# Smart Contract API & Gas Reference

This reference documents the deployed Solidity `0.8.34` (London EVM, optimizer
200 runs) contracts under [`contracts/contracts/`](../contracts/contracts/).
All contracts run on a permissioned Hyperledger Besu QBFT network with zero gas
price (`--min-gas-price=0`, `baseFeePerGas = 0`) while retaining EVM gas
metering and transaction/block limits (`DEFAULT_TX_GAS_LIMIT = 2,000,000`;
Besu block gas limit `30,000,000`).

---

## 1. Contract Architecture & Authorities

| Contract | Purpose | Admin / Governance Authority |
| --- | --- | --- |
| **`RrdsTimelockController`** | OpenZeppelin `5.6.1` `TimelockController` enforcing a `86,400`s (24-hour) delay on consortium-wide actions. | `PROPOSER_ROLE` & `CANCELLER_ROLE`: `consortiumSafe`. `EXECUTOR_ROLE`: open (`address(0)`). `DEFAULT_ADMIN_ROLE`: self only (zero deployer bypass). |
| **`AccessGovernance`** | Authoritative registry for organizations, versioned member signing/encryption keys, member lifecycle (`Active`/`Suspended`/`Revoked`), per-file Read/Write ACLs, version-scoped historical Read grants, and current envelope-set pointers. | `DEFAULT_ADMIN_ROLE`: `RrdsTimelockController`. `EMERGENCY_SUSPENDER_ROLE`: `emergencySafe` (suspend-only). `FILE_REGISTRY_ROLE`: `FileRegistry` (granted only via timelock). Per-org/per-file operations: configured `organizationSafe` / policy Safe. |
| **`FileRegistry`** | Authoritative registry for logical folders, opaque `fileId` metadata, append-only version records (`V1 -> V2 -> ...`), and mutable current-head pointer with optimistic concurrency (`parentManifestHash`). | Calls `AccessGovernance` via `FILE_REGISTRY_ROLE` during atomic file creation/version append. Metadata changes authorized via `FILE_METADATA_POLICY` (defaults to file organization's Safe). |

---

## 2. Key Public Functions

### `AccessGovernance`

- **Consortium / Timelock (`onlyRole(DEFAULT_ADMIN_ROLE)`):**
  - `registerOrganization(bytes32 organizationId, address authority)`
  - `changeOrganizationAuthority(bytes32 organizationId, address newAuthority)`
  - `reinstateMember(bytes32 memberId)`
  - `grantRole(FILE_REGISTRY_ROLE, address fileRegistry)` (scheduled & executed via `RrdsTimelockController`)
- **Emergency Safe (`onlyRole(EMERGENCY_SUSPENDER_ROLE)`):**
  - `emergencySuspendMember(bytes32 memberId)` — suspend-only; cannot grant ACLs or reinstate.
- **Organization / File Policy Safe:**
  - `registerMember(organizationId, memberId, signingAddress, signingKeyVersion, encryptionKeyVersion, encryptionPublicKey, proofNonce, proofDeadline, proofSignature)` — verifies EIP-712 `MemberKeyProof` proof-of-possession.
  - `supersedeMemberKeys(memberId, newSigningAddress, newSigningKeyVersion, newEncryptionKeyVersion, newEncryptionPublicKey, proofNonce, proofDeadline, proofSignature)` / `setMemberStatus(memberId, newStatus)`
  - `setFilePolicyAuthority(fileId, policy, authority)` (`READ_ACL_POLICY`, `WRITE_ACL_POLICY`, `FILE_METADATA_POLICY`)
  - `setFilePermission(fileId, memberId, permission, granted, proposalId)` — revoking Read increments `readPermissionEpochs[fileId][memberId]`, invalidating prior historical grants.
  - `setHistoricalReadAccess(fileId, versionNumber, memberId, granted, proposalId)`
- **Relayed Signed Envelope Updates (EIP-712 `EnvelopeSetUpdate`; any non-authority `msg.sender` / gateway relayer):**
  - `updateEnvelopeSet(EnvelopeSetUpdate request, bytes signature)` — verifies active member status, current file Read ACL, EIP-712 `EnvelopeSetUpdate` signature, deadline, nonce replay protection, canonical CIDv1, and `oldEnvelopeSetCid` continuity; increments `revision` and advances the current envelope-set pointer without modifying prior envelope sets, ciphertext, or any ACL permissions.
- **Read-Only Queries (`eth_call`, zero gas, no tx):**
  - `memberIdentity(bytes32 memberId) -> Member`
  - `isActiveMember(bytes32 memberId) -> bool`
  - `organizationAuthority(bytes32 organizationId) -> address`
  - `hasReadAccess(bytes32 memberId, bytes32 fileId) -> bool`
  - `hasWriteAccess(bytes32 memberId, bytes32 fileId) -> bool`
  - `hasHistoricalReadAccess(bytes32 memberId, bytes32 fileId, uint64 versionNumber) -> bool`
  - `currentEnvelopeSet(bytes32 fileId, uint64 versionNumber) -> (string cid, bytes32 epochId, uint32 revision)`

### `FileRegistry`

- **Relayed Signed Writes (EIP-712 `VersionAppend` recovered from signature; `msg.sender` is relayer):**
  - `createFile(VersionAppend request, string contentCid, string envelopeSetCid, string displayName, bytes32 parentFolderId, bytes signature)` — creates file + V1 atomically and calls `AccessGovernance.registerFilePolicy` and `AccessGovernance.initializeEnvelopeSet` (granting creator initial Read & Write ACL + envelope revision `1`).
  - `appendVersion(VersionAppend request, string contentCid, string envelopeSetCid, bytes signature)` — verifies active Write ACL, `versionNumber == currentVersion + 1`, `parentManifestHash == currentHeadManifestHash`, unique `epochId`, and valid CIDv1 strings; appends immutable version and advances head.
- **Governed Metadata / Folders (`FILE_METADATA_POLICY` / organization Safe; status via timelock):**
  - `createFolder(bytes32 folderId, bytes32 organizationId, bytes32 parentFolderId, string displayName)` / `renameFolder(bytes32 folderId, string displayName)`
  - `updateFileMetadata(bytes32 fileId, string displayName, bytes32 parentFolderId)` / `setFileStatus(bytes32 fileId, FileStatus newStatus)` (timelock-only)
- **Read-Only Queries (`eth_call`):**
  - `getFile(bytes32 fileId) -> File`
  - `getVersion(bytes32 fileId, uint64 versionNumber) -> VersionRecord`
  - `getFolder(bytes32 folderId) -> Folder`

---

## 3. Indexed Events (Consumed by `services/indexer`)

- **`AccessGovernance`:** `OrganizationRegistered`, `OrganizationAuthorityChanged`, `MemberRegistered`, `MemberStatusChanged`, `MemberKeyRegistered`, `MemberKeySuperseded`, `MemberKeyStatusChanged`, `FilePolicyRegistered`, `FilePolicyAuthorityChanged`, `ReadAccessGranted`, `ReadAccessRevoked`, `WriteAccessGranted`, `WriteAccessRevoked`, `HistoricalReadAccessGranted`, `HistoricalReadAccessRevoked`, `EnvelopeSetInitialized`, `EnvelopeSetUpdated`, plus OpenZeppelin `AccessControl` events (`RoleGranted`, `RoleRevoked`, `RoleAdminChanged`).
- **`FileRegistry`:** `FolderCreated`, `FolderRenamed`, `FileCreated`, `VersionAppended`, `CurrentHeadAdvanced`, `FileMetadataChanged`, `FileStatusChanged`.
- **`RrdsTimelockController` (when `CONTRACT_TIMELOCK_ADDRESS` is configured):** `CallScheduled`, `CallExecuted`, `CallSalt`, `Cancelled`, `MinDelayChange`, plus `RoleGranted`, `RoleRevoked`, `RoleAdminChanged`.

Routine read access lookups emit **no on-chain events** and submit **no blockchain transactions**; they are durably logged in PostgreSQL (`services/gateway`).

---

## 4. Verified Gas Bounds (`TECHNICAL_SPECIFICATION.md` §7.9)

Automated gas checks in [`contracts/test/GasBounds.ts`](../contracts/test/GasBounds.ts)
assert all major state transitions remain well below `DEFAULT_TX_GAS_LIMIT`
(`2,000,000` gas) and Besu's `30,000,000` block gas limit:

| Operation | Enforced Upper Bound in `GasBounds.ts` | Notes |
| --- | --- | --- |
| `FileRegistry.createFile` | `< 900,000` gas (~`799k` measured) | Atomic file creation + V1 + initial Read/Write ACL + envelope init |
| `FileRegistry.appendVersion` | `< 750,000` gas (~`657k` measured) | Immutable version append + head advance + initial envelope pointer |
| `AccessGovernance.setFilePermission` | `< 150,000` gas | O(1) mapping update + event emission |
| `AccessGovernance.updateEnvelopeSet` | `< 250,000` gas | EIP-712 verification + nonce consume + envelope pointer update |
| `AccessGovernance.registerMember` | `< 2,000,000` gas | EIP-712 `MemberKeyProof` + versioned signing & encryption keys |
| `RrdsTimelockController.scheduleBatch` / `executeBatch` | `< 2,000,000` gas | Batch `grantRole(FILE_REGISTRY_ROLE)` + `registerOrganization` |

Optimized `AccessGovernance` runtime bytecode is `17,229` bytes (well under the
`24,576`-byte EIP-170 contract size limit).
