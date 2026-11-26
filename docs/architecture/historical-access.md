# Historical Access Model

This document explains what **historical access** means in RRDS and how it is
enforced across smart contracts, the gateway, the indexer, and cryptographic
envelope sets. See also
[`docs/adr/version-scoped-historical-read-access.md`](../adr/version-scoped-historical-read-access.md).

## Default Sharing Scope vs. Historical Versions

Every file has an immutable linear version history (`V1 -> V2 -> V3 ...`) and a
single mutable `currentVersionNumber` / `currentHeadManifestHash` pointer in
`FileRegistry`.

- **File-level Read ACL (`AccessGovernance.setFilePermission`):**
  Authorizes an active member to retrieve the **current head version** and
  **future versions** created while their Read grant remains active (provided
  they also have a valid key envelope for that version).
- **Historical (non-head) version access (`versionNumber < currentVersionNumber`):**
  **Not implied** by a file-level Read grant. Accessing any older version
  requires an **explicit version-scoped grant** recorded on-chain via
  `AccessGovernance.setHistoricalReadAccess(fileId, versionNumber, memberId, true, proposalId)`
  under the file's configured `READ_ACL_POLICY` Safe.

## Three Independent Conditions Required to Decrypt a Historical Version

To retrieve and decrypt an older version `Vk` (`k < head`), **all** of the
following must hold at a single QBFT-committed block `B`:

1. **Authoritative on-chain identity and ACL (`AccessGovernance`):**
   - The member status is `Active` (not `Suspended` or `Revoked`).
   - The member holds the file-level `Read` ACL for `fileId`.
   - `hasHistoricalReadAccess(memberId, fileId, k)` is `true`.
2. **Authoritative version & pointer consistency (`FileRegistry` + `AccessGovernance`):**
   - File status is `Active`, `k <= head.versionNumber`, and `getVersion(fileId, k)`
     and `currentEnvelopeSet(fileId, k)` exist at block `B`.
   - The gateway durably appends the access attempt to the hash-chained
     PostgreSQL audit log **before** returning CIDs or streaming ciphertext.
3. **Cryptographic key envelope (`KeyEnvelopeSet` in IPFS):**
   - The current immutable envelope set referenced by `currentEnvelopeSet(fileId, k)`
     contains an HPKE envelope for `(memberId, encryptionKeyVersion)` wrapping
     version `Vk`'s version-specific DEK.
   - Because each version uses a fresh DEK, adding a reader to `Vk` requires an
     already-authorized reader to unwrap `Vk`'s DEK, wrap it for the new
     recipient's active X25519 key, pin a new canonical `KeyEnvelopeSet` at
     `revision + 1` (without re-encrypting the file bytes), and submit a signed
     `EnvelopeSetUpdate` under `ENVELOPE_UPDATE_POLICY`.

## Read-ACL Revocation Epochs (Preventing Stale Grant Resurfacing)

`AccessGovernance` tracks a per-`(fileId, memberId)` counter
`readPermissionEpochs[fileId][memberId]`:

- Granting historical read stores `readPermissionEpochs[fileId][memberId] + 1`
  in `historicalReadPermissions[fileId][versionNumber][memberId]`.
- Revoking file-level `Read` increments `readPermissionEpochs[fileId][memberId]`
  by `1`.
- Consequently, revoking file-level `Read` immediately invalidates **every**
  prior historical grant for that member on that file. If file-level `Read` is
  later re-granted, previously granted historical versions remain **denied**
  unless each version is explicitly granted again.
- The indexer mirrors this rule by clearing `historical_read_access_projection`
  when projecting `ReadAccessRevoked`. Its projection is informational only; the
  gateway always queries `AccessGovernance` at a single committed block.

## Explicit Cryptographic Limitation

Revoking on-chain Read or historical Read prevents future authorized lookups and
excludes the member from future versions' envelope sets. It **cannot**
retroactively erase a DEK or plaintext that the member already obtained and
saved before revocation.
