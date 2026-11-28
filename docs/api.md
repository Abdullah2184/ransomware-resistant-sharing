# Gateway API (Phase 4 authentication, read, and relayed write routes)

The local gateway exposes authentication, session introspection, contract-backed
public identity lookup, signed version access lookup, authorized ciphertext and
envelope-set retrieval, indexer-backed file/folder listing and version history,
self-audited member audit queries, relayed file/version/envelope write routes,
and process health. Multi-sig ACL/governance proposal submission remains
handled via the configured Safe/Timelock governance workflow.

## Read public identity information

`GET /v1/identities/{memberId}` reads `AccessGovernance.memberIdentity` at one
finalized block and returns public identity fields only: organization ID,
signing address and key version, encryption public key and key version, member
status, and the finalized block number/hash. Unregistered identities return
`404`; invalid identifiers return `400`. The identity directory is
contract-backed rather than sourced from an indexer projection.

## Create a login challenge

`POST /v1/auth/challenge`

```json
{
  "memberId": "0x<64 lowercase hex characters>"
}
```

The response contains the challenge to sign:

```json
{
  "memberId": "0x...",
  "nonce": "0x<64 hex characters>",
  "issuedAt": 1800000000,
  "expiresAt": 1800000120,
  "audience": "rrds-local",
  "protocolVersion": 1
}
```

Sign the following EIP-712 typed data with the active member signing key:

- Domain: `name = "RRDS Gateway"`, `version = "1"`, configured `chainId`, and
  the deployed `AccessGovernance` address as `verifyingContract`.
- Type:
  `LoginChallenge(bytes32 memberId,bytes32 nonce,uint64 issuedAt,uint64 expiresAt,string audience,uint32 protocolVersion)`.

The challenge is a proof of key possession only. File operations still require
their own typed signatures and authoritative contract authorization.

## Exchange challenge for a session

`POST /v1/auth/session`

```json
{
  "challenge": {
    "memberId": "0x...",
    "nonce": "0x...",
    "issuedAt": 1800000000,
    "expiresAt": 1800000120,
    "audience": "rrds-local",
    "protocolVersion": 1
  },
  "signature": "0x<65-byte recoverable secp256k1 signature>"
}
```

Signatures use `r || s || v`, with `v` equal to `27` or `28`; high-`s`
signatures are rejected. The gateway compares the recovered address with the
active member signing address returned by the configured Besu contract at its
latest QBFT-committed state. Challenge consumption, session insertion and the
successful authentication audit append commit atomically.

Successful responses contain a bearer token once:

```json
{
  "token": "0x<32 random bytes>",
  "tokenType": "Bearer",
  "expiresAt": 1800000900
}
```

The database stores only the Keccak-256 token hash and expiry.

## Inspect or revoke the current session

`GET /v1/auth/session` with:

```http
Authorization: Bearer 0x<32 random bytes>
```

The response returns the token's member ID only. Session validity is not
authorization to retrieve a file.

`DELETE /v1/auth/session` with the same `Authorization: Bearer ...` header
atomically sets `revoked_at` on the active session row and appends an
`auth.session.revoke` audit event, returning `204 No Content`. Subsequent uses
of the revoked token (including repeat `DELETE`) return `401 unauthorized`.

## Request correlation IDs and multi-budget rate limiting

- Every response includes an `X-Request-Id` header (echoing a sanitized
  alphanumeric/`-`/`_` caller ID up to 64 bytes, or generating a fresh 16-byte
  hex ID). Operational request logs are emitted as structured JSON containing
  `requestId`, `method`, `path`, hashed `sourceId`, `status`, and `latencyMs`
  (never bearer tokens, signatures, or keys).
- Protected routes enforce independent PostgreSQL token buckets per hashed
  source IP (`src:{action}:{source_id}`) and, for authenticated requests, per
  active member (`member:{action}:{member_id}`). Invalid-signature failures
  consume from a separate per-source bucket (`invalid_sig_src:{source_id}`) so
  spoofed claims against a victim's `memberId` cannot lock out the victim.

## Authorize access to a version

`POST /v1/files/{fileId}/versions/{version}/access` with a valid bearer session.
The body contains the current encryption-key version, a fresh nonzero random
operation nonce and a short deadline:

```json
{
  "encryptionKeyVersion": 1,
  "operationNonce": "0x<64 lowercase hex characters>",
  "deadline": 1800000060,
  "signature": "0x<65-byte recoverable secp256k1 signature>"
}
```

Sign EIP-712 `AccessLookup(bytes32 memberId,bytes32 fileId,uint64 versionNumber,uint32 encryptionKeyVersion,bytes32 operationNonce,uint256 deadline)` in the `RRDS AccessGovernance` version `1` domain, with the configured chain ID and `AccessGovernance` address. The nonce is consumed atomically in PostgreSQL. The gateway checks active member/key state, the file Read ACL, version/head state, and—when the requested version is historical—the explicit version-scoped grant. These contract queries use one finalized block. The authorization attempt is durably audited before the response releases references.

Successful responses contain the content CID, current envelope-set CID,
epoch ID, envelope revision, and finalized block number. CIDs are not access
credentials. This route does not fetch or validate the envelope contents and
does not stream ciphertext; a successful lookup therefore does not prove that
the member has a usable envelope until `GET /v1/files/{fileId}/versions/{version}/envelope`
verifies a recipient entry for the caller's active encryption key version.

File-level Read access covers the current head and future versions. Each
non-head version requires an explicit `setHistoricalReadAccess` grant under
the file's configured `READ_ACL_POLICY` Safe. Revoking file-level Read
invalidates historical grants; a later Read re-grant does not restore them.

## Stream encrypted content

`GET /v1/files/{fileId}/versions/{version}/content` with a valid bearer
session. The gateway repeats the finalized member, Read ACL, head, version,
and historical-grant checks, retrieves the content CID from `FileRegistry`,
and appends the access audit record before returning the IPFS CAR stream. The
response uses `Content-Type: application/vnd.ipld.car` and `Cache-Control:
no-store`. It contains ciphertext and manifest blocks only; decryption,
manifest validation, and AEAD verification remain client responsibilities.

The audit records an authorized content retrieval before streaming starts. It
does not prove that the client received the full CAR, decrypted it, or opened
the file. If IPFS cannot open the stream or the audit append fails, the
gateway returns an error without releasing content bytes.

## Retrieve canonical key envelope set

`GET /v1/files/{fileId}/versions/{version}/envelope` with a valid bearer
session. The gateway repeats the finalized member, Read ACL, head, version,
and historical-grant checks at one QBFT-committed block, reads the authoritative
`currentEnvelopeSet` pointer from `AccessGovernance`, fetches the bounded
envelope-set object from IPFS, validates canonical `rrds.key-envelope-set.v1`
format and pointer consistency (`fileId`, `versionNumber`, `epochId`,
`revision`), verifies that an envelope entry exists for the caller's
`(memberId, encryptionKeyVersion)` (failing closed with `401` if absent), and
durably commits a `file.envelope_retrieval` audit record before returning
`Content-Type: application/json` with `Cache-Control: no-store`.

## List files and folders (indexer projection)

`GET /v1/files?folderId=0x<64 lowercase hex>` (defaults to the organization
root `0x00...00`) with a valid bearer session. The gateway confirms the caller
is an active member at one QBFT-committed block, then returns projected folders
and readable files from PostgreSQL together with both `finalizedBlock` and
`indexedBlock` cursors and `"authoritative": false`.

## List file version history

`GET /v1/files/{fileId}/versions` with a valid bearer session. The gateway
first checks authoritative Read ACL and active file head at one QBFT-committed
block (`401` if denied or missing, without leaking existence), then returns the
authoritative `currentVersion` / `currentHeadManifestHash` alongside the
indexer-projected immutable version chain and `historicalReadGranted` flags.

## Query member audit trail

`GET /v1/audit?action=<optional>&limit=<1..100>` with a valid bearer session.
The gateway verifies the caller is an active member at one QBFT-committed
block, atomically appends an `audit.query` record to `gateway_audit_events`
first (failing closed if audit persistence fails), and returns only audit rows
belonging to the authenticated member.

## Stage encrypted content package (`POST /v1/blobs/content`)

Authenticated active members upload client-encrypted content packages using the
canonical `RRDSPKG1` binary frame defined in `crates/ports`
(`application/octet-stream`, bounded by `GATEWAY_MAX_BLOB_UPLOAD_BYTES`,
default 64 MiB). The gateway validates canonical `EncryptedFileManifest`
structure and every chunk's index, byte length, and SHA-256 CID before calling
`BlobStore::put_content(..., MIN_PIN_REPLICAS)`. Plaintext or malformed frames
are rejected with `400 invalid_request`. On satisfied Cluster pin quorum and
durable `blob.content_upload` audit commit, returns `201 Created`:

```json
{
  "cid": "bafy...",
  "bytesWritten": 1049120,
  "requiredReplicas": 2,
  "pinnedPeers": ["peer-1", "peer-2"]
}
```

## Stage canonical key-envelope set (`POST /v1/blobs/envelopes`)

Authenticated active members upload canonical `rrds.key-envelope-set.v1` JSON
(`application/json`, max 512 KiB). The gateway validates
`KeyEnvelopeSet::parse_canonical` before pinning via
`BlobStore::put_envelope_set(..., MIN_PIN_REPLICAS)`, audits
`blob.envelope_upload`, and returns `201 Created` with `cid`, `bytesWritten`,
`requiredReplicas`, and `pinnedPeers`.

## Create a file (version 1)

`POST /v1/files` with a valid bearer session and an active relayer.

```json
{
  "fileId": "0x<64 lowercase hex>",
  "displayName": "report.pdf",
  "parentFolderId": "0x<64 lowercase hex>",
  "versionNumber": 1,
  "parentManifestHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "manifestHash": "0x<64 lowercase hex>",
  "contentCid": "bafy...",
  "envelopeSetCid": "bafk...",
  "epochId": "0x<64 lowercase hex>",
  "operationNonce": "0x<64 lowercase hex>",
  "deadline": 1800000120,
  "signature": "0x<65-byte recoverable secp256k1 signature>"
}
```

Sign EIP-712 `VersionAppend` in the `RRDS FileRegistry` version `1` domain. The
gateway verifies active member status, verifies the EIP-712 signature against
the registered signing address, confirms `fileId` does not already exist
(`409 conflict`), enforces Cluster pin quorum (`MIN_PIN_REPLICAS`) on **both**
`contentCid` and `envelopeSetCid` before relaying (`503 replication_insufficient`
otherwise), relays `FileRegistry.createFile`, and durably audits the outcome.
Committed transactions return `201 Created` with `transactionHash`,
`blockNumber`, `blockHash`, and `gasUsed`. Reverted transactions return `409
contract_reverted` and timeouts return `504 confirmation_timed_out` (both with
`transactionHash`, never reporting success). When no relayer is configured,
write routes return `503 service_unavailable`.

## Append a new file version

`POST /v1/files/{fileId}/versions` with a valid bearer session and an active
relayer.

```json
{
  "versionNumber": 2,
  "parentManifestHash": "0x<64 lowercase hex>",
  "manifestHash": "0x<64 lowercase hex>",
  "contentCid": "bafy...",
  "envelopeSetCid": "bafk...",
  "epochId": "0x<64 lowercase hex>",
  "operationNonce": "0x<64 lowercase hex>",
  "deadline": 1800000120,
  "signature": "0x<65-byte recoverable secp256k1 signature>",
  "restoredFromVersion": 1
}
```

The optional `restoredFromVersion` field (when provided for append-only restore)
must satisfy `1 <= restoredFromVersion < versionNumber` (`400 invalid_request`
otherwise) and records the recovery source version in the hash-chained
`file.version_restore` PostgreSQL audit record (§9.7 #6).

The gateway checks active member identity, authoritative `hasWriteAccess`
(`401 unauthorized`), active head continuity (`409 stale_head` if
`versionNumber != head + 1` or `parentManifestHash` mismatches), EIP-712
`VersionAppend` signature, and Cluster pin quorum for both CIDs before relaying
`FileRegistry.appendVersion`. Returns `201 Created` only on committed receipt.

## Update a version's key-envelope set pointer

`POST /v1/files/{fileId}/versions/{version}/envelopes` with a valid bearer
session and an active relayer.

```json
{
  "epochId": "0x<64 lowercase hex>",
  "oldEnvelopeSetCid": "bafk...",
  "newEnvelopeSetCid": "bafk...",
  "proposalId": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "operationNonce": "0x<64 lowercase hex>",
  "deadline": 1800000120,
  "signature": "0x<65-byte recoverable secp256k1 signature>"
}
```

Sign EIP-712 `EnvelopeSetUpdate` in the `RRDS AccessGovernance` version `1`
domain. The gateway verifies active member identity, Read ACL, current on-chain
envelope pointer continuity (`409 stale_head` if `oldEnvelopeSetCid` or
`epochId` mismatches), EIP-712 signature, Cluster pin quorum for
`newEnvelopeSetCid`, and canonical `rrds.key-envelope-set.v1` structure at
`revision + 1` (`400 invalid_envelope_set` if malformed) before relaying
`AccessGovernance.updateEnvelopeSet` as a non-authority relayer (no elevated
contract role). Returns `200 OK` only on committed receipt. Envelope updates
only advance the encrypted key-envelope pointer and never grant or modify ACL
permissions (which remain strictly governed by the file's policy Safe).

## Reconcile a relayed transaction

`GET /v1/transactions/{txHash}` with a valid bearer session.

Looks up `txHash` in `gateway_relayed_transactions` (surviving gateway restarts
per §7.13 and §10.4.7). Returns `404 not_found` if the transaction does not
exist or belongs to a different member (preventing cross-member probing). When
the persisted status is `pending`, the gateway queries Besu via
`reconcile_transaction(txHash)`:

- On finalized commit: transitions status to `confirmed`, marks associated
  `contentCid`/`envelopeSetCid` blobs as `referenced` in `gateway_orphan_blobs`,
  writes a `transaction.reconcile` audit record, and returns `200 OK` with
  `blockNumber`, `blockHash`, and `gasUsed`.
- On finalized revert: transitions status to `reverted`, records associated
  blobs as `candidate` orphans (`reason = "contract_reverted"`), writes an
  audit record, and returns `200 OK` with `status: "reverted"`.
- If still pending on Besu: returns `200 OK` with `status: "pending"`.

All errors use a bounded JSON error code. Unauthorized session responses do
not distinguish unknown, inactive, or mismatched identities.
