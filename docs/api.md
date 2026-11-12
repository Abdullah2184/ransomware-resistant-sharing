# Gateway API (Phase 4 authentication and access lookup)

The local gateway exposes authentication, session introspection, signed
version access lookup, authorized ciphertext streaming, public identity lookup,
and process health. It does not expose envelope contents, ACL changes, file
listings/history, or audit queries.

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
`finalized` state. Challenge consumption, session insertion and the successful
authentication audit append commit atomically.

Successful responses contain a bearer token once:

```json
{
  "token": "0x<32 random bytes>",
  "tokenType": "Bearer",
  "expiresAt": 1800000900
}
```

The database stores only the Keccak-256 token hash and expiry.

## Inspect the current session

`GET /v1/auth/session` with:

```http
Authorization: Bearer 0x<32 random bytes>
```

The response returns the token's member ID only. Session validity is not
authorization to retrieve a file.

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
the member has a usable envelope. End-to-end historical sharing and download
remain incomplete.

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
gateway returns an error without releasing content bytes. This path does not
validate that the recipient has a usable key envelope; envelope retrieval and
membership validation remain incomplete.

All errors use a bounded JSON error code. Unauthorized session responses do
not distinguish unknown, inactive, or mismatched identities.
