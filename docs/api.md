# Gateway API (Phase 4 authentication increment)

The local gateway exposes only authentication, session introspection, and a
process health route at this stage. It does not expose file CIDs, ciphertext,
envelope references, ACL changes, or audit queries.

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
authorization to retrieve a file. Future protected routes must check current
member status and the requested file/version ACL at authoritative chain state,
then append a successful lookup audit record before returning any CID,
envelope reference, or ciphertext.

All errors use a bounded JSON error code. Unauthorized session responses do
not distinguish unknown, inactive, or mismatched identities.
