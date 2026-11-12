# ADR: Public contract-backed identity lookup route

**Status:** Accepted
**Decision scope:** Gateway public-key directory read API

## Context

The specification requires a public identity/key directory backed by
authoritative contract state. The gateway had challenge/session endpoints but
no route for clients to retrieve another member's public encryption key before
creating a recipient envelope. Identity data in PostgreSQL is an indexer
projection and cannot be treated as authoritative for this operation.

## Decision

- Provide `GET /v1/identities/{memberId}` without requiring a session. Expose
  only contract-registered public fields: organization ID, signing address and
  key version, encryption public key and key version, and lifecycle status.
- Read `AccessGovernance.memberIdentity` at one recorded QBFT-committed block;
  return the block number and hash with the response. Do not serve this route
  from the PostgreSQL projection.
- Apply the existing source-address token-bucket rate limit. Reject malformed
  identifiers with a bounded error response and return `404` for an
  unregistered identity.
- Treat public identity output as directory metadata only. It does not
  authorize file access or establish that a key has a usable file envelope.

## Consequences

- Clients can resolve public encryption keys for envelope construction without
  a separate privileged directory service.
- The route depends on Besu availability and reveals that a valid member ID is
  registered; this is the intended public directory behavior in §8.1.
- Private key material and session information are never returned.

## Verification

- Chain adapter tests assert the member identity call uses the supplied
  committed block number.
- Gateway tests assert the response includes only the documented public
  identity fields.
- `docs/api.md` documents response fields and error behavior.
