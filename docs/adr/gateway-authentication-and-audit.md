# Gateway authentication and audit foundation

## Status

Accepted for the Phase 4 MVP foundation.

## Context

The gateway must authenticate a member without treating a claimed member ID or
a bearer session as authorization for protected file operations. Login
challenges must be one-time and short-lived across gateway replicas. The
specification also requires rate limits shared across replicas and durable,
append-only audit records before a successful login is returned.

## Decisions

1. A challenge is an EIP-712 `LoginChallenge` signed by the member's registered
   secp256k1 signing key. Its fields are `memberId`, a random 32-byte nonce,
   issue and expiry Unix timestamps, gateway audience, and protocol version.
   The EIP-712 domain uses name `RRDS Gateway`, version `1`, the configured
   chain ID, and the deployed `AccessGovernance` address. The audience is
   included in the struct hash. Login verification compares the recovered
   signer with the active member's signing address read from Besu finalized
   state.
2. PostgreSQL stores challenge nonce state and session expiry, so one-time
   consumption and sessions are shared across replicas. Session bearer tokens
   are returned once and only their Keccak-256 hashes are persisted.
3. Challenge and session endpoints use PostgreSQL token buckets. Source
   addresses are hashed before they become bucket keys or audit identifiers;
   forwarded headers are not trusted by the local service.
4. Gateway audit records are serialized as a stable JSON structure and linked
   with a per-database append-only Keccak-256 hash chain. Authentication
   succeeds only after the session and audit record commit in one transaction.
   A database failure therefore fails closed.
5. Initial development defaults are a 120-second challenge, a 900-second
   session and a source-address bucket of 30 requests with a 0.5-token/second
   refill. These are configuration defaults, not a production policy.
6. Challenge/session JSON is capped at 8 KiB and parsed with bounded error
   responses. Authentication endpoints apply source-address limits before
   body parsing; malformed JSON failures are included in the auth audit.

## Consequences and limitations

- Login proves possession of the registered signing key; it does not prove a
  person is legitimate or replace operation-specific signatures and contract
  authorization.
- Login challenge retrieval does not reveal whether a member exists. A
  signature must verify and the finalized contract state must report an active
  member before a session can be created.
- The database migration installs mutation-blocking triggers, but production
  role separation, audit-query authorization, TLS termination, session
  revocation, key rotation policy, and protected file routes are not yet
  implemented. The service binds to loopback by default and must not be
  exposed directly to untrusted networks.
- This implementation does not claim that authentication alone authorizes a
  file read. Protected CIDs and ciphertext remain unavailable until the
  gateway performs finalized ACL checks and durably audits the lookup first.
