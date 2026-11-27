# Authentication and Challenge-Response Workflow

This document explains how a client authenticates to the RRDS Gateway and why
session authentication is strictly separated from operation-level contract
authorization. See also
[`docs/adr/gateway-authentication-and-audit.md`](../adr/gateway-authentication-and-audit.md)
and [`docs/adr/eip712-operation-schemas.md`](../adr/eip712-operation-schemas.md).

## Trust Rule: Login Proof != File Authorization

- A claimed `memberId` alone is never trusted.
- Challenge-response login proves **possession of the member's registered
  secp256k1 signing key** at the time of login.
- A bearer session token only authenticates the HTTP caller to the gateway; it
  **never** replaces authoritative contract checks or operation-specific EIP-712
  signatures (`VersionAppend`, `AccessLookup`, `EnvelopeSetUpdate`).

## Step-by-Step Login Flow

1. **Request one-time challenge (`POST /v1/auth/challenge`):**
   - Rate-limited by hashed source address in PostgreSQL (`gateway_rate_buckets`,
     serialized with `SELECT ... FOR UPDATE` without negative token debt).
   - Client sends `{"memberId": "0x<64 lowercase hex>"}`.
   - Gateway generates a fresh cryptographically random non-zero 32-byte `nonce`,
     sets `issuedAt` and `expiresAt = issuedAt + GATEWAY_CHALLENGE_TTL_SECONDS`
     (default 120s), attaches `audience` (`GATEWAY_AUDIENCE`) and
     `protocolVersion = 1`.
   - Gateway prunes expired login challenges, persists the new challenge in
     `gateway_login_challenges`, and appends an `auth.challenge` record to
     `gateway_audit_events` in one PostgreSQL transaction.
   - Challenge issuance does **not** reveal whether `memberId` is registered.

2. **Client validation and custody signing (`application::AuthService::login`):**
   - Client validates `AuthConfig`, verifies `memberId` matches its custody
     identity, `audience` matches the expected gateway, `protocolVersion == 1`,
     `nonce != 0`, `issuedAt <= now + 5s` (`MAX_CHALLENGE_CLOCK_SKEW_SECONDS = 5`
     for bounded client/gateway clock skew), `expiresAt > now`, and
     `expiresAt - issuedAt <= max_challenge_ttl_seconds`.
   - Client builds the EIP-712 `LoginChallenge` typed digest via
     `crates/crypto::LoginChallengeDigestInput` under domain
     `name = "RRDS Gateway"`, `version = "1"`, `chainId`, and
     `verifyingContract = AccessGovernance`.
   - Client calls `KeyCustodyProvider::sign_typed_digest` so the private signing
     key never leaves custody.

3. **Exchange signed challenge for a session (`POST /v1/auth/session`):**
   - Rate-limited before JSON parsing (8 KiB max body). Invalid signatures draw
     from a dedicated per-source bucket (`invalid_sig_src:{source_id}`) so
     spoofed claims against a victim's `memberId` throttle the caller without
     locking out the victim.
   - Gateway validates challenge fields, recomputes the EIP-712 digest using the
     same shared `crates/crypto` definition, and recovers the signer address
     (rejecting non-27/28 `v` and high-`s` malleable signatures).
   - Gateway queries `AccessGovernance.memberIdentity(memberId)` at Besu's
     latest QBFT-committed state and checks that the member is `Active` and
     their registered signing address equals the recovered address.
   - In a **single atomic PostgreSQL transaction**, the gateway:
     1. Prunes expired sessions and atomically marks the matching unconsumed,
        unexpired challenge row `consumed_at = clock_timestamp()` (preventing
        replay across concurrent gateway replicas).
     2. Generates a 32-byte random bearer token and stores **only** its
        Keccak-256 hash (`token_hash`) and `expires_at` in `gateway_sessions`.
     3. Appends an `auth.session` (`issued`) row to the hash-chained
        `gateway_audit_events` table under an advisory lock (`pg_advisory_xact_lock`).
   - If any step (including audit append) fails, the transaction rolls back and
     no session is issued (fail closed). The raw bearer token is returned once.
     (`apps/cli login` writes it to a `0600` session file via atomic rename and
     requires explicit `--print-token` to print to stdout.)

4. **Session inspection, revocation, and multi-budget rate limiting:**
   - `GET /v1/auth/session` validates the active unrevoked bearer token, audits
     `auth.session.validate`, and returns `{ "memberId": "0x..." }`.
   - `DELETE /v1/auth/session` (`rrds logout`) atomically sets `revoked_at` on
     the active session row and appends an `auth.session.revoke` audit event,
     returning `204 No Content`. Subsequent uses of the token return `401`.
   - All 16 API routes enforce independent per-source (`src:{action}:{source_id}`)
     and authenticated per-member (`member:{action}:{member_id}`) PostgreSQL
     token buckets (`services/gateway/src/routes/middleware.rs`), echo/generate
     an `X-Request-Id` header, and emit structured JSON operational logs without
     tokens, signatures, or keys.

## Operation-Specific Signatures After Login

| Operation | EIP-712 Type | Domain / Verifying Contract | Replay Nonce Enforcement & Gateway Route |
| --- | --- | --- | --- |
| Read access lookup (`POST /v1/files/{id}/versions/{v}/access`) | `AccessLookup` | `RRDS AccessGovernance` (`AccessGovernance`) | Consumed atomically in PostgreSQL (`gateway_used_access_nonces`); verifies active member, exact `encryptionKeyVersion`, Read ACL, head/historical grant, and returns authoritative `manifestHash` + CIDs at one QBFT-committed block; no blockchain tx. |
| Create file / Append version / Restore (`POST /v1/files`, `POST /v1/files/{id}/versions`) | `VersionAppend` | `RRDS FileRegistry` (`FileRegistry`) | Verified locally by gateway alongside existing Cluster pin quorum (`MIN_PIN_REPLICAS`) and staged canonical `KeyEnvelopeSet` before relaying via `TransactionRelayer`; consumed atomically on-chain in `FileRegistry.consumedOperationNonces`. |
| Update envelope set (`POST /v1/files/{id}/versions/{v}/envelopes`) | `EnvelopeSetUpdate` | `RRDS AccessGovernance` (`AccessGovernance`) | Verified locally by gateway alongside existing pin quorum and canonical `KeyEnvelopeSet` (`revision + 1`) before relaying; consumed atomically on-chain in `AccessGovernance.consumedOperationNonces`. |
| Register member / Rotate keys | `MemberKeyProof` | `RRDS AccessGovernance` (`AccessGovernance`) | Consumed atomically on-chain in `AccessGovernance.consumedKeyProofNonces` (executed via Organization Safe). |

## Audit Chain Integrity

`gateway_audit_events` enforces:
- Append-only database triggers (`gateway_audit_no_update_or_delete` and
  `gateway_audit_no_truncate` from migration `0006`) rejecting `UPDATE`,
  `DELETE`, and `TRUNCATE`, reinforced by least-privilege `rrfs_gateway`
  (`SELECT, INSERT` only) and `rrfs_audit_reader` (`SELECT` only) grants.
- Per-stream Keccak-256 hash chain serialized under `pg_advisory_xact_lock`:
  `record_hash = keccak256(previous_hash || canonical_json_bytes)`.
- Fail-closed release: protected CIDs, envelope sets, and ciphertext streams are
  never returned unless the audit commit succeeds first.
- Self-audited queries: `GET /v1/audit` appends its own `audit.query` row before
  returning only the authenticated active member's audit records.
