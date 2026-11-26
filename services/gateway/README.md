# Gateway

The current Phase 4 increment provides local login challenge and session
endpoints:

- `POST /v1/auth/challenge` issues a random, short-lived, audience-bound
  EIP-712 challenge for a claimed member ID.
- `POST /v1/auth/session` validates the challenge signature against the
  member's active signing address read from Besu's finalized state, then
  atomically consumes the stored challenge and creates a short-lived session.
- `GET /v1/auth/session` validates a bearer session and returns only the
  authenticated member ID.
- `DELETE /v1/auth/session` atomically revokes the bearer session
  (`revoked_at`), appends an `auth.session.revoke` audit record, and returns
  `204 No Content`.
- `GET /v1/identities/{memberId}` returns contract-backed public identity and
  key status at a single finalized block; it is source-rate-limited and does
  not use the PostgreSQL identity projection.
- `GET /v1/files` (optional `?folderId=...`) returns indexer-backed folder and
  file listings for an active member's organization (`authoritative: false`)
  with finalized and indexed block cursors.
- `GET /v1/files/{fileId}/versions` checks authoritative Read ACL at one
  committed block, then returns the authoritative head and projected version
  history.
- `POST /v1/files/{fileId}/versions/{version}/access` validates a signed
  EIP-712 `AccessLookup`, checks finalized ACL and historical-read grants,
  consumes the one-time nonce in PostgreSQL, audits, and returns CID references.
- `GET /v1/files/{fileId}/versions/{version}/content` repeats finalized ACL
  checks, audits, and streams the encrypted IPFS CAR (`Cache-Control: no-store`).
- `GET /v1/files/{fileId}/versions/{version}/envelope` repeats finalized ACL
  checks, fetches and validates the canonical `KeyEnvelopeSet` against the
  on-chain pointer and recipient key version, audits, and returns JSON
  (`Cache-Control: no-store`).
- `POST /v1/blobs/content` validates a framed (`RRDSPKG1`) client-encrypted
  content package (manifest + chunk CIDs), pins it to `MIN_PIN_REPLICAS` via
  Cluster, and audits `blob.content_upload` (`201`). Bounded by
  `GATEWAY_MAX_BLOB_UPLOAD_BYTES` (default 64 MiB).
- `POST /v1/blobs/envelopes` validates a canonical `KeyEnvelopeSet` JSON
  (max 512 KiB), pins it to `MIN_PIN_REPLICAS`, and audits
  `blob.envelope_upload` (`201`).
- `POST /v1/files` validates a signed EIP-712 `VersionAppend` for version 1,
  verifies Cluster pin quorum on both `contentCid` and `envelopeSetCid`, relays
  `FileRegistry.createFile`, and audits the outcome (`201` on commit).
- `POST /v1/files/{fileId}/versions` checks authoritative Write ACL, head
  continuity (`409 stale_head`), EIP-712 signature, and pin quorum before
  relaying `FileRegistry.appendVersion` (`201` on commit).
- `POST /v1/files/{fileId}/versions/{version}/envelopes` checks Read ACL,
  envelope pointer continuity (`409 stale_head`), EIP-712 `EnvelopeSetUpdate`
  signature, pin quorum, and canonical `KeyEnvelopeSet` at `revision + 1`
  before relaying `AccessGovernance.updateEnvelopeSet` (`200` on commit).
- `GET /v1/audit` returns an active member's own audit records after recording
  the `audit.query` event itself.
- `GET /healthz` is an unauthenticated process health response.

Challenges and token-bucket rate limits are stored in PostgreSQL for sharing
across gateway instances. Session tokens are returned once; only their
Keccak-256 hashes and expiry are stored. Authentication successes and
well-formed request failures are appended to a PostgreSQL hash chain before a
success response. Failed audit persistence prevents session issuance and
session identity disclosure. Request examples and the exact typed challenge
are in [docs/api.md](../../docs/api.md).

## Local configuration and run

Set `DATABASE_URL`, `BESU_RPC_URL`, `BESU_CHAIN_ID`,
`CONTRACT_ACCESS_GOVERNANCE_ADDRESS`, `CONTRACT_FILE_REGISTRY_ADDRESS`,
`GATEWAY_AUDIENCE`, and the IPFS/Cluster settings documented in `.env.example`.
Optional challenge/session TTLs, source-address token-bucket limits, storage
timeouts, and `GATEWAY_BIND` are also configured there.

The binary reads process environment variables; Cargo does not load `.env`
automatically. From the repository root in Bash, load the ignored local file
and launch it with:

```shell
set -a
. ./.env
set +a
cargo run --locked -p gateway
```

`infra/compose.yaml` provides PostgreSQL and IPFS/Cluster. The separate
`infra/besu-qbft/compose.yaml` provides the local Besu network; follow its
README before starting the gateway. Configure the two deployed contract
addresses in `.env` after deploying the contracts.

The gateway applies the shared SQLx migrations during startup. The default
listener binds only to `127.0.0.1:8080`; non-loopback binds are refused until a
TLS termination and deployment boundary are configured. Do not expose it
directly to an untrusted network.

## Current limits

The service provides authentication, contract-backed identity lookup, signed
access lookup, authorized ciphertext streaming, authorized canonical envelope
retrieval with recipient-membership validation, indexer-backed file/folder
listings and version history, self-audited member audit queries, and relayed
file/version/envelope write routes (with pin-before-commit quorum enforcement
and explicit commit/revert/timeout reporting). When no relayer signer is
configured at startup, the gateway runs in read-only mode and returns `503` on
write routes; software dev relayer keys require explicit
`GATEWAY_ALLOW_UNSAFE_DEV_RELAYER=true` opt-in and are rejected under
production policy. Multi-sig ACL/governance proposal execution remains handled
through Safe/Timelock governance.
The stream route returns an IPFS CAR response; its audit indicates
authorization before streaming, not full client receipt.

The current audit work covers challenge issuance, session issuance/validation/
revocation, rate-limited auth calls, signed access lookups, content/envelope
retrieval, ciphertext blob staging, relayed writes, and audit queries. Every
response includes an `X-Request-Id` correlation header and emits structured JSON
operational logs (without tokens or raw IPs). Rate limiting enforces independent
per-source, per-member (`GATEWAY_MEMBER_RATE_LIMIT_*`), and per-source
invalid-signature (`GATEWAY_INVALID_SIG_LIMIT_*`) token buckets. Least-privilege
PostgreSQL role separation grants are provided in
[`infra/postgres/init-roles.sql`](../../infra/postgres/init-roles.sql).
Production TLS termination and malformed pre-routing HTTP audit hooks remain
operational deployment tasks.

Verify the service with:

```shell
cargo test --locked -p gateway
cargo test --locked -p chain-adapter
```
