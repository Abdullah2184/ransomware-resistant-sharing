# Gateway (`services/gateway`)

Organization-hosted HTTP API, authoritative Besu `eth_call` authorization proxy,
encrypted IPFS/Cluster streaming adapter, Type-2 contract transaction relayer,
and append-only PostgreSQL audit service (`TECHNICAL_SPECIFICATION.md` §§7–10).

The gateway **never** handles plaintext file bytes, unwrapped DEKs, or member
private keys.

## HTTP Interface

- `GET /healthz` — unauthenticated process health check.
- `GET /v1/identities/{memberId}` — contract-backed public identity and key
  status at a single finalized block (never reads PostgreSQL identity
  projections).
- `POST /v1/auth/challenge` — issues a random, short-lived, audience-bound
  EIP-712 `LoginChallenge`.
- `POST /v1/auth/session` — validates the challenge signature against Besu's
  finalized signing address, atomically consumes the one-time challenge, and
  returns a short-lived bearer token once (only its Keccak-256 hash is stored).
- `GET /v1/auth/session` — validates a bearer session and returns the
  authenticated `memberId`.
- `DELETE /v1/auth/session` — atomically revokes the session (`revoked_at`),
  appends `auth.session.revoke` to the audit chain, and returns `204`.
- `GET /v1/files` (optional `?folderId=...`) — returns indexer-backed folder
  and file listings (`authoritative: false`) for an active member's
  organization with `finalizedBlock` and `indexedBlock` cursors.
- `GET /v1/files/{fileId}/versions` — verifies finalized Besu Read ACL first,
  then returns the authoritative head and projected version history.
- `POST /v1/files/{fileId}/versions/{version}/access` — verifies a signed
  EIP-712 `AccessLookup`, checks finalized Read ACL and version-scoped
  historical grants, consumes the one-time nonce, durably appends an audit
  record, and returns CID references.
- `GET /v1/files/{fileId}/versions/{version}/content` — repeats finalized ACL
  checks, durably audits, enforces bounded stream concurrency
  (`GATEWAY_MAX_CONCURRENT_STREAMS`), and streams the encrypted IPFS CARv1
  (`Cache-Control: no-store`).
- `GET /v1/files/{fileId}/versions/{version}/envelope` — repeats finalized ACL
  checks, validates the canonical `KeyEnvelopeSet` against on-chain pointers
  and recipient key version, durably audits, and returns JSON
  (`Cache-Control: no-store`).
- `POST /v1/blobs/content` — pre-authorizes file/ACL state, validates a framed
  (`RRDSPKG1`) client-encrypted package, pins to `MIN_PIN_REPLICAS`, records
  staging in `gateway_orphan_blobs`, and audits `blob.content_upload` (`201`).
- `POST /v1/blobs/envelopes` — pre-authorizes file/ACL state, validates a
  canonical `KeyEnvelopeSet` (max 512 KiB), pins to `MIN_PIN_REPLICAS`, records
  staging in `gateway_orphan_blobs`, and audits `blob.envelope_upload` (`201`).
- `POST /v1/files` — validates signed EIP-712 `VersionAppend` (V1) and Cluster
  pin quorum, broadcasts `FileRegistry.createFile`, persists `pending` metadata
  to `gateway_relayed_transactions` **before** confirmation polling, and
  returns `201` on commit.
- `POST /v1/files/{fileId}/versions` — validates Write ACL, head continuity
  (`409 stale_head`), optional `restoredFromVersion` (audited as
  `file.version_restore`), EIP-712 signature, and pin quorum before relaying
  `FileRegistry.appendVersion` (`201` on commit).
- `POST /v1/files/{fileId}/versions/{version}/envelopes` — Option B
  non-authority envelope-set update: validates Read ACL, pointer continuity,
  EIP-712 `EnvelopeSetUpdate`, pin quorum, and canonical `KeyEnvelopeSet` at
  `revision + 1` before relaying `AccessGovernance.updateEnvelopeSet` (`200`).
- `GET /v1/transactions/{txHash}` — authenticated reconciliation of relayed
  transactions persisted in `gateway_relayed_transactions` (survives timeouts
  and restarts; isolates cross-member lookups with `404`).
- `GET /v1/audit` — returns an active member's own hash-chained audit records
  after durably recording the `audit.query` event itself.

See [docs/api.md](../../docs/api.md) for request/response schemas and error
codes.

## Runtime Guards, Rate Limits & Background Workers

- **Environment policy (`RRDS_ENV`):** Under `RRDS_ENV=production`, the gateway
  refuses `GATEWAY_ALLOW_UNSAFE_DEV_RELAYER=true`, placeholder credentials, and
  non-HTTPS non-loopback infrastructure endpoints. Loopback bind
  (`GATEWAY_BIND=127.0.0.1:8080`) is enforced so TLS termination is handled by
  a dedicated reverse proxy (see [`infra/compose/gateway.yaml`](../../infra/compose/gateway.yaml)).
- **Least-privilege database migrations:** Apply SQLx migrations (`0001`–`0007`)
  once with `rrds-migrate run` as `rrfs_migrator`, apply
  [`infra/postgres/init-roles.sql`](../../infra/postgres/init-roles.sql), and
  run `gateway` as `rrfs_gateway` with `DATABASE_MIGRATION_MODE=verify`.
- **Rate limiting & observability:** PostgreSQL-backed token buckets enforce
  per-source, per-member (`GATEWAY_MEMBER_RATE_LIMIT_*`), per-organization
  (`GATEWAY_ORG_RATE_LIMIT_*`), and per-source invalid-signature
  (`GATEWAY_INVALID_SIG_LIMIT_*`) ceilings. Every response carries
  `X-Request-Id` and emits structured JSON logs (no tokens or raw IPs).
- **Maintenance workers (`src/maintenance.rs`):**
  - `PendingTransactionReconciler`: reconciles persisted `pending` transactions
    on startup and periodically against Besu receipts.
  - `OrphanBlobCleaner`: unpins (`DELETE /pins/{cid}`) unreferenced orphan
    candidates past `ORPHAN_RETENTION_SECONDS` only after confirming zero
    references in `gateway_relayed_transactions` (`pending`), PostgreSQL
    projections, and authoritative Besu state.
  - `StorageHealthMonitor`: periodically probes Kubo/Cluster peer health.

## Verification

```shell
# Offline unit & route tests
cargo test --locked --offline -p gateway
cargo test --locked --offline -p chain-adapter

# Live CLI -> Gateway -> 2-peer Kubo/IPFS Cluster E2E test
set -a && . ./.env && set +a
cargo test -p gateway \
  cli_binary_through_real_gateway_to_live_dual_node_ipfs_cluster_end_to_end \
  --locked --offline -- --ignored --nocapture

# Live PostgreSQL 18.6 & 4-role RBAC integration tests (use test DB, never rrfs_dev)
DATABASE_URL="${DATABASE_URL%/*}/rrfs_indexer_test" \
  cargo test -p gateway --locked --offline -- --ignored
```
