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
`CONTRACT_ACCESS_GOVERNANCE_ADDRESS`, `CONTRACT_FILE_REGISTRY_ADDRESS`, and
`GATEWAY_AUDIENCE` in the local environment. Optional challenge/session TTLs, source-address token-bucket
limits and `GATEWAY_BIND` are documented in `.env.example`.

Run with:

```shell
cargo run --locked -p gateway
```

The gateway applies the shared SQLx migrations during startup. The default
listener binds only to `127.0.0.1:8080`; non-loopback binds are refused until a
TLS termination and deployment boundary are configured. Do not expose it
directly to an untrusted network.

## Current limits

The service does not yet expose file, content, identity-directory, or audit
query routes. It does not yet perform ACL checks or release CIDs/ciphertext;
session authentication is not file authorization. The current audit work
covers challenge issuance, rate-limited auth calls, and well-formed session
attempts only. Authentication JSON parsing errors are rate-limited and
audited, but malformed HTTP requests rejected before routing are not.
PostgreSQL role separation, audit read controls, session revocation,
production TLS, and complete request/correlation IDs are also outstanding.

Verify the service with:

```shell
cargo test --locked -p gateway
cargo test --locked -p chain-adapter
```
