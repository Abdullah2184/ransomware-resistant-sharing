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
- `GET /v1/identities/{memberId}` returns contract-backed public identity and
  key status at a single finalized block; it is source-rate-limited and does
  not use the PostgreSQL identity projection.
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

The service has signed access-lookup and authorized ciphertext-stream routes,
but does not provide file-listing/history or audit-query routes. The lookup checks
finalized member, file Read ACL, head, version and envelope pointer state, then
records the attempt before returning CIDs. The current head is authorized by
the file Read ACL; historical versions additionally require an explicit
version-scoped grant under the same configured Read ACL Safe policy. Revoking
file Read invalidates old history grants, so a later file Read re-grant does
not restore them. The decision is recorded in
[`version-scoped-historical-read-access.md`](../../docs/adr/version-scoped-historical-read-access.md).
The lookup returns CIDs after authorization and audit; neither lookup nor the
stream route validates envelope contents or proves that the recipient has a
usable envelope. Historical sharing and client-side download/decryption are
not yet end-to-end workflows. The stream route returns an IPFS CAR response;
its audit indicates authorization before streaming, not full client receipt.

The current audit work covers challenge issuance, rate-limited auth calls,
well-formed session attempts, and signed access-lookup attempts. Authentication
JSON parsing errors are rate-limited and audited, but malformed HTTP requests
rejected before routing are not. PostgreSQL role separation, audit read
controls, session revocation, production TLS, and complete request/correlation
IDs are also outstanding.

Verify the service with:

```shell
cargo test --locked -p gateway
cargo test --locked -p chain-adapter
```
