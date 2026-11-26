# Command-Line Client (`apps/cli`, Phase 5)

Thin endpoint CLI wired to `crates/application` (`AuthService`, `UploadService`,
`DownloadService`, `ShareService`) and `GatewayHttpClient`.

## Trust Boundary

- All plaintext encryption/decryption (AES-256-GCM), HPKE DEK wrapping, CARv1
  raw-block CID verification, and EIP-712 signing occur locally on the client
  endpoint via `crates/application`, `crates/crypto`, and `KeyCustodyProvider`.
- The CLI communicates **exclusively** with the RRDS Gateway HTTP API; it never
  connects to Besu JSON-RPC, PostgreSQL, Kubo, or IPFS Cluster admin APIs.
- Key custody is checked through `key_custody::verify_provider_policy`:
  `CustodyStartupPolicy::Production` is the default and rejects software keys.
  Local development/testing requires explicit opt-in via
  `RRDS_ALLOW_UNSAFE_DEV_CUSTODY=true` and `RRDS_DEV_*` variables.

## Supported Commands

```shell
cargo run --locked -p cli -- health [gateway-url]
cargo run --locked -p cli -- login [--session-file <path>]
cargo run --locked -p cli -- whoami
cargo run --locked -p cli -- identity <member-id>
cargo run --locked -p cli -- ls [--folder <folder-id>]
cargo run --locked -p cli -- history <file-id>
cargo run --locked -p cli -- upload <path> --name <display-name> [--folder <id>] [--file-id <id>] [--reader <member-id>]...
cargo run --locked -p cli -- modify <file-id> <path> [--reader <member-id>]...
cargo run --locked -p cli -- download <file-id> <version> <output-path>
cargo run --locked -p cli -- share <file-id> <version> <recipient-member-id> [--proposal-id <id>]
cargo run --locked -p cli -- restore <file-id> <source-version> [--reader <member-id>]...
cargo run --locked -p cli -- audit [--action <action>] [--limit <1..100>]
```

- `login --session-file <path>` writes the bearer token with mode `0600` on
  Unix. Subsequent commands read `RRDS_SESSION_TOKEN` or `RRDS_SESSION_FILE`.
- `download` writes plaintext to `<output-path>` only after verifying the
  canonical `KeyEnvelopeSet`, HPKE unwrap, canonical `EncryptedFileManifest`,
  every raw CARv1 chunk SHA-256 CID, and every AES-256-GCM authentication tag.
- `restore` decrypts `<source-version>` and invokes `UploadService::restore_version`
  to append a brand-new head version under a fresh DEK without modifying or
  deleting prior history.
- Orphaned uploads (where IPFS Cluster pinning succeeded but the ledger commit
  failed) print the pinned orphan CIDs clearly rather than claiming commit.

## Environment Variables

- `GATEWAY_URL` (default `http://127.0.0.1:8080`, must not include userinfo,
  query, or fragment)
- `BESU_CHAIN_ID` (default `1337`)
- `CONTRACT_ACCESS_GOVERNANCE_ADDRESS` (required for `login`, `download`, `share`, `restore`)
- `CONTRACT_FILE_REGISTRY_ADDRESS` (required for `upload`, `modify`, `restore`)
- `GATEWAY_AUDIENCE` (default `rrds-local`)
- `MIN_PIN_REPLICAS` (default `2`)
- `RRDS_SESSION_TOKEN` or `RRDS_SESSION_FILE`

## Scope Boundaries (Safe Governance)

Member registration (`registerMember`), key rotation (`supersedeMemberKeys`),
Read/Write ACL grants/revocations (`setFilePermission`,
`setHistoricalReadAccess`), and emergency suspension (`emergencySuspendMember`)
are multisig Organization/Emergency/Consortium Safe contract operations and
intentionally have no unguarded direct CLI endpoint.

## Verification

```shell
cargo test -p cli --locked --offline
```
