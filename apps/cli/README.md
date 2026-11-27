# Command-Line Client (`apps/cli`, Phase 5)

Thin endpoint CLI wired to `crates/application` (`AuthService`, `UploadService`,
`DownloadService`, `ShareService`) and `GatewayHttpClient`.

## Trust Boundary

- All plaintext encryption/decryption (AES-256-GCM), HPKE DEK wrapping, CARv1
  DAG/root-CID verification (`dag-pb` `0x70` UnixFS directory root and `raw`
  `0x55` blocks), envelope-set CID verification, manifest-hash verification,
  and EIP-712 signing occur locally on the client endpoint via
  `crates/application`, `crates/crypto`, and `KeyCustodyProvider`.
- The CLI communicates **exclusively** with the RRDS Gateway HTTP API; it never
  connects to Besu JSON-RPC, PostgreSQL, Kubo, or IPFS Cluster admin APIs.
- `GatewayHttpClient` disables HTTP redirects (`Policy::none()`), bounds every
  HTTP response body in memory, and requires `https://` for all non-loopback
  hosts unless `RRDS_ALLOW_INSECURE_HTTP=true` is explicitly set for isolated
  local testing.
- Key custody is checked through `key_custody::verify_provider_policy`:
  `CustodyStartupPolicy::Production` is the default and rejects software keys.
  Local development/testing requires explicit opt-in via
  `RRDS_ALLOW_UNSAFE_DEV_CUSTODY=true` and `RRDS_DEV_*` variables.

## Supported Commands

```shell
cargo run --locked -p cli -- health [gateway-url]
cargo run --locked -p cli -- login [--session-file <path>] [--print-token]
cargo run --locked -p cli -- logout [--session-file <path>]
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

- `login` requires either `--session-file <path>` (or `RRDS_SESSION_FILE`,
  which persists the bearer token atomically with mode `0600` on Unix) or an
  explicit `--print-token` opt-in so bearer tokens are never accidentally
  printed to terminal scrollback. `logout` revokes the active session via
  `DELETE /v1/auth/session` and removes the local session file when present.
- `upload` and `modify` reject non-regular paths (symlinks, directories, special
  files), read plaintext into a `Zeroizing<Vec<u8>>` buffer bounded by
  `max_file_bytes`, and wire the default-disabled `PreUploadScanner`
  (`DisabledScanner`) before client-side encryption. Setting
  `RRDS_SCANNER_MODE` to anything other than `disabled` fails closed until an
  active scanner adapter is configured.
- `download` writes plaintext atomically via a `0600` `fsync`'d temporary file
  and `rename` only after verifying the CARv1 header root (`access.content_cid`),
  `dag-pb` UnixFS links and SHA-256 multihashes, authoritative on-chain
  `access.manifest_hash`, canonical `KeyEnvelopeSet` CID and HPKE unwrap,
  canonical `EncryptedFileManifest`, and every AES-256-GCM authentication tag.
- `restore` decrypts `<source-version>` and invokes `UploadService::restore_version`
  to append a brand-new head version under a fresh DEK without modifying or
  deleting prior history.
- Orphaned uploads (where IPFS Cluster pinning succeeded but the ledger commit
  failed) print the pinned orphan CIDs clearly rather than claiming commit.

## Environment Variables

- `GATEWAY_URL` (default `http://127.0.0.1:8080`, requires `https://` for
  non-loopback hosts; must not include userinfo, query, or fragment)
- `RRDS_ALLOW_INSECURE_HTTP` (`true` only to opt into non-loopback `http://` in
  isolated local testing)
- `RRDS_SCANNER_MODE` (default `disabled`; non-`disabled` values fail closed in
  the MVP)
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
