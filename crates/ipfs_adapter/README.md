# Kubo and IPFS Cluster adapter

Implements the `ports::BlobStore` boundary using the approved deterministic
UnixFS package profile in `docs/adr/content-package-unixfs-profile.md`.
Uploads receive a canonical encrypted manifest and ciphertext-only streams;
the adapter does not accept or process plaintext.

The adapter checks Kubo's manifest, envelope-set, and chunk CIDs, verifies the
returned root block against its SHA-256 CID, disables HTTP redirects
(`Policy::none()`), pins through the authenticated Cluster API with failover
across configured Cluster endpoints, and waits for the configured distinct-peer
quorum. `ensure_replication` verifies existing Cluster pin quorum and Kubo root
block integrity without repinning arbitrary unvalidated CIDs. Retrieval tries
configured Kubo endpoints in order. The application remains responsible for
validating the exported CARv1 DAG, manifest, and AEAD tags before accepting
decrypted content.

Configuration is read from `IPFS_API_URLS` (or `IPFS_API_URL`),
`IPFS_CLUSTER_API_URLS` (or `IPFS_CLUSTER_API_URL`), `IPFS_CLUSTER_USERNAME`,
`IPFS_CLUSTER_PASSWORD_FILE`, and the documented timeout/size settings.
Credentials are not included in debug output, and endpoint URLs must not embed
userinfo, queries, or fragments.

Run unit tests with:

```shell
cargo test -p ipfs-adapter --locked
```

The dual-node integration tests require the local Kubo (2 peers) and Cluster
services and are ignored during ordinary offline test runs. With the local
Compose stack running (`docker compose --env-file .env -f infra/compose.yaml up -d`),
run them with:

```shell
set -a && . ./.env && set +a
cargo test -p ipfs-adapter --test cluster_integration -p rrds-tests --test cross_component_integration --locked -- --ignored
```

Live two-peer integration status and host-independence limitations are
documented in `infra/ipfs-cluster/README.md`.
