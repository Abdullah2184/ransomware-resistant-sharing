# Kubo and IPFS Cluster adapter

Implements the `ports::BlobStore` boundary using the approved deterministic
UnixFS package profile in `docs/adr/content-package-unixfs-profile.md`.
Uploads receive a canonical encrypted manifest and ciphertext-only streams;
the adapter does not accept or process plaintext.

The adapter checks Kubo's manifest and chunk CIDs, verifies the returned root
block against its CID, pins through the authenticated Cluster API, and waits
for the configured distinct-peer quorum. Retrieval tries configured Kubo
endpoints in order. The application remains responsible for validating the
exported package, manifest, and AEAD tags before accepting decrypted content.

Configuration is read from `IPFS_API_URLS` (or `IPFS_API_URL`),
`IPFS_CLUSTER_API_URL`, `IPFS_CLUSTER_USERNAME`,
`IPFS_CLUSTER_PASSWORD_FILE`, and the documented timeout/size settings.
Credentials are not included in debug output.

Run unit tests with:

```shell
cargo test -p ipfs-adapter --locked
```

The two-peer integration test requires the local Kubo and Cluster services and
is ignored during ordinary test runs. Run it explicitly only after the
two-peer replication verifier succeeds:

```shell
cargo test -p ipfs-adapter --locked --test cluster_integration -- --ignored
```

The current replication limitation is documented in
`infra/ipfs-cluster/README.md`.
