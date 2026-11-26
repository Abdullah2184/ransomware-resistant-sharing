# Local two-peer IPFS Cluster

This development setup runs two separately configured Kubo daemons and two
CRDT Cluster peers. Each Kubo daemon and Cluster peer has its own persistent
Docker volume; the peer identities are generated independently on first start
and persist with those volumes.

## Security boundaries

- Both Kubo nodes use one generated private-network swarm key and disable
  public bootstrap peers. `kubo2` discovers `kubo`'s current identity at
  startup and configures it as its private swarm bootstrap peer. The Compose
  bridge (`rrfs-private`) does not publish Kubo swarm ports or HTTP gateway
  ports; commit `01e361f` removed Docker's `internal: true` flag so the host
  loopback bindings below can publish on Docker Desktop. Kubo's default
  private-address filters are cleared so peers can reach each other on the
  Docker bridge.
- For the host-run gateway and adapter, Kubo's administrative APIs are bound
  only to host loopback at `127.0.0.1:15001` and `127.0.0.1:15002`. They are
  not reachable from other machines or the public internet, but any process on
  the development host can access them. Do not use this development exposure
  in production. The Kubo HTTP gateway ports remain unpublished.
- Both Cluster peers use one generated 32-byte Cluster secret to authenticate
  Cluster protocol membership.
- `cluster2` waits for `cluster1` and uses its authenticated, runtime-discovered
  peer identity to bootstrap Cluster membership; this avoids relying on
  multicast discovery across Docker bridges.
- Cluster REST API BasicAuth uses a separately generated password. Only
  `cluster1` publishes the management API, bound to `127.0.0.1:9094`.
- Peer-to-peer Cluster and Kubo ports remain on the internal Docker network.
- The generated secrets are stored under the git-ignored `secrets/` directory.
  `init-secrets.sh` is idempotent and does not print, overwrite, or delete
  credentials.
- Do not use these development credentials outside this local environment.

Initialize secrets and start the services from the repository root:

```shell
sh infra/ipfs-cluster/init-secrets.sh
docker compose --env-file .env -f infra/compose.yaml up -d
```

The existing `ipfs_data` named volume is reused for the first Kubo node; the
second node and both Cluster peers use distinct new named volumes. Starting
the updated Compose configuration may recreate the existing Kubo container,
but does not remove its volume. Do not use `docker compose down -v`.

## Verify the two peers and a two-replica pin

```shell
sh infra/ipfs-cluster/verify.sh
```

The verification creates and pins a small non-sensitive test object
and leaves it pinned; it does not unpin or delete data. It requires the
services to be healthy. Check the `peers ls` output for two distinct peer
identities and the status output for allocations on both Cluster peers.

## Independence limitation

These are two peer processes and two Kubo stores, but they share one host,
Docker daemon, network, power source, and administrative boundary. This
environment verifies local allocation/replication only. It does **not**
establish two-organization independence or production fault tolerance.

## Current development status (updated 26 November 2026)

- **Live two-peer replication and Rust adapter integration verified (26 November 2026):**
  - All five Compose services (`postgres`, `kubo`, `kubo2`, `cluster1`, `cluster2`)
    are healthy with host loopback bindings (`127.0.0.1:5432`, `127.0.0.1:15001`,
    `127.0.0.1:15002`, `127.0.0.1:9094`).
  - `sh infra/ipfs-cluster/verify.sh` passed with both `rrfs-cluster-1` and
    `rrfs-cluster-2` reporting `PINNED` (0 attempts).
  - `cargo test -p ipfs-adapter --locked --test cluster_integration -- --ignored`
    passed (`1 passed; 0 failed` in 1.66s), verifying encrypted content-package
    upload, manifest/chunk/root CID verification, two-peer authenticated Cluster
    pin quorum, DAG export, and envelope-set upload/retrieval.
  - Fixes applied during live verification:
    1. `start-kubo.sh` now normalizes `/data/ipfs` ownership (`chown -R ipfs`)
       and runs bootstrap API queries via `gosu ipfs`; `infra/compose.yaml`
       healthchecks query Kubo over HTTP (`/ip4/127.0.0.1/tcp/5001`) as `ipfs`
       so healthchecks never open `/data/ipfs/datastore` as `root`.
    2. Amended the UnixFS profile (`docs/adr/content-package-unixfs-profile.md`)
       to 1 MiB plaintext chunks (`1,048,576` bytes; `1,048,592` ciphertext+tag)
       with `chunker=size-1048592` to stay within Kubo `0.43.1`'s `2,096,896`-byte
       chunker cap.
    3. Updated `ipfs_adapter` to accept Kubo's intermediate `"chunks"` directory
       entry on `wrap-with-directory=true` uploads and poll Cluster's `GET /pins/{cid}`
       pin-status endpoint.
  - Reminder: these two peers share one host and failure domain and do not
    demonstrate independent multi-organization operation.

### Historical bring-up notes (12 November 2026)

- Overriding the Cluster image entrypoint also removed its default command;
  the Compose services now explicitly invoke `daemon`.
- Cluster 1.1.6 expects the REST BasicAuth environment value in
  `username:password` map syntax. The local API password was rotated after the
  initial invalid value appeared in a startup diagnostic; credential values
  are not recorded here.
- Docker bridge multicast did not establish Cluster membership, so Cluster 2
  now discovers Cluster 1's runtime identity through its authenticated,
  internal REST API and starts with that peer as its bootstrap address.
- Kubo's default address filters rejected the private Docker bridge address.
  The local-only startup configuration clears those filters while leaving
  Kubo ports unpublished and the Compose network internal. Kubo 2 also
  discovers Kubo 1's current identity at startup and configures it as its
  private-swarm bootstrap peer.

For manual follow-up, first inspect the current container state without
deleting or recreating persistent volumes:

```shell
docker compose --env-file .env -f infra/compose.yaml ps
sh infra/ipfs-cluster/verify.sh
```

The verifier leaves its test object pinned and waits for both peers to report
`PINNED`. Diagnose any remaining error before interpreting the environment as
replicated. Never use `docker compose down -v` for this setup.

## Verification follow-up (12 November 2026)

The Docker Engine is available in this session. After Compose recreated Kubo,
Kubo 2, and PostgreSQL, all five services reported healthy. Both Kubo daemons
reported version `0.43.1`. The authenticated peer listing showed exactly two
distinct Cluster peers, each seeing one other peer. Running
`sh infra/ipfs-cluster/verify.sh` added a small test object and waited for
replication; Cluster 1 stayed `PINNED`, but Cluster 2 ended as
`PIN_ERROR: context canceled`. The test object remains pinned on Cluster 1.
Do not treat peer connectivity or container health as proof of a two-peer
quorum.

Compose configuration and Docker container inspection report the intended
loopback bindings `127.0.0.1:15001` and `127.0.0.1:15002`, but HTTP requests to
those ports from the current coding shell are refused. Continue host-port
troubleshooting when resuming this investigation. This shell limitation does
not establish whether a normal host process on the Docker Desktop machine can
reach the ports.

## Diagnostic follow-up (12 November 2026)

The verification CID remains recursively pinned on Kubo 1; Kubo 2 reports that
it is not locally pinned. Both Kubo daemons report the other Kubo peer in
`ipfs swarm peers`, and both Cluster peers see one another. A direct `ipfs cat`
for the CID from Kubo 2 did not complete during the diagnostic window and was
interrupted. Kubo 2's Bitswap wantlist contains the CID but has zero Bitswap
partners, and a time-bounded provider lookup returned no provider. This narrows
the issue to private-network provider discovery/transfer despite swarm and
Cluster membership; the cause remains unresolved. No pin, block, volume, or
database was removed or changed.

## Replication fix and verification (12 November 2026)

Kubo 0.43.1 started with AutoConf disabled while its default `"auto"`
placeholders remained, causing a fallback to WAN-only DHT. The startup script
now clears those optional endpoints and configures a private LAN DHT router.
Kubo 0.43.1's default sweep provider is a no-op with custom DHT routing, so the
local setup selects the legacy provider (`Provide.DHT.SweepEnabled=false`)
until the pinned version is upgraded. Public WAN DHT and delegated HTTP
routers are not configured.

After restarting only the two Kubo containers, both became healthy, the
fallback warning disappeared, Kubo 2 discovered Kubo 1 as the verification
CID's provider, and `ipfs cat` returned the expected payload. The full
`sh infra/ipfs-cluster/verify.sh` then passed: the CID was `PINNED` on both
Cluster peers with zero attempts. All named volumes and previous pins were
preserved. This verifies two-peer replication on one Docker host, not
independent production replicas.
