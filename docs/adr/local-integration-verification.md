# ADR: Safe local integration verification

**Status:** Accepted for local development troubleshooting  
**Decision scope:** PostgreSQL migration validation and local Cluster acceptance

## Context

The local `rrfs_dev` database has SQLx migration versions 1–3 recorded, but its
version 3 checksum differs from the checked-in migration file. After rebuilding
the metadata-store crate, integration tests correctly reject that database
with `VersionMismatch(3)`. Changing a historical migration or overwriting the
recorded checksum would hide the inconsistency and weaken repeatable upgrades.

The host shell in this session cannot reach the Compose-published host ports,
even though the Docker container configuration contains loopback bindings.
The test suite therefore could not reach PostgreSQL from its normal host-side
execution path. A new, empty database named `rrfs_indexer_test` was created so
tests can be retried without touching `rrfs_dev`.

## Decision

- Keep existing migration files immutable after they have been applied.
- Do not edit or delete migration history in `rrfs_dev` as a test workaround.
- Run PostgreSQL integration tests against a fresh, dedicated database from
  an environment that can reach the Compose network or published ports.
- Preserve `rrfs_dev` and inspect its migration history/schema before proposing
  any additive reconciliation migration.
- Treat Docker health and Cluster peer connectivity as necessary but
  insufficient. The local replication acceptance check passes only when the
  test CID is `PINNED` on both distinct peers.
- Do not remove volumes or delete the failed verification pin as part of
  diagnosis.
- Configure this private development swarm with only Kubo's LAN DHT router.
  Clear default AutoConf placeholders before disabling AutoConf, and do not
  enable public WAN or delegated routers. For the pinned Kubo 0.43.1 release,
  set `Provide.DHT.SweepEnabled=false`: its default sweep provider is a no-op
  when custom routing includes a DHT router. This uses Kubo's legacy provider
  to honor the configured LAN DHT. Revisit the version-bound workaround when
  upgrading Kubo.

## Verification evidence (12 November 2026)

- Five Compose services reported healthy after Kubo, Kubo 2, and PostgreSQL
  were recreated without removing named volumes.
- Both Kubo daemons reported version `0.43.1`; two distinct Cluster peers saw
  one another.
- The replication verifier reported `PINNED` on Cluster 1 and then
  `PIN_ERROR: context canceled` on Cluster 2.
- Read-only follow-up confirmed the test CID is recursively pinned on Kubo 1
  but absent from Kubo 2's local pin set. Both Kubo nodes report each other as
  swarm peers, and both Cluster peers report membership. Fetching the CID with
  `ipfs cat` on Kubo 2 did not complete during the diagnostic window and was
  interrupted. The failure is therefore narrowed to Kubo 2 content retrieval,
  not Cluster membership; the exact bitswap/DAG retrieval cause is unresolved.
- Kubo 2's Bitswap wantlist contains the CID but reports zero Bitswap partners;
  a bounded `ipfs routing findprovs` lookup returned no providers. Do not treat
  private swarm connectivity as proof of provider discovery or block transfer.
- The first routing change cleared AutoConf placeholders and set `Routing.Type`
  to `auto`, but Kubo still warned that public HTTP IPNIs were enabled and fell
  back to WAN-only DHT. The explicit LAN DHT removed that fallback; the
  default sweep provider then returned a successful-looking queue result
  without publishing. Disabling sweep mode enabled provider lookup and transfer.
- After the correction, `sh infra/ipfs-cluster/verify.sh` passed. The CID was
  `PINNED` on both Cluster peers with zero attempts, and Kubo 2 retrieved the
  expected payload. The verifier's CID remains pinned on both peers.
- `rrfs_dev` migration version 3's recorded SHA-384 was
  `6403afa97e42fea7088332236abb32feb0c8b0cb69b5ebdc944b36382295c24835f1d84174d19b683490e57bc27351a4`;
  the checked-in file's SHA-384 was
  `b63da730f674c02882b2e0cf13bd11fe132ff196ee2558957012ceb73d4ab72f879400816c4806a69d095e01a5348011`.
- Tests against `rrfs_dev` failed safely with `VersionMismatch(3)`. Tests
  against `rrfs_indexer_test` could not connect from the host shell. Running
  the host-built test binary inside the PostgreSQL container failed because
  that container's glibc is older than the binary's requirement.

## Follow-up

Resume with a Docker-networked Rust test runner for PostgreSQL integration,
check Docker Desktop host-port forwarding from the host itself, and inspect the
existing `rrfs_dev` schema before proposing any additive reconciliation for
its version 3 checksum mismatch.

## Specification references

- `TECHNICAL_SPECIFICATION.md` §§7.12, 13, 15, and 16 Phases 3 and 6.
- [Kubo 0.43.1 configuration](https://github.com/ipfs/kubo/blob/v0.43.1/docs/config.md)
  documents the custom routing/provider settings. Kubo issue
  [#11482](https://github.com/ipfs/kubo/issues/11482) records the sweep
  provider no-op when custom routing includes a DHT router.
