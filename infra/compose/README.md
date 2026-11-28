# Production-Oriented Per-Role Compose Templates (`infra/compose`)

In production, consortium infrastructure is separated onto independent hosts
and administrative domains (`TECHNICAL_SPECIFICATION.md` §§1.1, 15.4 #13,
[`docs/architecture/deployment-and-boundaries.md`](../../docs/architecture/deployment-and-boundaries.md)).

- **Local all-in-one development / integration:** continue using
  [`infra/compose.yaml`](../compose.yaml) (PostgreSQL + 2 local Kubo/Cluster
  peers) and [`infra/besu-qbft/compose.yaml`](../besu-qbft/compose.yaml)
  (4 local validators + RPC node).
- **Per-host production templates (this directory):**

| Template | Target Host / Domain | Services |
| --- | --- | --- |
| [`database.yaml`](database.yaml) | Organization Database Host | PostgreSQL `18.6` (bound to internal/loopback interface; run `rrds-migrate run` as `rrfs_migrator` and apply [`infra/postgres/init-roles.sql`](../postgres/init-roles.sql)) |
| [`gateway.yaml`](gateway.yaml) | Organization Gateway Host | RRDS Gateway (`RRDS_ENV=production`, `rrfs_gateway` least-privilege role, `DATABASE_MIGRATION_MODE=verify`) behind Caddy TLS termination ([`Caddyfile.example`](Caddyfile.example)) |
| [`indexer.yaml`](indexer.yaml) | Organization Indexer Host | RRDS Indexer (`RRDS_ENV=production`, `rrfs_indexer` least-privilege role, `DATABASE_MIGRATION_MODE=verify`) |
| [`ipfs-peer.yaml`](ipfs-peer.yaml) | Consortium Member Storage Host (1 per org) | Single Kubo `0.43.1` + IPFS Cluster `1.1.6` peer in private swarm |
| [`besu-validator.yaml`](besu-validator.yaml) | Consortium Validator Host (4+ independent orgs) | Single Besu `26.11.0` QBFT validator (no JSON-RPC exposed) |
| [`besu-rpc.yaml`](besu-rpc.yaml) | Organization RPC Host | Single non-validator Besu `26.11.0` RPC node serving `gateway` and `indexer` |

Before production use, replace loopback binds with private-network/VPN or
mutual-TLS ingress, mount host-managed secrets, and never co-locate multiple
validator or storage replicas in a single failure domain.
