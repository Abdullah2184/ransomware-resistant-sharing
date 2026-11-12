# ADR: Host-loopback Kubo APIs for development

**Status:** Accepted for local development  
**Decision scope:** Host-run gateway connectivity to the local Kubo daemons

## Context

The gateway is documented as a host-run Rust process, while the Kubo
administrative APIs were only reachable on the private Compose network. The
gateway's IPFS adapter needs Kubo's API for content retrieval and package
operations. The default Compose service names are not resolvable from a
host-run process.

## Decision

- Publish Kubo 1's API as `127.0.0.1:15001` and Kubo 2's API as
  `127.0.0.1:15002` for the local development Compose project.
- Configure host-run applications to use those loopback endpoints and the
  Cluster management API at `127.0.0.1:9094`.
- Keep Kubo swarm ports and HTTP gateway ports unpublished. Keep Compose on
  its internal Docker network.
- Treat the Kubo APIs as administrative interfaces: loopback binding prevents
  remote access, but any local process can still reach them. This is a
  development convenience, not a production deployment pattern.
- Production gateways must run in an authorized storage network or use an
  explicitly secured Kubo API path; do not expose Kubo APIs on non-loopback
  interfaces.

## Consequences

- The local gateway can use Kubo retrieval without moving it into the Compose
  network.
- Host ports `15001` and `15002` must be available when starting the local
  stack. A conflict requires changing the port bindings and matching
  application configuration together.
- The host-run gateway still requires the configured Besu RPC and PostgreSQL
  endpoints. Compose does not start Besu.

## Specification references

- `TECHNICAL_SPECIFICATION.md` §§4, 7.4, 10.4.3, 13, and 16 Phase 4.
