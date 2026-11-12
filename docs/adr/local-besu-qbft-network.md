# ADR: Local Besu QBFT development topology

**Status:** Accepted for local development  
**Decision scope:** Besu node roles, genesis parameters, and local key generation

## Context

The specification requires an initial four-validator QBFT network with a
three-validator quorum tolerating one faulty validator. It also separates RPC
nodes from validator credentials. The repository had no Besu network files or
services, although the gateway and indexer expect a local Besu JSON-RPC
endpoint.

Besu's current QBFT guidance requires four validators for Byzantine fault
tolerance and warns that block production stalls if more than one-third of
validators stop. Besu provides a generator that creates the QBFT genesis file
and validator keys together. The latest release as of 12 November 2026 is
26.11.0; the project pins its pulled OCI image by digest.

## Decision

- Add a local-only network with four validator services and a fifth, separate
  non-validator RPC service. Publish only RPC HTTP on host loopback at
  `127.0.0.1:8545`; keep P2P ports unpublished. Use a standard Docker bridge
  because Docker's `internal: true` network has no connection to host
  interfaces and prevents the required RPC port publication. The standard
  bridge has no published validator P2P ports; the Besu network remains
  development-only and local to one Docker host.
- Use Besu 26.11.0 at its pulled image digest
  `sha256:3d6ac0368d449c13c4ba075acac90d6b96afa5b3113295385d88c4d5122c8808`.
- Generate a fresh four-validator genesis and validator key set with Besu's
  `operator generate-blockchain-config`. Store generated files only under the
  Git-ignored `infra/besu-qbft/generated/` and `networkFiles/` directories.
  The preparation script refuses to overwrite existing generated output.
- Set local chain ID `1337`, QBFT block period 2 seconds, epoch length 30,000,
  request timeout 4 seconds, London EVM rules, zero genesis base fee, and
  `--min-gas-price=0` for the specification's zero-priced development
  transactions. Target London in the Hardhat Besu deployment build.
- Keep each validator P2P key separate. The RPC node uses its own non-validator
  P2P key and stores it in its own persistent data volume.
- Enable Besu DNS bootnode updates because bootnode URLs use Compose service
  names, whose addresses can change when Docker recreates the bridge network.
- Treat `eth_getBlockByNumber("latest")` as the latest QBFT-committed/finalized
  head and use explicit block numbers for state reads tied to a recorded head.
  Besu returns `Unknown block` for the generic `finalized` tag on this QBFT
  chain, so the proof-of-stake tag cannot implement the specification's QBFT
  finality requirement.
- Treat this as a single-host development/demo topology. It does not establish
  independent validator operators, production key custody, Safe compatibility,
  or production network security.

## Consequences and current verification boundary

- A fresh genesis or validator set is a new chain; its data volumes must not
  be reused with a different genesis. No automatic volume cleanup is
  provided.
- The network supplies read RPC for the gateway and indexer. Contract
  deployment, funded transaction policy, raw transaction relay, finalized
  receipts, and Safe/timelock activation still require implementation and
  verification.
- Runtime validator keys are plaintext local development credentials. They
  must never be reused outside this ignored development environment.
- The network must pass `infra/besu-qbft/verify.sh`, which checks chain ID,
  the latest QBFT-committed block, connected validator peers, and the active set
  count before gateway/indexer integration is claimed.
- The first runtime attempt used `internal: true`; Docker Desktop 29.9.2
  accepted the Compose mapping in container configuration but created no host
  port binding. Removing that setting and keeping only the loopback RPC
  publication is required for host-side gateway access.
- Recreating the bridge surfaced that Besu requires `--Xdns-update-enabled`
  alongside `--Xdns-enabled` when bootnodes use Docker DNS service names.
- The live network returned `-39001 Unknown block` for
  `eth_getBlockByNumber("finalized")` while `latest`, peer count, and the QBFT
  validator set were available. The chain adapter and network verifier now use
  the QBFT committed head per §7.10 instead of treating that PoS-only tag as
  QBFT finality.

## References

- [Besu QBFT network tutorial](https://docs.besu-eth.org/private-networks/tutorials/qbft/)
- [QBFT consensus configuration](https://docs.besu-eth.org/private-networks/how-to/configure/consensus/qbft/)
- [Besu node keys](https://docs.besu-eth.org/public-networks/concepts/node-keys/)
- [Besu 26.11.0 release](https://github.com/besu-eth/besu/releases/tag/26.11.0)
- `TECHNICAL_SPECIFICATION.md` §§7.6–7.14, 13, 15, and 16 Phases 2 and 6.
