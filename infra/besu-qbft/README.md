# Local Besu QBFT development network

This separate Compose project is the local blockchain architecture for the
application. It runs four QBFT validators and a fifth non-validator RPC node.
Only the RPC node's HTTP API is published, on `127.0.0.1:8545`; validator P2P
ports are not published. The services share a Docker bridge so the RPC port
can be bound to host loopback; an `internal: true` Docker network prevents host
interface port publication. The RPC node has its own P2P identity and no
validator key. Besu DNS updates are enabled because bootnode URLs use Docker
service names and their addresses may change when the bridge is recreated.

The local genesis parameters are chain ID `1337`, QBFT with a two-second block
period, a 30,000-block epoch, four-second request timeout, London EVM rules,
zero base fee, and a 30-million gas block limit. `BESU_CHAIN_ID` in the root
`.env` must match. Solidity's Besu deployment build targets the London EVM.
These are development settings, not a production network profile.

## Prepare and start

Prerequisites: Docker Compose v2, Python 3, and the root `.env`. The first
command generates four distinct QBFT validator keys and a genesis file using
Besu 26.11.0. Generated private keys and runtime data are ignored by Git and
remain local to this machine. The preparation script refuses to overwrite any
existing generated files.

```shell
sh infra/besu-qbft/prepare.sh
docker compose --env-file .env -f infra/besu-qbft/compose.yaml up -d
sh infra/besu-qbft/verify.sh
```

To stop the services without deleting chain data, run:

```shell
docker compose --env-file .env -f infra/besu-qbft/compose.yaml stop
```

Do not use `down -v` for this network. A changed genesis or validator set is a
new chain; preserve the existing data and obtain maintainer approval before
creating a replacement network.

The root `.env.example` already points `BESU_RPC_URL` and `BESU_CHAIN_ID` at
this network. The deployment key remains in the Hardhat keystore; no private
key should be added to `.env`, Compose, or tracked files. Contract deployment
and Safe/timelock activation remain separate steps and have not yet been
verified on this network.

## Network assumptions and limitations

The four validators satisfy the local QBFT 3-of-4 quorum model and can tolerate
one unavailable validator. All five nodes still share one machine, Docker
daemon, storage system, and administrator; this does not model independent
consortium operators or production fault tolerance. Validator keys are
development-only, cleartext files in the ignored generated directory and
must never be used in production.

Besu's official QBFT tutorial uses four validators for Byzantine fault
tolerance, and the QBFT documentation warns that losing more than one-third
of validators stalls block production. This setup follows that topology while
keeping the application RPC endpoint on a distinct non-validator node.

## Verification

`verify.sh` checks the configured chain ID, the latest QBFT-committed block,
connected validator peers, and the QBFT validator set through the RPC-only node.
Besu's generic `finalized` JSON-RPC tag is not supported for this QBFT network;
the latest committed head is final under QBFT consensus. It does not
deploy contracts or verify Safe, timelock, relayer, and gateway transactions.

The initial verification snapshot on 12 November 2026 reported chain ID
`1337`, four connected peers, four validators, and committed block `743`. A
later same-day snapshot in the root README recorded block `969`; these are
time-ordered observations of a progressing chain. The loopback RPC binding and
service-name bootnode resolution were checked after a Compose network
recreation.

References: [Besu QBFT network tutorial](https://docs.besu-eth.org/private-networks/tutorials/qbft/),
[QBFT consensus guidance](https://docs.besu-eth.org/private-networks/how-to/configure/consensus/qbft/),
[Besu node key handling](https://docs.besu-eth.org/public-networks/concepts/node-keys/).
