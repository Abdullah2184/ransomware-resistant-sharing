# Hardhat contract workspace

Hardhat 3, Solidity, `node:test` and `viem` are used for contract development, compilation, testing and deployment. The only configured external network is the local permissioned Besu development network; public-chain deployment is not supported.

The current `Counter` contract and its tests are retained as toolchain smoke tests; they are not ransomware-resistant-sharing functionality.

## Run tests

From this directory:

```shell
pnpm exec hardhat test
```

Solidity and Node.js tests can also be selected individually:

```shell
pnpm exec hardhat test solidity
pnpm exec hardhat test nodejs
```

The default and production Solidity build profiles enable the optimizer with
200 runs so local tests and Besu deployments use deployable bytecode. The
current optimized `AccessGovernance` runtime is 15,820 bytes, below the
24,576-byte EIP-170 limit.

## Deploy to local Besu

Start the local Besu QBFT development network and set its RPC endpoint and chain ID:

```shell
export BESU_RPC_URL=http://127.0.0.1:8545
export BESU_CHAIN_ID=1337
```

Store the local deployer key in Hardhat's keystore; do not put it in source control or command-line arguments:

```shell
pnpm exec hardhat keystore set BESU_DEPLOYER_PRIVATE_KEY
```

Deploy the RRDS contracts to Besu with a private Ignition parameter file
containing `consortiumSafeAddress` and `emergencySafeAddress`:

```shell
pnpm exec hardhat ignition deploy --network besuLocal \
  ignition/modules/RrdsDeployment.ts \
  --parameters ./ignition/parameters.local.json \
  --build-profile production
```

The deployment uses OpenZeppelin Contracts `5.6.1` with a 24-hour
`TimelockController`. The consortium Safe is its proposer and canceller; the
executor role is open, and no deployer/EOA receives an administrative bypass.
The module intentionally does not grant `FILE_REGISTRY_ROLE`. After deployment,
the consortium Safe must schedule that grant through the timelock, wait the
full delay, and have an account execute it. File creation remains unavailable
until that operation completes. Never put private keys in the parameter file.

`BESU_CHAIN_ID` defaults to the local development chain ID `1337` in the
Hardhat configuration. The actual Besu genesis configuration is authoritative;
configure the same chain ID there. `Counter.ts` remains only a toolchain
deployment smoke test. Deployment and role activation are covered by local
Solidity tests; a running Besu QBFT deployment and actual Safe integration have
not yet been verified.
