# Hardhat contract workspace

Hardhat 3, Solidity, `node:test` and `viem` are used for contract development, compilation, testing and deployment. The only configured external network is the local permissioned Besu development network; public-chain deployment is not supported.

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
current optimized `AccessGovernance` runtime is 17,475 bytes, below the
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
(copy [`ignition/parameters.example.json`](ignition/parameters.example.json) to
git-ignored `ignition/parameters.local.json`) containing `consortiumSafeAddress`
and `emergencySafeAddress`:

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
configure the same chain ID there. Deployment, role activation, Option B
relayed envelope updates, EIP-712 parity, and §7.9 gas bounds are covered by
local Hardhat tests (`36` passing: `30` Solidity, `6` Node.js including
`GasBounds.ts`).

## Local Dev Smoke-Test Bootstrap (`scripts/besu-bootstrap.mjs`)

For single-host local development smoke tests prior to deploying real Safe
multisig contracts on Besu, [`scripts/besu-bootstrap.mjs`](scripts/besu-bootstrap.mjs)
provides a zero-gas-price workflow that keeps all dev keys inside git-ignored
`contracts/secrets/besu-dev-accounts.json` (`0600`) and never prints private
keys:

```shell
node scripts/besu-bootstrap.mjs init-dev-accounts
node scripts/besu-bootstrap.mjs deploy
node scripts/besu-bootstrap.mjs schedule
node scripts/besu-bootstrap.mjs status
# After the 24-hour (86,400s) RrdsTimelockController delay expires:
node scripts/besu-bootstrap.mjs execute
# Enroll the local demo member (signs EIP-712 MemberKeyProof; secrets in git-ignored contracts/secrets/besu-dev-member.json):
node scripts/besu-bootstrap.mjs register-member
```

> **Development smoke-test limitation:** `init-dev-accounts` generates local
> EOA placeholders (`consortiumSafe`, `emergencySafe`, `organizationSafe`) to
> stand in for Safe smart accounts during local smoke testing only. Per
> [`docs/adr/governance-authority-and-timelock.md`](../docs/adr/governance-authority-and-timelock.md),
> production and staging deployments **must** use audited Safe threshold
> accounts and HSM/keystore custody, and real Safe proxy compatibility on Besu
> must be validated before any production claim.

### Current Local Besu Smoke-Test Deployment Snapshot (28 November 2026 — Option B)

- **Network:** Local Besu QBFT (`http://127.0.0.1:8545`, `chainId = 1337`, zero gas price)
- **Authority mode:** **Dev-only EOA placeholders** (stored in git-ignored `contracts/secrets/besu-dev-accounts.json`) — replace with real Safe multisigs later
- **`RrdsTimelockController`:** `0xc4647d02e8ba1c922d5c4fc22e04b3d1bcd75568` (block `60843`, `minDelay = 86400s`)
- **`AccessGovernance` (Option B):** `0x1efe4b8d6076a0ca115241346f8d7da516ce4055` (block `60845`, `17,475` runtime bytes)
- **`FileRegistry`:** `0x7ba5ef0f4c923942554c8b5788578280f7451f2d` (block `60846`)
- **Timelocked activation batch (`grantRole(FILE_REGISTRY_ROLE, FileRegistry)` + `registerOrganization(rrds-dev-org-1, orgSafe)`):**
  - `operationId`: `0xdb2a6855389bb2fa922f3110e7af84deabdf798c6c86b2c63261e665c16f8c56`
  - Scheduled at block `60850` (`delay = 86400s`); executable at **`2026-11-29T01:27:12.000Z`** via `node scripts/besu-bootstrap.mjs execute`
  - Verified on-chain: `deployer` has no admin role on either contract, `RrdsTimelockController` is sole `DEFAULT_ADMIN_ROLE` on `AccessGovernance`, `emergencySafe` holds `EMERGENCY_SUSPENDER_ROLE`, and `FILE_REGISTRY_ROLE` remains inactive until execution.
- **Previous snapshot (27 November 2026, pre-Option-B):** `RrdsTimelockController=0x18cd48bbff72acf29bd50f8e98397b1a07eba80f`, `AccessGovernance=0xe1304f22747114aafdd0c0c3f8e64b83c5326663`, `FileRegistry=0xf27d55447405f702299ed948325cfd9025fbe5cb` (timelock executed at block `59814`, demo member enrolled at block `59819`, full live `scripts/demo-local.sh` E2E verified through block `60745`; metadata archived under `contracts/ignition/deployments/chain-1337/pre-option-b/`).
