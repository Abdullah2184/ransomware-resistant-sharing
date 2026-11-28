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
configure the same chain ID there. Deployment, role activation, audited Safe
v1.4.1 `2-of-3` threshold governance, Option B relayed envelope updates,
EIP-712 parity, and §7.9 gas bounds are covered by local Hardhat tests (`37`
passing: `30` Solidity, `7` Node.js including `GasBounds.ts` and
`SafeGovernance.ts`).

## Local Besu Bootstrap with Audited Safe v1.4.1 Proxies (`scripts/besu-bootstrap.mjs`)

[`scripts/besu-bootstrap.mjs`](scripts/besu-bootstrap.mjs) (backed by
[`scripts/safe-helpers.mjs`](scripts/safe-helpers.mjs) and
`@safe-global/safe-contracts` `1.4.1`) deploys real audited Safe v1.4.1
infrastructure (`Safe` singleton, `SafeProxyFactory`,
`CompatibilityFallbackHandler`) and three independent **`2-of-3` threshold Safe
smart accounts** (`consortiumSafe`, `emergencySafe`, `organizationSafe`) using
zero-gas-price Besu transactions. Local development owner keys stay inside
git-ignored `contracts/secrets/besu-dev-accounts.json` (`0600`) and are never
printed:

```shell
node scripts/besu-bootstrap.mjs init-dev-accounts
node scripts/besu-bootstrap.mjs deploy
node scripts/besu-bootstrap.mjs schedule
node scripts/besu-bootstrap.mjs status
# After the 24-hour (86,400s) RrdsTimelockController delay expires:
node scripts/besu-bootstrap.mjs execute
# Enroll the local demo member through 2-of-3 organizationSafe execTransaction:
node scripts/besu-bootstrap.mjs register-member
# Grant / revoke Read ACL through 2-of-3 organizationSafe execTransaction:
node scripts/besu-bootstrap.mjs grant-read <fileId> <memberId> [proposalSeed]
node scripts/besu-bootstrap.mjs revoke-read <fileId> <memberId> [proposalSeed]
```

> **Signer custody note:** While the on-chain governance authorities are real
> audited Safe v1.4.1 `2-of-3` proxy contracts, local owner keys in
> `contracts/secrets/besu-dev-accounts.json` are development-only software keys.
> Production deployments must use hardware-backed / HSM Safe signers per
> [`docs/operations/consortium-policies.md`](../docs/operations/consortium-policies.md).

### Current Local Besu Deployment Snapshot (28 November 2026 — Safe v1.4.1 + Option B)

- **Network:** Local Besu QBFT (`http://127.0.0.1:8545`, `chainId = 1337`, zero gas price)
- **Authority mode:** **Audited Safe v1.4.1 `2-of-3` threshold proxy contracts** (`@safe-global/safe-contracts@1.4.1`)
  - `Safe` singleton: `0xd18d97A3fcb1727Bd6d985ADAe904d8037F65922` (block `62877`)
  - `SafeProxyFactory`: `0xCe4F7E2f1B578075f318bA3091E0dE0ea80F6E44` (block `62879`)
  - `CompatibilityFallbackHandler`: `0xCF157029fC460D85c101360fbD73d90931249201` (block `62881`)
  - `consortiumSafe` (`2-of-3`): `0xB22ABd007c759Ff1c8C02e88342AF9157a5bBd10` (block `62883`)
  - `emergencySafe` (`2-of-3`): `0xc6cB8012bb50d454b2A40EDb860968a2829e70bc` (block `62885`)
  - `organizationSafe` (`2-of-3`): `0xBB73518d8f0Fc9E99B7a590F3E2CA027b462b378` (block `62887`)
- **`RrdsTimelockController`:** `0x5a51c4bd51709838764c185b490221855e37e64d` (block `62889`, `minDelay = 86400s`)
- **`AccessGovernance` (Option B):** `0x04ec7bde5732ca6c5e04709641c53a564e1c5472` (block `62891`, `17,475` runtime bytes)
- **`FileRegistry`:** `0xeae1730d50eb47b7573c682afa2ee4995ba1968d` (block `62894`)
- **Timelocked activation batch (`grantRole(FILE_REGISTRY_ROLE, FileRegistry)` + `registerOrganization(rrds-dev-org-1, organizationSafe)`):**
  - `operationId`: `0xc15d21e8e81b88eda9328e2a6cd6dfa2cc59d3505318c4ba209447f7752f5254`
  - Scheduled via **`2-of-3` `consortiumSafe.execTransaction`** at block `62898` (`delay = 86400s`); executable at **`2026-11-29T03:19:33.000Z`** via `node scripts/besu-bootstrap.mjs execute`
  - Verified on-chain: all 3 Safe proxies report `getThreshold() == 2`, `deployer` has no admin role on either contract, `RrdsTimelockController` is sole `DEFAULT_ADMIN_ROLE` on `AccessGovernance`, `emergencySafe` holds `EMERGENCY_SUSPENDER_ROLE`, and `FILE_REGISTRY_ROLE` remains inactive until execution.
- **Archived prior snapshots:** Pre-Option-B E2E-verified snapshot (`0x18cd...`, `0xe130...`, `0xf27d...`) archived under `contracts/ignition/deployments/chain-1337/pre-option-b/`; Option B EOA-placeholder snapshot (`0xc464...`, `0x1efe...`, `0x7ba5...`) archived under `contracts/ignition/deployments/chain-1337/option-b-eoa-placeholder/`.
