# RRDS MVP End-to-End Demonstration Guide

This guide walks a maintainer step-by-step through demonstrating the complete
**Blockchain-Based Ransomware-Resistant Data Sharing (RRDS)** MVP from clean
infrastructure bring-up through QBFT node/block validation, audited Safe v1.4.1
(`2-of-3`) governance and 24-hour timelock activation, least-privilege indexer
and gateway startup, encrypted file upload/download, append-only ransomware
recovery, Safe-governed ACL changes, Option B file sharing, revocation, and
both on-chain and off-chain auditing.

Every command in this guide matches the current implemented architecture (Rust
`1.99.1`, Solidity `0.8.34` / `@safe-global/safe-contracts@1.4.1`, Hyperledger
Besu `26.11.0` QBFT, Kubo `0.43.1`, IPFS Cluster `1.1.6`, PostgreSQL `18.6`).

---

## 0. Production Topology vs. Local Demo Environment

> **Important — Separate Systems in Production:**
> In a real consortium deployment, RRDS infrastructure is **never** co-located
> on a single machine. Each trust domain runs on separate hosts and
> administrative boundaries using the per-role templates in
> [`infra/compose/`](infra/compose/README.md) and the governance policies in
> [`docs/operations/consortium-policies.md`](docs/operations/consortium-policies.md):
>
> | Trust Domain / Host | Production Template | Local Demo Co-Location |
> | --- | --- | --- |
> | **4+ Independent Consortium Validators** (no JSON-RPC) | [`infra/compose/besu-validator.yaml`](infra/compose/besu-validator.yaml) | `validator1`–`validator4` in [`infra/besu-qbft/compose.yaml`](infra/besu-qbft/compose.yaml) |
> | **Organization Non-Validator Besu RPC Node** | [`infra/compose/besu-rpc.yaml`](infra/compose/besu-rpc.yaml) | `rpcnode` (`127.0.0.1:8545`) in [`infra/besu-qbft/compose.yaml`](infra/besu-qbft/compose.yaml) |
> | **Consortium Member Storage Peers** (1 per org) | [`infra/compose/ipfs-peer.yaml`](infra/compose/ipfs-peer.yaml) | `kubo`/`kubo2` + `cluster1`/`cluster2` in [`infra/compose.yaml`](infra/compose.yaml) |
> | **Organization PostgreSQL `18.6` Host** | [`infra/compose/database.yaml`](infra/compose/database.yaml) | `postgres` (`127.0.0.1:5432`) in [`infra/compose.yaml`](infra/compose.yaml) |
> | **Organization Indexer Host** (`rrfs_indexer`) | [`infra/compose/indexer.yaml`](infra/compose/indexer.yaml) | Local `./target/debug/indexer` process |
> | **Organization Gateway Host** (`rrfs_gateway` + TLS) | [`infra/compose/gateway.yaml`](infra/compose/gateway.yaml) + [`Caddyfile.example`](infra/compose/Caddyfile.example) | Local `./target/debug/gateway` (`127.0.0.1:8080`) |
> | **End-User Workstations** (plaintext & DEK boundary) | [`apps/cli`](apps/cli/README.md) with hardware key custody | Local `./target/debug/cli` process |

> **MVP Key Custody Boundary:**
> This MVP uses `DevelopmentKeyCustody` (CLI) and `DevelopmentRelayerSigner`
> (gateway), explicitly gated by `RRDS_ALLOW_UNSAFE_DEV_CUSTODY=true` and
> `GATEWAY_ALLOW_UNSAFE_DEV_RELAYER=true` with `RRDS_ENV=development`. Both
> `gateway` and `indexer` refuse unsafe dev flags and placeholder credentials
> whenever `RRDS_ENV=production`. Hardware HSM / PKCS#11 custody adapters are
> post-MVP behind the existing `KeyCustodyProvider` and `RelayerSigner` traits.
>
> **Secret Hygiene:** Never print, copy, commit, or replace `.env`,
> `infra/ipfs-cluster/secrets/*`, `contracts/secrets/*`, or
> `infra/besu-qbft/networkFiles/keys/*`.

---

## 1. Prerequisites & Build

Confirm required tools are installed (`docker`, `cargo`, `node`, `pnpm`,
`psql`, `curl`, `python3`), then build the workspace binaries and compile the
Solidity contracts:

```shell
# Build standalone migrator, indexer, gateway, and user CLI (offline, locked)
cargo build --workspace --locked --offline

# Compile Solidity contracts (AccessGovernance, FileRegistry, RrdsTimelockController)
pnpm --dir contracts exec hardhat compile
```

Verify the compiled binaries are present:

- `./target/debug/rrds-migrate` — least-privilege SQLx migration runner (`run` / `verify`)
- `./target/debug/indexer` — finalized-block Besu event indexer
- `./target/debug/gateway` — authenticated HTTP API, IPFS Cluster proxy, and Type-2 relayer
- `./target/debug/cli` — end-user CLI (`rrds`)

Ensure your local git-ignored `.env` exists (based on [`.env.example`](.env.example))
with unique randomly generated passwords for `POSTGRES_PASSWORD`,
`RRFS_MIGRATOR_PASSWORD`, `RRFS_GATEWAY_PASSWORD`, and `RRFS_INDEXER_PASSWORD`.

---

## 2. Infrastructure Setup & Verification

### 2.1 Private 2-Peer IPFS / IPFS Cluster & PostgreSQL `18.6`

Generate local private-swarm and Cluster secrets once, launch PostgreSQL plus
both Kubo/Cluster peers, and verify 2-peer replication:

```shell
sh infra/ipfs-cluster/init-secrets.sh
docker compose --env-file .env -f infra/compose.yaml up -d
sh infra/ipfs-cluster/verify.sh
```

Expected output from `verify.sh`:
- Two distinct peers (`rrfs-cluster-1` and `rrfs-cluster-2`) in `peers ls`.
- A test CID imported with the RRDS UnixFS profile (`cid-version=1`,
  `sha2-256`, `size-1048592`, `raw-leaves=true`, `--pin=false`) reaching
  `PINNED` status on **both** Cluster peers and verified retrievable from both
  `kubo` and `kubo2`.

### 2.2 PostgreSQL Roles, Real SQLx Migrations (`0001`–`0007`), & RBAC

In production, `rrfs_migrator` runs schema migrations, while `rrfs_gateway` and
`rrfs_indexer` connect with least-privilege credentials and
`DATABASE_MIGRATION_MODE=verify` (read-only schema checksum check).

1. Create the least-privilege roles and `rrfs` schema once (substitute your
   actual generated passwords from `.env` without echoing them into shell
   history or logs):

   ```shell
   set -a && . ./.env && set +a
   docker compose --env-file .env -f infra/compose.yaml exec -T postgres \
     psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
     -v migrator_pw="$RRFS_MIGRATOR_PASSWORD" \
     -v gateway_pw="$RRFS_GATEWAY_PASSWORD" \
     -v indexer_pw="$RRFS_INDEXER_PASSWORD" <<'SQL'
   DO $$
   BEGIN
     IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rrfs_migrator') THEN
       EXECUTE format('CREATE ROLE rrfs_migrator LOGIN PASSWORD %L', :'migrator_pw');
     END IF;
     IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rrfs_gateway') THEN
       EXECUTE format('CREATE ROLE rrfs_gateway LOGIN PASSWORD %L', :'gateway_pw');
     END IF;
     IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'rrfs_indexer') THEN
       EXECUTE format('CREATE ROLE rrfs_indexer LOGIN PASSWORD %L', :'indexer_pw');
     END IF;
   END $$;
   CREATE SCHEMA IF NOT EXISTS rrfs AUTHORIZATION rrfs_migrator;
   ALTER ROLE rrfs_migrator SET search_path = rrfs;
   ALTER ROLE rrfs_gateway  SET search_path = rrfs;
   ALTER ROLE rrfs_indexer  SET search_path = rrfs;
   SQL
   ```

2. Run migrations `0001`–`0007` using `rrds-migrate` as `rrfs_migrator`:

   ```shell
   DATABASE_URL="postgres://rrfs_migrator:${RRFS_MIGRATOR_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}" \
     ./target/debug/rrds-migrate run
   ```

3. Apply least-privilege grants via [`infra/postgres/init-roles.sql`](infra/postgres/init-roles.sql):

   ```shell
   docker compose --env-file .env -f infra/compose.yaml exec -T postgres \
     psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
     -c "SET search_path = rrfs;" \
     -f - < infra/postgres/init-roles.sql
   ```

4. Confirm both runtime roles pass read-only migration verification (zero DDL
   privileges required):

   ```shell
   DATABASE_URL="postgres://rrfs_indexer:${RRFS_INDEXER_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}" \
     ./target/debug/rrds-migrate verify
   DATABASE_URL="postgres://rrfs_gateway:${RRFS_GATEWAY_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}" \
     ./target/debug/rrds-migrate verify
   ```

### 2.3 Permissioned 4-Validator + 1-RPC Hyperledger Besu `26.11.0` QBFT Network

Prepare the QBFT genesis/validator identities once, start the 5-node local Besu
network, and run the verifier:

```shell
sh infra/besu-qbft/prepare.sh
docker compose --env-file .env -f infra/besu-qbft/compose.yaml up -d
sh infra/besu-qbft/verify.sh
```

Expected output:

```text
chainId=1337
rpcPeerCount=4
qbftCommittedBlock=<N>
validatorCount=4
```

---

## 3. Organization, Node, & Block Validation

### 3.1 Verify QBFT Consensus, Validators, & Finalized Block Production

Query the non-validator RPC node (`127.0.0.1:8545`) directly to demonstrate
that 4 independent validator keys are sealing deterministic QBFT-finalized
blocks (`N >= 3f + 1`, tolerating 1 Byzantine/offline validator):

```shell
# 1. Confirm permissioned chain ID (0x539 == 1337) and RPC peer count (>= 3)
curl -sS -X POST http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}' && echo
curl -sS -X POST http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"net_peerCount","params":[]}' && echo

# 2. List the 4 active QBFT validators at the latest committed block
curl -sS -X POST http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":3,"method":"qbft_getValidatorsByBlockNumber","params":["latest"]}' && echo

# 3. Inspect two consecutive committed blocks (Besu QBFT blocks are immediately final)
curl -sS -X POST http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":4,"method":"eth_blockNumber","params":[]}' && echo
sleep 3
curl -sS -X POST http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":5,"method":"eth_getBlockByNumber","params":["latest",false]}' \
  | python3 -c 'import json,sys; b=json.load(sys.stdin)["result"]; print(f"block={int(b[\"number\"],16)} hash={b[\"hash\"]} parent={b[\"parentHash\"]} extraDataLen={len(b[\"extraData\"])}")'
```

Verify that:
- `qbft_getValidatorsByBlockNumber` returns exactly 4 distinct validator addresses.
- `eth_blockNumber` advances steadily and `extraData` carries the QBFT RLP
  round/commit seals.
- Validators do not expose public JSON-RPC ports; only `rpcnode` serves
  `127.0.0.1:8545`.

### 3.2 Deploy Audited Safe v1.4.1 (`2-of-3`) Governance & Option B Contracts

`contracts/scripts/besu-bootstrap.mjs` deploys real audited
`@safe-global/safe-contracts@1.4.1` (`Safe` singleton, `SafeProxyFactory`,
`CompatibilityFallbackHandler`), three independent `2-of-3` Safe proxies
(`consortiumSafe`, `emergencySafe`, `organizationSafe`),
`RrdsTimelockController` (`minDelay = 86,400s`), `AccessGovernance` (Option B),
and `FileRegistry`, storing local dev keys exclusively in git-ignored
`contracts/secrets/besu-dev-accounts.json` (`0600`):

```shell
# 1. Generate local dev deployer/relayer keys + 3x3 Safe owner sets (idempotent)
node contracts/scripts/besu-bootstrap.mjs init-dev-accounts

# 2. Deploy Safe v1.4.1 proxies + Timelock + AccessGovernance + FileRegistry
node contracts/scripts/besu-bootstrap.mjs deploy

# 3. Schedule activation batch via 2-of-3 consortiumSafe.execTransaction:
#    - Grant FILE_REGISTRY_ROLE to FileRegistry
#    - Register demo organization (authority = 2-of-3 organizationSafe)
node contracts/scripts/besu-bootstrap.mjs schedule

# 4. Inspect live on-chain governance invariants and timelock readiness
node contracts/scripts/besu-bootstrap.mjs status
```

> **Real 24-Hour Timelock Enforcement:**
> `RrdsTimelockController` enforces a non-bypassable `86,400`-second (24-hour)
> minimum delay. After `readyAtUtc` reported by `status`, execute the scheduled
> batch (any account may call `execute` because `EXECUTOR_ROLE` is open):
>
> ```shell
> node contracts/scripts/besu-bootstrap.mjs execute
> node contracts/scripts/besu-bootstrap.mjs status
> ```

Confirm the following security invariants in `status` output:
- `consortiumSafe`, `emergencySafe`, and `organizationSafe` each show `threshold=2`
- `timelock.minDelay: 86400s`
- `deployer admin bypass: timelock=false, governance=false`
- `timelock is gov admin: true`
- `emergencySafe suspender: true`
- `FILE_REGISTRY_ROLE live: true`
- `demoOrg authority: <organizationSafe address>`

### 3.3 Enroll Demo Members via `2-of-3` `organizationSafe`

Enroll Alice (the default demo member) via `2-of-3` `organizationSafe` using an
EIP-712 `MemberKeyProof` signed by Alice's keypair (saved to git-ignored
`contracts/secrets/besu-dev-member.json`, mode `0600`):

```shell
node contracts/scripts/besu-bootstrap.mjs register-member
```

For the **multi-user file sharing and revocation** walkthrough in Section 6,
enroll a second member (Bob) in the same organization via `2-of-3`
`organizationSafe.execTransaction` using `execSafeTransaction` from
[`contracts/scripts/safe-helpers.mjs`](contracts/scripts/safe-helpers.mjs)
calling `AccessGovernance.registerMember(...)` with Bob's own EIP-712
`MemberKeyProof` (storing Bob's dev keystore in a separate git-ignored `0600`
file such as `contracts/secrets/besu-dev-member-bob.json`).

---

## 4. Start Indexer & Gateway (Least-Privilege Runtime)

Load the deployed contract addresses from
`contracts/ignition/deployments/chain-1337/deployed_addresses.json` and note
the deployment block height from `bootstrap-state.json` (used for
`INDEXER_START_BLOCK`).

### Terminal 1 — Start the Event Indexer (`rrfs_indexer`)

```shell
set -a && . ./.env && set +a
eval "$(node -e '
const d = JSON.parse(require("fs").readFileSync("contracts/ignition/deployments/chain-1337/deployed_addresses.json","utf8"));
const s = JSON.parse(require("fs").readFileSync("contracts/ignition/deployments/chain-1337/bootstrap-state.json","utf8"));
console.log(`export CONTRACT_TIMELOCK_ADDRESS=${d["RrdsDeployment#RrdsTimelockController"]}`);
console.log(`export CONTRACT_ACCESS_GOVERNANCE_ADDRESS=${d["RrdsDeployment#AccessGovernance"]}`);
console.log(`export CONTRACT_FILE_REGISTRY_ADDRESS=${d["RrdsDeployment#FileRegistry"]}`);
console.log(`export INDEXER_START_BLOCK=${s.contracts?.timelock?.blockNumber ?? 0}`);
')"
export RRDS_ENV=development
export BESU_RPC_URL=http://127.0.0.1:8545
export BESU_CHAIN_ID=1337
export INDEXER_BATCH_SIZE=1000
export FINALITY_CHECK_INTERVAL=1
export DATABASE_URL="postgres://rrfs_indexer:${RRFS_INDEXER_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}"
export DATABASE_MIGRATION_MODE=verify

./target/debug/indexer
```

The indexer polls QBFT-committed blocks from `INDEXER_START_BLOCK`, decodes
`RrdsTimelockController`, `AccessGovernance`, and `FileRegistry` logs, writes
immutable raw events into `rrfs.indexed_contract_events`, and projects
informational browsing tables (`organizations_projection`, `members_projection`,
`files_projection`, `versions_projection`, `access_projection`,
`historical_read_access_projection`, `envelope_sets_projection`).

### Terminal 2 — Start the Organization Gateway (`rrfs_gateway`)

```shell
set -a && . ./.env && set +a
eval "$(node -e '
const d = JSON.parse(require("fs").readFileSync("contracts/ignition/deployments/chain-1337/deployed_addresses.json","utf8"));
const a = JSON.parse(require("fs").readFileSync("contracts/secrets/besu-dev-accounts.json","utf8"));
console.log(`export CONTRACT_ACCESS_GOVERNANCE_ADDRESS=${d["RrdsDeployment#AccessGovernance"]}`);
console.log(`export CONTRACT_FILE_REGISTRY_ADDRESS=${d["RrdsDeployment#FileRegistry"]}`);
console.log(`export GATEWAY_RELAYER_UNSAFE_DEV_KEY=${a.accounts.relayer.privateKey}`);
')"
export RRDS_ENV=development
export BESU_RPC_URL=http://127.0.0.1:8545
export BESU_CHAIN_ID=1337
export GATEWAY_BIND=127.0.0.1:8080
export GATEWAY_AUDIENCE=rrds-local
export DATABASE_URL="postgres://rrfs_gateway:${RRFS_GATEWAY_PASSWORD}@127.0.0.1:5432/${POSTGRES_DB}"
export DATABASE_MIGRATION_MODE=verify
export GATEWAY_ALLOW_UNSAFE_DEV_RELAYER=true
export IPFS_API_URLS="http://127.0.0.1:15001,http://127.0.0.1:15002"
export IPFS_CLUSTER_API_URL="http://127.0.0.1:9094"
export IPFS_CLUSTER_ADMIN_URL="http://127.0.0.1:9094"
export IPFS_CLUSTER_USERNAME="rrfs-admin"
export IPFS_CLUSTER_PASSWORD_FILE="infra/ipfs-cluster/secrets/cluster-api-password"
export MIN_PIN_REPLICAS=2

./target/debug/gateway
```

Expected startup log: `gateway listening on 127.0.0.1:8080`.
Background tasks started automatically inside the gateway:
- **`StorageHealthMonitor`:** periodically checks Kubo & IPFS Cluster health (`GATEWAY_STORAGE_HEALTH_INTERVAL_SECONDS`).
- **`OrphanBlobCleaner`:** safely unpins (`DELETE /pins/{cid}`) unreferenced uploaded blobs past `ORPHAN_RETENTION_SECONDS` only after confirming no pending/confirmed `gateway_relayed_transactions` row references the CID.

---

## 5. User Commands, Subsequent Indexing, Downloading, & Recovery

Open **Terminal 3 (Alice — User Endpoint)** and load Alice's dev keys without
echoing secrets:

```shell
eval "$(node -e '
const d = JSON.parse(require("fs").readFileSync("contracts/ignition/deployments/chain-1337/deployed_addresses.json","utf8"));
const m = JSON.parse(require("fs").readFileSync("contracts/secrets/besu-dev-member.json","utf8"));
console.log(`export CONTRACT_ACCESS_GOVERNANCE_ADDRESS=${d["RrdsDeployment#AccessGovernance"]}`);
console.log(`export CONTRACT_FILE_REGISTRY_ADDRESS=${d["RrdsDeployment#FileRegistry"]}`);
console.log(`export RRDS_DEV_MEMBER_ID=${m.memberId}`);
console.log(`export RRDS_DEV_SIGNING_KEY=${m.signingPrivateKey}`);
console.log(`export RRDS_DEV_ENCRYPTION_SEED=${m.encryptionSeed}`);
console.log(`export RRDS_DEV_SIGNING_KEY_VERSION=${m.signingKeyVersion}`);
console.log(`export RRDS_DEV_ENCRYPTION_KEY_VERSION=${m.encryptionKeyVersion}`);
')"
export GATEWAY_URL=http://127.0.0.1:8080
export GATEWAY_AUDIENCE=rrds-local
export BESU_CHAIN_ID=1337
export RRDS_ALLOW_UNSAFE_DEV_CUSTODY=true
export RRDS_SESSION_FILE=/tmp/rrds-alice.session
```

### 5.1 Health, Contract-Backed Identity Lookup, & EIP-712 Login

```shell
./target/debug/cli health
./target/debug/cli identity "$RRDS_DEV_MEMBER_ID"
./target/debug/cli login --session-file "$RRDS_SESSION_FILE"
./target/debug/cli whoami
```

What to highlight:
- `identity` queries `AccessGovernance` directly via Besu `eth_call` at the
  finalized block (never trusting the indexer for auth/keys).
- `login` completes the one-time EIP-712 `LoginChallenge` handshake and saves
  the bearer token with `0600` atomic permissions.

### 5.2 Logical Folder Creation (`2-of-3` Safe), Encrypted Upload (V1), & Storage Verification

Optionally demonstrate Safe-governed logical folder creation before uploading
so files can be browsed inside a nested folder hierarchy (`cli ls` and
`cli ls --folder <folderId>`):

```shell
# Create a root folder ("Finance") and nested child folder ("Q4") via 2-of-3 organizationSafe
FOLDER_OUT="$(node contracts/scripts/besu-bootstrap.mjs create-folder "Finance")"
echo "$FOLDER_OUT"
FINANCE_FOLDER_ID="$(printf '%s\n' "$FOLDER_OUT" | sed -n 's/.*folderId:[[:space:]]*\(0x[0-9a-f]\{64\}\).*/\1/p')"

CHILD_OUT="$(node contracts/scripts/besu-bootstrap.mjs create-folder "Q4" "$FINANCE_FOLDER_ID")"
echo "$CHILD_OUT"
Q4_FOLDER_ID="$(printf '%s\n' "$CHILD_OUT" | sed -n 's/.*folderId:[[:space:]]*\(0x[0-9a-f]\{64\}\).*/\1/p')"
```

Now encrypt and upload V1 (omit `--folder "$Q4_FOLDER_ID"` to upload to root):

```shell
DEMO_DIR="$(mktemp -d /tmp/rrds-walkthrough.XXXXXX)"
printf 'Confidential Q4 financial ledger — clean V1 (%s)\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$DEMO_DIR/ledger-v1.txt"

UPLOAD_OUT="$(./target/debug/cli upload "$DEMO_DIR/ledger-v1.txt" --name "q4-ledger.txt" --folder "$Q4_FOLDER_ID")"
echo "$UPLOAD_OUT"

FILE_ID="$(printf '%s\n' "$UPLOAD_OUT" | sed -n 's/.*fileId=\(0x[0-9a-f]\{64\}\).*/\1/p')"
CONTENT_CID="$(printf '%s\n' "$UPLOAD_OUT" | sed -n 's/.*contentCid=\([^ ]*\).*/\1/p')"
TX_HASH="$(printf '%s\n' "$UPLOAD_OUT" | sed -n 's/.*tx=\(0x[0-9a-f]\{64\}\).*/\1/p')"
```

What happened end-to-end:
1. **Endpoint (`apps/cli`):** generated a fresh 256-bit DEK, encrypted `ledger-v1.txt` in 1 MiB AES-256-GCM chunks, wrapped the DEK via RFC 9180 HPKE (`X25519 / HKDF-SHA256 / AES-256-GCM`) for Alice, and packed deterministic CARv1 streams.
2. **Gateway + IPFS Cluster:** validated the CARv1 structure, pinned both the content CID and envelope-set CID across **2 distinct Cluster peers** (`contentReplicas=2 envelopeReplicas=2`) **before** relaying any chain transaction.
3. **Gateway Relayer + Besu:** submitted Alice's EIP-712-signed `CreateFile` request to `FileRegistry.createFile(...)`, waited for QBFT finality, persisted the receipt in `gateway_relayed_transactions`, and returned `tx` and `block`.

Verify 2-peer Cluster pinning and persistent transaction reconciliation:

```shell
# Confirm both Cluster peers hold the pinned encrypted content CID
docker compose --env-file .env -f infra/compose.yaml exec -T cluster1 sh -ec '
  pw=$(cat /run/secrets/cluster-api-password)
  ipfs-cluster-ctl --host /ip4/127.0.0.1/tcp/9094 --basic-auth "rrfs-admin:$pw" --force-http status "$1"
' sh "$CONTENT_CID"

# Confirm persistent relayed-transaction reconciliation via authenticated gateway API
curl -sS -H "Authorization: Bearer $(cat "$RRDS_SESSION_FILE")" \
  "$GATEWAY_URL/v1/transactions/$TX_HASH" && echo
```

### 5.3 Verify Subsequent Indexing (`ls`, `history`, & PostgreSQL Projections)

Wait ~1–2 seconds for the indexer poll interval, then query indexed views:

```shell
./target/debug/cli ls
./target/debug/cli ls --folder "$FINANCE_FOLDER_ID"
./target/debug/cli ls --folder "$Q4_FOLDER_ID"
./target/debug/cli history "$FILE_ID"
```

Verify in the output:
- `ls` shows `finalizedBlock=<B> indexedBlock=Some(<B>) authoritative=false`
  (explicitly flagging that indexed listings are informational only).
- `history` displays `v1` with `manifest`, `parent=0x0000...`, `contentCid`,
  `envCid (rev 1)`, and `historicalRead=false`.

### 5.4 Download & Byte-for-Byte Verification (V1)

```shell
./target/debug/cli download "$FILE_ID" 1 "$DEMO_DIR/downloaded-v1.txt"
cmp -s "$DEMO_DIR/ledger-v1.txt" "$DEMO_DIR/downloaded-v1.txt" && echo "V1 plaintext verified byte-for-byte"
```

What happened during download:
- CLI signed an EIP-712 `AccessLookup` request.
- Gateway verified Alice's active membership, key status, and `AccessGovernance.canReadVersion(...)` directly against Besu `eth_call` at the finalized block.
- CLI downloaded the envelope set and encrypted CARv1 package, verified every CID and the canonical `manifestHash`, unwrapped the DEK via HPKE, decrypted all chunks with AES-256-GCM, and atomically wrote `downloaded-v1.txt`.

### 5.5 Simulate Ransomware Corruption (V2) & Append-Only Recovery (V3)

Upload a corrupted V2 (simulating a compromised endpoint overwriting a file):

```shell
printf 'RANSOMWARE_ENCRYPTED_GARBAGE_V2\n' > "$DEMO_DIR/ledger-v2-corrupted.txt"
./target/debug/cli modify "$FILE_ID" "$DEMO_DIR/ledger-v2-corrupted.txt"
./target/debug/cli history "$FILE_ID"
```

Now notice the **historical access invariant**: once V2 becomes head, V1 is a
historical version (`1 < 2`). Attempting `./target/debug/cli restore "$FILE_ID" 1`
or `./target/debug/cli download "$FILE_ID" 1 ...` fails closed with `403 unauthorized`
until the file's `READ_ACL_POLICY` Safe (`organizationSafe`) grants explicit
version-scoped historical read permission (`AccessGovernance.setHistoricalReadAccess(fileId, 1, aliceMemberId, true, proposalId)`).

After `organizationSafe` grants historical Read on V1 for Alice (see
[`docs/architecture/historical-access.md`](docs/architecture/historical-access.md)),
execute append-only recovery:

```shell
./target/debug/cli restore "$FILE_ID" 1
./target/debug/cli history "$FILE_ID"
./target/debug/cli download "$FILE_ID" 3 "$DEMO_DIR/recovered-v3.txt"
cmp -s "$DEMO_DIR/ledger-v1.txt" "$DEMO_DIR/recovered-v3.txt" && echo "V3 recovery matches clean V1 byte-for-byte"
```

What to highlight:
- V2 (the ransomware artifact) is **never deleted** — it remains in the
  immutable version chain for forensic audit.
- V3 is a brand-new head version encrypted under a **fresh DEK**, linked to V2
  as its linear parent, carrying `restoredFromVersion=1`, and audited
  distinctly as `file.version_restore`.

---

## 6. ACL Changes, Option B File Sharing, & Revocation

This section demonstrates **separation of governance from cryptography**:
- Only the file's `READ_ACL_POLICY` Safe (`2-of-3` `organizationSafe`) can
  grant or revoke Read permissions on-chain.
- An authorized member (Alice) can then share cryptographic access to an
  existing version with an already-authorized recipient (Bob) via **Option B**
  (`POST /v1/files/{fileId}/versions/{version}/envelopes`) **without**
  re-encrypting the ciphertext and **without** being able to grant ACLs.

Assume Bob is enrolled under the demo organization with `BOB_MEMBER_ID` (from
Section 3.3).

### 6.1 Negative Check — Sharing Without an On-Chain Read ACL Fails Closed

Before `organizationSafe` grants Read ACL to Bob, attempting to share fails on
the gateway / smart contract:

```shell
# Expected to fail closed (recipient lacks on-chain Read authorization)
./target/debug/cli share "$FILE_ID" 3 "$BOB_MEMBER_ID" || echo "Confirmed fail-closed without ACL"
```

### 6.2 Safe-Governed Read ACL Grant (`2-of-3` `organizationSafe`)

Execute `AccessGovernance.setFilePermission(fileId, bobMemberId, Read, true, proposalId)`
through the `2-of-3` `organizationSafe` proxy:

```shell
node contracts/scripts/besu-bootstrap.mjs grant-read "$FILE_ID" "$BOB_MEMBER_ID" "demo-grant-bob-read"
```

*(Note: File-level Read covers the current head and future versions. To share an
older version `< currentVersion`, `organizationSafe` must additionally call
`AccessGovernance.setHistoricalReadAccess(fileId, version, bobMemberId, true, proposalId)`.)*

### 6.3 Option B Member-Signed Envelope Update (`cli share`)

Alice now adds an HPKE key envelope for Bob to head version V3:

```shell
./target/debug/cli share "$FILE_ID" 3 "$BOB_MEMBER_ID"
./target/debug/cli history "$FILE_ID"
```

Verify in `history` output that V3's `contentCid` is **unchanged**, while
`envCid` has advanced to **`(rev 2)`** (indexed from `EnvelopeSetUpdated`).

### 6.4 Recipient Download & Verification (Bob)

In a separate shell (or subshell) configured with Bob's `RRDS_DEV_*` keys and a
separate session file (`/tmp/rrds-bob.session`):

```shell
export RRDS_SESSION_FILE=/tmp/rrds-bob.session
./target/debug/cli login --session-file "$RRDS_SESSION_FILE"
./target/debug/cli download "$FILE_ID" 3 "$DEMO_DIR/bob-v3.txt"
cmp -s "$DEMO_DIR/ledger-v1.txt" "$DEMO_DIR/bob-v3.txt" && echo "Bob decrypted shared V3 byte-for-byte"
```

### 6.5 Safe-Governed Read Revocation & Forward Key Isolation

Revoke Bob's Read permission through the `2-of-3` `organizationSafe`:

```shell
node contracts/scripts/besu-bootstrap.mjs revoke-read "$FILE_ID" "$BOB_MEMBER_ID" "demo-revoke-bob-read"
```

Verify revocation immediately:
1. **Immediate gateway & contract denial:** Bob running
   `./target/debug/cli download "$FILE_ID" 3 "$DEMO_DIR/bob-denied.txt"` now
   fails closed (`403 unauthorized`) because `AccessGovernance.canReadVersion`
   returns `false` (and automatically invalidates any prior historical-read
   grants for Bob on this file).
2. **Forward cryptographic isolation:** Alice uploads V4 (`cli modify` without
   passing `--reader "$BOB_MEMBER_ID"`):

   ```shell
   printf 'Post-revocation V4 update — Bob excluded\n' > "$DEMO_DIR/ledger-v4.txt"
   ./target/debug/cli modify "$FILE_ID" "$DEMO_DIR/ledger-v4.txt"
   ```

   V4 is encrypted under a fresh DEK containing no HPKE envelope for Bob.
3. **Explicit cryptographic limitation (be transparent during the demo):**
   Revocation blocks future gateway/on-chain access and excludes Bob from all
   new versions, but cannot retroactively erase plaintext or DEKs Bob already
   decrypted before revocation (see
   [`docs/architecture/recovery-and-revocation.md`](docs/architecture/recovery-and-revocation.md)).

### 6.6 Explicit Session Revocation (`cli logout`)

```shell
./target/debug/cli logout --session-file /tmp/rrds-alice.session
./target/debug/cli whoami || echo "Confirmed session revoked immediately on server"
```

---

## 7. Contract & Off-Chain Auditing

RRDS provides two complementary, independently verifiable audit planes:

### 7.1 Off-Chain Hash-Chained Audit Trail (`cli audit` & PostgreSQL)

Query the authenticated member audit trail (note: every `audit` query is itself
appended as an `audit.query` event in the hash chain):

```shell
# Re-authenticate Alice if logged out in 6.6
./target/debug/cli login --session-file /tmp/rrds-alice.session

# Inspect recent events (file.create, file.version_append, file.version_restore,
# file.envelope_update, file.access_lookup, auth.session_create, audit.query)
./target/debug/cli audit --limit 20

# Filter specifically for append-only recovery actions
./target/debug/cli audit --action file.version_restore --limit 10
```

Verify tamper-evidence and append-only database enforcement directly in
PostgreSQL:

```shell
set -a && . ./.env && set +a
docker compose --env-file .env -f infra/compose.yaml exec -T postgres \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
SELECT sequence,
       record->>'action' AS action,
       record->>'outcome' AS outcome,
       (record->>'block_number')::bigint AS block_number,
       resource_id,
       resource_version,
       encode(previous_hash, 'hex') AS prev_hash,
       encode(record_hash, 'hex') AS rec_hash
FROM rrfs.gateway_audit_events
ORDER BY sequence DESC
LIMIT 12;
"
```

Confirm:
- Every row's `prev_hash` matches the preceding row's `rec_hash` (unbroken
  Keccak-256 chain).
- Attempting to tamper with the audit log as `rrfs_gateway` (or even as an
  admin) is rejected by **both** least-privilege RBAC and the
  `gateway_audit_no_update_or_delete` trigger:

```shell
docker compose --env-file .env -f infra/compose.yaml exec -T postgres \
  psql -U rrfs_gateway -d "$POSTGRES_DB" \
  -c "DELETE FROM rrfs.gateway_audit_events WHERE sequence = 1;" \
  || echo "Confirmed: gateway_audit_events is strictly append-only"
```

### 7.2 On-Chain Contract & Governance Event Auditing

Inspect the immutable finalized contract logs captured by the indexer across
`RrdsTimelockController`, `AccessGovernance`, and `FileRegistry`:

```shell
docker compose --env-file .env -f infra/compose.yaml exec -T postgres \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "
SELECT block_number,
       log_index,
       event_name,
       contract_address,
       transaction_hash,
       event_data
FROM rrfs.indexed_contract_events
WHERE chain_id = 1337
ORDER BY block_number ASC, log_index ASC;
"
```

You should see the complete lifecycle in finalized block order:
- **Timelock & Governance Setup:** `RoleGranted`, `CallScheduled`,
  `CallExecuted`, `OrganizationRegistered`
- **Identity & Key Custody:** `MemberRegistered`, `MemberKeyRegistered`
- **File & Version Lifecycle:** `FilePolicyRegistered`, `FileCreated`,
  `VersionAppended`, `CurrentHeadAdvanced`, `EnvelopeSetInitialized`
- **ACL & Option B Sharing Audit:** `ReadAccessGranted`,
  `HistoricalReadAccessGranted`, `EnvelopeSetUpdated`, `ReadAccessRevoked`

### 7.3 Deterministic Projection Rebuild & Live On-Chain Verification

Demonstrate that PostgreSQL projections are purely derived and deterministically
rebuildable from persisted finalized chain logs (stop Terminal 1 first, then
run once with `--rebuild-projections`):

```shell
./target/debug/indexer --rebuild-projections
```

Finally, re-verify live on-chain Safe thresholds, timelock state, and
organization authority directly against Besu:

```shell
node contracts/scripts/besu-bootstrap.mjs status
```

---

## 8. Scripted & Automated Cross-Domain Verification Proofs

For repeatable demonstrations or CI/maintainer sign-off, RRDS includes four
automated suites covering the full stack:

1. **Scripted local CLI walkthrough** (health, identity, login, upload V1, `ls`,
   `history`, download & `cmp` V1, corrupted V2, audit trail):

   ```shell
   sh scripts/demo-local.sh
   ```

2. **Cross-domain live E2E test** (spawns the real `target/debug/cli` binary
   against a real Axum `services/gateway` server wired to the live 2-peer Kubo
   + IPFS Cluster swarm — covering 1.15 MiB multi-chunk upload, 2-peer pin
   quorum, download, V2 modify, historical-read fail-closed check + Option B
   `cli share` + Bob download, append-only `cli restore` V1→V3 +
   `file.version_restore` audit, plaintext/read-only/`MIN_PIN_REPLICAS=5`
   negative cases, live `OrphanBlobCleaner` `DELETE /pins/{cid}`, and
   `cli logout`):

   ```shell
   set -a && . ./.env && set +a
   cargo test -p gateway \
     cli_binary_through_real_gateway_to_live_dual_node_ipfs_cluster_end_to_end \
     --locked --offline -- --ignored --nocapture
   ```

3. **Smart contract, audited Safe v1.4.1 (`2-of-3`), Option B, & gas-bound suite**
   (37 Solidity + Node.js tests including `SafeGovernance.ts` and `GasBounds.ts`):

   ```shell
   pnpm --dir contracts exec hardhat test
   ```

4. **Live PostgreSQL `18.6` (`0001`–`0007` + 4-role RBAC) & live Besu QBFT tests**
   (never target `rrfs_dev` for test runs; use a dedicated test database such as
   `rrfs_indexer_test`):

   ```shell
   set -a && . ./.env && set +a
   DATABASE_URL="${DATABASE_URL%/*}/rrfs_indexer_test" \
     cargo test -p metadata-store -p indexer -p gateway --locked --offline -- --ignored
   ```
