#!/usr/bin/env node
/**
 * Local Besu QBFT development bootstrap helper (smoke-test ONLY).
 *
 * Security notes:
 * - Generates local development-only EOA keys strictly inside git-ignored
 *   `contracts/secrets/besu-dev-accounts.json` (mode 0600) and NEVER prints
 *   private keys to stdout/stderr.
 * - These EOA placeholders stand in for Safe multisig contracts ONLY for local
 *   single-host smoke testing. Production deployments MUST use audited Safe
 *   threshold accounts per `docs/adr/governance-authority-and-timelock.md`.
 * - Enforces the real 24-hour (`86400`s) `RrdsTimelockController` delay with
 *   no administrative bypass.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  createPublicClient,
  createWalletClient,
  defineChain,
  encodeFunctionData,
  http,
  keccak256,
  stringToBytes,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const contractsDir = path.resolve(__dirname, "..");
const secretsDir = path.join(contractsDir, "secrets");
const accountsFile = path.join(secretsDir, "besu-dev-accounts.json");
const demoMemberFile = path.join(secretsDir, "besu-dev-member.json");
const paramsFile = path.join(contractsDir, "ignition", "parameters.local.json");
const rpcUrl = process.env.BESU_RPC_URL ?? "http://127.0.0.1:8545";
const chainId = Number(process.env.BESU_CHAIN_ID ?? "1337");
const deploymentsDir = path.join(
  contractsDir,
  "ignition",
  "deployments",
  `chain-${chainId}`
);
const deployedAddressesFile = path.join(deploymentsDir, "deployed_addresses.json");
const bootstrapStateFile = path.join(deploymentsDir, "bootstrap-state.json");

const DEMO_ORG_ID = keccak256(stringToBytes("rrds-dev-org-1"));
const ACTIVATION_SALT = keccak256(stringToBytes("rrds-local-bootstrap-v1"));
const ZERO_BYTES32 = `0x${"00".repeat(32)}`;
const CONSORTIUM_DELAY = 86_400n;

const besuLocalChain = defineChain({
  id: chainId,
  name: "Besu QBFT Local",
  nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
  rpcUrls: { default: { http: [rpcUrl] } },
});

function loadArtifact(contractPath, contractName) {
  const artifactFile = path.join(
    contractsDir,
    "artifacts",
    "contracts",
    contractPath,
    `${contractName}.json`
  );
  if (!fs.existsSync(artifactFile)) {
    throw new Error(`Missing compiled artifact: ${artifactFile}`);
  }
  return JSON.parse(fs.readFileSync(artifactFile, "utf8"));
}

function loadDevAccounts() {
  if (!fs.existsSync(accountsFile)) {
    throw new Error(
      `Dev accounts file not found (${accountsFile}). Run 'node scripts/besu-bootstrap.mjs init-dev-accounts' first.`
    );
  }
  return JSON.parse(fs.readFileSync(accountsFile, "utf8"));
}

function loadDeployedAddresses() {
  if (fs.existsSync(deployedAddressesFile)) {
    const data = JSON.parse(fs.readFileSync(deployedAddressesFile, "utf8"));
    return {
      timelock: data["RrdsDeployment#RrdsTimelockController"],
      accessGovernance: data["RrdsDeployment#AccessGovernance"],
      fileRegistry: data["RrdsDeployment#FileRegistry"],
    };
  }
  const timelock = process.env.CONTRACT_TIMELOCK_ADDRESS;
  const accessGovernance = process.env.CONTRACT_ACCESS_GOVERNANCE_ADDRESS;
  const fileRegistry = process.env.CONTRACT_FILE_REGISTRY_ADDRESS;
  if (!timelock || !accessGovernance || !fileRegistry) {
    throw new Error(
      `No deployed addresses found in ${deployedAddressesFile} and CONTRACT_* env vars are unset.`
    );
  }
  return { timelock, accessGovernance, fileRegistry };
}

function makeClients(privateKey) {
  const account = privateKeyToAccount(privateKey);
  const publicClient = createPublicClient({
    chain: besuLocalChain,
    transport: http(rpcUrl),
  });
  const walletClient = createWalletClient({
    account,
    chain: besuLocalChain,
    transport: http(rpcUrl),
  });
  return { account, publicClient, walletClient };
}

function initDevAccounts() {
  if (fs.existsSync(accountsFile)) {
    const existing = loadDevAccounts();
    console.log("Local dev accounts already exist (refusing to overwrite):");
    printPublicSummary(existing);
    return;
  }

  fs.mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
  const roles = [
    "deployer",
    "consortiumSafe",
    "emergencySafe",
    "organizationSafe",
    "relayer",
  ];
  const accounts = {};
  for (const role of roles) {
    const privateKey = generatePrivateKey();
    const account = privateKeyToAccount(privateKey);
    accounts[role] = {
      address: account.address,
      privateKey,
    };
  }

  const payload = {
    warning:
      "DEVELOPMENT SMOKE-TEST ONLY. Never use these keys in staging or production. Replace with real Safe multisig accounts and HSM/keystore custody.",
    createdAt: new Date().toISOString(),
    chainId,
    demoOrganizationId: DEMO_ORG_ID,
    accounts,
  };

  fs.writeFileSync(accountsFile, `${JSON.stringify(payload, null, 2)}\n`, {
    mode: 0o600,
  });
  fs.chmodSync(accountsFile, 0o600);

  const ignitionParams = {
    RrdsDeployment: {
      consortiumSafeAddress: accounts.consortiumSafe.address,
      emergencySafeAddress: accounts.emergencySafe.address,
    },
  };
  fs.writeFileSync(paramsFile, `${JSON.stringify(ignitionParams, null, 2)}\n`, {
    mode: 0o644,
  });

  console.log("Generated git-ignored local dev-only authority accounts:");
  printPublicSummary(payload);
  console.log(`Wrote git-ignored Ignition parameters: ${paramsFile}`);
}

function printPublicSummary(payload) {
  console.log(`  mode: dev-only EOA placeholders (NOT real Safe multisigs)`);
  console.log(`  demoOrganizationId: ${payload.demoOrganizationId}`);
  for (const [role, entry] of Object.entries(payload.accounts)) {
    console.log(`  ${role}: ${entry.address}`);
  }
}

async function deployContracts() {
  if (fs.existsSync(deployedAddressesFile)) {
    console.log("Contracts already recorded in", deployedAddressesFile);
    console.log(fs.readFileSync(deployedAddressesFile, "utf8").trim());
    return;
  }

  const dev = loadDevAccounts();
  const { publicClient, walletClient } = makeClients(dev.accounts.deployer.privateKey);

  const liveChainId = await publicClient.getChainId();
  if (liveChainId !== chainId) {
    throw new Error(`Expected chainId ${chainId}, got ${liveChainId}`);
  }

  const timelockArt = loadArtifact("RrdsTimelockController.sol", "RrdsTimelockController");
  const govArt = loadArtifact("AccessGovernance.sol", "AccessGovernance");
  const regArt = loadArtifact("FileRegistry.sol", "FileRegistry");

  const deployOne = async (name, artifact, args) => {
    const hash = await walletClient.deployContract({
      abi: artifact.abi,
      bytecode: artifact.bytecode,
      args,
      maxFeePerGas: 0n,
      maxPriorityFeePerGas: 0n,
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    if (receipt.status !== "success" || !receipt.contractAddress) {
      throw new Error(`Deployment of ${name} failed (tx ${hash})`);
    }
    console.log(
      `Deployed ${name} at ${receipt.contractAddress} (block ${receipt.blockNumber}, tx ${hash})`
    );
    return { address: receipt.contractAddress, txHash: hash, blockNumber: Number(receipt.blockNumber) };
  };

  const timelock = await deployOne("RrdsTimelockController", timelockArt, [
    dev.accounts.consortiumSafe.address,
  ]);
  const accessGovernance = await deployOne("AccessGovernance", govArt, [
    timelock.address,
    dev.accounts.emergencySafe.address,
  ]);
  const fileRegistry = await deployOne("FileRegistry", regArt, [
    accessGovernance.address,
    timelock.address,
  ]);

  fs.mkdirSync(deploymentsDir, { recursive: true });
  const deployedMap = {
    "RrdsDeployment#RrdsTimelockController": timelock.address,
    "RrdsDeployment#AccessGovernance": accessGovernance.address,
    "RrdsDeployment#FileRegistry": fileRegistry.address,
  };
  fs.writeFileSync(
    deployedAddressesFile,
    `${JSON.stringify(deployedMap, null, 2)}\n`
  );
  fs.writeFileSync(
    bootstrapStateFile,
    `${JSON.stringify(
      {
        chainId,
        deployedAt: new Date().toISOString(),
        authorityMode: "dev-only-eoa-smoke-test",
        consortiumSafeAddress: dev.accounts.consortiumSafe.address,
        emergencySafeAddress: dev.accounts.emergencySafe.address,
        organizationSafeAddress: dev.accounts.organizationSafe.address,
        demoOrganizationId: DEMO_ORG_ID,
        contracts: { timelock, accessGovernance, fileRegistry },
      },
      null,
      2
    )}\n`
  );
  console.log(`Saved deployment record: ${deployedAddressesFile}`);
}

function buildActivationBatch(addresses, orgSafeAddress, govAbi) {
  const fileRegistryRole = keccak256(stringToBytes("FILE_REGISTRY_ROLE"));
  const grantCalldata = encodeFunctionData({
    abi: govAbi,
    functionName: "grantRole",
    args: [fileRegistryRole, addresses.fileRegistry],
  });
  const registerOrgCalldata = encodeFunctionData({
    abi: govAbi,
    functionName: "registerOrganization",
    args: [DEMO_ORG_ID, orgSafeAddress],
  });

  return {
    targets: [addresses.accessGovernance, addresses.accessGovernance],
    values: [0n, 0n],
    payloads: [grantCalldata, registerOrgCalldata],
    predecessor: ZERO_BYTES32,
    salt: ACTIVATION_SALT,
  };
}

async function scheduleActivation() {
  const dev = loadDevAccounts();
  const addresses = loadDeployedAddresses();
  const timelockArt = loadArtifact("RrdsTimelockController.sol", "RrdsTimelockController");
  const govArt = loadArtifact("AccessGovernance.sol", "AccessGovernance");
  const { publicClient, walletClient } = makeClients(
    dev.accounts.consortiumSafe.privateKey
  );

  const batch = buildActivationBatch(
    addresses,
    dev.accounts.organizationSafe.address,
    govArt.abi
  );

  const opId = await publicClient.readContract({
    address: addresses.timelock,
    abi: timelockArt.abi,
    functionName: "hashOperationBatch",
    args: [
      batch.targets,
      batch.values,
      batch.payloads,
      batch.predecessor,
      batch.salt,
    ],
  });

  const alreadyRegistered = await publicClient.readContract({
    address: addresses.timelock,
    abi: timelockArt.abi,
    functionName: "isOperation",
    args: [opId],
  });
  if (alreadyRegistered) {
    console.log(`Activation batch already scheduled (operationId=${opId}).`);
    await printStatus();
    return;
  }

  const hash = await walletClient.writeContract({
    address: addresses.timelock,
    abi: timelockArt.abi,
    functionName: "scheduleBatch",
    args: [
      batch.targets,
      batch.values,
      batch.payloads,
      batch.predecessor,
      batch.salt,
      CONSORTIUM_DELAY,
    ],
    maxFeePerGas: 0n,
    maxPriorityFeePerGas: 0n,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") {
    throw new Error(`scheduleBatch reverted (tx ${hash})`);
  }

  const readyTimestamp = await publicClient.readContract({
    address: addresses.timelock,
    abi: timelockArt.abi,
    functionName: "getTimestamp",
    args: [opId],
  });
  const readyAtIso = new Date(Number(readyTimestamp) * 1000).toISOString();

  if (fs.existsSync(bootstrapStateFile)) {
    const state = JSON.parse(fs.readFileSync(bootstrapStateFile, "utf8"));
    state.activationBatch = {
      operationId: opId,
      salt: ACTIVATION_SALT,
      scheduleTxHash: hash,
      scheduleBlockNumber: Number(receipt.blockNumber),
      readyTimestamp: Number(readyTimestamp),
      readyAtUtc: readyAtIso,
    };
    fs.writeFileSync(bootstrapStateFile, `${JSON.stringify(state, null, 2)}\n`);
  }

  console.log(`Scheduled timelock activation batch:`);
  console.log(`  operationId: ${opId}`);
  console.log(`  txHash:      ${hash} (block ${receipt.blockNumber})`);
  console.log(`  delay:       ${CONSORTIUM_DELAY}s (24 hours)`);
  console.log(`  readyAtUtc:  ${readyAtIso}`);
}

async function executeActivation() {
  const dev = loadDevAccounts();
  const addresses = loadDeployedAddresses();
  const timelockArt = loadArtifact("RrdsTimelockController.sol", "RrdsTimelockController");
  const govArt = loadArtifact("AccessGovernance.sol", "AccessGovernance");
  // EXECUTOR_ROLE is open (address(0)), so any account may execute once ready.
  const { publicClient, walletClient } = makeClients(dev.accounts.deployer.privateKey);

  const batch = buildActivationBatch(
    addresses,
    dev.accounts.organizationSafe.address,
    govArt.abi
  );

  const opId = await publicClient.readContract({
    address: addresses.timelock,
    abi: timelockArt.abi,
    functionName: "hashOperationBatch",
    args: [
      batch.targets,
      batch.values,
      batch.payloads,
      batch.predecessor,
      batch.salt,
    ],
  });

  const isDone = await publicClient.readContract({
    address: addresses.timelock,
    abi: timelockArt.abi,
    functionName: "isOperationDone",
    args: [opId],
  });
  if (isDone) {
    console.log(`Activation batch already executed (operationId=${opId}).`);
    return;
  }

  const isReady = await publicClient.readContract({
    address: addresses.timelock,
    abi: timelockArt.abi,
    functionName: "isOperationReady",
    args: [opId],
  });
  if (!isReady) {
    const ts = await publicClient.readContract({
      address: addresses.timelock,
      abi: timelockArt.abi,
      functionName: "getTimestamp",
      args: [opId],
    });
    throw new Error(
      `Activation batch is not ready yet. Ready at ${new Date(Number(ts) * 1000).toISOString()} (unix ${ts}).`
    );
  }

  const hash = await walletClient.writeContract({
    address: addresses.timelock,
    abi: timelockArt.abi,
    functionName: "executeBatch",
    args: [
      batch.targets,
      batch.values,
      batch.payloads,
      batch.predecessor,
      batch.salt,
    ],
    maxFeePerGas: 0n,
    maxPriorityFeePerGas: 0n,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") {
    throw new Error(`executeBatch reverted (tx ${hash})`);
  }

  console.log(`Executed timelock activation batch (tx ${hash}, block ${receipt.blockNumber}).`);
  await printStatus();
}

async function printStatus() {
  const dev = loadDevAccounts();
  const addresses = loadDeployedAddresses();
  const timelockArt = loadArtifact("RrdsTimelockController.sol", "RrdsTimelockController");
  const govArt = loadArtifact("AccessGovernance.sol", "AccessGovernance");
  const publicClient = createPublicClient({
    chain: besuLocalChain,
    transport: http(rpcUrl),
  });

  const [liveChainId, block, minDelay, proposerRole, cancellerRole, executorRole, defaultAdminRole, emergencyRole, fileRegistryRole] =
    await Promise.all([
      publicClient.getChainId(),
      publicClient.getBlock({ blockTag: "latest" }),
      publicClient.readContract({
        address: addresses.timelock,
        abi: timelockArt.abi,
        functionName: "getMinDelay",
      }),
      publicClient.readContract({
        address: addresses.timelock,
        abi: timelockArt.abi,
        functionName: "PROPOSER_ROLE",
      }),
      publicClient.readContract({
        address: addresses.timelock,
        abi: timelockArt.abi,
        functionName: "CANCELLER_ROLE",
      }),
      publicClient.readContract({
        address: addresses.timelock,
        abi: timelockArt.abi,
        functionName: "EXECUTOR_ROLE",
      }),
      publicClient.readContract({
        address: addresses.accessGovernance,
        abi: govArt.abi,
        functionName: "DEFAULT_ADMIN_ROLE",
      }),
      publicClient.readContract({
        address: addresses.accessGovernance,
        abi: govArt.abi,
        functionName: "EMERGENCY_SUSPENDER_ROLE",
      }),
      publicClient.readContract({
        address: addresses.accessGovernance,
        abi: govArt.abi,
        functionName: "FILE_REGISTRY_ROLE",
      }),
    ]);

  const batch = buildActivationBatch(
    addresses,
    dev.accounts.organizationSafe.address,
    govArt.abi
  );
  const opId = await publicClient.readContract({
    address: addresses.timelock,
    abi: timelockArt.abi,
    functionName: "hashOperationBatch",
    args: [
      batch.targets,
      batch.values,
      batch.payloads,
      batch.predecessor,
      batch.salt,
    ],
  });

  const [
    consortiumIsProposer,
    consortiumIsCanceller,
    openExecutor,
    deployerHasTimelockAdmin,
    timelockHasGovAdmin,
    deployerHasGovAdmin,
    emergencyHasSuspender,
    registryActive,
    orgAuthority,
    opPending,
    opReady,
    opDone,
    opTimestamp,
  ] = await Promise.all([
    publicClient.readContract({
      address: addresses.timelock,
      abi: timelockArt.abi,
      functionName: "hasRole",
      args: [proposerRole, dev.accounts.consortiumSafe.address],
    }),
    publicClient.readContract({
      address: addresses.timelock,
      abi: timelockArt.abi,
      functionName: "hasRole",
      args: [cancellerRole, dev.accounts.consortiumSafe.address],
    }),
    publicClient.readContract({
      address: addresses.timelock,
      abi: timelockArt.abi,
      functionName: "hasRole",
      args: [executorRole, "0x0000000000000000000000000000000000000000"],
    }),
    publicClient.readContract({
      address: addresses.timelock,
      abi: timelockArt.abi,
      functionName: "hasRole",
      args: [defaultAdminRole, dev.accounts.deployer.address],
    }),
    publicClient.readContract({
      address: addresses.accessGovernance,
      abi: govArt.abi,
      functionName: "hasRole",
      args: [defaultAdminRole, addresses.timelock],
    }),
    publicClient.readContract({
      address: addresses.accessGovernance,
      abi: govArt.abi,
      functionName: "hasRole",
      args: [defaultAdminRole, dev.accounts.deployer.address],
    }),
    publicClient.readContract({
      address: addresses.accessGovernance,
      abi: govArt.abi,
      functionName: "hasRole",
      args: [emergencyRole, dev.accounts.emergencySafe.address],
    }),
    publicClient.readContract({
      address: addresses.accessGovernance,
      abi: govArt.abi,
      functionName: "hasRole",
      args: [fileRegistryRole, addresses.fileRegistry],
    }),
    publicClient.readContract({
      address: addresses.accessGovernance,
      abi: govArt.abi,
      functionName: "organizationAuthority",
      args: [DEMO_ORG_ID],
    }),
    publicClient.readContract({
      address: addresses.timelock,
      abi: timelockArt.abi,
      functionName: "isOperationPending",
      args: [opId],
    }),
    publicClient.readContract({
      address: addresses.timelock,
      abi: timelockArt.abi,
      functionName: "isOperationReady",
      args: [opId],
    }),
    publicClient.readContract({
      address: addresses.timelock,
      abi: timelockArt.abi,
      functionName: "isOperationDone",
      args: [opId],
    }),
    publicClient.readContract({
      address: addresses.timelock,
      abi: timelockArt.abi,
      functionName: "getTimestamp",
      args: [opId],
    }),
  ]);

  console.log("=== Besu RRDS On-Chain Status ===");
  console.log(`chainId:                  ${liveChainId}`);
  console.log(`latestBlock:              ${block.number} (${new Date(Number(block.timestamp) * 1000).toISOString()})`);
  console.log(`RrdsTimelockController:   ${addresses.timelock}`);
  console.log(`AccessGovernance:         ${addresses.accessGovernance}`);
  console.log(`FileRegistry:             ${addresses.fileRegistry}`);
  console.log(`timelock.minDelay:        ${minDelay}s`);
  console.log(`consortiumSafe proposer:  ${consortiumIsProposer} (canceller: ${consortiumIsCanceller})`);
  console.log(`openExecutor (address 0): ${openExecutor}`);
  console.log(`deployer admin bypass:    timelock=${deployerHasTimelockAdmin}, governance=${deployerHasGovAdmin}`);
  console.log(`timelock is gov admin:    ${timelockHasGovAdmin}`);
  console.log(`emergencySafe suspender:  ${emergencyHasSuspender}`);
  console.log(`FILE_REGISTRY_ROLE live:  ${registryActive}`);
  console.log(`demoOrg authority:        ${orgAuthority}`);
  console.log(`activationBatch opId:     ${opId}`);
  console.log(
    `activationBatch state:    pending=${opPending}, ready=${opReady}, done=${opDone}` +
      (opTimestamp > 1n
        ? ` (readyAtUtc=${new Date(Number(opTimestamp) * 1000).toISOString()})`
        : "")
  );
}

/**
 * RFC 9180 DHKEM(X25519, HKDF-SHA256) DeriveKeyPair matching
 * `crypto::HpkeRecipientKeyPair::derive_from_seed`.
 */
function deriveHpkeX25519PublicKeyHex(seedHex) {
  const seed = Buffer.from(seedHex.replace(/^0x/, ""), "hex");
  const kemSuite = Buffer.concat([Buffer.from("KEM"), Buffer.from([0x00, 0x20])]);
  const hmac = (k, d) => crypto.createHmac("sha256", k).update(d).digest();
  const extract = (salt, ikm) => hmac(salt.length ? salt : Buffer.alloc(32), ikm);
  const expand = (prk, info, L) => {
    let out = Buffer.alloc(0);
    let t = Buffer.alloc(0);
    for (let i = 1; out.length < L; i++) {
      t = hmac(prk, Buffer.concat([t, info, Buffer.from([i])]));
      out = Buffer.concat([out, t]);
    }
    return out.subarray(0, L);
  };
  const dkpPrk = extract(
    Buffer.alloc(0),
    Buffer.concat([Buffer.from("HPKE-v1"), kemSuite, Buffer.from("dkp_prk"), seed])
  );
  const sk = expand(
    dkpPrk,
    Buffer.concat([
      Buffer.from([0x00, 0x20]),
      Buffer.from("HPKE-v1"),
      kemSuite,
      Buffer.from("sk"),
    ]),
    32
  );
  const pkcs8Prefix = Buffer.from("302e020100300506032b656e04220420", "hex");
  const priv = crypto.createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, sk]),
    format: "der",
    type: "pkcs8",
  });
  const pub = crypto
    .createPublicKey(priv)
    .export({ format: "der", type: "spki" })
    .subarray(-32);
  return `0x${pub.toString("hex")}`;
}

async function registerDemoMember() {
  const dev = loadDevAccounts();
  const addresses = loadDeployedAddresses();
  const govArt = loadArtifact("AccessGovernance.sol", "AccessGovernance");
  const { publicClient, walletClient } = makeClients(
    dev.accounts.organizationSafe.privateKey
  );

  let member;
  if (fs.existsSync(demoMemberFile)) {
    member = JSON.parse(fs.readFileSync(demoMemberFile, "utf8"));
  } else {
    fs.mkdirSync(secretsDir, { recursive: true, mode: 0o700 });
    const memberId = keccak256(stringToBytes("rrds-dev-member-alice"));
    const signingKey = generatePrivateKey();
    const signingAccount = privateKeyToAccount(signingKey);
    const encryptionSeed = `0x${crypto.randomBytes(32).toString("hex")}`;
    const encryptionPublicKey = deriveHpkeX25519PublicKeyHex(encryptionSeed);
    member = {
      warning:
        "DEVELOPMENT SMOKE-TEST ONLY. Never use these member keys in production.",
      memberId,
      organizationId: DEMO_ORG_ID,
      signingAddress: signingAccount.address,
      signingPrivateKey: signingKey,
      encryptionSeed,
      encryptionPublicKey,
      signingKeyVersion: 1,
      encryptionKeyVersion: 1,
    };
    fs.writeFileSync(demoMemberFile, `${JSON.stringify(member, null, 2)}\n`, {
      mode: 0o600,
    });
    fs.chmodSync(demoMemberFile, 0o600);
  }

  const active = await publicClient.readContract({
    address: addresses.accessGovernance,
    abi: govArt.abi,
    functionName: "isActiveMember",
    args: [member.memberId],
  });
  if (active) {
    console.log(
      `Demo member already active on-chain: memberId=${member.memberId} signingAddress=${member.signingAddress}`
    );
    return;
  }

  const orgAuth = await publicClient.readContract({
    address: addresses.accessGovernance,
    abi: govArt.abi,
    functionName: "organizationAuthority",
    args: [DEMO_ORG_ID],
  });
  if (orgAuth.toLowerCase() !== dev.accounts.organizationSafe.address.toLowerCase()) {
    throw new Error(
      `Organization ${DEMO_ORG_ID} is not yet registered (authority=${orgAuth}). Run 'node scripts/besu-bootstrap.mjs execute' after the 24h timelock delay first.`
    );
  }

  const latestBlock = await publicClient.getBlock({ blockTag: "latest" });
  const deadline = latestBlock.timestamp + 3600n;
  const proofNonce = `0x${crypto.randomBytes(32).toString("hex")}`;
  const memberSigner = privateKeyToAccount(member.signingPrivateKey);
  const signature = await memberSigner.signTypedData({
    domain: {
      name: "RRDS AccessGovernance",
      version: "1",
      chainId,
      verifyingContract: addresses.accessGovernance,
    },
    types: {
      MemberKeyProof: [
        { name: "memberId", type: "bytes32" },
        { name: "organizationId", type: "bytes32" },
        { name: "signingAddress", type: "address" },
        { name: "signingKeyVersion", type: "uint32" },
        { name: "encryptionKeyVersion", type: "uint32" },
        { name: "encryptionPublicKey", type: "bytes32" },
        { name: "operationNonce", type: "bytes32" },
        { name: "deadline", type: "uint256" },
      ],
    },
    primaryType: "MemberKeyProof",
    message: {
      memberId: member.memberId,
      organizationId: DEMO_ORG_ID,
      signingAddress: member.signingAddress,
      signingKeyVersion: member.signingKeyVersion,
      encryptionKeyVersion: member.encryptionKeyVersion,
      encryptionPublicKey: member.encryptionPublicKey,
      operationNonce: proofNonce,
      deadline,
    },
  });

  const hash = await walletClient.writeContract({
    address: addresses.accessGovernance,
    abi: govArt.abi,
    functionName: "registerMember",
    args: [
      DEMO_ORG_ID,
      member.memberId,
      member.signingAddress,
      member.signingKeyVersion,
      member.encryptionKeyVersion,
      member.encryptionPublicKey,
      proofNonce,
      deadline,
      signature,
    ],
    maxFeePerGas: 0n,
    maxPriorityFeePerGas: 0n,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") {
    throw new Error(`registerMember reverted (tx ${hash})`);
  }
  console.log(`Registered demo member on-chain (tx ${hash}, block ${receipt.blockNumber}):`);
  console.log(`  memberId:            ${member.memberId}`);
  console.log(`  organizationId:      ${member.organizationId}`);
  console.log(`  signingAddress:      ${member.signingAddress}`);
  console.log(`  encryptionPublicKey: ${member.encryptionPublicKey}`);
  console.log(`  dev secrets file:    ${demoMemberFile} (0600, git-ignored)`);
}

const command = process.argv[2];
switch (command) {
  case "init-dev-accounts":
    initDevAccounts();
    break;
  case "deploy":
    await deployContracts();
    break;
  case "schedule":
    await scheduleActivation();
    break;
  case "execute":
    await executeActivation();
    break;
  case "register-member":
    await registerDemoMember();
    break;
  case "status":
    await printStatus();
    break;
  default:
    console.error(
      "Usage: node scripts/besu-bootstrap.mjs <init-dev-accounts|deploy|schedule|execute|register-member|status>"
    );
    process.exit(1);
}
