import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

import { network } from "hardhat";
import {
  concatHex,
  encodeFunctionData,
  getAddress,
  keccak256,
  parseEventLogs,
  stringToBytes,
  zeroAddress,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const safeArtifactsRoot = path.resolve(
  __dirname,
  "..",
  "node_modules",
  "@safe-global",
  "safe-contracts",
  "build",
  "artifacts",
  "contracts"
);

function loadSafeArtifact(relPath: string) {
  return JSON.parse(
    fs.readFileSync(path.join(safeArtifactsRoot, relPath), "utf8")
  );
}

const ZERO_BYTES32 = `0x${"00".repeat(32)}` as const;
const CONSORTIUM_DELAY = 86_400n;
const READ_PERMISSION = 0;
const WRITE_PERMISSION = 1;

describe("Audited Safe v1.4.1 threshold multisig governance integration", async function () {
  const { viem, networkHelpers } = await network.connect();
  const publicClient = await viem.getPublicClient();
  const [deployer, relayer, nonOwner] = await viem.getWalletClients();
  const chainId = await publicClient.getChainId();

  const safeArt = loadSafeArtifact("Safe.sol/Safe.json");
  const factoryArt = loadSafeArtifact("proxies/SafeProxyFactory.sol/SafeProxyFactory.json");
  const fallbackArt = loadSafeArtifact(
    "handler/CompatibilityFallbackHandler.sol/CompatibilityFallbackHandler.json"
  );

  async function deploySafeInfrastructure() {
    const deployArt = async (artifact: any) => {
      const hash = await deployer.deployContract({
        abi: artifact.abi,
        bytecode: artifact.bytecode,
        args: [],
      });
      const receipt = await publicClient.waitForTransactionReceipt({ hash });
      assert.ok(receipt.contractAddress, "Safe infrastructure deployment must succeed");
      return receipt.contractAddress;
    };
    const singleton = await deployArt(safeArt);
    const factory = await deployArt(factoryArt);
    const fallbackHandler = await deployArt(fallbackArt);
    return { singleton, factory, fallbackHandler };
  }

  async function createSafeProxy(
    infra: { singleton: `0x${string}`; factory: `0x${string}`; fallbackHandler: `0x${string}` },
    owners: `0x${string}`[],
    threshold: bigint,
    saltNonce: bigint
  ): Promise<`0x${string}`> {
    const setupData = encodeFunctionData({
      abi: safeArt.abi,
      functionName: "setup",
      args: [
        owners,
        threshold,
        zeroAddress,
        "0x",
        infra.fallbackHandler,
        zeroAddress,
        0n,
        zeroAddress,
      ],
    });
    const hash = await deployer.writeContract({
      address: infra.factory,
      abi: factoryArt.abi,
      functionName: "createProxyWithNonce",
      args: [infra.singleton, setupData, saltNonce],
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    const logs = parseEventLogs({
      abi: factoryArt.abi,
      logs: receipt.logs,
      eventName: "ProxyCreation",
    }) as any[];
    assert.equal(logs.length, 1, "ProxyCreation event must be emitted once");
    return getAddress(logs[0].args.proxy);
  }

  async function execSafeTx(
    safeAddress: `0x${string}`,
    signers: ReturnType<typeof privateKeyToAccount>[],
    to: `0x${string}`,
    data: `0x${string}`
  ) {
    const nonce = (await publicClient.readContract({
      address: safeAddress,
      abi: safeArt.abi,
      functionName: "nonce",
    })) as bigint;

    const sorted = [...signers].sort((a, b) =>
      a.address.toLowerCase().localeCompare(b.address.toLowerCase())
    );

    const sigs: `0x${string}`[] = [];
    for (const signer of sorted) {
      const sig = await signer.signTypedData({
        domain: {
          chainId,
          verifyingContract: safeAddress,
        },
        types: {
          SafeTx: [
            { name: "to", type: "address" },
            { name: "value", type: "uint256" },
            { name: "data", type: "bytes" },
            { name: "operation", type: "uint8" },
            { name: "safeTxGas", type: "uint256" },
            { name: "baseGas", type: "uint256" },
            { name: "gasPrice", type: "uint256" },
            { name: "gasToken", type: "address" },
            { name: "refundReceiver", type: "address" },
            { name: "nonce", type: "uint256" },
          ],
        },
        primaryType: "SafeTx",
        message: {
          to,
          value: 0n,
          data,
          operation: 0,
          safeTxGas: 0n,
          baseGas: 0n,
          gasPrice: 0n,
          gasToken: zeroAddress,
          refundReceiver: zeroAddress,
          nonce,
        },
      });
      sigs.push(sig);
    }

    const packedSignatures = concatHex(sigs);
    const hash = await deployer.writeContract({
      address: safeAddress,
      abi: safeArt.abi,
      functionName: "execTransaction",
      args: [
        to,
        0n,
        data,
        0,
        0n,
        0n,
        0n,
        zeroAddress,
        zeroAddress,
        packedSignatures,
      ],
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    assert.equal(receipt.status, "success");
    return receipt;
  }

  it("enforces 2-of-3 Safe thresholds across timelock, org ACLs, Option B relay, and emergency suspension", async function () {
    const infra = await deploySafeInfrastructure();
    const makeOwners = () => [
      privateKeyToAccount(generatePrivateKey()),
      privateKeyToAccount(generatePrivateKey()),
      privateKeyToAccount(generatePrivateKey()),
    ];
    const consortiumOwners = makeOwners();
    const emergencyOwners = makeOwners();
    const orgOwners = makeOwners();

    const consortiumSafe = await createSafeProxy(
      infra,
      consortiumOwners.map((o) => o.address),
      2n,
      1001n
    );
    const emergencySafe = await createSafeProxy(
      infra,
      emergencyOwners.map((o) => o.address),
      2n,
      1002n
    );
    const orgSafe = await createSafeProxy(
      infra,
      orgOwners.map((o) => o.address),
      2n,
      1003n
    );

    assert.equal(
      await publicClient.readContract({
        address: consortiumSafe,
        abi: safeArt.abi,
        functionName: "getThreshold",
      }),
      2n
    );

    // Deploy RRDS contracts wired exclusively to real Safe proxy addresses.
    const timelock = await viem.deployContract("RrdsTimelockController", [consortiumSafe]);
    const governance = await viem.deployContract("AccessGovernance", [
      timelock.address,
      emergencySafe,
    ]);
    const registry = await viem.deployContract("FileRegistry", [
      governance.address,
      timelock.address,
    ]);

    const orgId = keccak256(stringToBytes("safe-org-1"));
    const fileRegistryRole = await governance.read.FILE_REGISTRY_ROLE();
    const grantRoleCall = encodeFunctionData({
      abi: governance.abi,
      functionName: "grantRole",
      args: [fileRegistryRole, registry.address],
    });
    const registerOrgCall = encodeFunctionData({
      abi: governance.abi,
      functionName: "registerOrganization",
      args: [orgId, orgSafe],
    });
    const salt = keccak256(stringToBytes("safe-activation-v1"));
    const scheduleData = encodeFunctionData({
      abi: timelock.abi,
      functionName: "scheduleBatch",
      args: [
        [governance.address, governance.address],
        [0n, 0n],
        [grantRoleCall, registerOrgCall],
        ZERO_BYTES32,
        salt,
        CONSORTIUM_DELAY,
      ],
    });

    // Bad case 1: 1-of-3 signature MUST revert on Safe threshold check (GS020).
    await assert.rejects(
      execSafeTx(consortiumSafe, [consortiumOwners[0]], timelock.address, scheduleData),
      /GS020/
    );

    // Bad case 2: Non-owner / wrong-Safe signer MUST revert (GS026).
    await assert.rejects(
      execSafeTx(
        consortiumSafe,
        [consortiumOwners[0], emergencyOwners[0]],
        timelock.address,
        scheduleData
      ),
      /GS026/
    );

    // Bad case 3: Direct EOA call to TimelockController MUST revert (AccessControlUnauthorizedAccount).
    await assert.rejects(
      nonOwner.writeContract({
        address: timelock.address,
        abi: timelock.abi,
        functionName: "scheduleBatch",
        args: [
          [governance.address, governance.address],
          [0n, 0n],
          [grantRoleCall, registerOrgCall],
          ZERO_BYTES32,
          salt,
          CONSORTIUM_DELAY,
        ],
      })
    );

    // Happy path: 2-of-3 Consortium Safe schedules the 24h timelock activation batch.
    await execSafeTx(
      consortiumSafe,
      [consortiumOwners[0], consortiumOwners[2]],
      timelock.address,
      scheduleData
    );

    // Advance 24 hours and execute via open executor.
    await networkHelpers.time.increase(Number(CONSORTIUM_DELAY) + 1);
    await relayer.writeContract({
      address: timelock.address,
      abi: timelock.abi,
      functionName: "executeBatch",
      args: [
        [governance.address, governance.address],
        [0n, 0n],
        [grantRoleCall, registerOrgCall],
        ZERO_BYTES32,
        salt,
      ],
    });
    assert.equal(
      (await governance.read.organizationAuthority([orgId])).toLowerCase(),
      orgSafe.toLowerCase()
    );

    // Enroll Alice and Bob through real 2-of-3 Organization Safe execTransaction.
    const latestBlock = await publicClient.getBlock({ blockTag: "latest" });
    const deadline = latestBlock.timestamp + 3600n;
    const alice = privateKeyToAccount(generatePrivateKey());
    const bob = privateKeyToAccount(generatePrivateKey());
    const aliceId = keccak256(stringToBytes("safe-alice"));
    const bobId = keccak256(stringToBytes("safe-bob"));
    const aliceEncPub = keccak256(stringToBytes("alice-x25519"));
    const bobEncPub = keccak256(stringToBytes("bob-x25519"));

    for (const [mId, acct, encPub, nonceSeed] of [
      [aliceId, alice, aliceEncPub, "nonce-alice"],
      [bobId, bob, bobEncPub, "nonce-bob"],
    ] as const) {
      const opNonce = keccak256(stringToBytes(nonceSeed));
      const proofSig = await acct.signTypedData({
        domain: {
          name: "RRDS AccessGovernance",
          version: "1",
          chainId,
          verifyingContract: governance.address,
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
          memberId: mId,
          organizationId: orgId,
          signingAddress: acct.address,
          signingKeyVersion: 1,
          encryptionKeyVersion: 1,
          encryptionPublicKey: encPub,
          operationNonce: opNonce,
          deadline,
        },
      });
      const regData = encodeFunctionData({
        abi: governance.abi,
        functionName: "registerMember",
        args: [orgId, mId, acct.address, 1, 1, encPub, opNonce, deadline, proofSig],
      });
      await execSafeTx(orgSafe, [orgOwners[0], orgOwners[1]], governance.address, regData);
    }
    assert.equal(await governance.read.isActiveMember([aliceId]), true);
    assert.equal(await governance.read.isActiveMember([bobId]), true);

    // Alice creates File V1 via gateway relayer.
    const fileId = keccak256(stringToBytes("safe-file-1"));
    const epochId = keccak256(stringToBytes("safe-epoch-1"));
    const manifestV1 = keccak256(stringToBytes("safe-manifest-1"));
    const contentCidV1 = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
    const envCidV1 = "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy";
    const envCidV2 = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";
    const createNonce = keccak256(stringToBytes("create-nonce-1"));
    const createSig = await alice.signTypedData({
      domain: {
        name: "RRDS FileRegistry",
        version: "1",
        chainId,
        verifyingContract: registry.address,
      },
      types: {
        VersionAppend: [
          { name: "fileId", type: "bytes32" },
          { name: "versionNumber", type: "uint64" },
          { name: "parentManifestHash", type: "bytes32" },
          { name: "contentCidHash", type: "bytes32" },
          { name: "envelopeSetCidHash", type: "bytes32" },
          { name: "epochId", type: "bytes32" },
          { name: "manifestHash", type: "bytes32" },
          { name: "memberId", type: "bytes32" },
          { name: "signerAddress", type: "address" },
          { name: "operationNonce", type: "bytes32" },
          { name: "deadline", type: "uint256" },
        ],
      },
      primaryType: "VersionAppend",
      message: {
        fileId,
        versionNumber: 1n,
        parentManifestHash: ZERO_BYTES32,
        contentCidHash: keccak256(stringToBytes(contentCidV1)),
        envelopeSetCidHash: keccak256(stringToBytes(envCidV1)),
        epochId,
        manifestHash: manifestV1,
        memberId: aliceId,
        signerAddress: alice.address,
        operationNonce: createNonce,
        deadline,
      },
    });
    await relayer.writeContract({
      address: registry.address,
      abi: registry.abi,
      functionName: "createFile",
      args: [
        {
          fileId,
          versionNumber: 1n,
          parentManifestHash: ZERO_BYTES32,
          contentCidHash: keccak256(stringToBytes(contentCidV1)),
          envelopeSetCidHash: keccak256(stringToBytes(envCidV1)),
          epochId,
          manifestHash: manifestV1,
          memberId: aliceId,
          signerAddress: alice.address,
          operationNonce: createNonce,
          deadline,
        },
        contentCidV1,
        envCidV1,
        "safe-report.txt",
        ZERO_BYTES32,
        createSig,
      ],
    });

    // Organization Safe (2-of-3) grants Bob Read ACL; Emergency Safe CANNOT grant ACLs!
    const proposalId = keccak256(stringToBytes("share-proposal-1"));
    const grantReadData = encodeFunctionData({
      abi: governance.abi,
      functionName: "setFilePermission",
      args: [fileId, bobId, READ_PERMISSION, true, proposalId],
    });
    await assert.rejects(
      execSafeTx(
        emergencySafe,
        [emergencyOwners[0], emergencyOwners[1]],
        governance.address,
        grantReadData
      )
    );
    await execSafeTx(orgSafe, [orgOwners[1], orgOwners[2]], governance.address, grantReadData);
    assert.equal(await governance.read.hasReadAccess([bobId, fileId]), true);
    assert.equal(await governance.read.hasWriteAccess([bobId, fileId]), false);

    // Option B: Alice signs EIP-712 EnvelopeSetUpdate and non-authority relayer submits it.
    const envNonce = keccak256(stringToBytes("env-update-nonce-1"));
    const envSig = await alice.signTypedData({
      domain: {
        name: "RRDS AccessGovernance",
        version: "1",
        chainId,
        verifyingContract: governance.address,
      },
      types: {
        EnvelopeSetUpdate: [
          { name: "fileId", type: "bytes32" },
          { name: "versionNumber", type: "uint64" },
          { name: "epochId", type: "bytes32" },
          { name: "oldEnvelopeSetCid", type: "string" },
          { name: "newEnvelopeSetCid", type: "string" },
          { name: "actorMemberId", type: "bytes32" },
          { name: "proposalId", type: "bytes32" },
          { name: "operationNonce", type: "bytes32" },
          { name: "deadline", type: "uint256" },
        ],
      },
      primaryType: "EnvelopeSetUpdate",
      message: {
        fileId,
        versionNumber: 1n,
        epochId,
        oldEnvelopeSetCid: envCidV1,
        newEnvelopeSetCid: envCidV2,
        actorMemberId: aliceId,
        proposalId,
        operationNonce: envNonce,
        deadline,
      },
    });
    await relayer.writeContract({
      address: governance.address,
      abi: governance.abi,
      functionName: "updateEnvelopeSet",
      args: [
        {
          fileId,
          versionNumber: 1n,
          epochId,
          oldEnvelopeSetCid: envCidV1,
          newEnvelopeSetCid: envCidV2,
          actorMemberId: aliceId,
          proposalId,
          operationNonce: envNonce,
          deadline,
        },
        envSig,
      ],
    });
    const [currentCid, , currentRevision] = await governance.read.currentEnvelopeSet([fileId, 1n]);
    assert.equal(currentCid, envCidV2);
    assert.equal(currentRevision, 2);

    // Emergency Safe (2-of-3) suspends Bob; Emergency Safe CANNOT reinstate Bob.
    const suspendData = encodeFunctionData({
      abi: governance.abi,
      functionName: "emergencySuspendMember",
      args: [bobId],
    });
    await execSafeTx(
      emergencySafe,
      [emergencyOwners[0], emergencyOwners[2]],
      governance.address,
      suspendData
    );
    assert.equal(await governance.read.isActiveMember([bobId]), false);

    const reinstateData = encodeFunctionData({
      abi: governance.abi,
      functionName: "reinstateMember",
      args: [bobId],
    });
    await assert.rejects(
      execSafeTx(
        emergencySafe,
        [emergencyOwners[0], emergencyOwners[1]],
        governance.address,
        reinstateData
      )
    );

    // Consortium Safe (2-of-3) schedules & executes timelocked reinstatement of Bob.
    const reinstateSalt = keccak256(stringToBytes("reinstate-bob-1"));
    const scheduleReinstate = encodeFunctionData({
      abi: timelock.abi,
      functionName: "schedule",
      args: [governance.address, 0n, reinstateData, ZERO_BYTES32, reinstateSalt, CONSORTIUM_DELAY],
    });
    await execSafeTx(
      consortiumSafe,
      [consortiumOwners[1], consortiumOwners[2]],
      timelock.address,
      scheduleReinstate
    );
    await networkHelpers.time.increase(Number(CONSORTIUM_DELAY) + 1);
    await relayer.writeContract({
      address: timelock.address,
      abi: timelock.abi,
      functionName: "execute",
      args: [governance.address, 0n, reinstateData, ZERO_BYTES32, reinstateSalt],
    });
    assert.equal(await governance.read.isActiveMember([bobId]), true);

    // Organization Safe revokes Bob's Read ACL and verifies Write ACL stays untouched.
    const revokeReadData = encodeFunctionData({
      abi: governance.abi,
      functionName: "setFilePermission",
      args: [fileId, bobId, READ_PERMISSION, false, keccak256(stringToBytes("revoke-1"))],
    });
    await execSafeTx(orgSafe, [orgOwners[0], orgOwners[2]], governance.address, revokeReadData);
    assert.equal(await governance.read.hasReadAccess([bobId, fileId]), false);
    assert.equal(await governance.read.hasWriteAccess([aliceId, fileId]), true);

    // Organization Safe (2-of-3) creates a nested folder hierarchy and renames a folder;
    // unauthorized EOA callers are rejected, and Alice places a file inside the nested folder.
    const rootFolderId = keccak256(stringToBytes("folder-finance"));
    const childFolderId = keccak256(stringToBytes("folder-finance-q4"));
    await assert.rejects(
      relayer.writeContract({
        address: registry.address,
        abi: registry.abi,
        functionName: "createFolder",
        args: [rootFolderId, orgId, ZERO_BYTES32, "Finance"],
      })
    );
    const createRootFolderData = encodeFunctionData({
      abi: registry.abi,
      functionName: "createFolder",
      args: [rootFolderId, orgId, ZERO_BYTES32, "Finance"],
    });
    await execSafeTx(orgSafe, [orgOwners[0], orgOwners[1]], registry.address, createRootFolderData);

    const createChildFolderData = encodeFunctionData({
      abi: registry.abi,
      functionName: "createFolder",
      args: [childFolderId, orgId, rootFolderId, "Q4"],
    });
    await execSafeTx(orgSafe, [orgOwners[1], orgOwners[2]], registry.address, createChildFolderData);

    const renameChildData = encodeFunctionData({
      abi: registry.abi,
      functionName: "renameFolder",
      args: [childFolderId, "Q4-Audited"],
    });
    await execSafeTx(orgSafe, [orgOwners[0], orgOwners[2]], registry.address, renameChildData);
    const childFolder = await registry.read.getFolder([childFolderId]);
    assert.equal(childFolder.displayName, "Q4-Audited");
    assert.equal(childFolder.parentFolderId, rootFolderId);

    const nestedFileId = keccak256(stringToBytes("safe-nested-file-1"));
    const nestedEpochId = keccak256(stringToBytes("safe-nested-epoch-1"));
    const nestedManifest = keccak256(stringToBytes("safe-nested-manifest-1"));
    const nestedNonce = keccak256(stringToBytes("safe-nested-nonce-1"));
    const nestedDeadline = (await publicClient.getBlock()).timestamp + 3600n;
    const nestedReq = {
      fileId: nestedFileId,
      versionNumber: 1n,
      parentManifestHash: ZERO_BYTES32,
      contentCidHash: keccak256(stringToBytes(contentCidV1)),
      envelopeSetCidHash: keccak256(stringToBytes(envCidV1)),
      epochId: nestedEpochId,
      manifestHash: nestedManifest,
      memberId: aliceId,
      signerAddress: alice.address,
      operationNonce: nestedNonce,
      deadline: nestedDeadline,
    };
    const nestedSig = await alice.signTypedData({
      domain: {
        name: "RRDS FileRegistry",
        version: "1",
        chainId,
        verifyingContract: registry.address,
      },
      types: {
        VersionAppend: [
          { name: "fileId", type: "bytes32" },
          { name: "versionNumber", type: "uint64" },
          { name: "parentManifestHash", type: "bytes32" },
          { name: "contentCidHash", type: "bytes32" },
          { name: "envelopeSetCidHash", type: "bytes32" },
          { name: "epochId", type: "bytes32" },
          { name: "manifestHash", type: "bytes32" },
          { name: "memberId", type: "bytes32" },
          { name: "signerAddress", type: "address" },
          { name: "operationNonce", type: "bytes32" },
          { name: "deadline", type: "uint256" },
        ],
      },
      primaryType: "VersionAppend",
      message: nestedReq,
    });
    await relayer.writeContract({
      address: registry.address,
      abi: registry.abi,
      functionName: "createFile",
      args: [nestedReq, contentCidV1, envCidV1, "q4-audit.txt", childFolderId, nestedSig],
    });
    const nestedFile = await registry.read.getFile([nestedFileId]);
    assert.equal(nestedFile.parentFolderId, childFolderId);
    assert.equal(nestedFile.currentVersionNumber, 1n);
    void WRITE_PERMISSION;
  });
});
