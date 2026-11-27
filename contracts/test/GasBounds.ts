import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { network } from "hardhat";
import { encodeFunctionData, keccak256, stringToHex } from "viem";

/**
 * Gas consumption verification for major RRDS contract operations
 * (`TECHNICAL_SPECIFICATION.md` §7.9).
 *
 * Verifies every major state transition stays comfortably within the
 * configured `DEFAULT_TX_GAS_LIMIT` (2,000,000 gas) and well below Besu's
 * 30,000,000 block gas limit.
 */
describe("RRDS contract gas bounds (§7.9)", function () {
  const DEFAULT_TX_GAS_LIMIT = 2_000_000n;
  const CONSORTIUM_DELAY = 86_400n;
  const ORG_ID = keccak256(stringToHex("gas-test-org"));
  const ALICE_ID = keccak256(stringToHex("gas-test-alice"));
  const BOB_ID = keccak256(stringToHex("gas-test-bob"));
  const FILE_ID = keccak256(stringToHex("gas-test-file"));
  const CONTENT_CID_V1 =
    "bafkreiaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq";
  const CONTENT_CID_V2 =
    "bafkreiafaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifau";
  const ENV_CID_V1 =
    "bafkreiambqgaydambqgaydambqgaydambqgaydambqgaydambqgaydambq";
  const ENV_CID_V1_R2 =
    "bafkreianbugq2dinbugq2dinbugq2dinbugq2dinbugq2dinbugq2dinbu";
  const ENV_CID_V2 =
    "bafkreiaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq";
  const ZERO_BYTES32 = `0x${"00".repeat(32)}` as const;

  it("measures and bounds gas for deployment, timelock, enrollment, createFile, appendVersion, ACLs, and updateEnvelopeSet", async function () {
    const { viem, networkHelpers } = await network.create();
    const publicClient = await viem.getPublicClient();
    const [consortiumSafe, emergencySafe, orgSafe, alice, bob, relayer] =
      await viem.getWalletClients();
    const chainId = await publicClient.getChainId();

    const timelock = await viem.deployContract("RrdsTimelockController", [
      consortiumSafe.account.address,
    ]);
    const governance = await viem.deployContract("AccessGovernance", [
      timelock.address,
      emergencySafe.account.address,
    ]);
    const registry = await viem.deployContract("FileRegistry", [
      governance.address,
      timelock.address,
    ]);

    const fileRegistryRole = await governance.read.FILE_REGISTRY_ROLE();
    const grantCall = encodeFunctionData({
      abi: governance.abi,
      functionName: "grantRole",
      args: [fileRegistryRole, registry.address],
    });
    const registerOrgCall = encodeFunctionData({
      abi: governance.abi,
      functionName: "registerOrganization",
      args: [ORG_ID, orgSafe.account.address],
    });
    const salt = keccak256(stringToHex("gas-bounds-bootstrap"));

    const scheduleTx = await timelock.write.scheduleBatch(
      [
        [governance.address, governance.address],
        [0n, 0n],
        [grantCall, registerOrgCall],
        ZERO_BYTES32,
        salt,
        CONSORTIUM_DELAY,
      ],
      { account: consortiumSafe.account },
    );
    const scheduleReceipt = await publicClient.waitForTransactionReceipt({
      hash: scheduleTx,
    });

    await networkHelpers.time.increase(Number(CONSORTIUM_DELAY));
    const executeTx = await timelock.write.executeBatch(
      [
        [governance.address, governance.address],
        [0n, 0n],
        [grantCall, registerOrgCall],
        ZERO_BYTES32,
        salt,
      ],
      { account: relayer.account },
    );
    const executeReceipt = await publicClient.waitForTransactionReceipt({
      hash: executeTx,
    });

    const latestBlock = await publicClient.getBlock();
    const deadline = latestBlock.timestamp + 3600n;

    const govDomain = {
      name: "RRDS AccessGovernance",
      version: "1",
      chainId,
      verifyingContract: governance.address,
    } as const;
    const regDomain = {
      name: "RRDS FileRegistry",
      version: "1",
      chainId,
      verifyingContract: registry.address,
    } as const;

    const registerMemberWithProof = async (
      memberId: `0x${string}`,
      wallet: typeof alice,
      encPub: `0x${string}`,
      nonce: `0x${string}`,
    ) => {
      const sig = await wallet.signTypedData({
        domain: govDomain,
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
          memberId,
          organizationId: ORG_ID,
          signingAddress: wallet.account.address,
          signingKeyVersion: 1,
          encryptionKeyVersion: 1,
          encryptionPublicKey: encPub,
          operationNonce: nonce,
          deadline,
        },
      });
      const tx = await governance.write.registerMember(
        [
          ORG_ID,
          memberId,
          wallet.account.address,
          1,
          1,
          encPub,
          nonce,
          deadline,
          sig,
        ],
        { account: orgSafe.account },
      );
      return publicClient.waitForTransactionReceipt({ hash: tx });
    };

    const registerAliceReceipt = await registerMemberWithProof(
      ALICE_ID,
      alice,
      `0x${"11".repeat(32)}`,
      `0x${"a1".repeat(32)}`,
    );
    await registerMemberWithProof(
      BOB_ID,
      bob,
      `0x${"22".repeat(32)}`,
      `0x${"b1".repeat(32)}`,
    );

    const versionAppendTypes = {
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
    } as const;

    const v1Manifest = `0x${"31".repeat(32)}` as const;
    const v1Req = {
      fileId: FILE_ID,
      versionNumber: 1n,
      parentManifestHash: ZERO_BYTES32,
      contentCidHash: keccak256(stringToHex(CONTENT_CID_V1)),
      envelopeSetCidHash: keccak256(stringToHex(ENV_CID_V1)),
      epochId: `0x${"41".repeat(32)}` as const,
      manifestHash: v1Manifest,
      memberId: ALICE_ID,
      signerAddress: alice.account.address,
      operationNonce: `0x${"51".repeat(32)}` as const,
      deadline,
    };
    const v1Sig = await alice.signTypedData({
      domain: regDomain,
      types: versionAppendTypes,
      primaryType: "VersionAppend",
      message: v1Req,
    });
    const createTx = await registry.write.createFile(
      [v1Req, CONTENT_CID_V1, ENV_CID_V1, "quarterly.pdf", ZERO_BYTES32, v1Sig],
      { account: relayer.account },
    );
    const createReceipt = await publicClient.waitForTransactionReceipt({
      hash: createTx,
    });

    const v2Req = {
      fileId: FILE_ID,
      versionNumber: 2n,
      parentManifestHash: v1Manifest,
      contentCidHash: keccak256(stringToHex(CONTENT_CID_V2)),
      envelopeSetCidHash: keccak256(stringToHex(ENV_CID_V2)),
      epochId: `0x${"42".repeat(32)}` as const,
      manifestHash: `0x${"32".repeat(32)}` as const,
      memberId: ALICE_ID,
      signerAddress: alice.account.address,
      operationNonce: `0x${"52".repeat(32)}` as const,
      deadline,
    };
    const v2Sig = await alice.signTypedData({
      domain: regDomain,
      types: versionAppendTypes,
      primaryType: "VersionAppend",
      message: v2Req,
    });
    const appendTx = await registry.write.appendVersion(
      [v2Req, CONTENT_CID_V2, ENV_CID_V2, v2Sig],
      { account: relayer.account },
    );
    const appendReceipt = await publicClient.waitForTransactionReceipt({
      hash: appendTx,
    });

    const aclGrantTx = await governance.write.setFilePermission(
      [FILE_ID, BOB_ID, 0, true, ZERO_BYTES32],
      { account: orgSafe.account },
    );
    const aclGrantReceipt = await publicClient.waitForTransactionReceipt({
      hash: aclGrantTx,
    });

    const histGrantTx = await governance.write.setHistoricalReadAccess(
      [FILE_ID, 1n, BOB_ID, true, ZERO_BYTES32],
      { account: orgSafe.account },
    );
    const histGrantReceipt = await publicClient.waitForTransactionReceipt({
      hash: histGrantTx,
    });

    const envReq = {
      fileId: FILE_ID,
      versionNumber: 1n,
      epochId: `0x${"41".repeat(32)}` as const,
      oldEnvelopeSetCid: ENV_CID_V1,
      newEnvelopeSetCid: ENV_CID_V1_R2,
      actorMemberId: ALICE_ID,
      proposalId: ZERO_BYTES32,
      operationNonce: `0x${"53".repeat(32)}` as const,
      deadline,
    };
    const envSig = await alice.signTypedData({
      domain: govDomain,
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
      message: envReq,
    });
    const envUpdateTx = await governance.write.updateEnvelopeSet(
      [envReq, envSig],
      { account: relayer.account },
    );
    const envUpdateReceipt = await publicClient.waitForTransactionReceipt({
      hash: envUpdateTx,
    });
    assert.equal(envUpdateReceipt.status, "success");
    const [updatedCid, , updatedRevision] = await governance.read.currentEnvelopeSet([
      FILE_ID,
      1n,
    ]);
    assert.equal(updatedCid, ENV_CID_V1_R2);
    assert.equal(updatedRevision, 2);

    // Confirm relayer still cannot mutate ACLs (policy Safe remains strictly required).
    await assert.rejects(
      governance.write.setFilePermission(
        [FILE_ID, BOB_ID, 1, true, ZERO_BYTES32],
        { account: relayer.account },
      ),
    );

    const measurements: Record<string, bigint> = {
      timelockScheduleBatch: scheduleReceipt.gasUsed,
      timelockExecuteBatch: executeReceipt.gasUsed,
      registerMember: registerAliceReceipt.gasUsed,
      createFile: createReceipt.gasUsed,
      appendVersion: appendReceipt.gasUsed,
      setFilePermission: aclGrantReceipt.gasUsed,
      setHistoricalReadAccess: histGrantReceipt.gasUsed,
      updateEnvelopeSet: envUpdateReceipt.gasUsed,
    };

    for (const [op, gasUsed] of Object.entries(measurements)) {
      assert.ok(gasUsed > 0n, `${op} gasUsed should be positive`);
      assert.ok(
        gasUsed < DEFAULT_TX_GAS_LIMIT,
        `${op} gasUsed (${gasUsed}) exceeded DEFAULT_TX_GAS_LIMIT (${DEFAULT_TX_GAS_LIMIT})`,
      );
    }

    // Specific tighter bounds guarding against accidental O(N) storage regressions.
    // Measured baseline: createFile ~799k gas, appendVersion ~657k gas.
    assert.ok(measurements.createFile < 900_000n, `createFile gas=${measurements.createFile}`);
    assert.ok(measurements.appendVersion < 750_000n, `appendVersion gas=${measurements.appendVersion}`);
    assert.ok(measurements.setFilePermission < 150_000n, `setFilePermission gas=${measurements.setFilePermission}`);
    assert.ok(measurements.updateEnvelopeSet < 250_000n, `updateEnvelopeSet gas=${measurements.updateEnvelopeSet}`);
  });
});
