import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import { hashTypedData, keccak256, stringToHex } from "viem";

const expected = JSON.parse(
  readFileSync(new URL("../../tests/fixtures/eip712-v1.json", import.meta.url), "utf8"),
) as Record<string, string>;

const fileRegistryDomain = {
  name: "RRDS FileRegistry",
  version: "1",
  chainId: 1337,
  verifyingContract: "0x1111111111111111111111111111111111111111",
} as const;

const accessGovernanceDomain = {
  name: "RRDS AccessGovernance",
  version: "1",
  chainId: 1337,
  verifyingContract: "0x2222222222222222222222222222222222222222",
} as const;

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

const accessLookupTypes = {
  AccessLookup: [
    { name: "memberId", type: "bytes32" },
    { name: "fileId", type: "bytes32" },
    { name: "versionNumber", type: "uint64" },
    { name: "encryptionKeyVersion", type: "uint32" },
    { name: "operationNonce", type: "bytes32" },
    { name: "deadline", type: "uint256" },
  ],
} as const;

const envelopeSetUpdateTypes = {
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
} as const;

const memberKeyProofTypes = {
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
} as const;

describe("approved EIP-712 operation schemas", function () {
  it("matches the Rust version-append digest vector", function () {
    const digest = hashTypedData({
      domain: fileRegistryDomain,
      types: versionAppendTypes,
      primaryType: "VersionAppend",
      message: {
        fileId: `0x${"01".repeat(32)}`,
        versionNumber: 3n,
        parentManifestHash: `0x${"02".repeat(32)}`,
        contentCidHash: keccak256(
          stringToHex("bafkreiaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq"),
        ),
        envelopeSetCidHash: keccak256(
          stringToHex("bafkreiafaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifau"),
        ),
        epochId: `0x${"06".repeat(32)}`,
        manifestHash: `0x${"03".repeat(32)}`,
        memberId: `0x${"07".repeat(32)}`,
        signerAddress: `0x${"10".repeat(20)}`,
        operationNonce: `0x${"99".repeat(32)}`,
        deadline: 1_800_000_000n,
      },
    });

    assert.equal(digest, expected.versionAppend);
  });

  it("matches the Rust access-lookup digest vector", function () {
    const digest = hashTypedData({
      domain: accessGovernanceDomain,
      types: accessLookupTypes,
      primaryType: "AccessLookup",
      message: {
        memberId: `0x${"08".repeat(32)}`,
        fileId: `0x${"09".repeat(32)}`,
        versionNumber: 3n,
        encryptionKeyVersion: 2,
        operationNonce: `0x${"99".repeat(32)}`,
        deadline: 1_800_000_000n,
      },
    });

    assert.equal(digest, expected.accessLookup);
  });

  it("matches the Rust envelope-set-update digest vector", function () {
    const digest = hashTypedData({
      domain: accessGovernanceDomain,
      types: envelopeSetUpdateTypes,
      primaryType: "EnvelopeSetUpdate",
      message: {
        fileId: `0x${"0a".repeat(32)}`,
        versionNumber: 3n,
        epochId: `0x${"0b".repeat(32)}`,
        oldEnvelopeSetCid: "bafkreiambqgaydambqgaydambqgaydambqgaydambqgaydambqgaydambq",
        newEnvelopeSetCid: "bafkreianbugq2dinbugq2dinbugq2dinbugq2dinbugq2dinbugq2dinbu",
        actorMemberId: `0x${"0e".repeat(32)}`,
        proposalId: `0x${"0f".repeat(32)}`,
        operationNonce: `0x${"99".repeat(32)}`,
        deadline: 1_800_000_000n,
      },
    });

    assert.equal(digest, expected.envelopeSetUpdate);
  });

  it("matches the Rust member-key proof digest vector", function () {
    const digest = hashTypedData({
      domain: accessGovernanceDomain,
      types: memberKeyProofTypes,
      primaryType: "MemberKeyProof",
      message: {
        memberId: `0x${"11".repeat(32)}`,
        organizationId: `0x${"12".repeat(32)}`,
        signingAddress: `0x${"13".repeat(20)}`,
        signingKeyVersion: 2,
        encryptionKeyVersion: 3,
        encryptionPublicKey: `0x${"14".repeat(32)}`,
        operationNonce: `0x${"15".repeat(32)}`,
        deadline: 1_800_000_000n,
      },
    });

    assert.equal(digest, expected.memberKeyProof);
  });
});
