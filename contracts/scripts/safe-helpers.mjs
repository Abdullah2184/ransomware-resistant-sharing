/**
 * Audited Safe v1.4.1 (`@safe-global/safe-contracts`) deployment and
 * multi-owner EIP-712 `execTransaction` helpers for Besu QBFT.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  concatHex,
  encodeFunctionData,
  getAddress,
  parseEventLogs,
  zeroAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

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

export function loadSafeArtifact(relPath) {
  const full = path.join(safeArtifactsRoot, relPath);
  if (!fs.existsSync(full)) {
    throw new Error(`Missing Safe v1.4.1 artifact: ${full}`);
  }
  return JSON.parse(fs.readFileSync(full, "utf8"));
}

export async function deploySafeInfrastructure(publicClient, walletClient) {
  const safeArt = loadSafeArtifact("Safe.sol/Safe.json");
  const factoryArt = loadSafeArtifact("proxies/SafeProxyFactory.sol/SafeProxyFactory.json");
  const fallbackArt = loadSafeArtifact(
    "handler/CompatibilityFallbackHandler.sol/CompatibilityFallbackHandler.json"
  );

  const deployOne = async (name, artifact) => {
    const hash = await walletClient.deployContract({
      abi: artifact.abi,
      bytecode: artifact.bytecode,
      args: [],
      maxFeePerGas: 0n,
      maxPriorityFeePerGas: 0n,
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    if (receipt.status !== "success" || !receipt.contractAddress) {
      throw new Error(`Deployment of ${name} failed (tx ${hash})`);
    }
    return {
      address: getAddress(receipt.contractAddress),
      txHash: hash,
      blockNumber: Number(receipt.blockNumber),
    };
  };

  const singleton = await deployOne("Safe (v1.4.1 singleton)", safeArt);
  const factory = await deployOne("SafeProxyFactory", factoryArt);
  const fallbackHandler = await deployOne("CompatibilityFallbackHandler", fallbackArt);
  return { singleton, factory, fallbackHandler };
}

export async function deploySafeProxy(
  publicClient,
  walletClient,
  infra,
  owners,
  threshold,
  saltNonce
) {
  const safeArt = loadSafeArtifact("Safe.sol/Safe.json");
  const factoryArt = loadSafeArtifact("proxies/SafeProxyFactory.sol/SafeProxyFactory.json");

  const setupData = encodeFunctionData({
    abi: safeArt.abi,
    functionName: "setup",
    args: [
      owners,
      BigInt(threshold),
      zeroAddress,
      "0x",
      infra.fallbackHandler.address,
      zeroAddress,
      0n,
      zeroAddress,
    ],
  });

  const hash = await walletClient.writeContract({
    address: infra.factory.address,
    abi: factoryArt.abi,
    functionName: "createProxyWithNonce",
    args: [infra.singleton.address, setupData, BigInt(saltNonce)],
    maxFeePerGas: 0n,
    maxPriorityFeePerGas: 0n,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") {
    throw new Error(`Safe proxy creation failed (tx ${hash})`);
  }
  const logs = parseEventLogs({
    abi: factoryArt.abi,
    logs: receipt.logs,
    eventName: "ProxyCreation",
  });
  if (logs.length !== 1) {
    throw new Error(`Expected 1 ProxyCreation event, got ${logs.length}`);
  }
  return {
    address: getAddress(logs[0].args.proxy),
    txHash: hash,
    blockNumber: Number(receipt.blockNumber),
    owners,
    threshold: Number(threshold),
  };
}

export async function execSafeTransaction({
  publicClient,
  walletClient,
  chainId,
  safeAddress,
  ownerPrivateKeys,
  to,
  data,
}) {
  const safeArt = loadSafeArtifact("Safe.sol/Safe.json");
  const threshold = Number(
    await publicClient.readContract({
      address: safeAddress,
      abi: safeArt.abi,
      functionName: "getThreshold",
    })
  );
  if (ownerPrivateKeys.length < threshold) {
    throw new Error(
      `Need at least ${threshold} Safe owner signatures, got ${ownerPrivateKeys.length}`
    );
  }

  const nonce = await publicClient.readContract({
    address: safeAddress,
    abi: safeArt.abi,
    functionName: "nonce",
  });

  const signers = ownerPrivateKeys
    .slice(0, threshold)
    .map((key) => privateKeyToAccount(key))
    .sort((a, b) => a.address.toLowerCase().localeCompare(b.address.toLowerCase()));

  const signatures = [];
  for (const signer of signers) {
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
    signatures.push(sig);
  }

  const packed = concatHex(signatures);
  const hash = await walletClient.writeContract({
    address: safeAddress,
    abi: safeArt.abi,
    functionName: "execTransaction",
    args: [to, 0n, data, 0, 0n, 0n, 0n, zeroAddress, zeroAddress, packed],
    maxFeePerGas: 0n,
    maxPriorityFeePerGas: 0n,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  if (receipt.status !== "success") {
    throw new Error(`Safe execTransaction reverted (tx ${hash})`);
  }
  return receipt;
}
