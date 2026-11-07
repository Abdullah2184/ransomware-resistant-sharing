import hardhatToolboxViemPlugin from "@nomicfoundation/hardhat-toolbox-viem";
import { configVariable, defineConfig } from "hardhat/config";

const besuChainId = Number(process.env.BESU_CHAIN_ID ?? "1337");

export default defineConfig({
  plugins: [hardhatToolboxViemPlugin],
  solidity: {
    profiles: {
      default: {
        version: "0.8.34",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
      production: {
        version: "0.8.34",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
        },
      },
    },
  },
  networks: {
    hardhatMainnet: {
      type: "edr-simulated",
      chainType: "l1",
    },
    hardhatOp: {
      type: "edr-simulated",
      chainType: "op",
    },
    besuLocal: {
      type: "http",
      chainType: "l1",
      url: process.env.BESU_RPC_URL ?? "http://127.0.0.1:8545",
      chainId: besuChainId,
      accounts: [configVariable("BESU_DEPLOYER_PRIVATE_KEY")],
    },
  },
});
