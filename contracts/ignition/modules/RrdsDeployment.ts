import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("RrdsDeployment", (m) => {
  const consortiumSafeAddress = m.getParameter("consortiumSafeAddress");
  const emergencySafeAddress = m.getParameter("emergencySafeAddress");

  const timelock = m.contract("RrdsTimelockController", [consortiumSafeAddress]);
  const accessGovernance = m.contract("AccessGovernance", [
    timelock,
    emergencySafeAddress,
  ]);
  const fileRegistry = m.contract("FileRegistry", [accessGovernance, timelock]);

  return { timelock, accessGovernance, fileRegistry };
});
