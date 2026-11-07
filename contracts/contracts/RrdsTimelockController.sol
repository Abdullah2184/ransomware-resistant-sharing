// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.34;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

contract RrdsTimelockController is TimelockController {
    uint256 public constant CONSORTIUM_DELAY = 86_400;

    error ZeroConsortiumSafe();

    constructor(address consortiumSafe)
        TimelockController(
            CONSORTIUM_DELAY,
            _singleProposer(consortiumSafe),
            _openExecutor(),
            address(0)
        )
    {
        if (consortiumSafe == address(0)) revert ZeroConsortiumSafe();
    }

    function _singleProposer(
        address proposer
    ) private pure returns (address[] memory proposers) {
        proposers = new address[](1);
        proposers[0] = proposer;
    }

    function _openExecutor() private pure returns (address[] memory executors) {
        executors = new address[](1);
        executors[0] = address(0);
    }
}
