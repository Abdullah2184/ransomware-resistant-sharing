// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {AccessGovernance} from "./AccessGovernance.sol";
import {FileRegistry} from "./FileRegistry.sol";
import {RrdsTimelockController} from "./RrdsTimelockController.sol";
import {RrdsEip712} from "./libraries/RrdsEip712.sol";

contract TimelockActivationTest is Test {
    uint256 private constant DELAY = 86_400;
    uint256 private constant MEMBER_PRIVATE_KEY = 0xA11CE;
    bytes32 private constant ORGANIZATION_ID = bytes32(uint256(1));
    bytes32 private constant FILE_ID = bytes32(uint256(2));
    bytes32 private constant MEMBER_ID = bytes32(uint256(3));
    string private constant CONTENT_CID =
        "bafkreiaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq";
    string private constant ENVELOPE_CID =
        "bafkreiafaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifau";

    RrdsTimelockController private timelock;
    AccessGovernance private governance;
    FileRegistry private registry;
    address private organizationSafe = address(0x300);

    function setUp() public {
        timelock = new RrdsTimelockController(address(this));
        governance = new AccessGovernance(address(timelock), address(0x200));
        registry = new FileRegistry(address(governance), address(timelock));

        assertEq(timelock.getMinDelay(), DELAY);
        assertTrue(timelock.hasRole(timelock.PROPOSER_ROLE(), address(this)));
        assertTrue(timelock.hasRole(timelock.CANCELLER_ROLE(), address(this)));
        assertTrue(timelock.hasRole(timelock.EXECUTOR_ROLE(), address(0)));
        assertTrue(timelock.hasRole(timelock.DEFAULT_ADMIN_ROLE(), address(timelock)));
        assertFalse(timelock.hasRole(timelock.DEFAULT_ADMIN_ROLE(), address(this)));
        assertTrue(governance.hasRole(governance.DEFAULT_ADMIN_ROLE(), address(timelock)));
        assertFalse(governance.hasRole(governance.DEFAULT_ADMIN_ROLE(), address(this)));
        assertFalse(
            governance.hasRole(governance.FILE_REGISTRY_ROLE(), address(registry))
        );

        vm.prank(address(timelock));
        governance.registerOrganization(ORGANIZATION_ID, organizationSafe);
        _registerMember();
    }

    function test_FileCreationWaitsForTimelockedRoleGrant() public {
        RrdsEip712.VersionAppend memory request = RrdsEip712.VersionAppend({
            fileId: FILE_ID,
            versionNumber: 1,
            parentManifestHash: bytes32(0),
            contentCidHash: keccak256(bytes(CONTENT_CID)),
            envelopeSetCidHash: keccak256(bytes(ENVELOPE_CID)),
            epochId: bytes32(uint256(10)),
            manifestHash: bytes32(uint256(20)),
            memberId: MEMBER_ID,
            signerAddress: vm.addr(MEMBER_PRIVATE_KEY),
            operationNonce: bytes32(uint256(30)),
            deadline: block.timestamp + 2 days
        });

        vm.expectRevert();
        registry.createFile(
            request,
            CONTENT_CID,
            ENVELOPE_CID,
            "report.txt",
            bytes32(0),
            _sign(request)
        );
        assertEq(
            uint256(registry.getFile(FILE_ID).status),
            uint256(FileRegistry.FileStatus.Unregistered)
        );

        bytes32 role = governance.FILE_REGISTRY_ROLE();
        bytes memory grantCall = abi.encodeCall(
            governance.grantRole,
            (role, address(registry))
        );
        bytes32 salt = keccak256("activate-file-registry");
        timelock.schedule(address(governance), 0, grantCall, bytes32(0), salt, DELAY);

        vm.warp(block.timestamp + DELAY - 1);
        vm.expectRevert();
        timelock.execute(address(governance), 0, grantCall, bytes32(0), salt);

        vm.warp(block.timestamp + 1);
        vm.prank(address(0xBEEF));
        timelock.execute(address(governance), 0, grantCall, bytes32(0), salt);
        assertTrue(governance.hasRole(role, address(registry)));

        registry.createFile(
            request,
            CONTENT_CID,
            ENVELOPE_CID,
            "report.txt",
            bytes32(0),
            _sign(request)
        );
        assertEq(registry.getFile(FILE_ID).currentVersionNumber, 1);
    }

    function _sign(
        RrdsEip712.VersionAppend memory request
    ) private view returns (bytes memory) {
        bytes32 digest = RrdsEip712.digest(
            RrdsEip712.fileRegistryDomainSeparator(block.chainid, address(registry)),
            RrdsEip712.hashVersionAppend(request)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MEMBER_PRIVATE_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _registerMember() private {
        bytes32 nonce = bytes32(uint256(901));
        uint256 deadline = block.timestamp + 1 days;
        RrdsEip712.MemberKeyProof memory proof = RrdsEip712.MemberKeyProof({
            memberId: MEMBER_ID,
            organizationId: ORGANIZATION_ID,
            signingAddress: vm.addr(MEMBER_PRIVATE_KEY),
            signingKeyVersion: 1,
            encryptionKeyVersion: 1,
            encryptionPublicKey: bytes32(uint256(7)),
            operationNonce: nonce,
            deadline: deadline
        });
        bytes32 digest = RrdsEip712.digest(
            RrdsEip712.accessGovernanceDomainSeparator(block.chainid, address(governance)),
            RrdsEip712.hashMemberKeyProof(proof)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MEMBER_PRIVATE_KEY, digest);
        vm.prank(organizationSafe);
        governance.registerMember(
            ORGANIZATION_ID,
            MEMBER_ID,
            vm.addr(MEMBER_PRIVATE_KEY),
            1,
            1,
            bytes32(uint256(7)),
            nonce,
            deadline,
            abi.encodePacked(r, s, v)
        );
    }
}
