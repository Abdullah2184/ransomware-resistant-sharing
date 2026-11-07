// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {AccessGovernance} from "./AccessGovernance.sol";
import {FileRegistry} from "./FileRegistry.sol";
import {RrdsEip712} from "./libraries/RrdsEip712.sol";

contract FileRegistryTest is Test {
    address private constant TIMELOCK = address(0x100);
    address private constant EMERGENCY_SAFE = address(0x200);
    address private constant ORGANIZATION_SAFE = address(0x300);
    address private constant FILE_METADATA_SAFE = address(0x500);
    bytes32 private constant ORGANIZATION_ID = bytes32(uint256(1));
    bytes32 private constant FILE_ID = bytes32(uint256(2));
    bytes32 private constant MEMBER_ID = bytes32(uint256(3));
    uint256 private constant MEMBER_PRIVATE_KEY = 0xA11CE;

    string private constant CONTENT_CID_V1 =
        "bafkreiaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq";
    string private constant ENVELOPE_CID_V1 =
        "bafkreiafaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifau";
    string private constant CONTENT_CID_V2 =
        "bafkreiambqgaydambqgaydambqgaydambqgaydambqgaydambqgaydambq";
    string private constant ENVELOPE_CID_V2 =
        "bafkreianbugq2dinbugq2dinbugq2dinbugq2dinbugq2dinbugq2dinbu";
    bytes32 private constant EPOCH_V1 = bytes32(uint256(10));
    bytes32 private constant EPOCH_V2 = bytes32(uint256(11));
    bytes32 private constant MANIFEST_V1 = bytes32(uint256(20));
    bytes32 private constant MANIFEST_V2 = bytes32(uint256(21));

    AccessGovernance private governance;
    FileRegistry private registry;

    function setUp() public {
        governance = new AccessGovernance(TIMELOCK, EMERGENCY_SAFE);
        vm.prank(TIMELOCK);
        governance.registerOrganization(ORGANIZATION_ID, ORGANIZATION_SAFE);
        registry = new FileRegistry(address(governance), TIMELOCK);
        bytes32 fileRegistryRole = governance.FILE_REGISTRY_ROLE();
        vm.prank(TIMELOCK);
        governance.grantRole(fileRegistryRole, address(registry));
        _registerMember();
    }

    function test_MetadataChangesRequireConfiguredFilePolicyAuthority() public {
        RrdsEip712.VersionAppend memory first = _request(
            1,
            bytes32(0),
            MANIFEST_V1,
            EPOCH_V1,
            CONTENT_CID_V1,
            ENVELOPE_CID_V1,
            bytes32(uint256(29)),
            block.timestamp + 1 days
        );
        registry.createFile(
            first,
            CONTENT_CID_V1,
            ENVELOPE_CID_V1,
            "report.txt",
            bytes32(0),
            _sign(first)
        );

        vm.expectRevert(FileRegistry.UnauthorizedMetadataAuthority.selector);
        vm.prank(TIMELOCK);
        registry.updateFileMetadata(FILE_ID, "renamed.txt", bytes32(0));

        vm.prank(ORGANIZATION_SAFE);
        registry.updateFileMetadata(FILE_ID, "renamed.txt", bytes32(0));

        bytes32 metadataPolicy = governance.FILE_METADATA_POLICY();
        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePolicyAuthority(
            FILE_ID,
            metadataPolicy,
            FILE_METADATA_SAFE
        );

        vm.expectRevert(FileRegistry.UnauthorizedMetadataAuthority.selector);
        vm.prank(ORGANIZATION_SAFE);
        registry.updateFileMetadata(FILE_ID, "unauthorized.txt", bytes32(0));

        vm.prank(FILE_METADATA_SAFE);
        registry.updateFileMetadata(FILE_ID, "approved.txt", bytes32(0));
        assertEq(registry.getFile(FILE_ID).displayName, "approved.txt");
    }

    function test_FolderHierarchyAndFileParentRemainOrganizationScoped() public {
        bytes32 rootFolderId = bytes32(uint256(70));
        bytes32 childFolderId = bytes32(uint256(71));
        bytes32 otherOrganizationId = bytes32(uint256(72));
        address otherOrganizationSafe = address(0x301);

        vm.prank(ORGANIZATION_SAFE);
        registry.createFolder(rootFolderId, ORGANIZATION_ID, bytes32(0), "Reports");
        vm.prank(ORGANIZATION_SAFE);
        registry.createFolder(childFolderId, ORGANIZATION_ID, rootFolderId, "Quarterly");

        FileRegistry.Folder memory child = registry.getFolder(childFolderId);
        assertEq(child.displayName, "Quarterly");
        assertEq(child.parentFolderId, rootFolderId);
        assertEq(child.organizationId, ORGANIZATION_ID);

        vm.expectRevert(FileRegistry.InvalidFolderParent.selector);
        vm.prank(ORGANIZATION_SAFE);
        registry.createFolder(
            bytes32(uint256(73)),
            ORGANIZATION_ID,
            bytes32(uint256(74)),
            "Missing parent"
        );

        RrdsEip712.VersionAppend memory first = _request(
            1,
            bytes32(0),
            MANIFEST_V1,
            EPOCH_V1,
            CONTENT_CID_V1,
            ENVELOPE_CID_V1,
            bytes32(uint256(28)),
            block.timestamp + 1 days
        );
        vm.prank(ORGANIZATION_SAFE);
        registry.createFolder(
            bytes32(uint256(75)),
            ORGANIZATION_ID,
            bytes32(0),
            "Archive"
        );
        registry.createFile(
            first,
            CONTENT_CID_V1,
            ENVELOPE_CID_V1,
            "report.txt",
            childFolderId,
            _sign(first)
        );
        assertEq(registry.getFile(FILE_ID).parentFolderId, childFolderId);

        vm.expectRevert(FileRegistry.InvalidFolderParent.selector);
        vm.prank(ORGANIZATION_SAFE);
        registry.updateFileMetadata(FILE_ID, "report.txt", bytes32(uint256(999)));

        vm.prank(TIMELOCK);
        governance.registerOrganization(otherOrganizationId, otherOrganizationSafe);
        vm.prank(otherOrganizationSafe);
        registry.createFolder(
            bytes32(uint256(76)),
            otherOrganizationId,
            bytes32(0),
            "Other organization"
        );
        vm.expectRevert(FileRegistry.InvalidFolderParent.selector);
        vm.prank(ORGANIZATION_SAFE);
        registry.updateFileMetadata(FILE_ID, "report.txt", bytes32(uint256(76)));

        vm.prank(ORGANIZATION_SAFE);
        registry.updateFileMetadata(FILE_ID, "report.txt", rootFolderId);
        assertEq(registry.getFile(FILE_ID).parentFolderId, rootFolderId);

        vm.expectRevert(FileRegistry.FolderAlreadyExists.selector);
        vm.prank(ORGANIZATION_SAFE);
        registry.createFolder(FILE_ID, ORGANIZATION_ID, bytes32(0), "Collision");

        vm.expectRevert(FileRegistry.UnauthorizedMetadataAuthority.selector);
        vm.prank(address(0x999));
        registry.createFolder(
            bytes32(uint256(77)),
            ORGANIZATION_ID,
            bytes32(0),
            "Unauthorized"
        );
    }

    function test_CreateAndAppendPreservesImmutableHistoryAndInitialEnvelope() public {
        RrdsEip712.VersionAppend memory first = _request(
            1,
            bytes32(0),
            MANIFEST_V1,
            EPOCH_V1,
            CONTENT_CID_V1,
            ENVELOPE_CID_V1,
            bytes32(uint256(30)),
            block.timestamp + 1 days
        );
        registry.createFile(
            first,
            CONTENT_CID_V1,
            ENVELOPE_CID_V1,
            "report.txt",
            bytes32(0),
            _sign(first)
        );

        FileRegistry.File memory file = registry.getFile(FILE_ID);
        assertEq(file.displayName, "report.txt");
        assertEq(file.creatorMemberId, MEMBER_ID);
        assertEq(file.organizationId, ORGANIZATION_ID);
        assertEq(file.currentVersionNumber, 1);
        assertEq(file.currentHeadManifestHash, MANIFEST_V1);
        assertTrue(governance.hasReadAccess(MEMBER_ID, FILE_ID));
        assertTrue(governance.hasWriteAccess(MEMBER_ID, FILE_ID));
        assertFalse(governance.hasReadAccess(bytes32(uint256(99)), FILE_ID));

        FileRegistry.VersionRecord memory storedFirst = registry.getVersion(FILE_ID, 1);
        assertEq(storedFirst.contentCid, CONTENT_CID_V1);
        assertEq(storedFirst.initialEnvelopeSetCid, ENVELOPE_CID_V1);
        assertEq(storedFirst.authorSigningAddress, vm.addr(MEMBER_PRIVATE_KEY));
        (string memory initialEnvelopeCid,, uint32 initialRevision) =
            governance.currentEnvelopeSet(FILE_ID, 1);
        assertEq(initialEnvelopeCid, ENVELOPE_CID_V1);
        assertEq(initialRevision, 1);

        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePermission(
            FILE_ID,
            MEMBER_ID,
            AccessGovernance.Permission.Write,
            true,
            bytes32(0)
        );
        RrdsEip712.VersionAppend memory second = _request(
            2,
            MANIFEST_V1,
            MANIFEST_V2,
            EPOCH_V2,
            CONTENT_CID_V2,
            ENVELOPE_CID_V2,
            bytes32(uint256(31)),
            block.timestamp + 1 days
        );
        registry.appendVersion(
            second,
            CONTENT_CID_V2,
            ENVELOPE_CID_V2,
            _sign(second)
        );

        assertEq(registry.getFile(FILE_ID).currentVersionNumber, 2);
        assertEq(registry.getFile(FILE_ID).currentHeadManifestHash, MANIFEST_V2);
        assertEq(registry.getVersion(FILE_ID, 1).manifestHash, MANIFEST_V1);
        assertEq(registry.getVersion(FILE_ID, 1).parentManifestHash, bytes32(0));
        assertEq(registry.getVersion(FILE_ID, 2).parentManifestHash, MANIFEST_V1);
        assertTrue(registry.consumedOperationNonces(MEMBER_ID, bytes32(uint256(30))));
        assertTrue(registry.consumedOperationNonces(MEMBER_ID, bytes32(uint256(31))));
    }

    function test_RejectsWrongSignatureExpiredAndReplayedAppend() public {
        RrdsEip712.VersionAppend memory first = _request(
            1,
            bytes32(0),
            MANIFEST_V1,
            EPOCH_V1,
            CONTENT_CID_V1,
            ENVELOPE_CID_V1,
            bytes32(uint256(40)),
            block.timestamp + 1 days
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MEMBER_PRIVATE_KEY + 1, _digest(first));
        vm.expectRevert(FileRegistry.InvalidOperationSignature.selector);
        registry.createFile(
            first,
            CONTENT_CID_V1,
            ENVELOPE_CID_V1,
            "report.txt",
            bytes32(0),
            abi.encodePacked(r, s, v)
        );

        bytes memory validSignature = _sign(first);
        registry.createFile(
            first,
            CONTENT_CID_V1,
            ENVELOPE_CID_V1,
            "report.txt",
            bytes32(0),
            validSignature
        );

        vm.expectRevert(FileRegistry.OperationNonceAlreadyConsumed.selector);
        registry.appendVersion(first, CONTENT_CID_V1, ENVELOPE_CID_V1, validSignature);

        RrdsEip712.VersionAppend memory expired = _request(
            2,
            MANIFEST_V1,
            MANIFEST_V2,
            EPOCH_V2,
            CONTENT_CID_V2,
            ENVELOPE_CID_V2,
            bytes32(uint256(41)),
            block.timestamp
        );
        vm.warp(block.timestamp + 1);
        vm.expectRevert(FileRegistry.ExpiredOperation.selector);
        registry.appendVersion(expired, CONTENT_CID_V2, ENVELOPE_CID_V2, _sign(expired));
    }

    function test_RejectsStaleHeadWrongVersionAndUnapprovedWriter() public {
        RrdsEip712.VersionAppend memory first = _request(
            1,
            bytes32(0),
            MANIFEST_V1,
            EPOCH_V1,
            CONTENT_CID_V1,
            ENVELOPE_CID_V1,
            bytes32(uint256(50)),
            block.timestamp + 1 days
        );
        registry.createFile(
            first,
            CONTENT_CID_V1,
            ENVELOPE_CID_V1,
            "report.txt",
            bytes32(0),
            _sign(first)
        );

        RrdsEip712.VersionAppend memory second = _request(
            2,
            bytes32(uint256(999)),
            MANIFEST_V2,
            EPOCH_V2,
            CONTENT_CID_V2,
            ENVELOPE_CID_V2,
            bytes32(uint256(51)),
            block.timestamp + 1 days
        );
        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePermission(
            FILE_ID,
            MEMBER_ID,
            AccessGovernance.Permission.Write,
            false,
            bytes32(0)
        );
        vm.expectRevert(FileRegistry.UnauthorizedMetadataAuthority.selector);
        registry.appendVersion(second, CONTENT_CID_V2, ENVELOPE_CID_V2, _sign(second));

        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePermission(
            FILE_ID,
            MEMBER_ID,
            AccessGovernance.Permission.Write,
            true,
            bytes32(0)
        );
        vm.expectRevert(FileRegistry.StaleHead.selector);
        registry.appendVersion(second, CONTENT_CID_V2, ENVELOPE_CID_V2, _sign(second));

        second.parentManifestHash = MANIFEST_V1;
        second.versionNumber = 3;
        vm.expectRevert(FileRegistry.InvalidVersionNumber.selector);
        registry.appendVersion(second, CONTENT_CID_V2, ENVELOPE_CID_V2, _sign(second));
    }

    function test_RejectsMalformedCidsAndReusedEpochs() public {
        RrdsEip712.VersionAppend memory first = _request(
            1,
            bytes32(0),
            MANIFEST_V1,
            EPOCH_V1,
            "not-a-cid",
            ENVELOPE_CID_V1,
            bytes32(uint256(60)),
            block.timestamp + 1 days
        );
        vm.expectRevert(FileRegistry.InvalidCid.selector);
        registry.createFile(
            first,
            "not-a-cid",
            ENVELOPE_CID_V1,
            "report.txt",
            bytes32(0),
            _sign(first)
        );

        first = _request(
            1,
            bytes32(0),
            MANIFEST_V1,
            EPOCH_V1,
            CONTENT_CID_V1,
            ENVELOPE_CID_V1,
            bytes32(uint256(61)),
            block.timestamp + 1 days
        );
        registry.createFile(
            first,
            CONTENT_CID_V1,
            ENVELOPE_CID_V1,
            "report.txt",
            bytes32(0),
            _sign(first)
        );
        RrdsEip712.VersionAppend memory second = _request(
            2,
            MANIFEST_V1,
            MANIFEST_V2,
            EPOCH_V1,
            CONTENT_CID_V2,
            ENVELOPE_CID_V2,
            bytes32(uint256(62)),
            block.timestamp + 1 days
        );
        vm.expectRevert(FileRegistry.ReusedEpoch.selector);
        registry.appendVersion(second, CONTENT_CID_V2, ENVELOPE_CID_V2, _sign(second));
    }

    function _request(
        uint64 versionNumber,
        bytes32 parentManifestHash,
        bytes32 manifestHash,
        bytes32 epochId,
        string memory contentCid,
        string memory envelopeSetCid,
        bytes32 operationNonce,
        uint256 deadline
    ) private pure returns (RrdsEip712.VersionAppend memory) {
        return RrdsEip712.VersionAppend({
            fileId: FILE_ID,
            versionNumber: versionNumber,
            parentManifestHash: parentManifestHash,
            contentCidHash: keccak256(bytes(contentCid)),
            envelopeSetCidHash: keccak256(bytes(envelopeSetCid)),
            epochId: epochId,
            manifestHash: manifestHash,
            memberId: MEMBER_ID,
            signerAddress: vm.addr(MEMBER_PRIVATE_KEY),
            operationNonce: operationNonce,
            deadline: deadline
        });
    }

    function _registerMember() private {
        bytes32 nonce = bytes32(uint256(900));
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
        vm.prank(ORGANIZATION_SAFE);
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

    function _digest(
        RrdsEip712.VersionAppend memory request
    ) private view returns (bytes32) {
        return RrdsEip712.digest(
            RrdsEip712.fileRegistryDomainSeparator(block.chainid, address(registry)),
            RrdsEip712.hashVersionAppend(request)
        );
    }

    function _sign(
        RrdsEip712.VersionAppend memory request
    ) private view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MEMBER_PRIVATE_KEY, _digest(request));
        return abi.encodePacked(r, s, v);
    }
}
