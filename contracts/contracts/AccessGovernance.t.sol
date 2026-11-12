// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {AccessGovernance} from "./AccessGovernance.sol";
import {RrdsEip712} from "./libraries/RrdsEip712.sol";

contract AccessGovernanceTest is Test {
    event MemberKeyRegistered(
        bytes32 indexed memberId,
        uint32 indexed keyVersion,
        bool encryptionKey,
        bytes32 publicKey
    );
    address private constant TIMELOCK = address(0x100);
    address private constant EMERGENCY_SAFE = address(0x200);
    address private constant ORGANIZATION_SAFE = address(0x300);
    address private constant FILE_REGISTRY = address(0x400);
    address private constant FILE_POLICY_SAFE = address(0x500);
    bytes32 private constant ORGANIZATION_ID = bytes32(uint256(1));
    bytes32 private constant FILE_ID = bytes32(uint256(2));
    bytes32 private constant MEMBER_ID = bytes32(uint256(3));
    bytes32 private constant OTHER_MEMBER_ID = bytes32(uint256(4));
    uint256 private constant MEMBER_PRIVATE_KEY = 0xA11CE;
    uint256 private constant OTHER_MEMBER_PRIVATE_KEY = 0xB0B;
    uint256 private constant ROTATED_MEMBER_PRIVATE_KEY = 0xCAFE;

    AccessGovernance private governance;

    function setUp() public {
        governance = new AccessGovernance(TIMELOCK, EMERGENCY_SAFE);
        vm.prank(TIMELOCK);
        governance.registerOrganization(ORGANIZATION_ID, ORGANIZATION_SAFE);
        bytes32 fileRegistryRole = governance.FILE_REGISTRY_ROLE();
        vm.prank(TIMELOCK);
        governance.grantRole(fileRegistryRole, FILE_REGISTRY);
        _registerMember(MEMBER_ID, MEMBER_PRIVATE_KEY, 1, bytes32(uint256(7)));
        _registerMember(OTHER_MEMBER_ID, OTHER_MEMBER_PRIVATE_KEY, 1, bytes32(uint256(8)));
        vm.prank(FILE_REGISTRY);
        governance.registerFilePolicy(FILE_ID, ORGANIZATION_ID, MEMBER_ID);
    }

    function test_FileCreationGrantsCreatorReadAndWriteAccess() public view {
        assertTrue(governance.hasReadAccess(MEMBER_ID, FILE_ID));
        assertTrue(governance.hasWriteAccess(MEMBER_ID, FILE_ID));
        assertFalse(governance.hasReadAccess(OTHER_MEMBER_ID, FILE_ID));
        assertFalse(governance.hasWriteAccess(OTHER_MEMBER_ID, FILE_ID));
    }

    function test_TimelockIsTheOnlyDefaultAdministrator() public view {
        assertTrue(governance.hasRole(governance.DEFAULT_ADMIN_ROLE(), TIMELOCK));
        assertFalse(governance.hasRole(governance.DEFAULT_ADMIN_ROLE(), address(this)));
        assertFalse(governance.hasRole(governance.DEFAULT_ADMIN_ROLE(), ORGANIZATION_SAFE));
    }

    function test_OnlyOrganizationAuthorityCanManageItsMembers() public {
        vm.prank(address(this));
        vm.expectRevert(
            abi.encodeWithSelector(
                AccessGovernance.UnauthorizedPolicyAuthority.selector,
                address(this),
                keccak256(abi.encode("ORGANIZATION", ORGANIZATION_ID))
            )
        );
        governance.registerMember(
            ORGANIZATION_ID,
            bytes32(uint256(5)),
            address(0x601),
            1,
            1,
            bytes32(uint256(8)),
            bytes32(uint256(50)),
            block.timestamp + 1 days,
            hex"01"
        );

        _registerMember(bytes32(uint256(5)), 0x1234, 1, bytes32(uint256(8)));
    }

    function test_KeySupersessionRetainsVersionedKeyStatus() public {
        address newSigningAddress = vm.addr(ROTATED_MEMBER_PRIVATE_KEY);
        bytes32 newEncryptionPublicKey = bytes32(uint256(99));
        bytes32 nonce = bytes32(uint256(51));
        uint256 deadline = block.timestamp + 1 days;

        bytes memory proofSignature = _keyProofSignature(
            MEMBER_ID,
            ORGANIZATION_ID,
            newSigningAddress,
            2,
            2,
            newEncryptionPublicKey,
            nonce,
            deadline,
            ROTATED_MEMBER_PRIVATE_KEY
        );
        vm.prank(ORGANIZATION_SAFE);
        governance.supersedeMemberKeys(
            MEMBER_ID,
            newSigningAddress,
            2,
            2,
            newEncryptionPublicKey,
            nonce,
            deadline,
            proofSignature
        );

        (address oldSigner, AccessGovernance.KeyStatus oldSigningKeyStatus) =
            governance.memberSigningKeys(MEMBER_ID, 1);
        (address currentSigner, AccessGovernance.KeyStatus currentSigningKeyStatus) =
            governance.memberSigningKeys(MEMBER_ID, 2);
        (bytes32 oldEncryptionKey, AccessGovernance.KeyStatus oldEncryptionKeyStatus) =
            governance.memberEncryptionKeys(MEMBER_ID, 1);
        (bytes32 currentEncryptionKey, AccessGovernance.KeyStatus currentEncryptionKeyStatus) =
            governance.memberEncryptionKeys(MEMBER_ID, 2);

        assertEq(oldSigner, vm.addr(MEMBER_PRIVATE_KEY));
        assertEq(
            uint256(oldSigningKeyStatus),
            uint256(AccessGovernance.KeyStatus.Superseded)
        );
        assertEq(currentSigner, newSigningAddress);
        assertEq(uint256(currentSigningKeyStatus), uint256(AccessGovernance.KeyStatus.Active));
        assertEq(oldEncryptionKey, bytes32(uint256(7)));
        assertEq(
            uint256(oldEncryptionKeyStatus),
            uint256(AccessGovernance.KeyStatus.Superseded)
        );
        assertEq(currentEncryptionKey, newEncryptionPublicKey);
        assertEq(
            uint256(currentEncryptionKeyStatus),
            uint256(AccessGovernance.KeyStatus.Active)
        );
        assertEq(governance.signingAddressMembers(newSigningAddress), MEMBER_ID);
        assertEq(governance.signingAddressMembers(oldSigner), bytes32(0));
    }

    function test_RegistrationEmitsBothVersionedPublicKeysForIndexer() public {
        bytes32 memberId = bytes32(uint256(99));
        address signingAddress = vm.addr(0x5151);
        bytes32 encryptionPublicKey = bytes32(uint256(0x6161));
        bytes32 nonce = bytes32(uint256(0x7171));
        uint256 deadline = block.timestamp + 1 days;
        bytes memory proof = _keyProofSignature(
            memberId,
            ORGANIZATION_ID,
            signingAddress,
            3,
            4,
            encryptionPublicKey,
            nonce,
            deadline,
            0x5151
        );

        vm.expectEmit(true, true, false, true, address(governance));
        emit MemberKeyRegistered(
            memberId,
            3,
            false,
            bytes32(uint256(uint160(signingAddress)))
        );
        vm.expectEmit(true, true, false, true, address(governance));
        emit MemberKeyRegistered(memberId, 4, true, encryptionPublicKey);
        vm.prank(ORGANIZATION_SAFE);
        governance.registerMember(
            ORGANIZATION_ID,
            memberId,
            signingAddress,
            3,
            4,
            encryptionPublicKey,
            nonce,
            deadline,
            proof
        );
    }

    function test_SigningAddressCannotIdentifyMultipleMembers() public {
        vm.expectRevert(AccessGovernance.SigningAddressAlreadyRegistered.selector);
        vm.prank(ORGANIZATION_SAFE);
        governance.registerMember(
            ORGANIZATION_ID,
            bytes32(uint256(5)),
            vm.addr(MEMBER_PRIVATE_KEY),
            1,
            1,
            bytes32(uint256(9)),
            bytes32(uint256(52)),
            block.timestamp + 1 days,
            hex"01"
        );
    }

    function test_KeyProofRejectsWrongSignerExpiredAndReplayedRequests() public {
        address proposedSigner = vm.addr(ROTATED_MEMBER_PRIVATE_KEY);
        bytes32 encryptionKey = bytes32(uint256(98));
        bytes32 nonce = bytes32(uint256(60));
        uint256 deadline = block.timestamp + 1 days;
        bytes memory wrongProof = _keyProofSignature(
            MEMBER_ID,
            ORGANIZATION_ID,
            proposedSigner,
            2,
            2,
            encryptionKey,
            nonce,
            deadline,
            MEMBER_PRIVATE_KEY
        );

        vm.expectRevert(AccessGovernance.InvalidOperationSignature.selector);
        vm.prank(ORGANIZATION_SAFE);
        governance.supersedeMemberKeys(
            MEMBER_ID,
            proposedSigner,
            2,
            2,
            encryptionKey,
            nonce,
            deadline,
            wrongProof
        );

        bytes memory validProof = _keyProofSignature(
            MEMBER_ID,
            ORGANIZATION_ID,
            proposedSigner,
            2,
            2,
            encryptionKey,
            nonce,
            deadline,
            ROTATED_MEMBER_PRIVATE_KEY
        );
        vm.prank(ORGANIZATION_SAFE);
        governance.supersedeMemberKeys(
            MEMBER_ID,
            proposedSigner,
            2,
            2,
            encryptionKey,
            nonce,
            deadline,
            validProof
        );

        address nextSigner = vm.addr(0xD00D);
        bytes memory replayProof = _keyProofSignature(
            MEMBER_ID,
            ORGANIZATION_ID,
            nextSigner,
            3,
            3,
            bytes32(uint256(97)),
            nonce,
            deadline,
            0xD00D
        );
        vm.expectRevert(AccessGovernance.OperationNonceAlreadyConsumed.selector);
        vm.prank(ORGANIZATION_SAFE);
        governance.supersedeMemberKeys(
            MEMBER_ID,
            nextSigner,
            3,
            3,
            bytes32(uint256(97)),
            nonce,
            deadline,
            replayProof
        );

        bytes32 expiredNonce = bytes32(uint256(61));
        uint256 expiredDeadline = block.timestamp;
        bytes memory expiredProof = _keyProofSignature(
            MEMBER_ID,
            ORGANIZATION_ID,
            nextSigner,
            3,
            3,
            bytes32(uint256(97)),
            expiredNonce,
            expiredDeadline,
            0xD00D
        );
        vm.warp(block.timestamp + 1);
        vm.expectRevert(AccessGovernance.ExpiredOperation.selector);
        vm.prank(ORGANIZATION_SAFE);
        governance.supersedeMemberKeys(
            MEMBER_ID,
            nextSigner,
            3,
            3,
            bytes32(uint256(97)),
            expiredNonce,
            expiredDeadline,
            expiredProof
        );
    }

    function test_CannotGrantAclToSuspendedMemberButCanRevoke() public {
        vm.expectEmit(true, true, true, true, address(governance));
        emit AccessGovernance.ReadAccessGranted(
            FILE_ID,
            OTHER_MEMBER_ID,
            ORGANIZATION_SAFE,
            bytes32(uint256(500))
        );
        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePermission(
            FILE_ID,
            OTHER_MEMBER_ID,
            AccessGovernance.Permission.Read,
            true,
            bytes32(uint256(500))
        );
        vm.prank(EMERGENCY_SAFE);
        governance.emergencySuspendMember(OTHER_MEMBER_ID);

        vm.expectRevert(AccessGovernance.MemberNotActive.selector);
        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePermission(
            FILE_ID,
            OTHER_MEMBER_ID,
            AccessGovernance.Permission.Write,
            true,
            bytes32(0)
        );

        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePermission(
            FILE_ID,
            OTHER_MEMBER_ID,
            AccessGovernance.Permission.Read,
            false,
            bytes32(0)
        );
        assertFalse(governance.hasReadAccess(OTHER_MEMBER_ID, FILE_ID));
    }

    function test_ReadAndWriteAclAreDistinctAndFileScoped() public {
        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePermission(
            FILE_ID,
            OTHER_MEMBER_ID,
            AccessGovernance.Permission.Read,
            true,
            bytes32(0)
        );
        assertTrue(governance.hasReadAccess(OTHER_MEMBER_ID, FILE_ID));
        assertFalse(governance.hasWriteAccess(OTHER_MEMBER_ID, FILE_ID));

        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePermission(
            FILE_ID,
            OTHER_MEMBER_ID,
            AccessGovernance.Permission.Write,
            true,
            bytes32(0)
        );
        assertTrue(governance.hasWriteAccess(OTHER_MEMBER_ID, FILE_ID));

        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePermission(
            FILE_ID,
            OTHER_MEMBER_ID,
            AccessGovernance.Permission.Read,
            false,
            bytes32(0)
        );
        assertFalse(governance.hasReadAccess(OTHER_MEMBER_ID, FILE_ID));
        assertTrue(governance.hasWriteAccess(OTHER_MEMBER_ID, FILE_ID));
        assertFalse(governance.hasReadAccess(OTHER_MEMBER_ID, bytes32(uint256(999))));
    }

    function test_HistoricalReadRequiresFileReadAndAnExplicitVersionGrant() public {
        string memory cid = "bafkreiaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq";
        vm.prank(FILE_REGISTRY);
        governance.initializeEnvelopeSet(FILE_ID, 1, bytes32(uint256(6)), cid);

        vm.expectRevert(AccessGovernance.InvalidPermission.selector);
        vm.prank(ORGANIZATION_SAFE);
        governance.setHistoricalReadAccess(
            FILE_ID, 1, OTHER_MEMBER_ID, true, bytes32(uint256(77))
        );

        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePermission(
            FILE_ID,
            OTHER_MEMBER_ID,
            AccessGovernance.Permission.Read,
            true,
            bytes32(0)
        );

        vm.expectEmit(true, true, true, true, address(governance));
        emit AccessGovernance.HistoricalReadAccessGranted(
            FILE_ID, 1, OTHER_MEMBER_ID, ORGANIZATION_SAFE, bytes32(uint256(77))
        );
        vm.prank(ORGANIZATION_SAFE);
        governance.setHistoricalReadAccess(
            FILE_ID, 1, OTHER_MEMBER_ID, true, bytes32(uint256(77))
        );
        assertTrue(governance.hasReadAccess(OTHER_MEMBER_ID, FILE_ID));
        assertTrue(governance.hasHistoricalReadAccess(OTHER_MEMBER_ID, FILE_ID, 1));
        assertFalse(governance.hasHistoricalReadAccess(OTHER_MEMBER_ID, FILE_ID, 2));

        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePermission(
            FILE_ID,
            OTHER_MEMBER_ID,
            AccessGovernance.Permission.Read,
            false,
            bytes32(0)
        );
        assertFalse(governance.hasHistoricalReadAccess(OTHER_MEMBER_ID, FILE_ID, 1));

        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePermission(
            FILE_ID,
            OTHER_MEMBER_ID,
            AccessGovernance.Permission.Read,
            true,
            bytes32(0)
        );
        assertFalse(governance.hasHistoricalReadAccess(OTHER_MEMBER_ID, FILE_ID, 1));

        vm.prank(ORGANIZATION_SAFE);
        governance.setHistoricalReadAccess(FILE_ID, 1, OTHER_MEMBER_ID, true, bytes32(0));
        assertTrue(governance.hasHistoricalReadAccess(OTHER_MEMBER_ID, FILE_ID, 1));
    }

    function test_HistoricalReadGrantRequiresExistingVersionAndReadPolicySafe() public {
        vm.expectRevert(AccessGovernance.InvalidEnvelopeReference.selector);
        vm.prank(ORGANIZATION_SAFE);
        governance.setHistoricalReadAccess(FILE_ID, 1, OTHER_MEMBER_ID, false, bytes32(0));

        string memory cid = "bafkreiaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq";
        vm.prank(FILE_REGISTRY);
        governance.initializeEnvelopeSet(FILE_ID, 1, bytes32(uint256(6)), cid);
        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePermission(
            FILE_ID,
            OTHER_MEMBER_ID,
            AccessGovernance.Permission.Read,
            true,
            bytes32(0)
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                AccessGovernance.UnauthorizedPolicyAuthority.selector,
                address(this),
                governance.READ_ACL_POLICY()
            )
        );
        governance.setHistoricalReadAccess(FILE_ID, 1, OTHER_MEMBER_ID, true, bytes32(0));
    }

    function test_FilePolicyCanUseADifferentSafeForWriteAcl() public {
        bytes32 writePolicy = governance.WRITE_ACL_POLICY();
        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePolicyAuthority(FILE_ID, writePolicy, FILE_POLICY_SAFE);

        vm.prank(ORGANIZATION_SAFE);
        vm.expectRevert(
            abi.encodeWithSelector(
                AccessGovernance.UnauthorizedPolicyAuthority.selector,
                ORGANIZATION_SAFE,
                writePolicy
            )
        );
        governance.setFilePermission(
            FILE_ID,
            OTHER_MEMBER_ID,
            AccessGovernance.Permission.Write,
            true,
            bytes32(0)
        );

        vm.prank(FILE_POLICY_SAFE);
        governance.setFilePermission(
            FILE_ID,
            OTHER_MEMBER_ID,
            AccessGovernance.Permission.Write,
            true,
            bytes32(0)
        );
        assertTrue(governance.hasWriteAccess(OTHER_MEMBER_ID, FILE_ID));
    }

    function test_EmergencySafeCanOnlySuspendAndTimelockMustReinstate() public {
        vm.prank(EMERGENCY_SAFE);
        governance.emergencySuspendMember(MEMBER_ID);
        assertFalse(governance.isActiveMember(MEMBER_ID));
        (, AccessGovernance.KeyStatus suspendedSigningKey) =
            governance.memberSigningKeys(MEMBER_ID, 1);
        assertEq(
            uint256(suspendedSigningKey),
            uint256(AccessGovernance.KeyStatus.Suspended)
        );

        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePermission(
            FILE_ID,
            MEMBER_ID,
            AccessGovernance.Permission.Read,
            true,
            bytes32(0)
        );
        assertFalse(governance.hasReadAccess(MEMBER_ID, FILE_ID));

        vm.expectRevert();
        vm.prank(EMERGENCY_SAFE);
        governance.reinstateMember(MEMBER_ID);

        vm.prank(TIMELOCK);
        governance.reinstateMember(MEMBER_ID);
        assertTrue(governance.isActiveMember(MEMBER_ID));
        (, AccessGovernance.KeyStatus activeSigningKey) =
            governance.memberSigningKeys(MEMBER_ID, 1);
        assertEq(uint256(activeSigningKey), uint256(AccessGovernance.KeyStatus.Active));
    }

    function test_RevokedMemberCannotBeReactivatedByOrganizationSafe() public {
        vm.prank(ORGANIZATION_SAFE);
        governance.setMemberStatus(MEMBER_ID, AccessGovernance.MemberStatus.Revoked);

        vm.expectRevert(AccessGovernance.InvalidStatusTransition.selector);
        vm.prank(ORGANIZATION_SAFE);
        governance.setMemberStatus(MEMBER_ID, AccessGovernance.MemberStatus.Active);
    }

    function test_FileRegistryAloneRegistersFileAndInitialEnvelopePointer() public {
        vm.expectRevert();
        governance.registerFilePolicy(bytes32(uint256(5)), ORGANIZATION_ID, MEMBER_ID);

        vm.prank(FILE_REGISTRY);
        string memory validCid =
            "bafkreiaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq";
        governance.initializeEnvelopeSet(FILE_ID, 1, bytes32(uint256(6)), validCid);
        (string memory cid, bytes32 epochId, uint32 revision) =
            governance.currentEnvelopeSet(FILE_ID, 1);
        assertEq(cid, "bafkreiaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq");
        assertEq(epochId, bytes32(uint256(6)));
        assertEq(revision, 1);

        vm.expectRevert(AccessGovernance.EnvelopePointerAlreadyInitialized.selector);
        vm.prank(FILE_REGISTRY);
        governance.initializeEnvelopeSet(FILE_ID, 1, bytes32(uint256(6)), validCid);
    }

    function test_EnvelopeUpdateRequiresMemberSignatureAndPolicySafeAndConsumesNonce() public {
        string memory oldCid = "bafkreiaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq";
        string memory newCid = "bafkreiafaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifau";
        bytes32 epochId = bytes32(uint256(6));
        bytes32 operationNonce = bytes32(uint256(99));
        vm.prank(FILE_REGISTRY);
        governance.initializeEnvelopeSet(FILE_ID, 1, epochId, oldCid);

        RrdsEip712.EnvelopeSetUpdate memory request = RrdsEip712.EnvelopeSetUpdate({
            fileId: FILE_ID,
            versionNumber: 1,
            epochId: epochId,
            oldEnvelopeSetCid: oldCid,
            newEnvelopeSetCid: newCid,
            actorMemberId: MEMBER_ID,
            proposalId: bytes32(0),
            operationNonce: operationNonce,
            deadline: block.timestamp + 1 days
        });
        bytes32 digest = RrdsEip712.digest(
            RrdsEip712.accessGovernanceDomainSeparator(block.chainid, address(governance)),
            RrdsEip712.hashEnvelopeSetUpdate(request)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MEMBER_PRIVATE_KEY, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePermission(
            FILE_ID,
            MEMBER_ID,
            AccessGovernance.Permission.Read,
            false,
            bytes32(0)
        );
        vm.expectRevert(AccessGovernance.UnauthorizedEnvelopeActor.selector);
        vm.prank(ORGANIZATION_SAFE);
        governance.updateEnvelopeSet(request, signature);

        vm.prank(ORGANIZATION_SAFE);
        governance.setFilePermission(
            FILE_ID,
            MEMBER_ID,
            AccessGovernance.Permission.Read,
            true,
            bytes32(0)
        );
        vm.prank(ORGANIZATION_SAFE);
        governance.updateEnvelopeSet(request, signature);
        (string memory currentCid,, uint32 revision) = governance.currentEnvelopeSet(FILE_ID, 1);
        assertEq(currentCid, newCid);
        assertEq(revision, 2);
        assertTrue(governance.consumedOperationNonces(MEMBER_ID, operationNonce));

        vm.expectRevert(AccessGovernance.OperationNonceAlreadyConsumed.selector);
        vm.prank(ORGANIZATION_SAFE);
        governance.updateEnvelopeSet(request, signature);
    }

    function test_EnvelopeUpdateRejectsWrongSignatureStaleCidAndExpiredRequest() public {
        string memory oldCid = "bafkreiaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq";
        string memory newCid = "bafkreiafaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifau";
        bytes32 epochId = bytes32(uint256(6));
        vm.prank(FILE_REGISTRY);
        governance.initializeEnvelopeSet(FILE_ID, 1, epochId, oldCid);

        RrdsEip712.EnvelopeSetUpdate memory request = RrdsEip712.EnvelopeSetUpdate({
            fileId: FILE_ID,
            versionNumber: 1,
            epochId: epochId,
            oldEnvelopeSetCid: oldCid,
            newEnvelopeSetCid: newCid,
            actorMemberId: MEMBER_ID,
            proposalId: bytes32(0),
            operationNonce: bytes32(uint256(100)),
            deadline: block.timestamp + 1 days
        });
        bytes32 digest = RrdsEip712.digest(
            RrdsEip712.accessGovernanceDomainSeparator(block.chainid, address(governance)),
            RrdsEip712.hashEnvelopeSetUpdate(request)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MEMBER_PRIVATE_KEY + 1, digest);
        bytes memory invalidSignature = abi.encodePacked(r, s, v);

        vm.prank(ORGANIZATION_SAFE);
        vm.expectRevert(AccessGovernance.InvalidOperationSignature.selector);
        governance.updateEnvelopeSet(request, invalidSignature);

        request.oldEnvelopeSetCid = "bafkreiacaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcai";
        bytes32 staleDigest = RrdsEip712.digest(
            RrdsEip712.accessGovernanceDomainSeparator(block.chainid, address(governance)),
            RrdsEip712.hashEnvelopeSetUpdate(request)
        );
        (v, r, s) = vm.sign(MEMBER_PRIVATE_KEY, staleDigest);
        vm.prank(ORGANIZATION_SAFE);
        vm.expectRevert(AccessGovernance.StaleEnvelopePointer.selector);
        governance.updateEnvelopeSet(request, abi.encodePacked(r, s, v));

        request.oldEnvelopeSetCid = oldCid;
        request.operationNonce = bytes32(uint256(101));
        request.deadline = block.timestamp;
        bytes32 expiredDigest = RrdsEip712.digest(
            RrdsEip712.accessGovernanceDomainSeparator(block.chainid, address(governance)),
            RrdsEip712.hashEnvelopeSetUpdate(request)
        );
        (v, r, s) = vm.sign(MEMBER_PRIVATE_KEY, expiredDigest);
        vm.warp(block.timestamp + 1);
        vm.prank(ORGANIZATION_SAFE);
        vm.expectRevert(AccessGovernance.ExpiredOperation.selector);
        governance.updateEnvelopeSet(request, abi.encodePacked(r, s, v));
    }

    function _registerMember(
        bytes32 memberId,
        uint256 privateKey,
        uint32 encryptionKeyVersion,
        bytes32 encryptionPublicKey
    ) private {
        address signer = vm.addr(privateKey);
        bytes32 nonce = keccak256(abi.encode(memberId, privateKey, "member-registration"));
        uint256 deadline = block.timestamp + 1 days;
        bytes memory proof = _keyProofSignature(
            memberId,
            ORGANIZATION_ID,
            signer,
            1,
            encryptionKeyVersion,
            encryptionPublicKey,
            nonce,
            deadline,
            privateKey
        );
        vm.prank(ORGANIZATION_SAFE);
        governance.registerMember(
            ORGANIZATION_ID,
            memberId,
            signer,
            1,
            encryptionKeyVersion,
            encryptionPublicKey,
            nonce,
            deadline,
            proof
        );
    }

    function _keyProofSignature(
        bytes32 memberId,
        bytes32 organizationId,
        address signer,
        uint32 signingKeyVersion,
        uint32 encryptionKeyVersion,
        bytes32 encryptionPublicKey,
        bytes32 nonce,
        uint256 deadline,
        uint256 privateKey
    ) private view returns (bytes memory) {
        RrdsEip712.MemberKeyProof memory proof = RrdsEip712.MemberKeyProof({
            memberId: memberId,
            organizationId: organizationId,
            signingAddress: signer,
            signingKeyVersion: signingKeyVersion,
            encryptionKeyVersion: encryptionKeyVersion,
            encryptionPublicKey: encryptionPublicKey,
            operationNonce: nonce,
            deadline: deadline
        });
        bytes32 digest = RrdsEip712.digest(
            RrdsEip712.accessGovernanceDomainSeparator(block.chainid, address(governance)),
            RrdsEip712.hashMemberKeyProof(proof)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
