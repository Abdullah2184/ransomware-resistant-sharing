// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.34;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {RrdsCid} from "./libraries/RrdsCid.sol";
import {RrdsEip712} from "./libraries/RrdsEip712.sol";

contract AccessGovernance is AccessControl {
    using ECDSA for bytes32;

    bytes32 public constant FILE_REGISTRY_ROLE = keccak256("FILE_REGISTRY_ROLE");
    bytes32 public constant EMERGENCY_SUSPENDER_ROLE =
        keccak256("EMERGENCY_SUSPENDER_ROLE");
    bytes32 public constant READ_ACL_POLICY = keccak256("READ_ACL_POLICY");
    bytes32 public constant WRITE_ACL_POLICY = keccak256("WRITE_ACL_POLICY");
    bytes32 public constant ENVELOPE_UPDATE_POLICY = keccak256("ENVELOPE_UPDATE_POLICY");
    bytes32 public constant FILE_METADATA_POLICY = keccak256("FILE_METADATA_POLICY");

    enum MemberStatus {
        Unregistered,
        Active,
        Suspended,
        Revoked
    }

    enum Permission {
        Read,
        Write
    }

    enum KeyStatus {
        Unregistered,
        Active,
        Suspended,
        Revoked,
        Superseded
    }

    struct Member {
        bytes32 organizationId;
        address signingAddress;
        uint32 signingKeyVersion;
        uint32 encryptionKeyVersion;
        bytes32 encryptionPublicKey;
        MemberStatus status;
    }

    struct SigningKey {
        address signingAddress;
        KeyStatus status;
    }

    struct EncryptionKey {
        bytes32 publicKey;
        KeyStatus status;
    }

    struct EnvelopePointer {
        string cid;
        bytes32 epochId;
        uint32 revision;
        bool initialized;
    }

    error ZeroAddress();
    error ZeroIdentifier();
    error AlreadyRegistered();
    error UnknownOrganization();
    error UnknownMember();
    error UnknownFile();
    error InvalidMemberKey();
    error InvalidKeyVersion();
    error InvalidFileCreator();
    error InvalidStatusTransition();
    error MemberNotActive();
    error SigningAddressAlreadyRegistered();
    error InvalidPermission();
    error InvalidEnvelopeReference();
    error EnvelopePointerAlreadyInitialized();
    error StaleEnvelopePointer();
    error UnauthorizedEnvelopeActor();
    error UnauthorizedPolicyAuthority(address caller, bytes32 policy);
    error ExpiredOperation();
    error OperationNonceAlreadyConsumed();
    error InvalidOperationNonce();
    error InvalidOperationSignature();

    event OrganizationRegistered(bytes32 indexed organizationId, address indexed authority);
    event OrganizationAuthorityChanged(
        bytes32 indexed organizationId,
        address indexed oldAuthority,
        address indexed newAuthority
    );
    event MemberRegistered(
        bytes32 indexed memberId,
        bytes32 indexed organizationId,
        address signingAddress
    );
    event MemberStatusChanged(
        bytes32 indexed memberId,
        MemberStatus oldStatus,
        MemberStatus newStatus
    );
    event MemberKeyRegistered(
        bytes32 indexed memberId,
        uint32 indexed keyVersion,
        bool encryptionKey,
        bytes32 publicKey
    );
    event MemberKeySuperseded(
        bytes32 indexed memberId,
        uint32 signingKeyVersion,
        uint32 encryptionKeyVersion
    );
    event MemberKeyStatusChanged(
        bytes32 indexed memberId,
        uint32 indexed keyVersion,
        bool encryptionKey,
        KeyStatus oldStatus,
        KeyStatus newStatus
    );
    event FilePolicyAuthorityChanged(
        bytes32 indexed fileId,
        bytes32 indexed policy,
        address authority
    );
    event FilePolicyRegistered(bytes32 indexed fileId, bytes32 indexed organizationId);
    event ReadAccessGranted(
        bytes32 indexed fileId,
        bytes32 indexed memberId,
        address indexed actor,
        bytes32 proposalId
    );
    event ReadAccessRevoked(
        bytes32 indexed fileId,
        bytes32 indexed memberId,
        address indexed actor,
        bytes32 proposalId
    );
    event WriteAccessGranted(
        bytes32 indexed fileId,
        bytes32 indexed memberId,
        address indexed actor,
        bytes32 proposalId
    );
    event WriteAccessRevoked(
        bytes32 indexed fileId,
        bytes32 indexed memberId,
        address indexed actor,
        bytes32 proposalId
    );
    event HistoricalReadAccessGranted(
        bytes32 indexed fileId,
        uint64 indexed versionNumber,
        bytes32 indexed memberId,
        address actor,
        bytes32 proposalId
    );
    event HistoricalReadAccessRevoked(
        bytes32 indexed fileId,
        uint64 indexed versionNumber,
        bytes32 indexed memberId,
        address actor,
        bytes32 proposalId
    );
    event EnvelopeSetInitialized(
        bytes32 indexed fileId,
        uint64 indexed versionNumber,
        bytes32 indexed epochId,
        string cid
    );
    event EnvelopeSetUpdated(
        bytes32 indexed fileId,
        uint64 indexed versionNumber,
        bytes32 indexed epochId,
        bytes32 actorMemberId,
        bytes32 proposalId,
        string oldCid,
        string newCid,
        uint32 revision,
        uint256 timestamp
    );

    address public immutable timelock;
    mapping(bytes32 organizationId => address authority) public organizationAuthorities;
    mapping(bytes32 memberId => Member member) private members;
    mapping(bytes32 memberId => mapping(uint32 keyVersion => SigningKey key)) public memberSigningKeys;
    mapping(bytes32 memberId => mapping(uint32 keyVersion => EncryptionKey key)) public memberEncryptionKeys;
    mapping(address signingAddress => bytes32 memberId) public signingAddressMembers;
    mapping(bytes32 fileId => bytes32 organizationId) public fileOrganizations;
    mapping(bytes32 fileId => mapping(bytes32 policy => address authority)) public filePolicyAuthorities;
    mapping(bytes32 fileId => mapping(bytes32 memberId => uint8 permissions)) private filePermissions;
    mapping(bytes32 fileId => mapping(uint64 versionNumber => mapping(bytes32 memberId => uint64 grantEpoch)))
        private historicalReadPermissions;
    mapping(bytes32 fileId => mapping(bytes32 memberId => uint64 epoch)) private readPermissionEpochs;
    mapping(bytes32 fileId => mapping(uint64 versionNumber => EnvelopePointer pointer)) private envelopePointers;
    mapping(bytes32 memberId => mapping(bytes32 operationNonce => bool consumed)) public consumedOperationNonces;
    mapping(bytes32 memberId => mapping(bytes32 operationNonce => bool consumed)) public consumedKeyProofNonces;

    constructor(address timelockAddress, address emergencySafe) {
        if (timelockAddress == address(0) || emergencySafe == address(0)) revert ZeroAddress();
        timelock = timelockAddress;
        _grantRole(DEFAULT_ADMIN_ROLE, timelockAddress);
        _grantRole(EMERGENCY_SUSPENDER_ROLE, emergencySafe);
    }

    function registerOrganization(
        bytes32 organizationId,
        address authority
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (organizationId == bytes32(0)) revert ZeroIdentifier();
        if (authority == address(0)) revert ZeroAddress();
        if (organizationAuthorities[organizationId] != address(0)) revert AlreadyRegistered();
        organizationAuthorities[organizationId] = authority;
        emit OrganizationRegistered(organizationId, authority);
    }

    function changeOrganizationAuthority(
        bytes32 organizationId,
        address newAuthority
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (organizationAuthorities[organizationId] == address(0)) revert UnknownOrganization();
        if (newAuthority == address(0)) revert ZeroAddress();
        address oldAuthority = organizationAuthorities[organizationId];
        organizationAuthorities[organizationId] = newAuthority;
        emit OrganizationAuthorityChanged(organizationId, oldAuthority, newAuthority);
    }

    function registerMember(
        bytes32 organizationId,
        bytes32 memberId,
        address signingAddress,
        uint32 signingKeyVersion,
        uint32 encryptionKeyVersion,
        bytes32 encryptionPublicKey,
        bytes32 proofNonce,
        uint256 proofDeadline,
        bytes calldata proofSignature
    ) external {
        _requireOrganizationAuthority(organizationId);
        if (memberId == bytes32(0)) revert ZeroIdentifier();
        if (members[memberId].status != MemberStatus.Unregistered) revert AlreadyRegistered();
        if (signingAddress == address(0) || encryptionPublicKey == bytes32(0)) revert InvalidMemberKey();
        if (signingAddressMembers[signingAddress] != bytes32(0)) {
            revert SigningAddressAlreadyRegistered();
        }
        if (signingKeyVersion == 0 || encryptionKeyVersion == 0) revert InvalidKeyVersion();
        _verifyMemberKeyProof(
            memberId,
            organizationId,
            signingAddress,
            signingKeyVersion,
            encryptionKeyVersion,
            encryptionPublicKey,
            proofNonce,
            proofDeadline,
            proofSignature
        );

        members[memberId] = Member({
            organizationId: organizationId,
            signingAddress: signingAddress,
            signingKeyVersion: signingKeyVersion,
            encryptionKeyVersion: encryptionKeyVersion,
            encryptionPublicKey: encryptionPublicKey,
            status: MemberStatus.Active
        });
        memberSigningKeys[memberId][signingKeyVersion] =
            SigningKey(signingAddress, KeyStatus.Active);
        memberEncryptionKeys[memberId][encryptionKeyVersion] =
            EncryptionKey(encryptionPublicKey, KeyStatus.Active);
        signingAddressMembers[signingAddress] = memberId;
        emit MemberRegistered(memberId, organizationId, signingAddress);
        emit MemberKeyRegistered(
            memberId,
            signingKeyVersion,
            false,
            bytes32(uint256(uint160(signingAddress)))
        );
        emit MemberKeyRegistered(memberId, encryptionKeyVersion, true, encryptionPublicKey);
    }

    function memberIdentity(bytes32 memberId) external view returns (Member memory) {
        return members[memberId];
    }

    function memberSigningAddress(bytes32 memberId) external view returns (address) {
        return members[memberId].signingAddress;
    }

    function memberOrganization(bytes32 memberId) external view returns (bytes32) {
        return members[memberId].organizationId;
    }

    function organizationAuthority(bytes32 organizationId) external view returns (address) {
        return organizationAuthorities[organizationId];
    }

    function isActiveMember(bytes32 memberId) external view returns (bool) {
        return members[memberId].status == MemberStatus.Active;
    }

    function setMemberStatus(bytes32 memberId, MemberStatus newStatus) external {
        Member storage member = members[memberId];
        if (member.status == MemberStatus.Unregistered) revert UnknownMember();
        _requireOrganizationAuthority(member.organizationId);
        if (
            newStatus == MemberStatus.Unregistered || newStatus == MemberStatus.Active
                || member.status == MemberStatus.Revoked || member.status == newStatus
        ) {
            revert InvalidStatusTransition();
        }
        _setMemberStatus(memberId, member, newStatus);
    }

    function emergencySuspendMember(bytes32 memberId) external onlyRole(EMERGENCY_SUSPENDER_ROLE) {
        Member storage member = members[memberId];
        if (member.status == MemberStatus.Unregistered) revert UnknownMember();
        if (member.status != MemberStatus.Active) revert InvalidStatusTransition();
        _setMemberStatus(memberId, member, MemberStatus.Suspended);
    }

    function reinstateMember(bytes32 memberId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        Member storage member = members[memberId];
        if (member.status != MemberStatus.Suspended) revert InvalidStatusTransition();
        _setMemberStatus(memberId, member, MemberStatus.Active);
    }

    function supersedeMemberKeys(
        bytes32 memberId,
        address newSigningAddress,
        uint32 newSigningKeyVersion,
        uint32 newEncryptionKeyVersion,
        bytes32 newEncryptionPublicKey,
        bytes32 proofNonce,
        uint256 proofDeadline,
        bytes calldata proofSignature
    ) external {
        Member storage member = members[memberId];
        if (member.status == MemberStatus.Unregistered) revert UnknownMember();
        _requireOrganizationAuthority(member.organizationId);
        if (member.status != MemberStatus.Active) revert InvalidStatusTransition();
        if (
            newSigningAddress == address(0) || newEncryptionPublicKey == bytes32(0)
                || (
                    signingAddressMembers[newSigningAddress] != bytes32(0)
                        && signingAddressMembers[newSigningAddress] != memberId
                )
        ) {
            revert InvalidMemberKey();
        }
        if (
            newSigningKeyVersion <= member.signingKeyVersion
                || newEncryptionKeyVersion <= member.encryptionKeyVersion
        ) revert InvalidKeyVersion();
        _verifyMemberKeyProof(
            memberId,
            member.organizationId,
            newSigningAddress,
            newSigningKeyVersion,
            newEncryptionKeyVersion,
            newEncryptionPublicKey,
            proofNonce,
            proofDeadline,
            proofSignature
        );

        _setSigningKeyStatus(memberId, member.signingKeyVersion, KeyStatus.Superseded);
        _setEncryptionKeyStatus(memberId, member.encryptionKeyVersion, KeyStatus.Superseded);
        delete signingAddressMembers[member.signingAddress];
        member.signingAddress = newSigningAddress;
        member.signingKeyVersion = newSigningKeyVersion;
        member.encryptionKeyVersion = newEncryptionKeyVersion;
        member.encryptionPublicKey = newEncryptionPublicKey;
        memberSigningKeys[memberId][newSigningKeyVersion] =
            SigningKey(newSigningAddress, KeyStatus.Active);
        memberEncryptionKeys[memberId][newEncryptionKeyVersion] =
            EncryptionKey(newEncryptionPublicKey, KeyStatus.Active);
        signingAddressMembers[newSigningAddress] = memberId;
        emit MemberKeySuperseded(memberId, newSigningKeyVersion, newEncryptionKeyVersion);
        emit MemberKeyRegistered(
            memberId,
            newSigningKeyVersion,
            false,
            bytes32(uint256(uint160(newSigningAddress)))
        );
        emit MemberKeyRegistered(
            memberId,
            newEncryptionKeyVersion,
            true,
            newEncryptionPublicKey
        );
    }

    function registerFilePolicy(
        bytes32 fileId,
        bytes32 organizationId,
        bytes32 creatorMemberId
    ) external onlyRole(FILE_REGISTRY_ROLE) {
        if (fileId == bytes32(0)) revert ZeroIdentifier();
        if (organizationAuthorities[organizationId] == address(0)) revert UnknownOrganization();
        if (fileOrganizations[fileId] != bytes32(0)) revert AlreadyRegistered();
        Member storage creator = members[creatorMemberId];
        if (
            creator.status != MemberStatus.Active
                || creator.organizationId != organizationId
        ) revert InvalidFileCreator();

        fileOrganizations[fileId] = organizationId;
        filePermissions[fileId][creatorMemberId] = 3;
        emit FilePolicyRegistered(fileId, organizationId);
        emit ReadAccessGranted(fileId, creatorMemberId, creator.signingAddress, bytes32(0));
        emit WriteAccessGranted(fileId, creatorMemberId, creator.signingAddress, bytes32(0));
    }

    function setFilePolicyAuthority(bytes32 fileId, bytes32 policy, address authority) external {
        bytes32 organizationId = fileOrganizations[fileId];
        if (organizationId == bytes32(0)) revert UnknownFile();
        _requireOrganizationAuthority(organizationId);
        if (policy == bytes32(0)) revert ZeroIdentifier();
        filePolicyAuthorities[fileId][policy] = authority;
        emit FilePolicyAuthorityChanged(fileId, policy, authority);
    }

    function isFilePolicyAuthority(
        bytes32 fileId,
        bytes32 policy,
        address account
    ) external view returns (bool) {
        bytes32 organizationId = fileOrganizations[fileId];
        if (organizationId == bytes32(0)) return false;
        address authority = filePolicyAuthorities[fileId][policy];
        if (authority == address(0)) authority = organizationAuthorities[organizationId];
        return account == authority;
    }

    function setFilePermission(
        bytes32 fileId,
        bytes32 memberId,
        Permission permission,
        bool granted,
        bytes32 proposalId
    ) external {
        bytes32 organizationId = fileOrganizations[fileId];
        if (organizationId == bytes32(0)) revert UnknownFile();
        if (members[memberId].status == MemberStatus.Unregistered) revert UnknownMember();
        bytes32 policy = permission == Permission.Read ? READ_ACL_POLICY : WRITE_ACL_POLICY;
        _requireFilePolicyAuthority(fileId, organizationId, policy);

        uint8 bit = permission == Permission.Read ? 1 : 2;
        bool wasGranted = (filePermissions[fileId][memberId] & bit) != 0;
        if (wasGranted == granted) return;
        if (granted && members[memberId].status != MemberStatus.Active) {
            revert MemberNotActive();
        }
        if (granted) {
            filePermissions[fileId][memberId] |= bit;
        } else {
            filePermissions[fileId][memberId] &= ~bit;
            if (permission == Permission.Read) {
                readPermissionEpochs[fileId][memberId] += 1;
            }
        }

        if (permission == Permission.Read) {
            if (granted) emit ReadAccessGranted(fileId, memberId, msg.sender, proposalId);
            else emit ReadAccessRevoked(fileId, memberId, msg.sender, proposalId);
        } else {
            if (granted) emit WriteAccessGranted(fileId, memberId, msg.sender, proposalId);
            else emit WriteAccessRevoked(fileId, memberId, msg.sender, proposalId);
        }
    }

    function hasReadAccess(bytes32 memberId, bytes32 fileId) external view returns (bool) {
        return _hasReadAccess(memberId, fileId);
    }

    function setHistoricalReadAccess(
        bytes32 fileId,
        uint64 versionNumber,
        bytes32 memberId,
        bool granted,
        bytes32 proposalId
    ) external {
        bytes32 organizationId = fileOrganizations[fileId];
        if (organizationId == bytes32(0)) revert UnknownFile();
        if (versionNumber == 0 || !envelopePointers[fileId][versionNumber].initialized) {
            revert InvalidEnvelopeReference();
        }
        if (members[memberId].status == MemberStatus.Unregistered) revert UnknownMember();
        _requireFilePolicyAuthority(fileId, organizationId, READ_ACL_POLICY);

        uint64 grantEpoch = readPermissionEpochs[fileId][memberId] + 1;
        bool wasGranted = historicalReadPermissions[fileId][versionNumber][memberId] == grantEpoch;
        if (wasGranted == granted) return;
        if (granted) {
            if (members[memberId].status != MemberStatus.Active) revert MemberNotActive();
            if ((filePermissions[fileId][memberId] & 1) == 0) revert InvalidPermission();
            historicalReadPermissions[fileId][versionNumber][memberId] = grantEpoch;
            emit HistoricalReadAccessGranted(
                fileId, versionNumber, memberId, msg.sender, proposalId
            );
        } else {
            delete historicalReadPermissions[fileId][versionNumber][memberId];
            emit HistoricalReadAccessRevoked(
                fileId, versionNumber, memberId, msg.sender, proposalId
            );
        }
    }

    function hasHistoricalReadAccess(
        bytes32 memberId,
        bytes32 fileId,
        uint64 versionNumber
    ) external view returns (bool) {
        return _hasReadAccess(memberId, fileId)
            && historicalReadPermissions[fileId][versionNumber][memberId]
                == readPermissionEpochs[fileId][memberId] + 1;
    }

    function hasWriteAccess(bytes32 memberId, bytes32 fileId) external view returns (bool) {
        return members[memberId].status == MemberStatus.Active
            && fileOrganizations[fileId] != bytes32(0)
            && (filePermissions[fileId][memberId] & 2) != 0;
    }

    function initializeEnvelopeSet(
        bytes32 fileId,
        uint64 versionNumber,
        bytes32 epochId,
        string calldata cid
    ) external onlyRole(FILE_REGISTRY_ROLE) {
        if (fileOrganizations[fileId] == bytes32(0)) revert UnknownFile();
        if (
            versionNumber == 0 || epochId == bytes32(0)
                || !RrdsCid.isCanonicalV1(cid)
        ) {
            revert InvalidEnvelopeReference();
        }
        EnvelopePointer storage pointer = envelopePointers[fileId][versionNumber];
        if (pointer.initialized) revert EnvelopePointerAlreadyInitialized();
        pointer.cid = cid;
        pointer.epochId = epochId;
        pointer.revision = 1;
        pointer.initialized = true;
        emit EnvelopeSetInitialized(fileId, versionNumber, epochId, cid);
    }

    function currentEnvelopeSet(
        bytes32 fileId,
        uint64 versionNumber
    ) external view returns (string memory cid, bytes32 epochId, uint32 revision) {
        EnvelopePointer storage pointer = envelopePointers[fileId][versionNumber];
        if (!pointer.initialized) revert InvalidEnvelopeReference();
        return (pointer.cid, pointer.epochId, pointer.revision);
    }

    function updateEnvelopeSet(
        RrdsEip712.EnvelopeSetUpdate calldata request,
        bytes calldata signature
    ) external {
        if (request.deadline < block.timestamp) revert ExpiredOperation();
        if (request.operationNonce == bytes32(0)) revert InvalidOperationNonce();
        if (consumedOperationNonces[request.actorMemberId][request.operationNonce]) {
            revert OperationNonceAlreadyConsumed();
        }

        Member storage actor = members[request.actorMemberId];
        if (
            actor.status != MemberStatus.Active
                || actor.signingAddress == address(0)
                || !RrdsCid.isCanonicalV1(request.newEnvelopeSetCid)
                || keccak256(bytes(request.oldEnvelopeSetCid))
                    == keccak256(bytes(request.newEnvelopeSetCid))
        ) revert InvalidEnvelopeReference();
        if (!_hasReadAccess(request.actorMemberId, request.fileId)) {
            revert UnauthorizedEnvelopeActor();
        }

        bytes32 digest = RrdsEip712.digest(
            RrdsEip712.accessGovernanceDomainSeparator(block.chainid, address(this)),
            RrdsEip712.hashEnvelopeSetUpdate(request)
        );
        if (digest.recover(signature) != actor.signingAddress) {
            revert InvalidOperationSignature();
        }

        bytes32 organizationId = fileOrganizations[request.fileId];
        if (organizationId == bytes32(0)) revert UnknownFile();
        _requireFilePolicyAuthority(
            request.fileId,
            organizationId,
            ENVELOPE_UPDATE_POLICY
        );

        EnvelopePointer storage pointer = envelopePointers[request.fileId][request.versionNumber];
        if (
            !pointer.initialized || pointer.epochId != request.epochId
                || keccak256(bytes(pointer.cid)) != keccak256(bytes(request.oldEnvelopeSetCid))
        ) revert StaleEnvelopePointer();
        if (pointer.revision == type(uint32).max) revert InvalidEnvelopeReference();

        consumedOperationNonces[request.actorMemberId][request.operationNonce] = true;
        string memory oldCid = pointer.cid;
        pointer.cid = request.newEnvelopeSetCid;
        pointer.revision += 1;
        emit EnvelopeSetUpdated(
            request.fileId,
            request.versionNumber,
            request.epochId,
            request.actorMemberId,
            request.proposalId,
            oldCid,
            request.newEnvelopeSetCid,
            pointer.revision,
            block.timestamp
        );
    }

    function _setMemberStatus(bytes32 memberId, Member storage member, MemberStatus newStatus) private {
        MemberStatus oldStatus = member.status;
        member.status = newStatus;
        KeyStatus keyStatus = newStatus == MemberStatus.Suspended
            ? KeyStatus.Suspended
            : newStatus == MemberStatus.Revoked
                ? KeyStatus.Revoked
                : KeyStatus.Active;
        _setSigningKeyStatus(memberId, member.signingKeyVersion, keyStatus);
        _setEncryptionKeyStatus(memberId, member.encryptionKeyVersion, keyStatus);
        emit MemberStatusChanged(memberId, oldStatus, newStatus);
    }

    function _setSigningKeyStatus(
        bytes32 memberId,
        uint32 keyVersion,
        KeyStatus newStatus
    ) private {
        SigningKey storage key = memberSigningKeys[memberId][keyVersion];
        KeyStatus oldStatus = key.status;
        if (oldStatus == newStatus) return;
        key.status = newStatus;
        emit MemberKeyStatusChanged(memberId, keyVersion, false, oldStatus, newStatus);
    }

    function _setEncryptionKeyStatus(
        bytes32 memberId,
        uint32 keyVersion,
        KeyStatus newStatus
    ) private {
        EncryptionKey storage key = memberEncryptionKeys[memberId][keyVersion];
        KeyStatus oldStatus = key.status;
        if (oldStatus == newStatus) return;
        key.status = newStatus;
        emit MemberKeyStatusChanged(memberId, keyVersion, true, oldStatus, newStatus);
    }

    function _verifyMemberKeyProof(
        bytes32 memberId,
        bytes32 organizationId,
        address signingAddress,
        uint32 signingKeyVersion,
        uint32 encryptionKeyVersion,
        bytes32 encryptionPublicKey,
        bytes32 proofNonce,
        uint256 proofDeadline,
        bytes calldata proofSignature
    ) private {
        if (proofNonce == bytes32(0)) revert InvalidOperationNonce();
        if (consumedKeyProofNonces[memberId][proofNonce]) {
            revert OperationNonceAlreadyConsumed();
        }
        if (proofDeadline < block.timestamp) revert ExpiredOperation();

        RrdsEip712.MemberKeyProof memory proof = RrdsEip712.MemberKeyProof({
            memberId: memberId,
            organizationId: organizationId,
            signingAddress: signingAddress,
            signingKeyVersion: signingKeyVersion,
            encryptionKeyVersion: encryptionKeyVersion,
            encryptionPublicKey: encryptionPublicKey,
            operationNonce: proofNonce,
            deadline: proofDeadline
        });
        bytes32 digest = RrdsEip712.digest(
            RrdsEip712.accessGovernanceDomainSeparator(block.chainid, address(this)),
            RrdsEip712.hashMemberKeyProof(proof)
        );
        if (digest.recover(proofSignature) != signingAddress) {
            revert InvalidOperationSignature();
        }
        consumedKeyProofNonces[memberId][proofNonce] = true;
    }

    function _requireOrganizationAuthority(bytes32 organizationId) private view {
        address authority = organizationAuthorities[organizationId];
        if (authority == address(0)) revert UnknownOrganization();
        if (msg.sender != authority) {
            revert UnauthorizedPolicyAuthority(
                msg.sender,
                keccak256(abi.encode("ORGANIZATION", organizationId))
            );
        }
    }

    function _requireFilePolicyAuthority(
        bytes32 fileId,
        bytes32 organizationId,
        bytes32 policy
    ) private view {
        address authority = filePolicyAuthorities[fileId][policy];
        if (authority == address(0)) authority = organizationAuthorities[organizationId];
        if (msg.sender != authority) revert UnauthorizedPolicyAuthority(msg.sender, policy);
    }

    function _hasReadAccess(bytes32 memberId, bytes32 fileId) private view returns (bool) {
        return members[memberId].status == MemberStatus.Active
            && fileOrganizations[fileId] != bytes32(0)
            && (filePermissions[fileId][memberId] & 1) != 0;
    }
}
