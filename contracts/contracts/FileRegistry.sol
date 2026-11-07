// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.34;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {RrdsCid} from "./libraries/RrdsCid.sol";
import {RrdsEip712} from "./libraries/RrdsEip712.sol";

interface IAccessGovernanceForFiles {
    function memberSigningAddress(bytes32 memberId) external view returns (address);
    function memberOrganization(bytes32 memberId) external view returns (bytes32);
    function isActiveMember(bytes32 memberId) external view returns (bool);
    function hasWriteAccess(bytes32 memberId, bytes32 fileId) external view returns (bool);
    function FILE_METADATA_POLICY() external view returns (bytes32);
    function isFilePolicyAuthority(
        bytes32 fileId,
        bytes32 policy,
        address account
    ) external view returns (bool);
    function organizationAuthority(bytes32 organizationId) external view returns (address);
    function registerFilePolicy(
        bytes32 fileId,
        bytes32 organizationId,
        bytes32 creatorMemberId
    ) external;
    function initializeEnvelopeSet(
        bytes32 fileId,
        uint64 versionNumber,
        bytes32 epochId,
        string calldata cid
    ) external;
}

contract FileRegistry {
    using ECDSA for bytes32;

    enum FileStatus {
        Unregistered,
        Active,
        Archived
    }

    struct File {
        string displayName;
        bytes32 parentFolderId;
        bytes32 creatorMemberId;
        bytes32 organizationId;
        uint64 creationTimestamp;
        FileStatus status;
        uint64 currentVersionNumber;
        bytes32 currentHeadManifestHash;
    }

    struct Folder {
        string displayName;
        bytes32 parentFolderId;
        bytes32 organizationId;
        uint64 creationTimestamp;
    }

    struct VersionRecord {
        bytes32 fileId;
        uint64 versionNumber;
        bytes32 parentManifestHash;
        string contentCid;
        string initialEnvelopeSetCid;
        bytes32 epochId;
        bytes32 manifestHash;
        bytes32 authorMemberId;
        address authorSigningAddress;
    }

    error ZeroIdentifier();
    error InvalidMetadata();
    error FileAlreadyExists();
    error FileNotFound();
    error FileNotWritable();
    error UnauthorizedMetadataAuthority();
    error MemberNotActive();
    error InvalidSigner();
    error InvalidOperationNonce();
    error OperationNonceAlreadyConsumed();
    error ExpiredOperation();
    error InvalidOperationSignature();
    error InvalidCid();
    error InvalidManifestHash();
    error InvalidVersionNumber();
    error StaleHead();
    error ReusedEpoch();
    error FolderAlreadyExists();
    error FolderNotFound();
    error InvalidFolderParent();

    event FileCreated(
        bytes32 indexed fileId,
        bytes32 indexed organizationId,
        bytes32 indexed creatorMemberId,
        string displayName,
        bytes32 parentFolderId
    );
    event FileMetadataChanged(
        bytes32 indexed fileId,
        string displayName,
        bytes32 parentFolderId,
        address indexed actor
    );
    event FileStatusChanged(bytes32 indexed fileId, FileStatus oldStatus, FileStatus newStatus);
    event VersionAppended(
        bytes32 indexed fileId,
        uint64 indexed versionNumber,
        bytes32 indexed manifestHash,
        bytes32 parentManifestHash,
        bytes32 epochId,
        bytes32 authorMemberId,
        address authorSigningAddress,
        string contentCid,
        string initialEnvelopeSetCid
    );
    event CurrentHeadAdvanced(
        bytes32 indexed fileId,
        uint64 versionNumber,
        bytes32 manifestHash
    );
    event FolderCreated(
        bytes32 indexed folderId,
        bytes32 indexed organizationId,
        bytes32 indexed parentFolderId,
        string displayName,
        address actor
    );
    event FolderRenamed(bytes32 indexed folderId, string displayName, address indexed actor);

    IAccessGovernanceForFiles public immutable accessGovernance;
    address public immutable timelock;
    mapping(bytes32 fileId => File file) private files;
    mapping(bytes32 folderId => Folder folder) private folders;
    mapping(bytes32 fileId => mapping(uint64 versionNumber => VersionRecord record)) private history;
    mapping(bytes32 fileId => mapping(bytes32 epochId => bool used)) public usedEpochs;
    mapping(bytes32 memberId => mapping(bytes32 operationNonce => bool consumed)) public consumedOperationNonces;

    constructor(address accessGovernanceAddress, address timelockAddress) {
        if (accessGovernanceAddress == address(0) || timelockAddress == address(0)) {
            revert InvalidMetadata();
        }
        accessGovernance = IAccessGovernanceForFiles(accessGovernanceAddress);
        timelock = timelockAddress;
    }

    function createFile(
        RrdsEip712.VersionAppend calldata request,
        string calldata contentCid,
        string calldata envelopeSetCid,
        string calldata displayName,
        bytes32 parentFolderId,
        bytes calldata signature
    ) external {
        if (request.fileId == bytes32(0)) revert ZeroIdentifier();
        if (files[request.fileId].status != FileStatus.Unregistered) revert FileAlreadyExists();
        if (folders[request.fileId].organizationId != bytes32(0)) revert FileAlreadyExists();
        if (bytes(displayName).length == 0) revert InvalidMetadata();
        if (
            request.versionNumber != 1 || request.parentManifestHash != bytes32(0)
        ) revert InvalidVersionNumber();

        _verifyAppend(request, contentCid, envelopeSetCid, signature);
        bytes32 organizationId = accessGovernance.memberOrganization(request.memberId);
        if (organizationId == bytes32(0)) revert MemberNotActive();
        _requireFolderInOrganization(parentFolderId, organizationId);

        files[request.fileId] = File({
            displayName: displayName,
            parentFolderId: parentFolderId,
            creatorMemberId: request.memberId,
            organizationId: organizationId,
            creationTimestamp: uint64(block.timestamp),
            status: FileStatus.Active,
            currentVersionNumber: 0,
            currentHeadManifestHash: bytes32(0)
        });

        accessGovernance.registerFilePolicy(
            request.fileId,
            organizationId,
            request.memberId
        );
        _append(request, contentCid, envelopeSetCid);
        consumedOperationNonces[request.memberId][request.operationNonce] = true;
        emit FileCreated(
            request.fileId,
            organizationId,
            request.memberId,
            displayName,
            parentFolderId
        );
    }

    function appendVersion(
        RrdsEip712.VersionAppend calldata request,
        string calldata contentCid,
        string calldata envelopeSetCid,
        bytes calldata signature
    ) external {
        File storage file = files[request.fileId];
        if (file.status == FileStatus.Unregistered) revert FileNotFound();
        if (file.status != FileStatus.Active) revert FileNotWritable();
        if (!accessGovernance.hasWriteAccess(request.memberId, request.fileId)) {
            revert UnauthorizedMetadataAuthority();
        }

        _verifyAppend(request, contentCid, envelopeSetCid, signature);
        if (request.versionNumber != file.currentVersionNumber + 1) {
            revert InvalidVersionNumber();
        }
        if (request.parentManifestHash != file.currentHeadManifestHash) revert StaleHead();
        _append(request, contentCid, envelopeSetCid);
        consumedOperationNonces[request.memberId][request.operationNonce] = true;
    }

    function getFile(bytes32 fileId) external view returns (File memory) {
        return files[fileId];
    }

    function getVersion(
        bytes32 fileId,
        uint64 versionNumber
    ) external view returns (VersionRecord memory) {
        if (files[fileId].status == FileStatus.Unregistered) revert FileNotFound();
        if (versionNumber == 0 || versionNumber > files[fileId].currentVersionNumber) {
            revert InvalidVersionNumber();
        }
        return history[fileId][versionNumber];
    }

    function createFolder(
        bytes32 folderId,
        bytes32 organizationId,
        bytes32 parentFolderId,
        string calldata displayName
    ) external {
        if (folderId == bytes32(0) || organizationId == bytes32(0)) {
            revert ZeroIdentifier();
        }
        if (files[folderId].status != FileStatus.Unregistered) revert FolderAlreadyExists();
        if (folders[folderId].organizationId != bytes32(0)) revert FolderAlreadyExists();
        if (
            files[folderId].status != FileStatus.Unregistered
                || accessGovernance.organizationAuthority(organizationId) != msg.sender
        ) revert UnauthorizedMetadataAuthority();
        if (bytes(displayName).length == 0) revert InvalidMetadata();
        _requireFolderInOrganization(parentFolderId, organizationId);

        folders[folderId] = Folder({
            displayName: displayName,
            parentFolderId: parentFolderId,
            organizationId: organizationId,
            creationTimestamp: uint64(block.timestamp)
        });
        emit FolderCreated(folderId, organizationId, parentFolderId, displayName, msg.sender);
    }

    function getFolder(bytes32 folderId) external view returns (Folder memory) {
        if (folders[folderId].organizationId == bytes32(0)) revert FolderNotFound();
        return folders[folderId];
    }

    function renameFolder(bytes32 folderId, string calldata displayName) external {
        Folder storage folder = folders[folderId];
        if (folder.organizationId == bytes32(0)) revert FolderNotFound();
        if (accessGovernance.organizationAuthority(folder.organizationId) != msg.sender) {
            revert UnauthorizedMetadataAuthority();
        }
        if (bytes(displayName).length == 0) revert InvalidMetadata();
        folder.displayName = displayName;
        emit FolderRenamed(folderId, displayName, msg.sender);
    }

    function updateFileMetadata(
        bytes32 fileId,
        string calldata displayName,
        bytes32 parentFolderId
    ) external {
        File storage file = files[fileId];
        if (file.status == FileStatus.Unregistered) revert FileNotFound();
        if (
            !accessGovernance.isFilePolicyAuthority(
                fileId,
                accessGovernance.FILE_METADATA_POLICY(),
                msg.sender
            )
        ) revert UnauthorizedMetadataAuthority();
        if (bytes(displayName).length == 0) revert InvalidMetadata();
        _requireFolderInOrganization(parentFolderId, file.organizationId);
        file.displayName = displayName;
        file.parentFolderId = parentFolderId;
        emit FileMetadataChanged(fileId, displayName, parentFolderId, msg.sender);
    }

    function setFileStatus(bytes32 fileId, FileStatus newStatus) external {
        if (msg.sender != timelock) revert UnauthorizedMetadataAuthority();
        File storage file = files[fileId];
        if (file.status == FileStatus.Unregistered) revert FileNotFound();
        if (newStatus == FileStatus.Unregistered || newStatus == file.status) {
            revert InvalidMetadata();
        }
        FileStatus oldStatus = file.status;
        file.status = newStatus;
        emit FileStatusChanged(fileId, oldStatus, newStatus);
    }

    function _verifyAppend(
        RrdsEip712.VersionAppend calldata request,
        string calldata contentCid,
        string calldata envelopeSetCid,
        bytes calldata signature
    ) private view {
        if (!accessGovernance.isActiveMember(request.memberId)) revert MemberNotActive();
        address registeredSigner = accessGovernance.memberSigningAddress(request.memberId);
        if (registeredSigner == address(0) || request.signerAddress != registeredSigner) {
            revert InvalidSigner();
        }
        if (request.operationNonce == bytes32(0)) revert InvalidOperationNonce();
        if (consumedOperationNonces[request.memberId][request.operationNonce]) {
            revert OperationNonceAlreadyConsumed();
        }
        if (request.deadline < block.timestamp) revert ExpiredOperation();
        if (!RrdsCid.isCanonicalV1(contentCid) || !RrdsCid.isCanonicalV1(envelopeSetCid)) {
            revert InvalidCid();
        }
        if (
            request.contentCidHash != keccak256(bytes(contentCid))
                || request.envelopeSetCidHash != keccak256(bytes(envelopeSetCid))
        ) revert InvalidCid();
        if (
            request.manifestHash == bytes32(0)
                || request.epochId == bytes32(0)
        ) revert InvalidManifestHash();
        if (usedEpochs[request.fileId][request.epochId]) revert ReusedEpoch();

        bytes32 digest = RrdsEip712.digest(
            RrdsEip712.fileRegistryDomainSeparator(block.chainid, address(this)),
            RrdsEip712.hashVersionAppend(request)
        );
        if (digest.recover(signature) != registeredSigner) revert InvalidOperationSignature();
    }

    function _append(
        RrdsEip712.VersionAppend calldata request,
        string calldata contentCid,
        string calldata envelopeSetCid
    ) private {
        File storage file = files[request.fileId];
        if (request.versionNumber != file.currentVersionNumber + 1) {
            revert InvalidVersionNumber();
        }
        if (request.parentManifestHash != file.currentHeadManifestHash) revert StaleHead();
        if (usedEpochs[request.fileId][request.epochId]) revert ReusedEpoch();

        history[request.fileId][request.versionNumber] = VersionRecord({
            fileId: request.fileId,
            versionNumber: request.versionNumber,
            parentManifestHash: request.parentManifestHash,
            contentCid: contentCid,
            initialEnvelopeSetCid: envelopeSetCid,
            epochId: request.epochId,
            manifestHash: request.manifestHash,
            authorMemberId: request.memberId,
            authorSigningAddress: request.signerAddress
        });
        usedEpochs[request.fileId][request.epochId] = true;
        file.currentVersionNumber = request.versionNumber;
        file.currentHeadManifestHash = request.manifestHash;
        accessGovernance.initializeEnvelopeSet(
            request.fileId,
            request.versionNumber,
            request.epochId,
            envelopeSetCid
        );
        emit VersionAppended(
            request.fileId,
            request.versionNumber,
            request.manifestHash,
            request.parentManifestHash,
            request.epochId,
            request.memberId,
            request.signerAddress,
            contentCid,
            envelopeSetCid
        );
        emit CurrentHeadAdvanced(request.fileId, request.versionNumber, request.manifestHash);
    }

    function _requireFolderInOrganization(
        bytes32 folderId,
        bytes32 organizationId
    ) private view {
        if (folderId == bytes32(0)) return;
        if (
            folders[folderId].organizationId == bytes32(0)
                || folders[folderId].organizationId != organizationId
        ) revert InvalidFolderParent();
    }
}
