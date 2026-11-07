// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.34;

library RrdsEip712 {
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant VERSION_APPEND_TYPEHASH =
        keccak256(
            "VersionAppend(bytes32 fileId,uint64 versionNumber,bytes32 parentManifestHash,bytes32 contentCidHash,bytes32 envelopeSetCidHash,bytes32 epochId,bytes32 manifestHash,bytes32 memberId,address signerAddress,bytes32 operationNonce,uint256 deadline)"
        );
    bytes32 internal constant ACCESS_LOOKUP_TYPEHASH =
        keccak256(
            "AccessLookup(bytes32 memberId,bytes32 fileId,uint64 versionNumber,uint32 encryptionKeyVersion,bytes32 operationNonce,uint256 deadline)"
        );
    bytes32 internal constant ENVELOPE_SET_UPDATE_TYPEHASH =
        keccak256(
            "EnvelopeSetUpdate(bytes32 fileId,uint64 versionNumber,bytes32 epochId,string oldEnvelopeSetCid,string newEnvelopeSetCid,bytes32 actorMemberId,bytes32 proposalId,bytes32 operationNonce,uint256 deadline)"
        );
    bytes32 internal constant MEMBER_KEY_PROOF_TYPEHASH =
        keccak256(
            "MemberKeyProof(bytes32 memberId,bytes32 organizationId,address signingAddress,uint32 signingKeyVersion,uint32 encryptionKeyVersion,bytes32 encryptionPublicKey,bytes32 operationNonce,uint256 deadline)"
        );

    struct VersionAppend {
        bytes32 fileId;
        uint64 versionNumber;
        bytes32 parentManifestHash;
        bytes32 contentCidHash;
        bytes32 envelopeSetCidHash;
        bytes32 epochId;
        bytes32 manifestHash;
        bytes32 memberId;
        address signerAddress;
        bytes32 operationNonce;
        uint256 deadline;
    }

    struct AccessLookup {
        bytes32 memberId;
        bytes32 fileId;
        uint64 versionNumber;
        uint32 encryptionKeyVersion;
        bytes32 operationNonce;
        uint256 deadline;
    }

    struct EnvelopeSetUpdate {
        bytes32 fileId;
        uint64 versionNumber;
        bytes32 epochId;
        string oldEnvelopeSetCid;
        string newEnvelopeSetCid;
        bytes32 actorMemberId;
        bytes32 proposalId;
        bytes32 operationNonce;
        uint256 deadline;
    }

    struct MemberKeyProof {
        bytes32 memberId;
        bytes32 organizationId;
        address signingAddress;
        uint32 signingKeyVersion;
        uint32 encryptionKeyVersion;
        bytes32 encryptionPublicKey;
        bytes32 operationNonce;
        uint256 deadline;
    }

    function fileRegistryDomainSeparator(
        uint256 chainId,
        address verifyingContract
    ) internal pure returns (bytes32) {
        return _domainSeparator("RRDS FileRegistry", chainId, verifyingContract);
    }

    function accessGovernanceDomainSeparator(
        uint256 chainId,
        address verifyingContract
    ) internal pure returns (bytes32) {
        return _domainSeparator("RRDS AccessGovernance", chainId, verifyingContract);
    }

    function hashVersionAppend(VersionAppend memory request) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                VERSION_APPEND_TYPEHASH,
                request.fileId,
                request.versionNumber,
                request.parentManifestHash,
                request.contentCidHash,
                request.envelopeSetCidHash,
                request.epochId,
                request.manifestHash,
                request.memberId,
                request.signerAddress,
                request.operationNonce,
                request.deadline
            )
        );
    }

    function hashAccessLookup(AccessLookup memory request) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                ACCESS_LOOKUP_TYPEHASH,
                request.memberId,
                request.fileId,
                request.versionNumber,
                request.encryptionKeyVersion,
                request.operationNonce,
                request.deadline
            )
        );
    }

    function hashEnvelopeSetUpdate(
        EnvelopeSetUpdate memory request
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                ENVELOPE_SET_UPDATE_TYPEHASH,
                request.fileId,
                request.versionNumber,
                request.epochId,
                keccak256(bytes(request.oldEnvelopeSetCid)),
                keccak256(bytes(request.newEnvelopeSetCid)),
                request.actorMemberId,
                request.proposalId,
                request.operationNonce,
                request.deadline
            )
        );
    }

    function hashMemberKeyProof(
        MemberKeyProof memory request
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                MEMBER_KEY_PROOF_TYPEHASH,
                request.memberId,
                request.organizationId,
                request.signingAddress,
                request.signingKeyVersion,
                request.encryptionKeyVersion,
                request.encryptionPublicKey,
                request.operationNonce,
                request.deadline
            )
        );
    }

    function digest(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _domainSeparator(
        string memory name,
        uint256 chainId,
        address verifyingContract
    ) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes("1")),
                chainId,
                verifyingContract
            )
        );
    }
}
