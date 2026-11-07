// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.34;

import {Test} from "forge-std/Test.sol";
import {RrdsEip712} from "./libraries/RrdsEip712.sol";

contract RrdsEip712Test is Test {
    function test_VersionAppendMatchesRustAndViemVector() public pure {
        RrdsEip712.VersionAppend memory request = RrdsEip712.VersionAppend({
            fileId: _b32(0x01),
            versionNumber: 3,
            parentManifestHash: _b32(0x02),
            contentCidHash: keccak256(
                bytes("bafkreiaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaq")
            ),
            envelopeSetCidHash: keccak256(
                bytes("bafkreiafaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifaucqkbifau")
            ),
            epochId: _b32(0x06),
            manifestHash: _b32(0x03),
            memberId: _b32(0x07),
            signerAddress: address(uint160(uint256(_b32(0x10)))),
            operationNonce: _b32(0x99),
            deadline: 1_800_000_000
        });
        bytes32 domainSeparator = RrdsEip712.fileRegistryDomainSeparator(
            1337,
            address(uint160(uint256(_b32(0x11))))
        );

        assertEq(
            RrdsEip712.digest(domainSeparator, RrdsEip712.hashVersionAppend(request)),
            0x2f875c599ad40349bd612635666249101d10cdf8c2d4072a24447152451c0a96
        );
    }

    function test_AccessLookupMatchesRustAndViemVector() public pure {
        RrdsEip712.AccessLookup memory request = RrdsEip712.AccessLookup({
            memberId: _b32(0x08),
            fileId: _b32(0x09),
            versionNumber: 3,
            encryptionKeyVersion: 2,
            operationNonce: _b32(0x99),
            deadline: 1_800_000_000
        });
        bytes32 domainSeparator = RrdsEip712.accessGovernanceDomainSeparator(
            1337,
            address(uint160(uint256(_b32(0x22))))
        );

        assertEq(
            RrdsEip712.digest(domainSeparator, RrdsEip712.hashAccessLookup(request)),
            0xdcf26981a7273b720753da55021baa9865272b237c180c268064aeb39d355907
        );
    }

    function test_EnvelopeSetUpdateMatchesRustAndViemVector() public pure {
        RrdsEip712.EnvelopeSetUpdate memory request = RrdsEip712.EnvelopeSetUpdate({
            fileId: _b32(0x0a),
            versionNumber: 3,
            epochId: _b32(0x0b),
            oldEnvelopeSetCid: "bafkreiambqgaydambqgaydambqgaydambqgaydambqgaydambqgaydambq",
            newEnvelopeSetCid: "bafkreianbugq2dinbugq2dinbugq2dinbugq2dinbugq2dinbugq2dinbu",
            actorMemberId: _b32(0x0e),
            proposalId: _b32(0x0f),
            operationNonce: _b32(0x99),
            deadline: 1_800_000_000
        });
        bytes32 domainSeparator = RrdsEip712.accessGovernanceDomainSeparator(
            1337,
            address(uint160(uint256(_b32(0x22))))
        );

        assertEq(
            RrdsEip712.digest(domainSeparator, RrdsEip712.hashEnvelopeSetUpdate(request)),
            0xd15c807d4cfc3321aef3d710d2b014420127a575490a8b22450d5ee1956d8046
        );
    }

    function test_MemberKeyProofMatchesRustAndViemVector() public pure {
        RrdsEip712.MemberKeyProof memory request = RrdsEip712.MemberKeyProof({
            memberId: _b32(0x11),
            organizationId: _b32(0x12),
            signingAddress: address(uint160(uint256(_b32(0x13)))),
            signingKeyVersion: 2,
            encryptionKeyVersion: 3,
            encryptionPublicKey: _b32(0x14),
            operationNonce: _b32(0x15),
            deadline: 1_800_000_000
        });
        bytes32 domainSeparator = RrdsEip712.accessGovernanceDomainSeparator(
            1337,
            address(uint160(uint256(_b32(0x22))))
        );

        assertEq(
            RrdsEip712.digest(domainSeparator, RrdsEip712.hashMemberKeyProof(request)),
            0x21fa5a8fc625d220a73645305ced46dd8fe78881cd748c1892bba8dd571858f6
        );
    }

    function test_DomainSeparatorsBindChainAndVerifyingContract() public pure {
        bytes32 original = RrdsEip712.fileRegistryDomainSeparator(
            1337,
            address(uint160(uint256(_b32(0x11))))
        );
        bytes32 otherChain = RrdsEip712.fileRegistryDomainSeparator(
            1338,
            address(uint160(uint256(_b32(0x11))))
        );
        bytes32 otherContract = RrdsEip712.fileRegistryDomainSeparator(
            1337,
            address(uint160(uint256(_b32(0x12))))
        );

        assertNotEq(original, otherChain);
        assertNotEq(original, otherContract);
    }

    function _b32(uint8 value) private pure returns (bytes32) {
        return bytes32(
            uint256(value)
                * 0x0101010101010101010101010101010101010101010101010101010101010101
        );
    }
}
