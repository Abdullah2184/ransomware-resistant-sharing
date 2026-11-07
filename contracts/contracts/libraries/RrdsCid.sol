// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.34;

library RrdsCid {
    function isCanonicalV1(string memory value) internal pure returns (bool) {
        bytes memory text = bytes(value);
        if (text.length < 2 || text[0] != bytes1("b")) return false;

        uint256 encodedLength = text.length - 1;
        uint256 decodedLength = (encodedLength * 5) / 8;
        if (((decodedLength * 8 + 4) / 5) != encodedLength) return false;

        bytes memory cid = new bytes(decodedLength);
        if (!_decodeBase32(text, cid)) return false;
        return _validCid(cid);
    }

    function _decodeBase32(bytes memory text, bytes memory cid) private pure returns (bool) {
        uint256 accumulator;
        uint256 bits;
        uint256 outputIndex;
        for (uint256 i = 1; i < text.length; ++i) {
            uint8 digit = _base32Value(uint8(text[i]));
            if (digit == type(uint8).max) return false;
            accumulator = (accumulator << 5) | digit;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                cid[outputIndex++] = bytes1(uint8(accumulator >> bits));
                accumulator &= (uint256(1) << bits) - 1;
            }
        }
        return accumulator == 0 && outputIndex == cid.length;
    }

    function _validCid(bytes memory cid) private pure returns (bool) {
        (uint256 version, uint256 cursor, bool valid) = _readVarint(cid, 0);
        if (!valid || version != 1) return false;
        uint256 codec;
        (codec, cursor, valid) = _readVarint(cid, cursor);
        if (!valid || codec == 0) return false;
        uint256 hashCode;
        (hashCode, cursor, valid) = _readVarint(cid, cursor);
        if (!valid || hashCode == 0) return false;
        uint256 digestLength;
        (digestLength, cursor, valid) = _readVarint(cid, cursor);
        if (!valid || digestLength == 0) return false;
        return cursor <= cid.length && digestLength == cid.length - cursor;
    }

    function _base32Value(uint8 character) private pure returns (uint8) {
        if (character >= 0x61 && character <= 0x7a) {
            return character - 0x61;
        }
        if (character >= 0x32 && character <= 0x37) {
            return character - 0x32 + 26;
        }
        return type(uint8).max;
    }

    function _readVarint(
        bytes memory data,
        uint256 offset
    ) private pure returns (uint256 value, uint256 nextOffset, bool valid) {
        uint256 shift;
        uint256 start = offset;
        while (offset < data.length && offset - start < 10) {
            uint8 current = uint8(data[offset++]);
            uint8 payload = current & 0x7f;
            if (shift >= 256 || (uint256(payload) << shift) >> shift != payload) {
                return (0, offset, false);
            }
            value |= uint256(payload) << shift;
            if ((current & 0x80) == 0) {
                if (offset - start > 1 && payload == 0) return (0, offset, false);
                return (value, offset, true);
            }
            shift += 7;
        }
        return (0, offset, false);
    }
}
