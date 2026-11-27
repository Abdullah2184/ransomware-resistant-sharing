//! Shared hexadecimal encoding and decoding utilities.
//!
//! Kept dependency-free inside `domain` so every workspace crate and service
//! shares one canonical, allocation-efficient implementation.

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Encodes `bytes` as lowercase hexadecimal without a `0x` prefix.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
        output.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
    }
    output
}

/// Encodes `bytes` as lowercase hexadecimal with a leading `0x` prefix.
#[must_use]
pub fn encode_prefixed_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(2 + bytes.len() * 2);
    output.push_str("0x");
    for &byte in bytes {
        output.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
        output.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
    }
    output
}

/// Decodes a `0x`-prefixed, even-length ASCII hexadecimal string into bytes.
#[must_use]
pub fn decode_prefixed_hex(value: &str) -> Option<Vec<u8>> {
    let digits = value.strip_prefix("0x")?;
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    let mut output = Vec::with_capacity(digits.len() / 2);
    for pair in digits.as_bytes().as_chunks::<2>().0 {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output.push((high << 4) | low);
    }
    Some(output)
}

/// Decodes a `0x`-prefixed fixed-size (`N`-byte) hexadecimal string (case-insensitive).
#[must_use]
pub fn parse_fixed_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    let digits = value.strip_prefix("0x")?;
    if digits.len() != N * 2 {
        return None;
    }
    let mut output = [0u8; N];
    for (slot, pair) in output
        .iter_mut()
        .zip(digits.as_bytes().as_chunks::<2>().0.iter())
    {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        *slot = (high << 4) | low;
    }
    Some(output)
}

/// Decodes a `0x`-prefixed fixed-size (`N`-byte) strictly lowercase hexadecimal string.
#[must_use]
pub fn parse_lowercase_fixed_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    let digits = value.strip_prefix("0x")?;
    if digits.len() != N * 2 {
        return None;
    }
    let mut output = [0u8; N];
    for (slot, pair) in output
        .iter_mut()
        .zip(digits.as_bytes().as_chunks::<2>().0.iter())
    {
        let high = lowercase_hex_nibble(pair[0])?;
        let low = lowercase_hex_nibble(pair[1])?;
        *slot = (high << 4) | low;
    }
    Some(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn lowercase_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_decodes_hex_consistently() {
        let bytes = [0x00, 0x0a, 0x7f, 0xff];
        assert_eq!(encode_hex(&bytes), "000a7fff");
        assert_eq!(encode_prefixed_hex(&bytes), "0x000a7fff");
        assert_eq!(decode_prefixed_hex("0x000a7fFF"), Some(bytes.to_vec()));
        assert_eq!(decode_prefixed_hex("0x"), Some(Vec::new()));
        assert_eq!(decode_prefixed_hex("000a7fff"), None);
        assert_eq!(decode_prefixed_hex("0x0"), None);
        assert_eq!(decode_prefixed_hex("0xzz"), None);
    }

    #[test]
    fn parses_fixed_and_lowercase_fixed_hex() {
        assert_eq!(parse_fixed_hex::<2>("0xAbCd"), Some([0xab, 0xcd]));
        assert_eq!(parse_fixed_hex::<2>("0xabc"), None);
        assert_eq!(parse_fixed_hex::<2>("abcd"), None);
        assert_eq!(parse_lowercase_fixed_hex::<2>("0xabcd"), Some([0xab, 0xcd]));
        assert_eq!(parse_lowercase_fixed_hex::<2>("0xAbCd"), None);
    }
}
