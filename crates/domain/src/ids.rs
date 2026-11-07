use std::fmt;

use cid::{Cid, Version};

use crate::DomainError;

macro_rules! bytes32_identifier {
    ($name:ident) => {
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub const fn into_bytes(self) -> [u8; 32] {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_hex(formatter, &self.0, true)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "{}({self})", stringify!($name))
            }
        }
    };
}

bytes32_identifier!(FileId);
bytes32_identifier!(MemberId);
bytes32_identifier!(OrganizationId);
bytes32_identifier!(EpochId);
bytes32_identifier!(ManifestHash);
bytes32_identifier!(ProposalId);
bytes32_identifier!(OperationNonce);

impl ManifestHash {
    pub const ZERO: Self = Self([0; 32]);

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 32]
    }
}

/// An EVM signing address, represented in its canonical 20-byte form.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EvmAddress([u8; 20]);

impl EvmAddress {
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 20] {
        self.0
    }
}

impl fmt::Display for EvmAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(formatter, &self.0, true)
    }
}

impl fmt::Debug for EvmAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "EvmAddress({self})")
    }
}

/// A non-zero, monotonically increasing file-version number.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VersionNumber(std::num::NonZeroU64);

impl VersionNumber {
    pub const ONE: Self = Self(std::num::NonZeroU64::MIN);

    pub fn new(value: u64) -> Result<Self, DomainError> {
        std::num::NonZeroU64::new(value)
            .map(Self)
            .ok_or(DomainError::InvalidVersionNumber)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub fn next(self) -> Result<Self, DomainError> {
        self.get()
            .checked_add(1)
            .and_then(std::num::NonZeroU64::new)
            .map(Self)
            .ok_or(DomainError::InvalidVersionNumber)
    }
}

impl fmt::Display for VersionNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

/// A non-zero version for a member's registered signing or encryption key.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyVersion(std::num::NonZeroU32);

impl KeyVersion {
    pub fn new(value: u32) -> Result<Self, DomainError> {
        std::num::NonZeroU32::new(value)
            .map(Self)
            .ok_or(DomainError::InvalidKeyVersion)
    }

    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Display for KeyVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(formatter)
    }
}

/// A canonical CIDv1 value for an encrypted content package.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ContentCid(Cid);

impl ContentCid {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        parse_cid(value).map(Self)
    }

    pub const fn as_cid(&self) -> &Cid {
        &self.0
    }
}

impl fmt::Display for ContentCid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Debug for ContentCid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ContentCid({self})")
    }
}

/// A canonical CIDv1 value for an immutable key-envelope-set object.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct EnvelopeSetCid(Cid);

impl EnvelopeSetCid {
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        parse_cid(value).map(Self)
    }

    pub const fn as_cid(&self) -> &Cid {
        &self.0
    }
}

impl fmt::Display for EnvelopeSetCid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Debug for EnvelopeSetCid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "EnvelopeSetCid({self})")
    }
}

fn parse_cid(value: &str) -> Result<Cid, DomainError> {
    let cid = Cid::try_from(value).map_err(|_| DomainError::InvalidCid)?;
    if cid.version() != Version::V1 || cid.to_string() != value {
        return Err(DomainError::InvalidCid);
    }
    Ok(cid)
}

fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8], prefix: bool) -> fmt::Result {
    if prefix {
        formatter.write_str("0x")?;
    }
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes32_identifiers_have_canonical_hex_display() {
        let file_id = FileId::from_bytes([0xabu8; 32]);

        assert_eq!(file_id.to_string(), format!("0x{}", "ab".repeat(32)));
        assert_eq!(file_id.as_bytes(), &[0xabu8; 32]);
    }

    #[test]
    fn version_and_key_versions_reject_zero() {
        assert_eq!(
            VersionNumber::new(0),
            Err(DomainError::InvalidVersionNumber)
        );
        assert_eq!(VersionNumber::ONE.next().unwrap().get(), 2);
        assert_eq!(KeyVersion::new(0), Err(DomainError::InvalidKeyVersion));
    }

    #[test]
    fn content_and_envelope_cids_require_canonical_cidv1() {
        let cid = Cid::new_v1(
            0x55,
            cid::multihash::Multihash::<64>::wrap(0x12, &[7; 32]).unwrap(),
        )
        .to_string();

        assert_eq!(ContentCid::parse(&cid).unwrap().to_string(), cid);
        assert_eq!(EnvelopeSetCid::parse(&cid).unwrap().to_string(), cid);
        assert_eq!(ContentCid::parse("not-a-cid"), Err(DomainError::InvalidCid));
    }
}
