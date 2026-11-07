use std::fmt;

use domain::{
    ContentCid, EnvelopeSetCid, EpochId, EvmAddress, FileId, KeyVersion, ManifestHash, MemberId,
    OperationNonce, OrganizationId, ProposalId, VersionNumber,
};
use sha3::{Digest, Keccak256};

const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const DOMAIN_VERSION: &str = "1";
const VERSION_APPEND_TYPE: &str = "VersionAppend(bytes32 fileId,uint64 versionNumber,bytes32 parentManifestHash,bytes32 contentCidHash,bytes32 envelopeSetCidHash,bytes32 epochId,bytes32 manifestHash,bytes32 memberId,address signerAddress,bytes32 operationNonce,uint256 deadline)";
const ACCESS_LOOKUP_TYPE: &str = "AccessLookup(bytes32 memberId,bytes32 fileId,uint64 versionNumber,uint32 encryptionKeyVersion,bytes32 operationNonce,uint256 deadline)";
const ENVELOPE_SET_UPDATE_TYPE: &str = "EnvelopeSetUpdate(bytes32 fileId,uint64 versionNumber,bytes32 epochId,string oldEnvelopeSetCid,string newEnvelopeSetCid,bytes32 actorMemberId,bytes32 proposalId,bytes32 operationNonce,uint256 deadline)";
const MEMBER_KEY_PROOF_TYPE: &str = "MemberKeyProof(bytes32 memberId,bytes32 organizationId,address signingAddress,uint32 signingKeyVersion,uint32 encryptionKeyVersion,bytes32 encryptionPublicKey,bytes32 operationNonce,uint256 deadline)";

/// Domain contract that binds a typed message to the contract responsible for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyingContractKind {
    FileRegistry,
    AccessGovernance,
}

/// An EVM chain identifier represented as a full unsigned 256-bit EIP-712 word.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ChainId([u8; 32]);

impl ChainId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn from_u64(value: u64) -> Self {
        let bytes = value.to_be_bytes();
        let mut word = [0; 32];
        let mut index = 0;
        while index < 8 {
            word[24 + index] = bytes[index];
            index += 1;
        }
        Self(word)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ChainId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChainId(0x")?;
        write_hex(formatter, &self.0)?;
        formatter.write_str(")")
    }
}

/// EIP-712 domain configured for the system's specific verifying contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Eip712Domain {
    kind: VerifyingContractKind,
    chain_id: ChainId,
    verifying_contract: EvmAddress,
}

impl Eip712Domain {
    pub const fn file_registry(chain_id: ChainId, verifying_contract: EvmAddress) -> Self {
        Self {
            kind: VerifyingContractKind::FileRegistry,
            chain_id,
            verifying_contract,
        }
    }

    pub const fn access_governance(chain_id: ChainId, verifying_contract: EvmAddress) -> Self {
        Self {
            kind: VerifyingContractKind::AccessGovernance,
            chain_id,
            verifying_contract,
        }
    }

    pub const fn kind(&self) -> VerifyingContractKind {
        self.kind
    }

    pub fn separator(&self) -> [u8; 32] {
        let name = match self.kind {
            VerifyingContractKind::FileRegistry => "RRDS FileRegistry",
            VerifyingContractKind::AccessGovernance => "RRDS AccessGovernance",
        };
        let fields = [
            keccak(name.as_bytes()),
            keccak(DOMAIN_VERSION.as_bytes()),
            *self.chain_id.as_bytes(),
            address_word(self.verifying_contract),
        ];
        struct_hash(DOMAIN_TYPE, &fields)
    }
}

/// Unix-seconds deadline represented as a `uint256` EIP-712 word.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixDeadline([u8; 32]);

impl UnixDeadline {
    pub fn from_unix_seconds(seconds: u64) -> Result<Self, SigningError> {
        if seconds == 0 {
            return Err(SigningError::ZeroDeadline);
        }
        Ok(Self(uint_word_u64(seconds)))
    }

    pub fn from_uint256(bytes: [u8; 32]) -> Result<Self, SigningError> {
        if bytes == [0; 32] {
            return Err(SigningError::ZeroDeadline);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// EIP-712 digest to be passed to the configured key-custody signer.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct TypedDigest([u8; 32]);

impl TypedDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TypedDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TypedDigest(0x")?;
        write_hex(formatter, &self.0)?;
        formatter.write_str(")")
    }
}

/// Stable validation failures for EIP-712 message construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningError {
    ZeroOperationNonce,
    ZeroDeadline,
    WrongVerifyingContract,
    UnchangedEnvelopeSet,
    InvalidKeyProof,
}

impl fmt::Display for SigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ZeroOperationNonce => "operation nonce must be non-zero",
            Self::ZeroDeadline => "operation deadline must be non-zero",
            Self::WrongVerifyingContract => "typed operation has the wrong verifying contract",
            Self::UnchangedEnvelopeSet => "envelope update must change the envelope-set CID",
            Self::InvalidKeyProof => "member key proof contains an invalid key",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SigningError {}

/// EIP-712 authorization request for appending a file version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionAppend {
    file_id: FileId,
    version_number: VersionNumber,
    parent_manifest_hash: ManifestHash,
    manifest_hash: ManifestHash,
    content_cid: ContentCid,
    envelope_set_cid: EnvelopeSetCid,
    epoch_id: EpochId,
    author_member_id: MemberId,
    signer_address: EvmAddress,
    operation_nonce: OperationNonce,
    deadline: UnixDeadline,
}

impl VersionAppend {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        file_id: FileId,
        version_number: VersionNumber,
        parent_manifest_hash: ManifestHash,
        manifest_hash: ManifestHash,
        content_cid: ContentCid,
        envelope_set_cid: EnvelopeSetCid,
        epoch_id: EpochId,
        author_member_id: MemberId,
        signer_address: EvmAddress,
        operation_nonce: OperationNonce,
        deadline: UnixDeadline,
    ) -> Result<Self, SigningError> {
        validate_nonce(operation_nonce)?;
        Ok(Self {
            file_id,
            version_number,
            parent_manifest_hash,
            manifest_hash,
            content_cid,
            envelope_set_cid,
            epoch_id,
            author_member_id,
            signer_address,
            operation_nonce,
            deadline,
        })
    }

    pub fn digest(&self, domain: &Eip712Domain) -> Result<TypedDigest, SigningError> {
        require_kind(domain, VerifyingContractKind::FileRegistry)?;
        let content_cid_hash = keccak(self.content_cid.to_string().as_bytes());
        let envelope_set_cid_hash = keccak(self.envelope_set_cid.to_string().as_bytes());
        let fields = [
            self.file_id.into_bytes(),
            uint_word_u64(self.version_number.get()),
            self.parent_manifest_hash.into_bytes(),
            content_cid_hash,
            envelope_set_cid_hash,
            self.epoch_id.into_bytes(),
            self.manifest_hash.into_bytes(),
            self.author_member_id.into_bytes(),
            address_word(self.signer_address),
            self.operation_nonce.into_bytes(),
            *self.deadline.as_bytes(),
        ];
        Ok(typed_digest(
            domain,
            struct_hash(VERSION_APPEND_TYPE, &fields),
        ))
    }
}

/// Signed request to authorize retrieval of one explicit file version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessLookup {
    member_id: MemberId,
    file_id: FileId,
    version_number: VersionNumber,
    encryption_key_version: KeyVersion,
    operation_nonce: OperationNonce,
    deadline: UnixDeadline,
}

impl AccessLookup {
    pub fn new(
        member_id: MemberId,
        file_id: FileId,
        version_number: VersionNumber,
        encryption_key_version: KeyVersion,
        operation_nonce: OperationNonce,
        deadline: UnixDeadline,
    ) -> Result<Self, SigningError> {
        validate_nonce(operation_nonce)?;
        Ok(Self {
            member_id,
            file_id,
            version_number,
            encryption_key_version,
            operation_nonce,
            deadline,
        })
    }

    pub fn digest(&self, domain: &Eip712Domain) -> Result<TypedDigest, SigningError> {
        require_kind(domain, VerifyingContractKind::AccessGovernance)?;
        let fields = [
            self.member_id.into_bytes(),
            self.file_id.into_bytes(),
            uint_word_u64(self.version_number.get()),
            uint_word_u32(self.encryption_key_version.get()),
            self.operation_nonce.into_bytes(),
            *self.deadline.as_bytes(),
        ];
        Ok(typed_digest(
            domain,
            struct_hash(ACCESS_LOOKUP_TYPE, &fields),
        ))
    }
}

/// EIP-712 authorization request for replacing an immutable envelope set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeSetUpdate {
    file_id: FileId,
    version_number: VersionNumber,
    epoch_id: EpochId,
    old_envelope_set_cid: EnvelopeSetCid,
    new_envelope_set_cid: EnvelopeSetCid,
    actor_member_id: MemberId,
    proposal_id: ProposalId,
    operation_nonce: OperationNonce,
    deadline: UnixDeadline,
}

impl EnvelopeSetUpdate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        file_id: FileId,
        version_number: VersionNumber,
        epoch_id: EpochId,
        old_envelope_set_cid: EnvelopeSetCid,
        new_envelope_set_cid: EnvelopeSetCid,
        actor_member_id: MemberId,
        proposal_id: ProposalId,
        operation_nonce: OperationNonce,
        deadline: UnixDeadline,
    ) -> Result<Self, SigningError> {
        validate_nonce(operation_nonce)?;
        if old_envelope_set_cid == new_envelope_set_cid {
            return Err(SigningError::UnchangedEnvelopeSet);
        }
        Ok(Self {
            file_id,
            version_number,
            epoch_id,
            old_envelope_set_cid,
            new_envelope_set_cid,
            actor_member_id,
            proposal_id,
            operation_nonce,
            deadline,
        })
    }

    pub fn digest(&self, domain: &Eip712Domain) -> Result<TypedDigest, SigningError> {
        require_kind(domain, VerifyingContractKind::AccessGovernance)?;
        let old_cid = keccak(self.old_envelope_set_cid.to_string().as_bytes());
        let new_cid = keccak(self.new_envelope_set_cid.to_string().as_bytes());
        let fields = [
            self.file_id.into_bytes(),
            uint_word_u64(self.version_number.get()),
            self.epoch_id.into_bytes(),
            old_cid,
            new_cid,
            self.actor_member_id.into_bytes(),
            self.proposal_id.into_bytes(),
            self.operation_nonce.into_bytes(),
            *self.deadline.as_bytes(),
        ];
        Ok(typed_digest(
            domain,
            struct_hash(ENVELOPE_SET_UPDATE_TYPE, &fields),
        ))
    }
}

/// EIP-712 proof that the proposed member signing key is controlled by its owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberKeyProof {
    member_id: MemberId,
    organization_id: OrganizationId,
    signing_address: EvmAddress,
    signing_key_version: KeyVersion,
    encryption_key_version: KeyVersion,
    encryption_public_key: [u8; 32],
    operation_nonce: OperationNonce,
    deadline: UnixDeadline,
}

impl MemberKeyProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        member_id: MemberId,
        organization_id: OrganizationId,
        signing_address: EvmAddress,
        signing_key_version: KeyVersion,
        encryption_key_version: KeyVersion,
        encryption_public_key: [u8; 32],
        operation_nonce: OperationNonce,
        deadline: UnixDeadline,
    ) -> Result<Self, SigningError> {
        validate_nonce(operation_nonce)?;
        if encryption_public_key == [0; 32] {
            return Err(SigningError::InvalidKeyProof);
        }
        Ok(Self {
            member_id,
            organization_id,
            signing_address,
            signing_key_version,
            encryption_key_version,
            encryption_public_key,
            operation_nonce,
            deadline,
        })
    }

    pub fn digest(&self, domain: &Eip712Domain) -> Result<TypedDigest, SigningError> {
        require_kind(domain, VerifyingContractKind::AccessGovernance)?;
        let fields = [
            self.member_id.into_bytes(),
            self.organization_id.into_bytes(),
            address_word(self.signing_address),
            uint_word_u32(self.signing_key_version.get()),
            uint_word_u32(self.encryption_key_version.get()),
            self.encryption_public_key,
            self.operation_nonce.into_bytes(),
            *self.deadline.as_bytes(),
        ];
        Ok(typed_digest(
            domain,
            struct_hash(MEMBER_KEY_PROOF_TYPE, &fields),
        ))
    }
}

fn validate_nonce(nonce: OperationNonce) -> Result<(), SigningError> {
    if nonce.as_bytes() == &[0; 32] {
        return Err(SigningError::ZeroOperationNonce);
    }
    Ok(())
}

fn require_kind(
    domain: &Eip712Domain,
    expected: VerifyingContractKind,
) -> Result<(), SigningError> {
    if domain.kind != expected {
        return Err(SigningError::WrongVerifyingContract);
    }
    Ok(())
}

fn typed_digest(domain: &Eip712Domain, struct_hash: [u8; 32]) -> TypedDigest {
    let mut encoded = Vec::with_capacity(66);
    encoded.extend_from_slice(b"\x19\x01");
    encoded.extend_from_slice(&domain.separator());
    encoded.extend_from_slice(&struct_hash);
    TypedDigest(keccak(&encoded))
}

fn struct_hash(type_string: &str, fields: &[[u8; 32]]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(32 * (fields.len() + 1));
    encoded.extend_from_slice(&keccak(type_string.as_bytes()));
    for field in fields {
        encoded.extend_from_slice(field);
    }
    keccak(&encoded)
}

fn uint_word_u64(value: u64) -> [u8; 32] {
    let mut word = [0; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn uint_word_u32(value: u32) -> [u8; 32] {
    let mut word = [0; 32];
    word[28..].copy_from_slice(&value.to_be_bytes());
    word
}

fn address_word(address: EvmAddress) -> [u8; 32] {
    let mut word = [0; 32];
    word[12..].copy_from_slice(address.as_bytes());
    word
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    let hash = Keccak256::digest(bytes);
    let mut output = [0; 32];
    output.copy_from_slice(&hash);
    output
}

fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(fill: u8) -> ContentCid {
        use cid::Cid;
        let digest = [fill; 32];
        let multihash = cid::multihash::Multihash::<64>::wrap(0x12, &digest).unwrap();
        ContentCid::parse(&Cid::new_v1(0x55, multihash).to_string()).unwrap()
    }

    fn envelope_cid(fill: u8) -> EnvelopeSetCid {
        EnvelopeSetCid::parse(&cid(fill).to_string()).unwrap()
    }

    fn file_domain() -> Eip712Domain {
        Eip712Domain::file_registry(ChainId::from_u64(1337), EvmAddress::from_bytes([0x11; 20]))
    }

    fn governance_domain() -> Eip712Domain {
        Eip712Domain::access_governance(ChainId::from_u64(1337), EvmAddress::from_bytes([0x22; 20]))
    }

    fn nonce() -> OperationNonce {
        OperationNonce::from_bytes([0x99; 32])
    }

    fn deadline() -> UnixDeadline {
        UnixDeadline::from_unix_seconds(1_800_000_000).unwrap()
    }

    #[test]
    fn operation_digests_are_bound_to_their_verifying_contract() {
        let version = VersionAppend::new(
            FileId::from_bytes([0x01; 32]),
            VersionNumber::new(3).unwrap(),
            ManifestHash::from_bytes([0x02; 32]),
            ManifestHash::from_bytes([0x03; 32]),
            cid(0x04),
            envelope_cid(0x05),
            EpochId::from_bytes([0x06; 32]),
            MemberId::from_bytes([0x07; 32]),
            EvmAddress::from_bytes([0x10; 20]),
            nonce(),
            deadline(),
        )
        .unwrap();
        let lookup = AccessLookup::new(
            MemberId::from_bytes([0x08; 32]),
            FileId::from_bytes([0x09; 32]),
            VersionNumber::new(3).unwrap(),
            KeyVersion::new(2).unwrap(),
            nonce(),
            deadline(),
        )
        .unwrap();
        let update = EnvelopeSetUpdate::new(
            FileId::from_bytes([0x0a; 32]),
            VersionNumber::new(3).unwrap(),
            EpochId::from_bytes([0x0b; 32]),
            envelope_cid(0x0c),
            envelope_cid(0x0d),
            MemberId::from_bytes([0x0e; 32]),
            ProposalId::from_bytes([0x0f; 32]),
            nonce(),
            deadline(),
        )
        .unwrap();
        let member_key_proof = MemberKeyProof::new(
            MemberId::from_bytes([0x11; 32]),
            OrganizationId::from_bytes([0x12; 32]),
            EvmAddress::from_bytes([0x13; 20]),
            KeyVersion::new(2).unwrap(),
            KeyVersion::new(3).unwrap(),
            [0x14; 32],
            OperationNonce::from_bytes([0x15; 32]),
            deadline(),
        )
        .unwrap();

        assert_eq!(
            version.digest(&file_domain()).unwrap().as_bytes(),
            &fixture_digest("versionAppend")
        );
        assert_eq!(
            lookup.digest(&governance_domain()).unwrap().as_bytes(),
            &fixture_digest("accessLookup")
        );
        assert_eq!(
            update.digest(&governance_domain()).unwrap().as_bytes(),
            &fixture_digest("envelopeSetUpdate")
        );
        assert_eq!(
            member_key_proof
                .digest(&governance_domain())
                .unwrap()
                .as_bytes(),
            &fixture_digest("memberKeyProof")
        );
        assert_eq!(
            version.digest(&governance_domain()),
            Err(SigningError::WrongVerifyingContract)
        );
        assert_eq!(
            lookup.digest(&file_domain()),
            Err(SigningError::WrongVerifyingContract)
        );
    }

    #[test]
    fn rejects_zero_nonce_deadline_and_noop_envelope_update() {
        let zero_nonce = OperationNonce::from_bytes([0; 32]);
        assert_eq!(
            AccessLookup::new(
                MemberId::from_bytes([1; 32]),
                FileId::from_bytes([2; 32]),
                VersionNumber::ONE,
                KeyVersion::new(1).unwrap(),
                zero_nonce,
                deadline(),
            ),
            Err(SigningError::ZeroOperationNonce)
        );
        assert_eq!(
            UnixDeadline::from_unix_seconds(0),
            Err(SigningError::ZeroDeadline)
        );
        assert_eq!(
            EnvelopeSetUpdate::new(
                FileId::from_bytes([1; 32]),
                VersionNumber::ONE,
                EpochId::from_bytes([2; 32]),
                envelope_cid(3),
                envelope_cid(3),
                MemberId::from_bytes([4; 32]),
                ProposalId::from_bytes([0; 32]),
                nonce(),
                deadline(),
            ),
            Err(SigningError::UnchangedEnvelopeSet)
        );
    }

    #[test]
    fn domain_separator_changes_with_chain_and_verifying_contract() {
        let original = file_domain().separator();
        let other_chain = Eip712Domain::file_registry(
            ChainId::from_u64(1338),
            EvmAddress::from_bytes([0x11; 20]),
        );
        let other_contract = Eip712Domain::file_registry(
            ChainId::from_u64(1337),
            EvmAddress::from_bytes([0x12; 20]),
        );

        assert_ne!(original, other_chain.separator());
        assert_ne!(original, other_contract.separator());
    }

    fn fixture_digest(name: &str) -> [u8; 32] {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/eip712-v1.json")).unwrap();
        let value = fixture[name].as_str().unwrap().strip_prefix("0x").unwrap();
        let mut digest = [0; 32];
        for (index, byte) in digest.iter_mut().enumerate() {
            let start = index * 2;
            *byte = u8::from_str_radix(&value[start..start + 2], 16).unwrap();
        }
        digest
    }
}
