use crate::{
    ContentCid, DomainError, EnvelopeSetCid, EpochId, EvmAddress, FileId, ManifestHash, MemberId,
    VersionNumber,
};

/// Immutable application view of one accepted file version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionRecord {
    file_id: FileId,
    number: VersionNumber,
    parent_manifest_hash: ManifestHash,
    manifest_hash: ManifestHash,
    content_cid: ContentCid,
    initial_envelope_set_cid: EnvelopeSetCid,
    epoch_id: EpochId,
    author_member_id: MemberId,
    author_signing_address: EvmAddress,
}

impl VersionRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        file_id: FileId,
        number: VersionNumber,
        parent_manifest_hash: ManifestHash,
        manifest_hash: ManifestHash,
        content_cid: ContentCid,
        initial_envelope_set_cid: EnvelopeSetCid,
        epoch_id: EpochId,
        author_member_id: MemberId,
        author_signing_address: EvmAddress,
    ) -> Self {
        Self {
            file_id,
            number,
            parent_manifest_hash,
            manifest_hash,
            content_cid,
            initial_envelope_set_cid,
            epoch_id,
            author_member_id,
            author_signing_address,
        }
    }

    pub const fn file_id(&self) -> FileId {
        self.file_id
    }

    pub const fn number(&self) -> VersionNumber {
        self.number
    }

    pub const fn parent_manifest_hash(&self) -> ManifestHash {
        self.parent_manifest_hash
    }

    pub const fn manifest_hash(&self) -> ManifestHash {
        self.manifest_hash
    }

    pub const fn content_cid(&self) -> &ContentCid {
        &self.content_cid
    }

    pub const fn initial_envelope_set_cid(&self) -> &EnvelopeSetCid {
        &self.initial_envelope_set_cid
    }

    pub const fn epoch_id(&self) -> EpochId {
        self.epoch_id
    }

    pub const fn author_member_id(&self) -> MemberId {
        self.author_member_id
    }

    pub const fn author_signing_address(&self) -> EvmAddress {
        self.author_signing_address
    }
}

/// In-memory append-only version history with the same parent/head invariants
/// required by FileRegistry.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct VersionGraph {
    records: Vec<VersionRecord>,
}

impl VersionGraph {
    pub fn append(&mut self, record: VersionRecord) -> Result<(), DomainError> {
        match self.records.last() {
            None => {
                if record.number != VersionNumber::ONE || !record.parent_manifest_hash.is_zero() {
                    return Err(DomainError::InvalidManifest);
                }
            }
            Some(head) => {
                if record.file_id != head.file_id {
                    return Err(DomainError::FileIdMismatch);
                }
                if record.number != head.number.next()? {
                    return Err(DomainError::InvalidVersionNumber);
                }
                if record.parent_manifest_hash != head.manifest_hash {
                    return Err(DomainError::StaleHead);
                }
                if self
                    .records
                    .iter()
                    .any(|existing| existing.epoch_id == record.epoch_id)
                {
                    return Err(DomainError::DuplicateEpochId);
                }
            }
        }

        self.records.push(record);
        Ok(())
    }

    pub fn head(&self) -> Option<&VersionRecord> {
        self.records.last()
    }

    pub fn versions(&self) -> &[VersionRecord] {
        &self.records
    }
}

#[cfg(test)]
mod tests {
    use cid::Cid;

    use super::*;

    fn cid_text() -> String {
        Cid::new_v1(
            0x55,
            cid::multihash::Multihash::<64>::wrap(0x12, &[7; 32]).unwrap(),
        )
        .to_string()
    }

    fn record(
        number: u64,
        parent: ManifestHash,
        manifest: u8,
        epoch: u8,
        file: u8,
    ) -> VersionRecord {
        let cid = cid_text();
        VersionRecord::new(
            FileId::from_bytes([file; 32]),
            VersionNumber::new(number).unwrap(),
            parent,
            ManifestHash::from_bytes([manifest; 32]),
            ContentCid::parse(&cid).unwrap(),
            EnvelopeSetCid::parse(&cid).unwrap(),
            EpochId::from_bytes([epoch; 32]),
            MemberId::from_bytes([4; 32]),
            EvmAddress::from_bytes([5; 20]),
        )
    }

    #[test]
    fn appends_a_linear_version_history() {
        let first = record(1, ManifestHash::ZERO, 1, 1, 9);
        let second = record(2, first.manifest_hash(), 2, 2, 9);
        let mut graph = VersionGraph::default();

        graph.append(first).unwrap();
        graph.append(second).unwrap();

        assert_eq!(graph.versions().len(), 2);
        assert_eq!(graph.head().unwrap().number().get(), 2);
    }

    #[test]
    fn rejects_a_stale_parent_without_mutating_the_graph() {
        let mut graph = VersionGraph::default();
        graph
            .append(record(1, ManifestHash::ZERO, 1, 1, 9))
            .unwrap();

        assert_eq!(
            graph.append(record(2, ManifestHash::from_bytes([8; 32]), 2, 2, 9)),
            Err(DomainError::StaleHead)
        );
        assert_eq!(graph.versions().len(), 1);
    }

    #[test]
    fn rejects_non_sequential_or_cross_file_versions() {
        let mut graph = VersionGraph::default();
        graph
            .append(record(1, ManifestHash::ZERO, 1, 1, 9))
            .unwrap();

        assert_eq!(
            graph.append(record(3, ManifestHash::from_bytes([1; 32]), 3, 3, 9)),
            Err(DomainError::InvalidVersionNumber)
        );
        assert_eq!(
            graph.append(record(2, ManifestHash::from_bytes([1; 32]), 2, 2, 8)),
            Err(DomainError::FileIdMismatch)
        );
        assert_eq!(graph.versions().len(), 1);
    }

    #[test]
    fn rejects_reused_key_epochs() {
        let mut graph = VersionGraph::default();
        graph
            .append(record(1, ManifestHash::ZERO, 1, 1, 9))
            .unwrap();

        assert_eq!(
            graph.append(record(2, ManifestHash::from_bytes([1; 32]), 2, 1, 9)),
            Err(DomainError::DuplicateEpochId)
        );
        assert_eq!(graph.versions().len(), 1);
    }
}
