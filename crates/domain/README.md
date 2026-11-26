# Domain (`crates/domain`)

Pure domain model for RRDS with zero infrastructure, network, database, or
cryptographic implementation dependencies (only `cid` for canonical CIDv1
syntax validation).

## Contents

- **Typed identifiers (`ids.rs`):** `OrganizationId`, `MemberId`, `FileId`,
  `FolderId` (`FolderId::ROOT`), `EpochId`, `ManifestHash`, `OperationNonce`,
  `ProposalId`, `EvmAddress`, `VersionNumber`, `KeyVersion`, `ContentCid`, and
  `EnvelopeSetCid`.
- **Core domain models (`model.rs`):** `MemberStatus`, `FileStatus`,
  `PublicMemberIdentity`, `FileMetadata`, `AccessReference`, `LoginChallenge`,
  and `TransactionReceipt`.
- **Append-only version history (`version_graph.rs`):** `VersionNode` and
  `VersionHistory` enforcing sequential version numbers and linear
  `parentManifestHash` continuity.
- **Error taxonomy (`errors.rs`):** `DomainError`.

## Verification

```shell
cargo test -p domain --locked --offline
```
