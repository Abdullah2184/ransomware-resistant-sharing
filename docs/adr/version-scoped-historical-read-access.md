# ADR: Version-scoped historical read access

**Status:** Accepted by maintainer; ACL primitive, gateway check, and projection implemented  
**Decision scope:** Read authorization for current, future, and historical file versions

## Context

The specification's default sharing scope is the current version plus future
versions. It requires older-version access to be explicitly selected. The
existing contracts expose a file-wide Read ACL, while the gateway access route
accepts any extant version under that ACL. This makes historical access broader
than the specified default.

The maintainer confirmed that historical access must require an explicit
per-version grant.

## Decision

- A member's file-level Read grant authorizes retrieval of the current head and
  future versions while that file-level grant remains active.
- A file-level Read grant alone does not authorize a non-head historical
  version.
- A historical version requires an explicit Read grant scoped to that
  `(fileId, versionNumber)`, in addition to active membership, the file-level
  Read grant, and a matching recipient envelope in the current envelope set.
- Historical grants use the existing file `READ_ACL_POLICY` authority and its
  configured Safe threshold. They are emitted as append-only events and
  indexed for history/audit views.
- Revoking file-level Read access blocks all versions, including versions
  with a historical grant or a previously issued envelope. Revocation also
  invalidates prior historical grants, so later re-granting file Read does not
  silently restore old-version access; each desired historical version must be
  granted again. As already specified, this cannot make a recipient forget a
  DEK or plaintext already obtained.
- The gateway must compare the requested version with the authoritative head
  at the same finalized block used for authorization. For a non-head version,
  it must require the version-scoped grant before appending a successful
  access audit record or returning any CID.

## Consequences

- `AccessGovernance` needs explicit version-scoped read state, a governed
  grant/revoke operation, a point-query interface, grant/revoke events, and a
  per-member/file Read-ACL generation so re-grants do not reactivate stale
  historical grants.
- The indexer must project those events so users can inspect granted history
  scope; its projection remains non-authoritative.
- The gateway and chain adapter must query the point authorization at one
  consistent finalized block. This check is implemented. The end-to-end share
  workflow and envelope-content membership verification are still pending; a
  successful access lookup currently returns CIDs after authorization and audit
  but does not prove that the recipient has a usable envelope in that object.
  Do not represent historical sharing or download as complete until that
  verification and retrieval path is implemented.
- This is an ABI change for any deployed contract. No persistent Phase 2
  deployment is recorded, but a future deployment must use the updated ABI.

## Approval record

The maintainer approved explicit per-version grants for historical access.

## Specification references

- `TECHNICAL_SPECIFICATION.md` §§6.3, 8.1, 9.5, 9.6, 15.3, and Phase 4.
