# ADR: Folder registry policy

**Status:** Accepted by maintainer  
**Decision scope:** On-chain folder identity, hierarchy, and authority

## Context

Specification §§7.1, 7.2.1, 8.1 and acceptance criterion 9 require a stable
logical file/folder hierarchy with indexer-backed listings and on-chain
metadata authority. They do not define folder creation/rename authority,
whether folders may move, or whether IDs may overlap file IDs.

## Decision

- `FileRegistry` owns folder records alongside file records. Folder IDs are
  stable opaque `bytes32` values and may not collide with a file or another
  folder ID.
- The zero `parentFolderId` denotes the organization root. A nonzero parent
  must be an existing folder in the same organization.
- Only the configured organization Safe may create or rename folders.
- A folder's parent is immutable after creation. This gives the hierarchy an
  acyclic construction without requiring unbounded ancestor traversal or a
  guessed maximum nesting depth.
- Files may be created in or moved to the root or an existing folder in their
  organization. File renames/moves continue to use the file's configured
  `FILE_METADATA_POLICY` authority.
- Folder enumeration remains an indexer responsibility; contracts expose
  point queries and events, not on-chain lists.

## Consequences

- Folder move/reparent and deletion workflows are not part of this increment.
  Adding them requires a cycle-safe bounded-depth policy and a migration or
  compatibility design for existing folder trees.
- Contract events contain visible names and folder relationships, consistent
  with the specification's MVP metadata-visibility decision.

## Specification references

- `TECHNICAL_SPECIFICATION.md` §§7.1, 7.2.1, 8.1 and 15.4.
