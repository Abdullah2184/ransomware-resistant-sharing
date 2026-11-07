# ADR: Deterministic UnixFS content package

**Status:** Accepted by maintainer  
**Decision scope:** Encrypted content root DAG, import parameters and Kubo
adapter boundary

## Context

Specification §§2, 6.1, 10.4.2, 12.2, 14 and Phase 3 require a root content
CID that commits to both the canonical encrypted manifest and every ciphertext
chunk. It also requires streamed uploads, canonical CID validation, Cluster
replication verification and private storage access. The specification does
not prescribe a concrete UnixFS or CAR import profile.

The maintainer selected a deterministic UnixFS directory profile rather than
a CAR upload format. Kubo's `/api/v0/add` accepts multipart streams and
constructs the directory DAG while returning each child CID and the root CID.

## Decision

- Represent a content package as one directory with `manifest.json` and
  `chunks/00000001`, `chunks/00000002`, etc. Chunk names use one-based,
  eight-digit, zero-padded decimal indexes.
- The manifest is the canonical compact JSON from the existing v1 schema.
  Chunk file bytes must match its ordered chunk references and declared byte
  lengths. The adapter rejects mismatched indexes or lengths before upload.
- Import with Kubo CIDv1, `sha2-256`, fixed-size `size-4194320` chunking
  (the maximum 4 MiB ciphertext chunk including its 16-byte AEAD tag),
  raw UnixFS leaves, `wrap-with-directory=true`, and no local pin. Do not
  preserve filesystem mode or modification time. These options make package
  names and content, not host filesystem metadata or upload order, determine
  the root DAG.
- Validate the canonical CID returned for each chunk against its manifest
  entry. Return the root directory CID as the file's `ContentCid`.
- Envelope sets remain separate canonical JSON objects imported as single
  UnixFS files with CIDv1 and SHA-256, using the same fixed-size chunking and
  raw-leaf settings but without a wrapping directory.
- Pin returned root CIDs through the authenticated IPFS Cluster API and do
  not return upload success until the configured count of distinct peer IDs
  reports `pinned`.
- Content retrieval exports the root UnixFS DAG as a CAR stream. Envelope-set
  retrieval returns the file contents. Consumers verify the manifest, chunk
  CIDs and AEAD tags before treating a download as successful.
- The replication count is configurable. Two peers on one development host
  verify allocation only and do not establish organization independence.

## Consequences

- The content upload port accepts a validated manifest plus individually
  streamed ciphertext chunks rather than an opaque file stream. This lets the
  adapter verify every manifest-to-chunk CID and build the required root DAG.
- The content root CID is a UnixFS directory CID; it is not the CID of the
  manifest file or the SHA-256 digest of plaintext.
- A `dag/export` response is a transport CAR representation of the UnixFS
  root. It does not change the stored root encoding.
- Changes to the directory layout, Kubo importer flags, CID version/hash,
  chunker or leaf profile require a new versioned profile and migration
  compatibility review.
- Kubo and Cluster APIs are trusted storage infrastructure for transport.
  End-to-end download integrity still requires the consumer to verify each
  CID and each encrypted chunk's authentication tag.

## Specification references

- `TECHNICAL_SPECIFICATION.md` §§2, 6.1, 10.4.2, 12.2, 14 and 16 Phase 3.

## Approval record

The maintainer selected the deterministic UnixFS directory profile over a
CAR v1 upload with an explicitly encoded DAG root.
