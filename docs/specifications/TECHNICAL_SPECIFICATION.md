# Blockchain-Based Ransomware-Resistant Data Sharing

## Technical Specification for Coding-Agent Implementation

**Document ID:** RRDS-TS-001  
**Version:** 1.0  
**Status:** Implementation baseline for prototype  
**Date:** 26 October 2026  
**Audience:** Coding agent, software engineers, reviewers

---

\newpage

# Contents

1. Purpose and implementation rules
2. Binding architecture decisions
3. Technology stack
4. System architecture and trust boundaries
5. Cryptographic specification
6. IPFS data formats
7. Blockchain Architecture and Contract requirements
8. Gateway and HTTP API
9. Core application workflows
10. Data model and event model
11. Project structure
12. Module interfaces and dependency direction
13. Configuration and operational behavior
14. Security and privacy requirements
15. Testing requirements
16. Implementation phases for the coding agent
17. Explicitly open deployment decisions
18. References and standards

\newpage

# 1. Purpose and implementation rules

This specification defines the prototype architecture, module boundaries, APIs, cryptographic formats, on-chain state transitions, workflows, tests and acceptance criteria for a consortium-operated encrypted file-sharing and recovery system.

The coding agent MUST implement the system in small, testable increments. It MUST NOT replace an interface or protocol with a convenient alternative without documenting the change in an Architecture Decision Record (ADR). It MUST NOT implement custom cryptographic primitives, persist raw keys to disk, silently ignore failed authorization, or describe a demo key provider as production HSM support.

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT** and **MAY** are normative requirements.

## Primary goals

- Store files encrypted before they leave the client endpoint.
- Store ciphertext redundantly in a private consortium IPFS Cluster.
- Store identities, ACL state, file-version history and security-relevant state transitions on a permissioned EVM ledger.
- Make successful access lookups and governance changes auditable.
- Support upload, download, modify, share, revoke, version history, restore/revert and recovery.
- Keep signing and long-term decryption private keys in a pluggable hardware-backed key-custody provider.
- Separate the CLI, application logic, cryptography, key custody, gateway, IPFS, indexer and contracts so the desktop GUI can be added later without rewriting domain logic.

## Non-goals for the first prototype

- Preventing endpoint infection or protecting plaintext while a compromised endpoint is actively processing it.
- A production-grade enterprise GUI, automatic sync daemon or filesystem driver.
- Automatic classification of every version as clean/malicious.
- Production PKI enrollment workflows, all enterprise HSM vendors, or cross-consortium regulatory compliance.
- Proxy re-encryption, zero-knowledge proofs, public IPFS publication, public-chain deployment or token economics.
- On-chain scanning of file bytes. Smart contracts cannot fetch IPFS data or inspect endpoint files.

# 2. Binding architecture decisions

These decisions are fixed for the first implementation unless changed through an ADR.

1. **Client-first encryption:** plaintext is encrypted locally by the client before upload. The gateway and IPFS adapter receive ciphertext only.
2. **Version-specific key:** generate a fresh random 256-bit data-encryption key (DEK, also called the version epoch key) for every new file version. Do not reuse the prior version's key for routine edits.
3. **Key envelopes off-chain:** the DEK is wrapped separately for each authorized reader and the envelope set is stored as an immutable IPFS object, not as raw keys or wrapped-key entries in contract storage. The chain stores the CID/reference and authorization state. A per-version envelope-set pointer can be updated by appending a `KEY_ENVELOPE_UPDATE` record; earlier envelope sets remain immutable.
4. **Content and envelope objects are separate:** encrypted content is one IPFS object/package; recipient-wrapped keys are a separate IPFS object. This lets a share operation add an envelope without re-encrypting the file bytes. Both CIDs are referenced by the ledger. This mechanism is abstracted away from the end-user.
5. **Upload ordering:** the encrypted content object and envelope object must be uploaded and pinned to the configured replication threshold before the version transaction is submitted to the chain. If chain submission fails, leave the blob unreferenced and let the retention/cleanup process deal with it later.
6. **Besu + QBFT:** use a permissioned Hyperledger Besu network with QBFT consensus. No proof-of-work and no public-chain deployment in the prototype.
7. **Solidity contracts:** `FileRegistry` owns file/folder metadata and version records, including the current-head pointer. `AccessGovernance` owns registered member keys, member status, Read/Write ACL state, policy/approval information and key-envelope references/updates. They are separate contracts with narrow interfaces. Routine access attempts are audited off-chain in PostgreSQL; they do not create blockchain transactions.
8. **Off-chain services are not the authority for authorization:** the gateway may pre-check requests, but state-changing operations must be independently authorized by the contracts. An indexer/database is a query projection, not an authorization source of truth. Additionally, the gateway runs on an independent system, not at the client-endpoint, so no invalid data or functionality references should be made.
9. **Identity proof:** registration binds an approved member identity to versioned signing and encryption public keys. Login uses a one-time signed challenge; a claimed member ID alone is not proof. EIP-712 operation signatures use domain separation, and contracts/gateway enforce nonce and expiry to prevent replay. 
10. **Separate key pairs:** use a signing key and an encryption/unwrap key as different key pairs. Do not reuse one private key for both purposes.
11. **Governance:** sensitive ACL, member, key and consortium operations use policy-defined approval thresholds. Consortium-wide changes require timelock. Emergency suspension may use a specifically configured emergency route, but remains auditable and must not allow an unauthenticated caller to lock out another identity. The specific access thresholds (such as multi-sig or specific IDs) for each file or governance-level changes (adding an organization, or user or removing one) should be configurable on a case-by-case basis.
12. **No `trustedVersion` flag in the MVP:** every accepted append is recorded as a version. An anomaly scanner can warn or hold a submission locally, but the ledger does not pretend that a signature proves content is benign. Recovery selects a version reviewed/identified as clean.
13. **Restore/revert is append-only:** restoring V1 when V2 is current creates V3 containing the recovered V1 plaintext re-encrypted under a fresh DEK. V3's parent is V2. Do not move the head backward or delete V2.
14. **Names/folders:** file display name and logical folder relationship may be visible to consortium participants on-chain for file browsing. 
15. **CLI first, GUI later:** build a CLI over the shared application core. Do not put business rules in CLI command handlers.
16. **Rate limiting:** enforce request throttling and failed-attempt telemetry at the gateway; enforce signatures, nonce/replay checks, ACL checks and state-transition invariants in contracts.

## Important terminology

- **File ID:** stable logical identity of a file across its versions.
- **Version:** immutable content snapshot with a parent version/hash.
- **DEK / version epoch key:** fresh 32-byte symmetric key used to encrypt one version.
- **Epoch ID:** identifier for the version-specific key epoch; a new one is generated for every version in the MVP.
- **Envelope set:** immutable object containing one HPKE-wrapped DEK per member/key version allowed to decrypt that particular version.
- **Content CID:** IPFS CID for the encrypted content package.
- **Envelope-set CID:** IPFS CID for the wrapped-key envelope object.
- **Current head:** mutable pointer to the latest accepted version; changing it does not rewrite prior version records.
- **Gateway:** off-chain authenticated API/relay/storage adapter. It is not a validator and is not part of QBFT consensus.
- **Indexer:** rebuildable service/database projection of finalized chain state and events.

# 3. Technology stack

| Area | Selected technology | Implementation rule |
| ---  |        ---          |        ---          |
| Workspace and core off-chain code | Rust stable, Cargo workspace | Pin toolchain and dependency versions in repository; keep domain logic independent from network/UI adapters. |
| Async runtime / HTTP API | Tokio + Axum | Use typed request/response models, timeouts, cancellation and bounded streaming. |
| Serialization | Serde + JSON for API and versioned JSON objects | Version every external schema; reject unknown required versions and malformed fields. Use deterministic canonical bytes when a byte-level hash/signature requires them. |
| EVM client | Alloy Rust ecosystem (provider, contract bindings, EIP-712 typed data) | Put all RPC/ABI details behind `chain_adapter`; do not spread ABI encoding through the domain layer. |
| Smart contracts | Solidity 0.8.x, compiled/tested with Hardhat 3 + TypeScript | Pin compiler and npm dependencies. Use OpenZeppelin Contracts for appropriate standard primitives. Do not invent a bespoke multisig if a maintained Safe / standard governance integration fits the chosen deployment. |
| Permissioned blockchain | Hyperledger Besu with QBFT | Keep validator keys and RPC credentials out of source control. Use a local multi-validator setup for integration tests. |
| Encrypted blob store | Kubo/IPFS + IPFS Cluster | Use private consortium deployment. Pin ciphertext/envelope objects and confirm replication before ledger commit. Never use a public gateway as the default storage backend. |
| Projection and gateway operational state | PostgreSQL | Stores derived indexer rows, gateway rate-limit counters and operational metadata only. It is not the source of truth for ACL decisions. |
| Key custody integration | Provider interface; PKCS#11 or vendor SDK adapter where supported | HSM topology/model is an ADR/open deployment decision. A test provider may be used only for local development. Production configuration must reject a software-key provider unless an explicit unsafe-development flag is set. |
| Logging/telemetry | `tracing` and structured JSON logs | Never log plaintext, DEKs, private keys, auth tokens, full envelope contents or unredacted sensitive metadata. |
| Integration environment | Docker Compose for development services | Besu, IPFS Cluster and PostgreSQL configs must be separate from application configuration. No production secrets in Compose files. |
| Tests | Rust unit/integration tests; Hardhat Solidity + TypeScript tests; end-to-end tests | Include negative authorization tests, crypto vectors, concurrency tests, failure injection and storage-replication checks. |
| User interface | CLI first (Rust `clap` or equivalent) | Commands delegate to application services. A later GUI calls the same application/API contracts. |


# 4. System architecture and trust boundaries

```text
                 USER / UNTRUSTED ENDPOINT
┌──────────────────────────────────────────────────────────────────┐
│ CLI (MVP) / future GUI                                            │
│        │                                                          │
│        v                                                          │
│ Shared application core ─── Crypto module (encrypt/decrypt/sign)   │
│        │                         │                                │
│        │                         v                                │
│        │                 KeyCustodyProvider interface              │
│        │                         │                                │
│        │                   HSM / hardware token                    │
└────────┼─────────────────────────┼────────────────────────────────┘
         │ authenticated HTTPS     │ signing / unwrap operations
         v                         │
┌──────────────────────── OFF-CHAIN SERVICES ────────────────────────┐
│ Rust API gateway: authentication, request validation, throttling, │
│ relay, successful lookup logging, streamed ciphertext upload      │
│       │                         │                                 │
│       ├── EVM adapter ───────────┼─────> Besu QBFT validator nodes │
│       │                         │        ├─ FileRegistry          │
│       │                         │        └─ AccessGovernance      │
│       ├── IPFS Cluster adapter ──┼─────> ciphertext/envelope CIDs  │
│       └── PostgreSQL <──────── Indexer (finalized event projection)│
└───────────────────────────────────────────────────────────────────┘

Trust notes:
- Plaintext and the DEK exist transiently in the client process during encryption/decryption.
- Gateway sees request metadata and ciphertext, not file plaintext or unwrapped keys by design.
- HSM protects long-term private keys; it does not automatically protect plaintext already on the endpoint.
- Contracts enforce authorization and state transitions; gateway pre-checks are not sufficient alone.
- IPFS CIDs are content identifiers, not secret access tokens. Encrypt content and keep the cluster private.
```

## 4.1 Layer responsibilities

| Layer/module | Responsibility | Must not do |
|     ---      |      ---       |     ---     |
| CLI / GUI    | Gather input, display results, call application use cases | No direct contract ABI logic; no security policy in UI code. |
| Domain       | File, version, member, ACL, policy and typed errors | No network, database, filesystem or HSM calls. |
| Application services | Orchestrate use cases and transaction order | No duplicated crypto primitives or direct SQL in use cases. |
| Crypto | Encrypt/decrypt bytes; wrap/unwrap DEK; build and verify manifests/signatures; hash helpers | No chain authorization decisions; no logging of secrets. |
| Key custody | Invoke HSM/token operations; key IDs and public-key lookup; sign/unwrap interface | Never persist private keys from production HSMs to a file. |
| Gateway | Challenge login, validate requests, rate-limit, stream ciphertext, relay authorized chain operations | Never assume session token alone authorizes a sensitive operation; never return CID/key-envelope reference before ACL check and successful lookup logging. |
| IPFS adapter | Add/get content packages and envelope sets; pin/verify replica counts; CID validation | Never accept plaintext input from application services; never mark upload durable just because `add` returned a CID. |
| `FileRegistry` | Stable file identity, folder/name metadata, version history and current head | No delete/update of historical version records; no IPFS/network calls. |
| `AccessGovernance` | Identity/key versions, member status, Read/Write ACL, proposals/approvals, envelope-set pointer updates and governance events | No raw DEKs or wrapped-key bytes in contract storage. |
| Indexer | Consume finalized events, rebuild searchable read model and history | Never be the final authorization authority; tolerate restart/replay. |
| Recovery tooling | Select candidate historical version, verify/decrypt and restore as a new version | Never overwrite or delete ledger history. |

## 4.2 Source of truth

- Member status, registered public keys and key versions: `AccessGovernance` contract.
- Current Read/Write permissions and suspension: `AccessGovernance` contract.
- File identity, visible name/folder metadata, accepted versions and head: `FileRegistry` contract.
- Latest envelope-set CID for a particular version: on-chain pointer updated only through an authorized `KEY_ENVELOPE_UPDATE` transition. Envelope contents themselves remain in IPFS.
- Ciphertext and envelope bytes: IPFS Cluster, addressed by their CIDs.
- Search/filter results and human-friendly history views: PostgreSQL indexer projection derived from finalized events.
- Gateway request counters, invalid attempts and operational health: off-chain operational state; selected security events can be appended to chain.
- Long-term private keys: HSM/hardware token or approved offline custody. Never the database, IPFS or chain.

Because a projection may lag, gateway-sensitive reads must either read authoritative contract state at a known block or verify that the projection is caught up to a finalised block. An out-of-date index may affect availability/search results, but must not grant access.

# 5. Cryptographic specification

Use reviewed, maintained library implementations. The algorithm identifiers and format version MUST be explicit in every encrypted package. Unknown algorithms or unsupported versions fail closed.

## 5.1 File encryption

- Algorithm: **AES-256-GCM** (256-bit key, 96-bit nonce, 128-bit authentication tag).
- Key: fresh 32-byte DEK generated with the operating system cryptographically secure random number generator for each file version.
- Chunk size: default 4 MiB, configurable only within documented tested limits.
- For large files, encrypt independently authenticated chunks rather than buffering the complete file in memory. For each version, generate a fresh random 64-bit nonce prefix. Construct the 96-bit GCM nonce as `noncePrefix[8] || chunkIndex[4-byte big-endian]`. Reserve chunk index 0 for encrypted private metadata, if present; file chunks use indexes 1..N. A version has a new DEK and prefix, so the nonce space is distinct by version. Reject a chunk count that would overflow the 32-bit index.
- Associated authenticated data (AAD) for each chunk MUST bind at least the protocol version, file ID, version number, epoch ID, chunk index and total chunk count. A chunk must not be transplantable between files/versions without authentication failure.
- Each chunk stores ciphertext and the GCM tag (combined or represented separately with an unambiguous versioned encoding). Store nonce prefix and algorithm identifiers in the manifest.
- No nonce may be reused with the same DEK. The implementation must have unit tests for nonce/index construction and verify every tag during decryption.
- On any authentication-tag failure, stop decryption, delete partial output securely where feasible, return an integrity error and do not deliver a successful restored file.

## 5.2 Recipient key wrapping

- Preferred scheme: **HPKE, RFC 9180 base mode**, with `DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`, and `AES-256-GCM` as the selected ciphersuite, when supported by the chosen maintained library and the chosen HSM/key-custody integration.
- Wrap exactly the 32-byte DEK for each authorized recipient's X25519 public encryption key. The envelope entry contains the recipient member ID, encryption-key version, HPKE encapsulated key, and wrapped DEK ciphertext (plus any format-required bytes).
- Use a domain-separated `info` string such as `rrds/key-wrap/v1`. Bind the file ID, version number, epoch ID, recipient member ID and recipient key version in authenticated context/AAD according to the HPKE API. Verify that these values match on unwrap.
- The wrapping implementation must have cross-implementation or published test vectors and negative tests (wrong recipient key, altered ciphertext, altered context, wrong version).
- Do not invent an ECIES variant or directly use raw ECDH output as an AES key.
- **HSM compatibility gate:** X25519/HPKE support varies by HSM. Keep wrapping and unwrapping behind `KeyCustodyProvider`. Before selecting production hardware, verify support for the chosen curves, operations, exportability policy and integration API. If unsupported, stop and record an ADR for a compatible standards-based alternative (for example, RSA-OAEP with SHA-256 and a suitable key size); do not silently downgrade or mix formats.

## 5.3 Digital signatures and request authentication

- EVM-compatible signing identity: **ECDSA over secp256k1**, so the contract can recover/verify the associated EVM address.
- Use **EIP-712 typed structured data** for version append, access lookup, envelope update, and other relayed operations. The EIP-712 domain MUST include chain ID and verifying contract address; messages must include an operation-specific nonce and deadline/expiry. EIP-712 by itself does not provide replay protection.
- Register the member's signing address/public key and a separate X25519 encryption public key. Store explicit key-version numbers and status (`Active`, `Suspended`, `Revoked`, `Superseded`).
- An HSM/token signs a challenge or typed operation; the private signing key never leaves custody. Do not allow a generic `sign arbitrary bytes` API to bypass operation-specific confirmation without an explicit policy.
- A new signing-key registration requires approved onboarding/proof of possession and a logged key-supersession flow. Registration is a binding to an approved organizational identity; it is not proof that the human using a compromised endpoint is legitimate.

## 5.4 Hashes and identifiers

- IPFS CIDs provide content addressing and verify the encoded IPFS DAG according to its CID profile. Do not equate a CID string with the SHA-256 digest of the original plaintext file.
- Use `keccak256` for EVM/EIP-712 typed digests, contract domain messages and Solidity signature verification.
- Use SHA-256 where required by the IPFS CID profile, file-level checksums and manifest integrity checks. Make hash purpose explicit in type and field names.
- File IDs should be opaque `bytes32` identifiers derived from secure randomness or a documented domain-separated derivation; do not derive IDs directly from a sensitive filename.
- A manifest signature binds the exact version metadata and content/envelope references. The contract also checks the current head and ACL; a valid signature alone is insufficient.

## 5.5 HSM and transient secret-handling rules

Define a `KeyCustodyProvider` interface for: obtaining the registered public keys/key IDs; signing a typed digest; unwrapping a DEK from a recipient envelope; provider health/capability checks; and optionally key provisioning or key-supersession operations. Provide adapters for supported production hardware and a clearly labelled test-only implementation.

The prototype may need the unwrapped DEK in client-process memory to run AES-GCM locally. Therefore, non-exportable HSM private keys do **not** mean the DEK is invisible to a compromised client process during file operations. If the hardware can perform HPKE decapsulation but returns the DEK to the client, the DEK is transiently exposed to the process. Document this limitation. Do not persist the DEK or log it. Use zeroizing secret buffers where practical and minimize the time the secret exists in memory.

Login must use challenge-response:
1. Client requests a challenge containing a cryptographically random nonce, issue time, short expiry, gateway audience and protocol version.
2. HSM signs the typed challenge with the registered signing key.
3. Gateway verifies signature, active member status, expiry, audience and one-time nonce; the nonce is consumed atomically.
4. Gateway issues a short-lived session token.
5. Any sensitive chain operation still requires its own typed operation signature/nonce. A session token is not a substitute for contract-level authorization.

# 6. IPFS data formats

The content package and envelope set are separate immutable IPFS objects. Use CIDv1 with a documented deterministic codec/chunking profile. Avoid relying on a public IPFS gateway. The CID is a locator/integrity identifier, not a password.

## 6.1 Encrypted content package

The package contains a versioned manifest and encrypted chunks. A conceptual manifest follows; implement the schema under `schemas/encrypted-file-manifest-v1.json` and validate it before decryption.

```json
{
  "schema": "rrds.encrypted-content.v1",
  "fileId": "0x...bytes32...",
  "versionNumber": 3,
  "parentManifestHash": "0x...",
  "epochId": "0x...bytes32...",
  "cipher": "AES-256-GCM",
  "nonceScheme": "prefix64-index32-v1",
  "chunkSizeBytes": 4194304,
  "chunkCount": 12,
  "noncePrefix": "base64url-8-bytes",
  "privateMetadata": {
    "encoding": "AES-256-GCM",
    "nonceIndex": 0,
    "ciphertext": "base64url..."
  },
  "chunks": [
    { "index": 1, "cid": "bafy...", "ciphertextBytes": 4194320 }
  ]
}
```

This is illustrative, not a fully escaped production example. Implement a canonical, versioned schema. For large files, store chunks as separate IPFS blocks and a root DAG/CAR package instead of embedding all ciphertext in JSON. The root CID must commit to all chunk data and manifest fields. Private metadata may include a sensitive description or original filename. Visible file display name and parent folder are kept in the on-chain file-manager metadata per the MVP decision.

## 6.2 Envelope-set object

```json
{
  "schema": "rrds.key-envelope-set.v1",
  "fileId": "0x...",
  "versionNumber": 3,
  "epochId": "0x...",
  "wrappingSuite": "HPKE-X25519-HKDF-SHA256-AES256GCM",
  "revision": 2,
  "envelopes": [
    {
      "memberId": "0x...",
      "encryptionKeyVersion": 1,
      "encapsulatedKey": "base64url...",
      "wrappedDek": "base64url..."
    }
  ]
}
```

The real schema MUST document byte encodings, maximum list sizes, duplicate-member rejection, sorted/canonical order (sort by stable member ID and key version), suite IDs and version compatibility. The envelope set contains no plaintext DEK and no private keys. Do not store wrapped DEKs in a Solidity mapping.

## 6.3 Envelope updates

Envelope sets are immutable. Adding a reader to an existing version creates a new envelope-set object and calls an authorized `KEY_ENVELOPE_UPDATE` transition that changes the current pointer for that version and emits an event containing the old/new CIDs (or hashes), actor, policy/proposal ID and timestamp. The old object is not modified. Access to a version requires both (a) current authorization under policy and (b) an envelope for the recipient's current encryption key version.

Historical access is **not implied** by a current-file grant; the default UI/CLI must make the history scope explicit. The system cannot revoke a key or plaintext that the recipient already obtained.

# 7. Contract Requirements and Blockchain Transaction Architecture

## 7.1 Contract Separation and Responsibilities

The application shall use two primary Solidity contracts: `AccessGovernance.sol` and `FileRegistry.sol`. Each contract shall maintain a clearly defined category of authoritative state. Their responsibilities shall remain separate to avoid duplicated state, inconsistent authorization decisions and unnecessary contract coupling.

`AccessGovernance.sol` — Identity, authorization and governance state

This contract shall manage:

- Organization and member registration and lifecycle management.
- Member identity records, including stable member identifiers, organization association and registered signing addresses.
- Versioned encryption public keys and their registration status.
- Active, suspended and revoked member/key states.
- Per-file Read and Write ACL membership, optimized for membership queries.
- Scoped governance policies and approval thresholds.
- Governance proposal identifiers, approval records, nonces, execution status and expiry conditions, either directly or through reviewed governance modules.
- Timelock integration and authorized governance execution.
- Current envelope-set CID pointers and revisions for individual file versions.
- Envelope-set update history events.

The contract shall never store plaintext DEKs, private keys or envelope-set contents. Only references and associated integrity metadata shall be stored on-chain.

ACL membership shall be represented using mappings keyed by file and stable member identity. Enumerating ACL members shall be handled through emitted events and the PostgreSQL indexer rather than on-chain array iteration.

`FileRegistry.sol` — File and version state

This contract shall manage:

- File creation using opaque, stable File IDs.
- Visible file names and folder relationships, subject to the consortium's metadata-visibility policy.
- Creator identity, organization association, file status and creation metadata.
- Append-only per-file version records.
- A single mutable current-head pointer for each file.
- Version numbering, parent-manifest consistency and optimistic concurrency validation.
- Visible file renaming, moving and supported metadata changes as logged state transitions.
- Restore/revert operations, implemented as new version creation rather than modification of historical records.

A common registry shall manage all files using mappings keyed by File ID. One contract shall not be deployed per file.

Both contracts shall expose narrow, explicitly defined interfaces. Events shall provide the historical audit record and indexer input. Since contracts cannot query their own historical event logs as contract state, every invariant requiring a current answer shall have an explicit storage field or a query to the authoritative contract.

## 7.1.1 Interaction Between the Contracts

The contracts shall interact through defined Solidity interfaces.

| Responsibility                                   | `FileRegistry.sol`                                                 | `AccessGovernance.sol`                                    |
| ------------------------------------------------ | ------------------------------------------------------------------ | --------------------------------------------------------- |
| File IDs, display names and folder relationships | Authoritative                                                      | References File IDs                                       |
| File metadata and status                         | Authoritative                                                      | Reads where required for authorization                    |
| Version records                                  | Authoritative                                                      | References version identifiers                            |
| Current file head                                | Authoritative                                                      | No authority                                              |
| Member identities and organization association   | Reads through interface                                            | Authoritative                                             |
| Registered public keys and key status            | Reads through interface                                            | Authoritative                                             |
| Read and Write ACLs                              | Checks through interface                                           | Authoritative                                             |
| Current envelope-set pointer per version         | Stores the initial envelope reference in immutable version context | Authoritative current pointer and revision                |
| Governance policies and approvals                | No governance authority                                            | Authoritative or delegated to reviewed governance modules |
| Read authorization                               | No read-side state mutation                                        | Authoritative Read ACL and member-status query            |
| Access-attempt audit                             | Not stored                                                          | Not stored; gateway writes the protected PostgreSQL audit record |

Cross-contract operations shall execute within the same EVM transaction whenever atomic consistency is required.

For initial version creation:

1. The client uploads and pins the encrypted content package and initial envelope-set object to IPFS.
2. The client submits the signed version-creation operation through the gateway.
3. `FileRegistry.sol` validates the application signature, active member identity and organization association, application nonce, deadline and expected initial file state.
4. `FileRegistry.sol` creates the immutable version record and advances the current head.
5. It calls a restricted initialization function in `AccessGovernance.sol` to register the file policy, grant the signed creator initial Read and Write access, and register the initial envelope-set CID and revision for that file version.
6. Both contracts' state changes either complete successfully or revert atomically. The signed creator's initial ACL grants are part of file creation; subsequent version appends require an existing Write ACL.

Only `FileRegistry.sol` shall be authorized to initialize envelope pointers as part of version creation. Subsequent envelope-set changes shall use the relevant authorized governance or access-management functions in `AccessGovernance.sol`.

For later sharing or recipient-key updates, a new immutable envelope-set object shall be uploaded to IPFS. `AccessGovernance.sol` shall update the current envelope-set pointer and revision for the relevant version. Existing file-version records and encrypted content packages shall not be rewritten.

PostgreSQL shall maintain searchable projections of these states but shall not become an alternative authority for ACLs, member status or envelope pointers.

## 7.2 File and File-Version Data Model

### 7.2.1 File Record

Each file shall be identified by a stable opaque File ID.

The file record shall contain, at minimum:

- `fileId`
- `displayName`
- `parentFolderId`
- `creatorMemberId`
- `organizationId`
- `creationTimestamp`
- `fileStatus`
- `currentVersionNumber`
- `currentHeadManifestHash`

The File ID shall remain unchanged throughout the file's lifecycle. File renaming, moving and metadata modifications shall not generate a new File ID.

Folder relationships shall use stable folder identifiers. File and folder listings shall be exposed through indexer-backed application queries. The contract shall not rely on expensive on-chain enumeration loops.

Visible names and folder relationships may be stored on-chain only under the assumption that their contents are visible to consortium participants. Sensitive descriptions and metadata shall be encrypted or retained off-chain where required.

### 7.2.2 File-Version Record

Each successful version append shall create an immutable record containing at least:

- `fileId`
- Monotonically increasing `versionNumber`
- `parentManifestHash` — zero only for the initial version.
- `contentCID` — complete, retrievable IPFS content-package identifier.
- `initialEnvelopeSetCID` — initial envelope-set object reference.
- `epochId` — identifier of the key epoch associated with the version.
- `manifestHash` — digest of the canonical signed version manifest.
- `authorMemberId`
- `authorSigningAddress`

CIDs shall be stored in a representation that preserves their complete retrieval identifiers, such as canonical strings or typed encoded CID bytes. Storing only a digest of a CID is insufficient unless the complete identifier can be recovered from another authoritative record.

The `currentHeadManifestHash` and `currentVersionNumber` shall be maintained separately from the immutable version history. A successful append shall atomically create the version record and advance the file's current head.

Block timestamp, block number, transaction hash and transaction index shall be obtained from the blockchain block and transaction receipt by the indexer. They shall not be treated as arbitrary client-supplied metadata.

### 7.2.3 Version Append Validation

A version append shall be rejected unless all applicable conditions are satisfied:

- The application signature is valid.
- The signer maps to a registered member identity.
- The member and signing key are active and not suspended or revoked.
- The member is present in the file's Write ACL.
- The application nonce has not previously been consumed.
- The operation deadline has not expired.
- The file exists and is in a writable state.
- The submitted version number is the expected next version number.
- The submitted parent manifest hash matches the current file head.
- Required CID and manifest fields are correctly encoded.
- The envelope-set reference is provided and satisfies the expected format.

The contract shall enforce optimistic concurrency through the expected-parent check. If another editor has already appended a version, a request referencing the previous head shall fail. The client must retrieve the new head, reconcile its changes and submit a new version operation.

The contract cannot inspect IPFS content, independently verify the plaintext-to-ciphertext transformation or determine whether sufficient IPFS replicas exist. The application and storage layers shall complete upload verification and required pin acknowledgements before submitting the version transaction.

### 7.2.4 Version-Specific Encryption and Envelope State

Each newly created file version shall use a fresh cryptographically random DEK. The `epochId` shall identify the key epoch used for that version.

Recipient-specific wrapped DEKs shall be stored in an envelope-set object in IPFS. The corresponding version's initial envelope-set CID shall be captured in its immutable version context, while `AccessGovernance.sol` maintains the authoritative current envelope-set CID and revision.

Sharing an existing version shall add a recipient-specific wrapped DEK to a new envelope set for that version, subject to the applicable authorization policy. Access to historical versions shall be granted explicitly rather than automatically inferred from permission to access the current version.

A restored version shall be created as a new version with a fresh DEK. The restored content shall be re-encrypted and appended against the current head. Historical version records shall remain unchanged.

## 7.3 On-Chain Signing Envelope and Operation Authorization

Application-level operations shall use EIP-712 typed-data signatures.

For a version append, the typed message shall bind at least:

- `fileId`
- `versionNumber`
- `parentManifestHash`
- Hash of the complete `contentCID` representation
- Hash of the initial `envelopeSetCID` representation
- `epochId`
- `manifestHash`
- `memberId`
- `signerAddress`
- `operationNonce`
- `deadline`

The EIP-712 domain shall include:

- Chain ID.
- Verifying contract address.
- Domain name.
- Domain version.

For operations authorized by `FileRegistry.sol`, the verifying contract shall be the deployed FileRegistry address. Governance operations shall use the appropriate `AccessGovernance.sol` domain and operation-specific typed structures.

The contract shall recover the signing address and resolve it to the registered member identity. It shall then validate the current identity state and relevant ACL permissions.

The member signing key shall remain separate from the member encryption key. The signing mechanism and HSM integration shall support the Ethereum-compatible ECDSA signing requirements used for EIP-712 verification.

Matching typed structures and canonical encodings shall be implemented in Solidity and Rust. The project shall include fixed test vectors covering successful signing, invalid signatures, incorrect domain values, modified parameters, expired operations and replayed operations. Any encoding mismatch shall result in a test failure. Raw-message signing shall not be used as a fallback.

### 7.3.1 Relayed Transaction Authorization

The prototype shall use gateway-operated transaction relayers.

The member signs an EIP-712 application operation. The gateway verifies the signature and submits a separate Ethereum transaction using its own relayer account.

Since the relayer submits the Ethereum transaction, `msg.sender` identifies the relayer rather than the originating member. The contracts shall therefore recover and authenticate the application signer from the EIP-712 message.

The recovered member identity shall be used as the logical author/requester in file records and audit events. The relayer address shall not be treated as the file author or requesting member.

Gateway-side signature verification shall be an early rejection mechanism only. Contract-side signature and authorization validation shall remain authoritative.

If direct user-signed Ethereum transactions are introduced in a future implementation, they shall use the same application authorization rules.

## 7.4 Access Authorization and Retrieval Audit

Routine access is a read operation, not a blockchain state transition. The gateway shall query authoritative Besu contract state with `eth_call` at a sufficiently recent finalized block to verify member status, Read ACL membership, version existence and the current envelope-set reference. It shall not submit an access-lookup transaction, consume an on-chain application nonce, or wait for QBFT finality for an ordinary read. When an access lookup uses an EIP-712 operation nonce, the gateway shall consume it atomically in the protected PostgreSQL replay store before releasing protected references or ciphertext; it is not an on-chain nonce.

Every access attempt shall be recorded in the protected PostgreSQL audit store, including successful and failed authentication, authorization, version lookup, content retrieval and envelope retrieval attempts. Each record shall contain, as applicable:

- Actor identity and signing-key version, or the unauthenticated source identifier when no verified actor exists.
- Resource type and stable resource identifier (file/version/CID); do not record plaintext names or secret material.
- Action and outcome, with a bounded reason code for failures.
- UTC event timestamp, request/operation identifier and correlation/trace identifier.
- Relevant organization, gateway instance and authoritative chain ID/block reference used for the authorization decision.

The audit append shall be committed before the gateway returns protected content references or ciphertext. If the required audit append fails, the gateway shall fail closed and not release protected data. Failed attempts shall be recorded without revealing whether a private file, version, CID or envelope exists to the requester.

Audit records shall be append-only to application roles and integrity-protected by a per-stream cryptographic hash chain. Database privileges shall separate audit insertion from read access and prohibit ordinary gateway roles from updating or deleting audit rows. Access to audit queries shall be restricted and audited. Selected security alerts may be emitted on-chain or periodically anchored by digest under the configured security/governance policy; this does not put every access attempt on-chain.

IPFS CIDs are content identifiers, not access credentials. Anyone who obtains a CID may attempt to retrieve the corresponding ciphertext if the storage network is reachable. The prototype shall restrict application-facing IPFS RPC access to authorized gateway and storage services and route normal client retrieval through the gateway. The system shall nevertheless document that a leaked CID and previously obtained encryption key may permit access to copied ciphertext outside the controlled retrieval path.

IPFS CIDs are content identifiers, not access credentials. Anyone who obtains a CID may attempt to retrieve the corresponding ciphertext if the storage network is reachable. The prototype shall restrict application-facing IPFS RPC access to authorized gateway and storage services and route normal client retrieval through the gateway. The system shall nevertheless document that a leaked CID and previously obtained encryption key may permit access to copied ciphertext outside the controlled retrieval path.

## 7.5 Governance, Multisignature and Timelock Requirements

Governance authorization shall use a reviewed threshold-approval implementation rather than a custom multisignature cryptographic scheme.

The deployment shall evaluate a Safe-compatible threshold account integrated with OpenZeppelin `TimelockController`, or an equivalent reviewed implementation. The selected design, executor permissions and role configuration shall be recorded in an architecture decision record (ADR).

Protected contract functions shall only be executable through their configured governance authority. Temporary deployment-owner or administrator privileges shall be removed or restricted before the deployment is considered operational.

Governance shall be scoped according to organizational authority:

| Operation                                | Required authorization                                                   |
| ---------------------------------------- | ------------------------------------------------------------------------ |
| Consortium membership changes            | Consortium-level threshold approvals and configured timelock             |
| Validator-set changes                    | Consortium-level threshold approvals and configured timelock             |
| Organization-level member management     | Relevant organization's internal threshold policy                        |
| Organization-level ACL changes           | Relevant organization's internal threshold policy                        |
| Permission-expanding system-wide changes | Threshold approvals and configured timelock                              |
| Emergency member suspension              | Explicitly configured emergency quorum or pre-authorized circuit breaker |
| Emergency suspension reversal            | Human-reviewed governance approval                                       |

Emergency suspension shall be narrowly scoped. It shall not provide a general mechanism for granting permissions, modifying file versions or bypassing governance approval requirements. Suspension events shall be logged, and reinstatement shall require reviewed governance authorization.

The automated circuit breaker shall use authenticated signals and configured thresholds. Invalid requests containing a claimed victim identity shall not independently cause that identity to be suspended. Rate-limit enforcement and suspension policies shall be designed to prevent deliberate denial-of-service against legitimate members.

Read and Write ACL modifications shall remain distinct:

- Removing a member from the Write ACL prevents future authorized version appends by that member.
- Removing a member from the Read ACL prevents future authorized retrievals and requires subsequent envelope sets to exclude that member's key.
- Any future version shall use a fresh DEK and recipient-specific envelopes for the currently authorized readers.
- Previously issued DEKs and plaintext shall not be considered retroactively revoked.

ACL changes shall not modify file-version history. Each governance operation shall record its approval policy, approving signers, effective time, operation scope and affected file/epoch references where appropriate.

QBFT validator consensus shall remain separate from application governance. Validator approval of a block does not replace the required multisignature authorization for ACL, membership or governance changes.

The initial network shall contain at least four independently operated validators to tolerate one faulty validator under the selected QBFT fault model.

## 7.6 Blockchain Network, Native Currency and Token Requirements

The blockchain network shall use Hyperledger Besu with QBFT consensus and the EVM execution environment.

The system shall not require an ERC-20, ERC-721 or other application-level economic token. File IDs, member IDs, ACL entries, version identifiers and epoch IDs shall be represented through contract state and shall not be implemented as cryptocurrency or NFT assets.

The private network shall use its own configured chain ID and native currency parameters. Its native currency shall not represent a tradable asset or require a public-market value.

The prototype shall use a zero-gas-price configuration to eliminate monetary transaction fees. Gas metering and execution limits shall remain enabled.

All Besu nodes shall use consistent genesis configuration, chain ID, QBFT parameters, EVM fork configuration and gas policy. Network-level configuration shall be recorded and version-controlled independently of application configuration.

Besu nodes are independent of user end-points and the gateway. No invalid data access or interdependent
function calls should be made. Communication is only through the pre-defined protocols and interfaces.

The system shall use separate node roles where appropriate:

- Validator nodes: Participate in QBFT consensus and block finalization.
- RPC nodes: Provide JSON-RPC access for gateways and development tools; shall not hold validator credentials unless explicitly configured as validators.
- Gateway/relayer services: Authenticate application requests and submit blockchain transactions.
- Indexer services: Consume finalized block events and maintain PostgreSQL projections.

Validator private keys shall remain within validator infrastructure and shall never be made available to gateway or ordinary client processes.

## 7.7 Accounts, Relayers and Ethereum Transaction Submission

### 7.7.1 Key and Account Separation

The system shall maintain separate cryptographic credentials for the following purposes:

| Credential              | Purpose                                                | Custody                             |
| ----------------------- | ------------------------------------------------------ | ----------------------------------- |
| Member signing key      | EIP-712 application-operation authorization            | Member HSM/key-custody provider     |
| Member encryption key   | Unwrapping recipient-specific DEKs                     | Member HSM/key-custody provider     |
| Relayer transaction key | Signing Ethereum transactions submitted by the gateway | Organization-controlled key custody |
| Validator key material  | QBFT validator authentication and consensus            | Validator infrastructure            |

The member signing key and encryption key shall remain independent. Relayer keys shall not be reused as member signing keys. Validator keys shall not be reused as application or relayer credentials.

The selected key-custody implementation shall be validated against the required cryptographic algorithms and hardware interface capabilities. Support for PKCS#11 alone shall not be assumed to imply support for every required curve or cryptographic operation.

### 7.7.2 Relayer Responsibilities

The gateway shall submit approved application operations using an organization-controlled relayer account.

The gateway shall:

- Verify the member's EIP-712 signature.
- Validate the structure and expiry of the application request.
- Perform preliminary identity and permission checks.
- Apply rate limits and resource limits.
- Construct the ABI-encoded contract call.
- Assign an appropriate transaction gas limit.
- Manage the relayer's Ethereum account nonce.
- Sign the Ethereum transaction using the relayer key.
- Submit the transaction to a configured Besu RPC endpoint.
- Track the transaction hash and finalization status.
- Return the operation outcome to the client.

Relayer privileges shall not bypass contract authorization. The contracts must independently validate the original member signature and applicable authorization state.

Relayer key compromise shall be treated as a transaction-submission infrastructure incident. A compromised relayer must not be able to create valid member signatures or independently grant file permissions.

### 7.7.3 Ethereum Transaction Structure

State-changing operations shall use Ethereum-compatible signed transactions containing:

| Field                               | Purpose                                                               |
| ----------------------------------- | --------------------------------------------------------------------- |
| `chainId`                           | Identifies the target private blockchain                              |
| `nonce`                             | Sequential transaction nonce of the relayer account                   |
| `to`                                | Destination smart-contract address                                    |
| `value`                             | Native currency transferred; zero for ordinary application operations |
| `input`                             | ABI-encoded contract function and parameters                          |
| `gasLimit`                          | Maximum gas allocated to transaction execution                        |
| `gasPrice` or applicable fee fields | Transaction fee configuration                                         |
| `signature`                         | Relayer's Ethereum transaction signature                              |

Transaction format and fee fields shall be compatible with the configured Besu network and EVM fork.

File contents shall never be submitted as transaction calldata. Transactions shall contain only the references, identifiers, hashes, signatures and metadata necessary for contract execution.

## 7.8 Transaction Nonces and Replay Protection

Two independent nonce mechanisms shall be implemented.

Ethereum transaction nonce: The sequential nonce associated with the relayer's Ethereum account. It establishes transaction ordering and prevents reuse of previously processed sender transactions.

Application operation nonce: The nonce associated with a member's application authorization. For state-changing operations, the appropriate smart contract validates and consumes the nonce atomically. For routine read-only access lookups, the gateway validates and consumes the signed nonce atomically in the protected PostgreSQL replay store, consistent with §7.4; it does not submit a blockchain transaction.

Operation nonces shall be bound to their signed typed-data messages. Nonce scope and storage shall distinguish state-changing contract operations from read-only access lookups.

The nonce mechanisms shall support concurrent operations without allowing the same authorization message to execute more than once. The selected nonce policy, including sequencing and concurrent-submission behavior, shall be documented and tested.

All sensitive application operations shall include an expiry deadline. Expired operations shall be rejected by the contracts, even if the gateway accepted the request earlier.

Governance proposals shall use their own proposal identifiers and lifecycle state. A governance proposal shall not rely solely on an application member's ordinary operation nonce.

## 7.9 Gas Management and Execution Limits

Gas shall be used to meter EVM computation and constrain transaction execution.

The implementation shall distinguish between:

- `gasLimit`: Maximum gas allocated to the transaction.
- `gasUsed`: Actual gas consumed during execution.
- `gasPrice`: Monetary cost per unit of gas.
- Transaction fee: Gas consumed multiplied by the applicable gas price.

The prototype shall use zero-priced transactions while retaining gas metering, transaction-level limits and block-level gas limits.

The Besu network shall be configured consistently to accept the selected zero-gas-price transaction policy, including the relevant minimum gas price, sender-balance checks and base-fee configuration where applicable to the selected EVM fork.

The gateway shall estimate gas or assign operation-specific gas limits for supported contract functions. Gas limits shall be bounded and configurable. The application shall reject requests that exceed configured transaction resource limits before submission.

Large encrypted files and file chunks shall remain in IPFS. Only the content identifiers and necessary metadata shall be recorded on-chain.

Gas consumption shall be measured for major contract operations, including file creation, version append, ACL modification, envelope-pointer update and governance execution. Routine access checks are read-only and shall not require gas-consuming transactions. Excessive storage writes, expensive enumeration and oversized event payloads shall be avoided.

## 7.10 QBFT Consensus and Validator Responsibilities

QBFT validators shall maintain a consistent blockchain state through block proposal, transaction execution and consensus.

Each validator shall:

- Validate incoming Ethereum transactions according to network rules.
- Verify Ethereum transaction signatures and sender nonces.
- Verify applicable transaction parameters and gas constraints.
- Execute transactions against the current EVM state.
- Execute smart-contract code deterministically.
- Participate in QBFT block proposal and consensus.
- Verify proposed blocks and resulting state transitions.
- Finalize blocks when the required validator quorum is achieved.
- Maintain the finalized blockchain state.

The QBFT fault model shall follow:

\\[ N \geq 3f+1 \\]

where \\(N\\) is the number of validators and \\(f\\) is the maximum number of faulty validators the network is designed to tolerate.

The initial four-validator deployment shall tolerate one faulty validator and require a three-validator quorum for finalization.

For a QBFT network, the latest block returned by the trusted execution client is the latest block committed by the required QBFT quorum and is treated as finalized. The generic JSON-RPC `finalized` tag is a proof-of-stake finality tag and MUST NOT be assumed to work on QBFT networks. Implementations MUST query and record the QBFT committed head (and its hash), then use its explicit block number for related authoritative contract reads.

If the required quorum cannot be achieved, block finalization may halt. Application operations shall remain pending or fail according to their transaction lifecycle status; they shall not be treated as committed without finality.

Validator execution shall enforce contract rules through deterministic EVM execution. This includes execution of the EIP-712 signature-recovery logic and application authorization checks implemented in the contracts.

QBFT consensus does not independently determine whether a file upload is legitimate. It establishes agreement on the execution and resulting blockchain state. Application-level authorization is enforced by the smart contracts.

## 7.11 Transaction Finality, Receipts and Event Emission

A state-changing transaction shall be treated as committed only after its inclusion in a finalized QBFT block.

The gateway shall not release protected content references based solely on transaction submission, transaction-pool acceptance or the existence of a pending transaction hash.

The implementation shall distinguish between:

- Transaction accepted by an RPC endpoint.
- Transaction pending in the network.
- Transaction included in a block.
- Transaction finalized.
- Transaction execution successful.
- Transaction execution reverted.

A transaction may be included and finalized even when its contract execution fails. In that case, the transaction receipt shall indicate failed execution, and its contract state changes shall have been reverted. The client shall not report the requested operation as successful.

Smart contracts shall emit structured events for significant successful state transitions.

The event model shall include, at minimum:

| Event category      | Representative events                                                            |
| ------------------- | -------------------------------------------------------------------------------- |
| File management     | `FileCreated`, `FileVersionAppended`, `FileRenamed`, `FileMoved`, `FileRestored` |
| Access governance   | `AccessGranted`, `AccessRevoked`, `EnvelopeSetUpdated`                           |
| Identity management | `MemberRegistered`, `MemberSuspended`, `MemberRevoked`, `SigningKeyUpdated`      |
| Governance          | `ProposalCreated`, `ProposalApproved`, `ProposalExecuted`, `ProposalCancelled`   |
| Security            | `EmergencySuspension`, `SecurityAlertRecorded`                                   |

Events shall contain the identifiers and references required by the indexer while avoiding confidential file metadata.

The indexer shall consume finalized events, decode them and update PostgreSQL projections. It shall maintain checkpoints using finalized block numbers and block hashes and process events idempotently using transaction hashes and log indices.

An event shall be treated as historical evidence of a successful contract state transition, not as an independent authoritative state store. Current authorization and file-head decisions shall continue to use contract state.

## 7.12 Indexer Consistency and Authoritative State

PostgreSQL shall maintain searchable projections of finalized blockchain data. It shall not independently authorize file access or mutate the authoritative state held by the smart contracts.

The indexer shall maintain:

- Last processed finalized block number.
- Corresponding block hash.
- Decoded contract events.
- Reconstructed file and version projections.
- Reconstructed identity and ACL projections.
- Envelope-set revision projections.
- Searchable audit records.

Indexer processing shall be idempotent and recoverable. It shall be possible to rebuild the database projections from the blockchain event history and the relevant contract state.

Because a projection may lag behind the blockchain, gateway-sensitive operations shall not rely solely on PostgreSQL permissions or membership status.

For security-sensitive reads, the gateway shall either:

1. Query the authoritative contract state at a known finalized block; or
2. Verify that the indexer has processed all relevant events through the required finalized block and that the projection corresponds to that block.

Where consistency cannot be established, the gateway shall use an authoritative contract query or reject/defer the operation. It shall not grant access based on potentially stale projected state.

A stale index may affect file search results, availability and application performance, but it shall never grant authorization that the current contract state rejects.

## 7.13 Transaction Failure Handling and Recovery

The gateway and client shall implement explicit handling for transaction failures and uncertain submission outcomes.

The implementation shall account for:

- Invalid Ethereum transaction signatures.
- Invalid or reused relayer transaction nonces.
- Invalid EIP-712 application signatures.
- Reused application operation nonces.
- Expired application requests.
- Insufficient gas limits.
- Contract authorization failures.
- Stale parent-manifest references.
- Reverted contract operations.
- Relayer RPC failures.
- Transactions remaining pending.
- Validator unavailability and failure to finalize blocks.
- Gateway or indexer interruption.

A transaction submission timeout shall not automatically be considered a failed transaction. The gateway shall query the transaction hash, relayer account nonce and relevant transaction receipt before deciding whether to retry or replace a transaction.

The application shall use idempotent submission handling and contract-side replay protection to prevent duplicate operations.

A stale-parent rejection shall trigger the concurrent-edit workflow: retrieve the latest finalized head, reconcile the client's changes and create a new signed version operation.

A successful IPFS upload followed by a rejected or reverted blockchain transaction may leave an unreferenced encrypted object. Such objects shall be recorded as orphan candidates and handled through a configurable retention and cleanup process. Cleanup shall verify that an object is not referenced by any finalized version or active envelope set before unpinning or deleting it.

A failed or reverted contract operation shall not modify the authoritative file-version, ACL or governance state.

## 7.14 Required Blockchain Configuration Parameters

The following parameters shall be configurable through environment-specific deployment configuration. Private keys and sensitive credentials shall be supplied through secure key-custody or secret-management mechanisms rather than committed to source control.

| Parameter                            | Description                                               |
| ------------------------------------ | --------------------------------------------------------- |
| `CHAIN_ID`                           | Private blockchain chain identifier                       |
| `BESU_RPC_URL`                       | Besu JSON-RPC endpoint                                    |
| `QBFT_BLOCK_PERIOD`                  | Configured QBFT block period                              |
| `QBFT_VALIDATOR_SET`                 | Authorized validator membership                           |
| `MIN_GAS_PRICE`                      | Minimum accepted transaction gas price                    |
| `BLOCK_GAS_LIMIT`                    | Maximum gas permitted per block                           |
| `DEFAULT_TX_GAS_LIMIT`               | Default transaction gas limit                             |
| `RELAYER_ADDRESS`                    | Gateway relayer Ethereum address                          |
| `RELAYER_KEY_PROVIDER`               | Key-custody provider for relayer signing                  |
| `CONTRACT_FILE_REGISTRY_ADDRESS`     | Deployed FileRegistry contract address                    |
| `CONTRACT_ACCESS_GOVERNANCE_ADDRESS` | Deployed AccessGovernance contract address                |
| `APPLICATION_NONCE_POLICY`           | Application-level nonce handling configuration            |
| `TRANSACTION_CONFIRMATION_TIMEOUT`   | Maximum configured transaction-status waiting period      |
| `INDEXER_START_BLOCK`                | Initial block from which the indexer processes events     |
| `FINALITY_CHECK_INTERVAL`            | Frequency of finalized-block monitoring                   |
| `INDEXER_CONFIRMATION_POLICY`        | Rule used to determine the block height safe for indexing |
| `GOVERNANCE_EXECUTOR_ADDRESS`        | Authorized governance execution address                   |
| `TIMELOCK_DELAY`                     | Configured delay for applicable governance operations     |

Contract addresses, chain identifiers, validator configuration, gas policies and governance parameters shall be environment-specific. Development, integration-testing and production deployments shall use separate configurations.


# 8. Gateway and HTTP API

The gateway is a replicable off-chain Rust service. It authenticates requests, checks current state, applies rate limits, streams ciphertext to storage, relays typed signed transactions and provides a stable API to CLI/GUI. It is not a blockchain validator. It should be as stateless as possible; PostgreSQL/Redis-like shared counters may be used for distributed throttling if needed, but no new mandatory Redis dependency is introduced unless warranted. In the overall system, the distributed gateway can live on a server specific to a particular organization. So based on user meta-data, the requests from an endpoint is sent to that organization's server. The gateway accepts requests from multiple endpoints and should be able to seamlessly and safely provide services for all of them. Mechanisms to prevent data races, invalid data accesses and duplicated login challenges should be implemented. It should also be hardened from potential DDoS attacks.

The gateway should apply independent budgets for:
- Unauthenticated traffic: challenges, malformed requests and failed signature checks, primarily limited by source IP or network.
- Authenticated activity: per member, organization and enrolled device, where applicable.
- Resource consumption: concurrent streams, upload/download bytes, active uploads and costly chain RPC operations.
- Sensitive operations: version appends, access lookups, key-envelope updates and governance requests.
For the prototype, I recommend a configurable token-bucket-style limiter backed by PostgreSQL. It should use atomic database updates or row locking, so concurrent gateway replicas cannot all read the same remaining quota and independently exceed it.

## 8.1 API requirements

All endpoints use TLS in non-local deployments, JSON for control metadata and streaming binary/multipart bodies for large ciphertext objects. Apply body-size limits, timeouts, request IDs and structured error responses. Exact endpoint shape may be refined in `docs/api.md`, but the logical operations below MUST exist.

| Logical operation | Suggested route | Behavior |
|---|---|---|
| Create login challenge | `POST /v1/auth/challenge` | Generate random nonce + expiry + audience; do not accept an identity without signature. |
| Complete login | `POST /v1/auth/session` | Verify challenge signature, registered key and one-time nonce; issue short-lived token. |
| Register/list identity info | `GET /v1/identities/{memberId}` and governed admin routes | Return public identity/key status only; no private material. Public-key directory must be backed by the contract state. |
| List files/folders | `GET /v1/files?folderId=...` | Use indexer for search/listing; enforce visibility rules; return a final block/version cursor for consistency. |
| Create file metadata | `POST /v1/files` | Submit approved registration transaction; persist logical name/folder metadata according to policy. |
| Upload version | `POST /v1/files/{fileId}/versions` | Stream encrypted package; pin/verify replication; then submit user-signed append transaction; return finalized version receipt. |
| Retrieve version | `POST /v1/files/{fileId}/versions/{version}/access` | Require typed signature; verify ACL/status; record successful lookup; only then return CIDs/envelope reference. |
| Download content/envelope | `GET /v1/content/{cid}` / internal adapter | Authorized API path streams ciphertext; verify CID and apply download throttles. Never return plaintext. |
| Update envelope set | `POST /v1/files/{fileId}/versions/{version}/envelopes` | Require an authorized key-grant operation; verify the new immutable envelope CID was uploaded/pinned; submit authorized update transaction. |
| Modify | Same upload-version route | Use existing File ID and current head as parent; it is a new version, not an in-place overwrite. |
| History | `GET /v1/files/{fileId}/versions` | Return event-derived immutable chain and current head. |
| Share / revoke | `POST /v1/files/{fileId}/acl/proposals` and governed execution | Create/approve scoped governance proposal; rotate future version key by always-new-per-version rule; update envelope sets for selected old versions if history is granted. |
| Restore/revert | Application command using history + upload-version flow | Decrypt selected old content and append newly encrypted version parented to the current head. |
| Audit | `GET /v1/audit?...` | Return access-controlled PostgreSQL audit records and relevant finalized chain events; enforce audit-query authorization and record the query itself. |

## 8.2 Rate limiting and circuit breaker

Apply independent limits by authenticated member, organization, source IP/device fingerprint where available, endpoint and operation class. Configure limits externally. Track invalid signature failures by source and claimed identity separately, so spoofed claims do not let an attacker permanently lock out a victim. Use progressive throttling and alerting; automatic suspension must follow a pre-approved policy and use a reversible, scoped action. Human-reviewed governance is required to lift a governance suspension.

The gateway MUST not reveal whether a private File ID, CID or envelope exists before authenticating and checking the relevant ACL, except for explicitly public metadata. The contract must independently verify all critical state changes and replay protection. The indexer cache must not bypass these checks.

# 9. Core application workflows

Note: The code for each workflow should be modular to allow for workflow-specific design modifications
if later required. 

## 9.1 Register member / rotate keys

1. An approved administrator establishes the organization/member identity out-of-band.
2. Generate or import distinct signing and encryption key pairs through the selected key custody provider. Private key material stays in custody.
3. Register signing address, encryption public key, key versions, organization and status through a governed transaction; prove possession of the signing key and, where supported, the encryption key.
4. Log key supersession rather than silently replacing a key. Suspend/revoke old keys when compromised. Rewrap selected historical DEKs to a replacement encryption key only through authorized recovery and envelope-update workflow.

## 9.2 Upload a new file

1. CLI obtains file path, display name, parent folder and desired ACL. File creation atomically grants the signed creator initial Read and Write access with the first version; additional recipients are added through the governed sharing workflow in §9.5. Validate path, ensure input is a regular file (unless explicit symlink policy allows otherwise), and enforce configured size limits. Also run wildcard checks for any malware-related code or wording in the text.
2. Resolve approved member public keys from authoritative identity state. Reject missing, suspended or revoked identities.
3. Create stable File ID if new. For an update, obtain current head and latest state at a consistent finalised block.
4. Generate new DEK, epoch ID and nonce prefix using CSPRNG. Encrypt any sensitive metadata and the file in chunks using AES-256-GCM.
5. Create one HPKE envelope for each reader permitted to decrypt that version. No plaintext DEK appears in the bundle.
6. Upload encrypted content package and envelope set to IPFS Cluster. Verify resulting CIDs and await configured independent pin quorum (`MIN_PIN_REPLICAS`, default 2 for local prototype; production target should be higher and spread across organizations). Verify retrieve/re-hash for the root package when configured.
7. Build a version manifest containing File ID, version number, parent manifest hash, epoch ID, content CID, envelope-set CID, file size, algorithm/format IDs and any permitted metadata. Compute its digest and ask key custody to sign the EIP-712 typed append request.
8. Gateway re-checks member/session and applies rate limits, then relays the typed signed request. For initial creation, the contracts verify the active signed creator and atomically initialize the creator's Read/Write ACL with the file policy and first version. For later appends, the contracts require an existing Write ACL. Both paths validate nonce, deadline and expected file state; each append advances the current head atomically.
9. Wait for the configured confirmation/finality condition. Return a receipt and refresh the indexer view. Only then report the version committed.
10. If upload/pinning succeeds but the chain transaction fails, report a failed commit and retain the CID as an orphan candidate. Never claim it is a registered version. Cleanup must not delete a CID that later becomes referenced by a finalized record.

## 9.3 Download / view

1. Client requests a specific version or current head and supplies the required request authentication.
2. Gateway validates the session and any required signed request, then checks active membership and Read ACL against authoritative Besu state at a known finalized block using `eth_call`.
3. Gateway appends the successful authorization/access-attempt record to the protected PostgreSQL audit store. It does not submit an access-lookup transaction.
4. Only after the authorization and audit append succeed, the gateway returns the content CID and current envelope-set CID for that version; download encrypted package and envelope set through the controlled IPFS adapter.
5. Verify CID/DAG integrity and version-manifest digest before attempting decryption.
6. Find the envelope matching member ID and encryption key version; use key custody to unwrap DEK; verify the DEK/epoch context; decrypt all chunks and verify every GCM tag.
7. Write output to a temporary file with restrictive permissions, fsync/close where supported, then atomically rename into target destination after full integrity validation. Do not expose partially decrypted output as a successful file.
8. Do not log plaintext or key data. If recipient lacks an envelope, fail closed even if their ACL is erroneously true, and raise a consistency alert.

## 9.4 Modify / create a new version

An edit is a new snapshot. Load current head, ensure Write permission, encrypt the updated input with a fresh DEK, wrap it for all current readers, upload/pin content and envelope objects, and append a version whose parent is the observed current head. If another update changes the head first, reject the stale append and ask the user to reconcile/retry. Do not overwrite any old CID.

## 9.5 Share / grant read/write/owner access

1. Create a scoped proposal stating file, recipient member/key version, operation and historical scope (default: current version only plus future versions).
2. Apply the configured organization-level governance approval policy. Do not allow one owner to bypass the policy.
3. For each explicitly selected historical/current version, an already-authorized party uses key custody to unwrap that version's DEK and creates a recipient-specific HPKE envelope. Combine current authorized envelopes plus new envelope in a canonical envelope set.
4. Upload/pin the new envelope-set object before publishing its CID.
5. Governance executes the ACL change and the authorized `KEY_ENVELOPE_UPDATE` pointer update; emit append-only ACL/envelope events. The recipient must not be granted usable retrieval before the governed transition is finalized.
6. Future versions create their own fresh DEK and include only current Read ACL members.
7. Ownership of the file means the member has the ability to grant read/write access to others as per the specified threshold conditions.

## 9.6 Revoke read/write access

- Revoke Write: governance removes the member from the Write ACL; all later version appends fail for that key.
- Revoke Read: governance removes the member from Read ACL. Future versions use fresh DEKs and omit the member's key envelope. If a version has already been encrypted and its DEK shared, the system cannot make the recipient forget it; old versions remain decryptable by members who already possess their key/envelope. Revoking the access route alone is not cryptographic retroactive revocation.
- For an emergency suspected compromise, use narrowly scoped suspension first, log it and then run permanent governed revocation/key supersession. Do not automatically permanently suspend a target solely because another actor supplied a spoofed identity string.

## 9.7 History and restore/revert

1. Query `FileRegistry`/indexer to list all finalized versions and their parent chain; verify the event projection against contract head when needed.
2. An operator identifies a recovery candidate using incident time, known indicators, version author and human review. The system does not automatically guarantee a version is malware-free.
3. Download selected content and envelope CIDs from IPFS. Verify CIDs and signed manifest; try another pinning peer if retrieval fails.
4. Unwrap the old version DEK using an authorized key custody identity and decrypt on a known-good machine.
5. To restore as current, treat recovered plaintext as input to the ordinary upload pipeline: generate a fresh DEK and epoch ID, encrypt, wrap for the current Read ACL, pin and append a new version with parent equal to the current head. This preserves linear immutable history and current ACLs.
6. Record a recovery reason/reference in non-sensitive metadata or an audit event. Preserve the source version reference. Never move the head backwards or delete an allegedly malicious version.

## 9.8 Successful lookup and audit

Successful and failed access attempts are recorded in the protected PostgreSQL audit store for the MVP. Security-significant events may additionally be represented by an on-chain alert or a periodically anchored audit digest under the configured policy. Audit queries distinguish `authorization granted/reference returned`, `ciphertext retrieval completed` and `plaintext opened`; do not overclaim what the audit log proves. A gateway audit record cannot capture direct IPFS access that bypasses the gateway.

## 9.9 What should happen automatically
 The points mentioned here may tak place in differeent systems (user end-point, gateway, etc).
 Adjacency does not necessitate it is the same system. Refer to the sections on the detailed architecture for specific location and system-wise breakdown. 
# A. When a user uploads or modifies a file
  Triggered by request
  1. Validate the request and enforce file-size limits.
  2. Scan the plaintext if scanning is enabled 
  3. Encrypt the file and construct its manifest.
  4. Upload the encrypted content to IPFS.
  5. Request pinning through IPFS Cluster.
  6. Verify that the configured minimum replica count has been satisfied.
  7. Only then submit the blockchain transaction registering the new version.

# B. While the system is running
  Background automation
  - Monitor IPFS peers and Cluster health.
  - Detect unavailable or disconnected nodes.
  - Monitor pin status and replication levels.
  - Record failures and alert operators.
  - Retry recoverable operations according to bounded retry policies.

# C. Before accepting blockchain state changes
  Automated validation
  - Check the user's authentication and authorization.
  - Verify signatures, nonces, and request expiry.
  - Verify that the expected file version is still current.
  - Check that the upload workflow's required pinning conditions have been met.
  - Validate the transaction receipt and finality policy.

# 10. Data model and event model

## 10.1 Core domain types

Define typed domain models and avoid raw strings for IDs where possible:

- `MemberId`, `OrganizationId`, `FileId`, `VersionNumber`, `EpochId`, `ManifestHash`, `ContentCid`, `EnvelopeSetCid`, `KeyVersion`, `ProposalId`, `OperationNonce`.
- `MemberIdentity`: member ID, organization ID, signing address, encryption public key, signing/encryption key versions, status, registration/supersession block references.
- `FileMetadata`: File ID, display name, parent folder ID, owner organization, creator ID, created/updated event references and file status.
- `VersionRecord`: file ID, version number, parent manifest hash, manifest hash, content CID, initial/current envelope-set CID reference, epoch ID, author ID/address and on-chain timestamp/transaction details.
- `AccessPolicy`: readers and writers (non-enumerable membership map in contract; list is reconstructed from events/indexer), policy scope and required approval threshold.
- `AuditEvent`: event type, actor/key version or unauthenticated source, target resource/file/member, action, outcome/reason code, version/epoch/operation reference, UTC timestamp, correlation identifier, authoritative chain/block reference where applicable, and safe metadata. PostgreSQL access-attempt records are distinct from finalized contract events.

## 10.2 Event names

Use stable, versioned Solidity events with indexed IDs where sensible. At minimum:

- `MemberRegistered`, `MemberStatusChanged`, `MemberKeySuperseded`;
- `FileCreated`, `FileMetadataChanged`, `FileStatusChanged`;
- `VersionAppended`, `CurrentHeadAdvanced` (may be one event if atomic and clear);
- `ReadAccessGranted`, `ReadAccessRevoked`, `WriteAccessGranted`, `WriteAccessRevoked`, `AccessPolicyChanged`;
- `EnvelopeSetUpdated` / `KeyEnvelopeUpdate`;
- `GovernanceProposalCreated`, `GovernanceProposalApproved`, `GovernanceProposalExecuted`, `GovernanceProposalCancelled`;
- `IdentitySuspended`, `IdentityReinstated`, `SecurityAlertRecorded`, `RecoveryVersionAppended` where needed.

Do not emit sensitive descriptions, plaintext names designated confidential, DEKs, full wrapped-key envelope bytes, session tokens or private signing material as events. Events are visible to consortium participants and may be permanently retained.

## 10.3 Indexer consistency

Process finalized blocks idempotently and persist the last processed block/hash. On a gap or chain mismatch, halt, alert and backfill from a trusted checkpoint; periodically reconcile projected heads against contract state.

## 10.4 Additional Core Rules regarding Gateway, Smart Contract and Blockchain Validation Responsibilities

### 10.4.1 Separation of Validation Responsibilities

The system MUST maintain a clear separation between off-chain application validation, on-chain authorization and state-transition enforcement, and blockchain consensus.

**Gateway (off-chain validation and orchestration):**
- Authenticate users and validate sessions, challenges, request signatures, expiry and application nonces.
- Validate request formats, file-size limits, supported file formats and configured scanning policies.
- Enforce rate limits, request deadlines and operational security policies.
- Coordinate encryption, IPFS uploads, pinning verification and blockchain transaction submission.
- Check authorization before initiating expensive operations, using authoritative and sufficiently recent contract state.
- Handle transaction submission, receipt verification, finality checks and uncertain transaction outcomes.
- Record operational events and detailed off-chain audit information.

**Smart contracts (on-chain enforcement):**
- Enforce authoritative membership, suspension and file-access policies.
- Verify the required user authorization signatures and application nonces for state-changing operations.
- Enforce writer permissions, valid state transitions and expected-current-version checks.
- Validate submitted file identifiers, version relationships, CID references and other required transaction parameters.
- Maintain authoritative blockchain state and emit events for relevant operations.
- Reject unauthorized, replayed or invalid state-changing transactions, regardless of whether they originate through the gateway or another RPC client.

The gateway and smart contracts SHOULD independently enforce critical authorization rules. Gateway validation improves efficiency and avoids unnecessary operations, while contract enforcement prevents a compromised or bypassed gateway from unilaterally modifying authoritative blockchain state.

The gateway MUST NOT be treated as the sole authority for blockchain state changes.

### 10.4.2 Limitations of On-Chain Validation

Smart contracts execute within the EVM and cannot directly access external services such as IPFS, IPFS Cluster, PostgreSQL or arbitrary HTTP endpoints.

Consequently:
- Smart contracts cannot independently inspect uploaded files or verify their plaintext contents.
- Smart contracts cannot independently verify that an IPFS CID is retrievable or that the content is pinned on the required number of peers.
- Smart contracts cannot independently verify that malware scanning or other off-chain validation procedures were actually performed.
- Smart contracts can validate submitted metadata, signatures, permissions and state-transition conditions, but cannot establish the truth of external operational claims without an additional trusted attestation mechanism.

The gateway MUST verify that the required IPFS pinning conditions are satisfied before submitting a file-version registration transaction.

### 10.4.3 IPFS Access Control and CID Confidentiality

A CID is a content identifier, not an authorization credential. Knowledge of a CID MUST NOT be treated as evidence of permission to retrieve or decrypt its associated content.

The system MUST enforce confidentiality through client-side encryption and controlled access to IPFS infrastructure.

The following requirements apply:

- IPFS nodes SHOULD operate within a restricted private network accessible only to authorized infrastructure components and peers.
- Kubo administrative APIs MUST NOT be exposed to ordinary clients or the public internet.
- IPFS administrative and Cluster management endpoints MUST be restricted through network isolation, firewall rules and appropriate authentication.
- Ordinary client retrieval SHOULD be mediated by the gateway, which authenticates the requester and checks current file-access permissions before retrieving and returning encrypted content.
- Clients MUST NOT receive unrestricted access to IPFS administrative interfaces.
- Encryption MUST remain the primary confidentiality mechanism, since a CID may be visible to consortium participants or other parties with access to blockchain metadata.
- Only authorized recipients SHOULD possess the cryptographic material required to decrypt the corresponding file version.

Network restrictions reduce unauthorized direct retrieval but cannot guarantee per-file access control against an attacker who already has access to an IPFS peer or storage interface. Encryption therefore remains essential even when private-network restrictions are enforced.

### 10.4.4 Blockchain Read and Write Operations

The system MUST distinguish between read-only smart-contract queries and state-changing blockchain transactions.

**Read operations:**

Read-only operations SHOULD use Ethereum JSON-RPC `eth_call` against the relevant smart-contract functions.

Examples include:
- Checking a member's read or write permissions.
- Retrieving current file-version information.
- Checking membership or suspension status.
- Retrieving relevant governance and access-control state.

An `eth_call` executes contract code against the state available at the queried node but does not:
- Create a blockchain transaction.
- Consume an Ethereum transaction nonce.
- Modify blockchain state.
- Produce a new block.
- Require QBFT consensus for that individual query.

For security-sensitive authorization decisions, the gateway MUST use a trusted RPC endpoint and ensure that the queried state is sufficiently recent and consistent with the configured blockchain finality policy. Stale indexer projections MUST NOT be used as the sole basis for granting access.

**Write operations:**

State-changing operations MUST be submitted as blockchain transactions and processed by the Besu network.

Examples include:
- File registration and initial version creation.
- File modification and new-version registration.
- Access grants and revocations.
- Member registration, suspension and removal.
- Governance-policy changes.
- Selected security-alert or audit-anchor transactions when required by the configured policy.

Transactions are executed by Besu nodes and processed through the configured QBFT consensus protocol. The gateway MUST distinguish between transaction submission, execution success, block inclusion and finality before reporting an operation as successfully committed.

The gateway MUST NOT assume that a transaction failed merely because its RPC request timed out. It MUST query transaction status and reconcile the outcome before attempting resubmission.

### 10.4.5 QBFT Consensus Scope

QBFT consensus applies to state-changing blockchain transactions and the blocks containing them. It is not invoked separately for every ordinary `eth_call`, file listing or file download.

Besu validator nodes:
- Validate proposed blocks and their transactions.
- Execute the relevant EVM operations.
- Participate in QBFT consensus.
- Agree on the ordering and resulting state of committed transactions.

Once a block is committed under QBFT's consensus guarantees, its state changes are treated as finalized according to the configured network assumptions.

A successful read-only query does not represent a consensus-backed transaction. The gateway MUST therefore use trusted blockchain nodes and suitable state/finality checks when making authorization decisions.

### 10.4.6 On-Chain and Off-Chain Audit Strategy

Routine access authorization and retrieval MUST use read-only contract queries and MUST NOT require a blockchain write transaction. Every successful and failed access attempt handled by the gateway MUST be recorded in PostgreSQL with the actor (or unauthenticated source), resource, action, UTC timestamp, outcome, reason code where applicable, chain/block reference and correlation identifiers.

The PostgreSQL audit store MUST protect integrity and availability through append-only audit tables, a per-stream cryptographic hash chain, restrictive database roles, and access-controlled/audited reads. Audit records MUST exclude plaintext, DEKs, private keys, session tokens and unnecessary confidential metadata. Failure to durably append an access result MUST prevent the gateway from releasing protected references or ciphertext.

On-chain records remain authoritative for shared state transitions: file/version creation, ACL/governance changes, membership/key-status changes and selected security alerts. A configured policy MAY anchor batches of off-chain audit records by submitting their digest, or submit a selected security alert; it MUST NOT turn every routine read into a blockchain transaction. Audit digest anchoring does not replace the protected PostgreSQL records.

The system MUST NOT claim that gateway audit records capture direct IPFS retrievals that bypass the gateway, nor that an authorization record proves ciphertext was fully downloaded, decrypted or opened.

### 10.4.7 Performance and Security Requirements

- Routine file reads and authorization checks SHOULD NOT require blockchain write transactions.
- Critical authorization decisions MUST be based on authoritative, sufficiently recent access-control state.
- PostgreSQL indexer projections MAY be used for file discovery, history presentation and other query optimizations, but MUST NOT independently authorize access using potentially stale data.
- State-changing operations MUST undergo contract-level authorization and validation.
- IPFS retrieval MUST follow the configured access-control and network-restriction policies.
- Gateway timeouts and bounded retries MUST be applied to RPC and IPFS operations.
- Transaction submission MUST use operation identifiers, nonces and expected-state checks where appropriate to prevent duplicate or conflicting operations.
- The gateway MUST maintain sufficient transaction metadata to reconcile uncertain outcomes after timeouts or service restarts.

# 11. Project structure

Use a Cargo workspace for Rust and a separate Hardhat project for Solidity. Start with the required module folders below; do not create empty abstractions for every hypothetical future feature. Each crate should have a clear responsibility and public API.

```text
ransomware-resistant-sharing/
├── README.md
├── TECHNICAL_SPECIFICATION.md
├── Cargo.toml
├── rust-toolchain.toml
├── .env.example
├── .gitignore
├── apps/
│   └── cli/
│       ├── Cargo.toml
│       └── src/main.rs
├── crates/
│   ├── domain/src/{file.rs,version.rs,identity.rs,acl.rs,folder.rs,errors.rs}
│   ├── application/src/{upload.rs,download.rs,modify.rs,share.rs,revoke.rs,history.rs,recover.rs,auth.rs}
│   ├── ports/src/{blob_store.rs,ledger.rs,key_custody.rs,identity.rs,scanner.rs,clock.rs}
│   ├── crypto/src/{encryption.rs,key_wrapping.rs,signing.rs,manifest.rs,nonce.rs}
│   ├── ipfs_adapter/src/lib.rs
│   ├── chain_adapter/src/{lib.rs,contracts.rs,typed_data.rs}
│   ├── key_custody/src/{lib.rs,development.rs,pkcs11.rs}
│   ├── scanner/src/{lib.rs,disabled.rs,clamav.rs}
│   └── metadata_store/src/{lib.rs,postgres.rs,migrations/}
├── services/
│   ├── gateway/src/{main.rs,auth.rs,routes.rs,rate_limit.rs,request_validation.rs,audit.rs,storage.rs}
│   └── indexer/src/{main.rs,consumer.rs,decoder.rs,projector.rs,reconcile.rs}
├── contracts/
│   ├── contracts/{FileRegistry.sol,AccessGovernance.sol,interfaces/}
│   ├── test/
│   ├── scripts/
│   ├── ignition/modules/
│   ├── hardhat.config.ts
│   ├── package.json
│   └── tsconfig.json
├── schemas/
│   ├── encrypted-file-manifest-v1.json
│   ├── key-envelope-set-v1.json
│   ├── access-request-v1.json
│   └── version-manifest-v1.json
├── infra/
│   ├── besu-qbft/
│   ├── ipfs-cluster/
│   ├── postgres/
│   └── compose.yaml
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── crypto-and-key-management.md
│   ├── contract-api.md
│   ├── api.md
│   ├── recovery-runbook.md
│   └── decisions/
└── tests/
    ├── integration/
    ├── end_to_end/
    ├── security/
    └── fixtures/
```

The brace notation above is explanatory; actual source files must be created individually. Future desktop GUI layout can be added under `apps/desktop/` and must use `crates/application` or the stable gateway API rather than re-implementing business logic.

# 12. Module interfaces and dependency direction

## 12.1 Dependency rule

`domain` depends on no infrastructure. `application` depends on domain types and port traits. `crypto`, `ipfs_adapter`, `chain_adapter`, `key_custody`, `metadata_store` and `scanner` implement ports. CLI and gateway call application use cases. Indexer consumes chain events and writes projection tables, not domain authorization decisions. Dependency direction must not form cycles.

Each independently built component needs its dependencies declared, but not necessarily a completely separate dependency lockfile. The exact arrangement depends on the language and whether components share a build workspace.

## 12.2 Core ports (conceptual Rust contracts)

```rust
trait BlobStore {
    async fn put_content(&self, reader: /* async reader */, meta: ContentMeta)
        -> Result<StoredObject, StorageError>;
    async fn put_envelope_set(&self, bytes: &[u8]) -> Result<StoredObject, StorageError>;
    async fn get(&self, cid: &ContentCid) -> Result<Box<dyn AsyncRead + Send + Unpin>, StorageError>;
    async fn ensure_replication(&self, cid: &ContentCid, min_replicas: usize)
        -> Result<ReplicationReceipt, StorageError>;
    async fn verify_retrievable(&self, cid: &ContentCid) -> Result<(), StorageError>;
}

trait KeyCustodyProvider {
    async fn public_identity(&self) -> Result<PublicIdentityKeys, CustodyError>;
    async fn sign_typed_digest(&self, key_id: &KeyId, digest: &[u8; 32])
        -> Result<Signature, CustodyError>;
    async fn unwrap_dek(&self, key_id: &KeyId, envelope: &KeyEnvelope, context: &WrapContext)
        -> Result<Zeroizing<[u8; 32]>, CustodyError>;
    async fn health_check(&self) -> Result<CustodyHealth, CustodyError>;
}

trait LedgerPort {
    async fn get_file_head(&self, file_id: FileId) -> Result<Option<HeadRecord>, LedgerError>;
    async fn get_member(&self, member_id: MemberId) -> Result<MemberIdentity, LedgerError>;
    async fn check_read_access(&self, member: MemberId, file_id: FileId, version: VersionNumber) -> Result<bool, LedgerError>;
    async fn append_version(&self, request: SignedAppendRequest) -> Result<TxReceipt, LedgerError>;
    async fn update_envelope_set(&self, request: SignedEnvelopeUpdate) -> Result<TxReceipt, LedgerError>;
}
```

These signatures illustrate separation, not exact compilation-ready trait definitions. Use concrete, consistent async traits and error types in the implementation. Streams must support large files without loading them wholly into memory. Do not allow a caller to bypass domain validation by invoking an adapter directly from the CLI.

## 12.3 Error model

Define stable typed errors at the domain/application boundary: `Unauthenticated`, `Unauthorized`, `MemberSuspended`, `InvalidSignature`, `ReplayDetected`, `ExpiredRequest`, `StaleHead`, `InvalidManifest`, `UnsupportedCryptoSuite`, `IntegrityCheckFailed`, `StorageUnavailable`, `ReplicationInsufficient`, `KeyCustodyUnavailable`, `ContractRejected`, `GovernancePending`, `RateLimited`, `IndexerLagging`, `OrphanedUpload`, and `Internal`. Do not return stack traces, secret values, RPC credentials or private state to users. Preserve correlation IDs for support while redacting sensitive details.

# 13. Configuration and operational behavior

Provide a typed configuration layer. The `.env.example` must contain placeholders only. At minimum configure:

- `BESU_RPC_URL`, chain ID, deployed contract addresses and receipt/finality policy;
- `IPFS_API_URL`, IPFS Cluster endpoint(s), request timeout and private-network settings;
- `DATABASE_URL` and migration mode;
- key-custody provider type, provider endpoint/module, non-secret key IDs and expected capabilities;
- `MIN_PIN_REPLICAS` (local default 2), max upload bytes, chunk size and request deadlines;
- session TTL, challenge TTL, nonce store TTL, per-endpoint limits and circuit-breaker thresholds;
- scanner enablement/provider and anomaly hold policy (disabled by default);
- log level, audit retention and privacy options.

The app must refuse to start in non-development mode when a development key provider, unsafe crypto suite, default signing key, open IPFS admin API or placeholder secret is configured. Keep secrets out of CLI arguments, logs and checked-in config. Apply timeouts and bounded retries with exponential backoff for RPC/IPFS operations; retries must be idempotent or guarded with operation IDs/nonces. On timeout after transaction submission, query transaction status before resubmitting.

# 14. Security and privacy requirements

- Assume any endpoint can be compromised. Treat client-side scanning and behavioral signals as best-effort defense-in-depth.
- Validate identity and authorization both at the gateway and in the contracts. The gateway does not make consortium policy true merely by forwarding a request.
- Separate signing and encryption key roles and key versions. Support suspending/revoking old keys with an audit record.
- Use secure RNG and maintained crypto libraries. No custom algorithms, deterministic hard-coded DEKs, fixed nonces, or silent algorithm fallback.
- Raw DEKs/private keys are never persisted in PostgreSQL, IPFS, source code, logs or crash reports. Unwrapped DEKs should use zeroizing buffers where practical.
- Secrets and sensitive descriptions are not placed in events. File display names/folder names are visible by the chosen MVP policy; document this clearly in UI and threat model.
- Private IPFS Cluster and gateway access restrictions are required for confidentiality and better access accounting; content encryption remains mandatory even on a private network.
- Verify CIDs and AEAD tags before declaring download/recovery successful. Never trust an IPFS node response solely because it came from a known peer.
- Enforce nonce uniqueness, expiry and one-time use. Include domain separation and chain/contract IDs in typed signatures. A stale or replayed signature must fail.
- Rate-limit requests, cap body size and file/chunk count, and protect against zip bombs/path traversal if any archive extraction is added. Do not auto-extract arbitrary user files in MVP.
- Use constant-time comparisons where appropriate. Avoid verbose auth error messages that leak whether a target identity/file exists.
- PostgreSQL/Indexer permissions must not permit the gateway API role to change the contract-derived access truth.
- Backup Besu node configuration, IPFS pinning configuration, database projections and governance addresses. Private-key backups require separately governed, offline procedures.
- On chain, immutability prevents undetected history rewriting but does not prove the submitted content was safe, intended or human-approved.

# 15. Testing requirements

## 15.1 Unit tests

- AES-256-GCM encrypt/decrypt round trip for empty, small, boundary-size and multi-chunk files.
- One-bit ciphertext/tag/AAD mutation fails decryption; chunks cannot be reordered, removed or transplanted across file/version IDs.
- Nonce-index encoding uniqueness across metadata and all content chunks; overflow rejected.
- HPKE wrap/unwrap round trip; wrong recipient key, altered encapsulation/ciphertext, wrong member ID, wrong key version and wrong epoch context fail.
- Typed-data digest and Solidity EIP-712 recovery match checked-in deterministic test vectors.
- Manifest/schema rejection for unsupported versions, malformed CIDs, duplicate envelope members, oversized fields and inconsistent chunk counts.
- Secret zeroization wrapper behavior and redaction tests where realistically testable.

## 15.2 Contract tests

- Only active registered identity in Write ACL can append a version.
- Invalid/replayed/expired signatures fail; wrong chain/contract domain fails.
- Stale parent/head and wrong version number fail; valid append advances head once and leaves history intact.
- Direct gateway identity cannot impersonate a requester just by being `msg.sender`.
- Authoritative read authorization rejects absent/suspended members; routine checks do not mutate contract state or emit access events.
- ACL grant/revoke, envelope pointer update and policy approval rules enforce required scopes and thresholds.
- Emergency suspension does not allow arbitrary users to suspend a victim; reinstatement is governed and logged.
- Historical `VersionAppended` records cannot be edited/deleted; revert creates a new version.
- Invalid CIDs/manifest hashes and repeated nonce fail; unrelated file state cannot be modified by a signed request for another File ID.
- Re-entrancy and external-call attack surfaces are minimized; no external IPFS call exists in Solidity.

## 15.3 Integration and end-to-end tests

- Start local Besu QBFT test network (target four validator nodes), IPFS Cluster and PostgreSQL using reproducible configuration.
- Happy path: enroll test identities, create file, upload/pin content+envelopes, append version, list it, authorize/log lookup, download, verify and decrypt.
- Negative path: tampered CID/package, insufficient replicas, gateway outage, HSM unavailable, expired token, wrong recipient, storage peer outage, contract revert and indexer delay.
- Concurrency: two writers start from the same head; first accepted append wins, second gets `StaleHead` and must reconcile.
- Share current version to new reader, confirm they can decrypt only selected versions; history must require explicit grant.
- Revoke a reader, upload another version and confirm the revoked reader receives no future envelope; explicitly demonstrate old-key limitations in the test.
- Restore historical plaintext into a new version and confirm current head advances while all prior records stay present.
- Upload succeeds but contract transaction fails: app reports an orphan, doesn't display it as committed, and does not lose the failed transaction details.
- Stop/restart indexer and replay events; projected file list/head matches contract state.

## 15.4 Definition of done / acceptance criteria

The MVP is not complete until these criteria pass:

1. A new file is encrypted locally with a fresh DEK, produces content/envelope CIDs, reaches configured pin quorum, and is only then registered on-chain.
2. The chain stores the version metadata and pointers, not file bytes, plaintext metadata marked private, raw DEKs or wrapped key bytes.
3. Authorized user can download, verify and decrypt. A user without a valid envelope cannot decrypt even if they obtain ciphertext.
4. Upload/modify rejects unauthorized writers, replayed/expired signatures and stale parents.
5. Successful and failed access attempts are durably recorded off-chain in the protected PostgreSQL audit store; audit failure prevents protected data release. Selected security alerts or digest anchors may be on-chain, but routine reads are not.
6. A share operation adds a new envelope through a governed update without re-encrypting ciphertext. Historical sharing is explicit.
7. Revoke blocks future versions by removing the user from the Read ACL and excluding them from new version envelope sets. The known inability to retroactively revoke already obtained keys is documented and tested.
8. Restore appends a new version with the old current head as parent and a fresh DEK; no history is deleted or moved backwards.
9. A user can browse a logical folder/file hierarchy. Indexer views are rebuildable and do not grant access.
10. The client, gateway, contract and storage modules have automated tests and can be run using documented local setup commands.
11. No plaintext/DEK/private key leaks appear in logs/test fixtures/repository. Production mode refuses the test-only key provider.
12. Every module has a short README or rustdoc documenting purpose, interface and test command.
13. Set-up functionality should be built so all the nodes of the application can be run simultaneously and the various workflows can be tested.

# 16. Implementation phases for the coding agent

Implement one phase at a time. For each phase: add tests first where practical, implement minimal behavior, run relevant tests, update README. All features are implemented in the agent/development branch and merging is only done after explicit approval by the human reviewer. Use the relevant folders for the different applications and interfaces and only communicate via defined protocols. 

## Phase 0 — repository and decision scaffolding
- Create workspace/project layout, lint/format rules, pinned toolchains/dependencies, configuration example and CI tests.
- Write ADRs for HSM provider/topology, multisig/timelock deployment, CID/package encoding profile and governance thresholds.
- No placeholder cryptography should be used to claim security.

## Phase 1 — domain and cryptographic package
- Implement typed domain IDs, errors, version graph and schema definitions.
- Implement versioned AES-256-GCM chunk format and tests.
- Implement HPKE wrapper with fixed suite; publish test vectors/fixtures.
- Implement manifest and EIP-712 typed-data digest cross-tests.
- Use a test-only key custody provider behind the interface.

## Phase 2 — contracts and local EVM tests
- Implement `AccessGovernance` and `FileRegistry` with access checks, nonces, event definitions, version append and envelope pointer update.
- Integrate reviewed governance/timelock primitives as selected in ADR.
- Test invalid caller/signature/replay/stale-head/ACL/governance cases before integrating IPFS.

## Phase 3 — IPFS adapter and indexer
- Implement stream-based upload/download, CID parsing/verification, pin quorum wait and peer retry.
- Create PostgreSQL schema and idempotent event indexer with reconciliation.
- No use-case authorization is allowed to rely solely on the indexer.

## Phase 4 — gateway and authentication
- Implement one-time challenge login, short-lived sessions, typed operation signatures, rate limiting and structured audit logs.
- Implement gateway storage and chain adapters; never accept plaintext from clients at these endpoints.
- Confirm authoritative read authorization and durable PostgreSQL audit append before releasing CIDs; no read-side blockchain transaction is submitted.

## Phase 5 — CLI use cases
- Implement register/identity display, file/folder listing, create/upload, download, modify, history, share, revoke and recovery/revert commands.
- Keep commands thin and invoke `application` services.
- Include understandable errors and transaction/storage receipts.

## Phase 6 — integration hardening and demo
- Run multi-validator integration environment; test replication failures, service restart, concurrent edits and recovery.
- Add a recovery runbook and a scripted demonstration.
- Only after these pass should optional entropy scanning, auto-sync or desktop GUI work begin.

# 17. Explicitly open deployment decisions

The following remain configurable/open and must not be guessed silently by the coding agent:

1. **HSM topology and model:** one HSM per user, organization-level HSM or centralized custody service; exact PKCS#11/vendor API and support for secp256k1 signing plus X25519/HPKE decapsulation. This affects trust and threat model.
2. **Governance implementation:** Safe threshold accounts + OpenZeppelin TimelockController versus another well-reviewed equivalent; thresholds per action and timelock durations.
3. **Organization onboarding/identity proof:** who verifies that a registered member ID belongs to the real person/organization; this is an operational governance workflow, not supplied by a cryptographic signature alone.
4. **Storage replication policy:** `MIN_PIN_REPLICAS` and how replica independence is measured; two local peers are not equivalent to two organizations.
5. **File size and retention:** max bytes, retention duration, orphan cleanup age, and whether old historical versions can be unpinned under policy. Never unpin a still-referenced version without governed retention policy.
6. **History sharing defaults:** MVP default is current version + future versions; older-version access requires explicit selection and wrappers per selected historical version.
7. **Metadata visibility:** display names and folder relations are visible to consortium members in MVP; descriptions can be encrypted. Any different privacy policy must be designed before deployment.
8. **Emergency access recovery:** who can recover when a member is unavailable or key custody fails, and how that is audited. Never add an undocumented administrator bypass.

# 18. References and standards

These references explain standards and components selected above; the implementation must still pin concrete software versions and test them together.

- Supplied source: *Blockchain-Based Ransomware-Resistant Data Sharing — System Design Document: Architecture, Use Cases, and Implementation Plan* (provided in this conversation).
- RFC 9180, *Hybrid Public Key Encryption (HPKE)*: https://www.rfc-editor.org/rfc/rfc9180
- EIP-712, *Typed structured data hashing and signing*: https://eips.ethereum.org/EIPS/eip-712
- IPFS documentation, *Content Identifiers (CIDs)*: https://docs.ipfs.tech/concepts/content-addressing/
- IPFS documentation, *Privacy and encryption*: https://docs.ipfs.tech/concepts/privacy-and-encryption/
- IPFS Cluster documentation, *Architecture overview*: https://ipfscluster.io/documentation/deployment/architecture/
- OpenZeppelin Contracts 5.x governance documentation: https://docs.openzeppelin.com/contracts/5.x/governance
- OpenZeppelin Contracts 5.x access-control documentation: https://docs.openzeppelin.com/contracts/5.x/access-control
- Hardhat 3 testing guide: https://hardhat.org/docs/guides/testing

---

# Final instruction to the coding agent

Treat this document as the implementation baseline. Record unavoidable deviations in an ADR. Build small end-to-end milestones. Report success only after storage replication and chain finality; keep security-critical choices explicit and testable.
