# ADR: EIP-712 operation schemas

**Status:** Accepted by maintainer  
**Scope:** EIP-712 authorization messages for version append, access lookup, and envelope-set update

## Context

The technical specification requires EIP-712 for version appends, access
lookups, envelope updates, and other relayed operations. It requires domain
separation with chain ID and verifying-contract address, operation-specific
nonces, and expiry. It does not define the exact message fields, EIP-712 domain
names, nonce-consumption ownership, or verifying contract for each operation.
Those choices affect the Solidity ABI, Rust digest implementation, gateway
replay handling, and cross-language test vectors.

The accepted design follows the responsibility split in
`TECHNICAL_SPECIFICATION.md`: `FileRegistry` owns version records;
`AccessGovernance` owns access policy and envelope references.

## Decision

Use the standard EIP-712 domain fields:

```text
EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)
```

Use version `"1"` and these domain names:

| Operation | Domain name | Verifying contract |
|---|---|---|
| Version append | `RRDS FileRegistry` | `FileRegistry` |
| Access lookup | `RRDS AccessGovernance` | `AccessGovernance` |
| Envelope-set update | `RRDS AccessGovernance` | `AccessGovernance` |

`chainId` and `verifyingContract` are deployment configuration values; the
client must not accept caller-supplied values that disagree with the connected
network and deployed contracts.

### Version append

The signer is `authorMemberId`'s active registered signing address. The exact
proposed EIP-712 type string is:

```text
VersionAppend(bytes32 fileId,uint64 versionNumber,bytes32 parentManifestHash,bytes32 contentCidHash,bytes32 envelopeSetCidHash,bytes32 epochId,bytes32 manifestHash,bytes32 memberId,address signerAddress,bytes32 operationNonce,uint256 deadline)
```

The CID hash fields are `keccak256` of the canonical CIDv1 string's UTF-8
bytes. The signature binds all required version metadata and the registered
signer's address, a unique operation nonce, and an expiry. `FileRegistry`
still checks membership, write authorization, that the recovered signer
matches `signerAddress`, expected current head, version sequence, and epoch
uniqueness independently.

### Access lookup

The proposed type string is:

```text
AccessLookup(bytes32 memberId,bytes32 fileId,uint64 versionNumber,uint32 encryptionKeyVersion,bytes32 operationNonce,uint256 deadline)
```

The signature scopes a lookup to a member, file, explicit version, and
encryption-key version. `AccessGovernance` remains the authorization-state
source. Because a routine lookup is read-only, its signed nonce is consumed
atomically by the gateway's durable PostgreSQL replay store, not by an
on-chain state mutation. Successful and failed lookup attempts remain subject
to the PostgreSQL audit requirements in the specification.

### Envelope-set update

The proposed type string is:

```text
EnvelopeSetUpdate(bytes32 fileId,uint64 versionNumber,bytes32 epochId,string oldEnvelopeSetCid,string newEnvelopeSetCid,bytes32 actorMemberId,bytes32 proposalId,bytes32 operationNonce,uint256 deadline)
```

Including the old reference provides compare-and-swap protection against
stale updates. The new reference identifies the immutable replacement set.
`proposalId` is zero only for an operation that policy permits without a
governance proposal. For proposal-backed operations, the nonzero ID is
correlation metadata linking the contract event to the corresponding Safe
transaction. The configured Safe's threshold execution is the approval
boundary; the contract does not treat the ID as an approval credential or
maintain a duplicate proposal registry. `AccessGovernance` checks the actor's
current authority and policy before changing the current envelope-set
reference.

## Nonce and expiry

- `operationNonce` is a cryptographically random, non-zero `bytes32`, matching
  the domain's `OperationNonce` representation.
- Each nonce is single-use per actor and operation type. State-changing
  operations are consumed atomically by their verifying contract; read-only
  access lookups are consumed atomically by the gateway's durable replay store.
- `deadline` is a Unix timestamp in seconds encoded as `uint256`; expired
  requests are rejected by the contract or gateway that consumes the nonce.
- Nonces are not inferred from a session token. A session is not a substitute
  for operation authorization.

## Encoding and verification

- CIDs are canonical CIDv1 strings accepted by the domain CID parser. The
  append and envelope update messages sign `bytes32` hashes of each complete
  canonical CID string's UTF-8 representation.
- Rust and Solidity/TypeScript must use identical type strings, field order,
  widths, domain names, and value encodings.
- Add fixed cross-language vectors using explicit chain IDs and contract
  addresses. Verify that changing any signed field, nonce, deadline, chain ID,
  or verifying-contract address changes the digest.
- Digest validity is not authorization. Contracts independently enforce ACL,
  membership status, nonce consumption, expiry, and state-transition
  invariants.

## Approval record

The maintainer approved the original design, then approved this §7.3
conformance amendment and the PostgreSQL read-nonce policy:

1. Verifying-contract ownership and domain names.
2. Operation fields and integer widths, including §7.3's `signerAddress` and
   `bytes32` hashes of complete canonical CID representations.
3. Random `bytes32` nonce semantics and atomic PostgreSQL consumption for
   read-only access lookups; state-changing operation nonces remain
   contract-consumed.
4. `proposalId == 0` for policy-authorized envelope updates without a
   separately tracked proposal; nonzero values correlate governed actions with
   Safe transactions and do not replace Safe authorization.

## Specification references

- `TECHNICAL_SPECIFICATION.md` §§2, 5.3–5.5, 6.3, 7, 10.1–10.2, 12.2, and
  Phase 1.
