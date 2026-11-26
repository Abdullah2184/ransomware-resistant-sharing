# Data Recovery and Key Revocation

This document describes how RRDS handles ransomware, compromised endpoints,
malicious version uploads, key compromise, and member revocation under
`TECHNICAL_SPECIFICATION.md` §§2, 5.5, 7.5, 9.1, 9.6–9.7, and 14.

## Threat Reality and What RRDS Guarantees

- RRDS **cannot prevent** malware from infecting an endpoint or reading/corrupting
  plaintext while a compromised endpoint is actively processing it.
- RRDS **prevents** a compromised endpoint from silently overwriting, deleting,
  or rewriting historical versions:
  - Every version is stored under immutable IPFS CIDs replicated across private
    consortium Cluster peers (`MIN_PIN_REPLICAS`).
  - `FileRegistry` version records are strictly append-only; neither a writer,
    nor a relayer, nor a compromised gateway can delete or alter a committed
    version or move `currentHeadManifestHash` backward.

## Incident Containment: Emergency Suspension vs. Permanent Revocation

When an endpoint or member key is suspected compromised:

1. **Immediate Containment — Emergency Suspension (`AccessGovernance.emergencySuspendMember`):**
   - Executed by the narrow `EMERGENCY_SUSPENDER_ROLE` (the configured Emergency
     Safe).
   - Transitions member status `Active -> Suspended` and marks the member's
     current signing and encryption key versions `Suspended`.
   - Immediately blocks future login sessions, gateway access lookups, and
     contract-level `createFile`, `appendVersion`, and `updateEnvelopeSet` calls.
   - Cannot grant permissions, modify files, or reinstate a member.
   - Unauthenticated callers or spoofed identity strings cannot trigger
     suspension.
2. **Investigation & Permanent Revocation (`AccessGovernance.setMemberStatus(..., Revoked)`):**
   - Executed by the member's Organization Safe.
   - Permanently marks the member and their active keys `Revoked` (irreversible
     by the Organization Safe).
3. **Controlled Reinstatement (`AccessGovernance.reinstateMember`):**
   - Only `DEFAULT_ADMIN_ROLE` (`RrdsTimelockController`, backed by the
     Consortium Safe with the 24-hour delay) can reinstate a `Suspended` member.
4. **Key Supersession / Rotation (`AccessGovernance.supersedeMemberKeys`):**
   - Requires Organization Safe execution **plus** a fresh EIP-712
     `MemberKeyProof` signed by the **new** signing key (preventing an authority
     from binding a key the member does not control).
   - Marks prior signing and encryption key versions `Superseded` while keeping
     their historical records queryable.
   - Re-wrapping selected historical DEKs for a replacement encryption key is an
     explicit, audited envelope-update workflow, never automatic.

## Read and Write ACL Revocation

Read and Write permissions are enforced independently in `AccessGovernance`:

- **Revoking Write (`setFilePermission(..., Write, false, proposalId)`):**
  Blocks all future `appendVersion` calls by that member.
- **Revoking Read (`setFilePermission(..., Read, false, proposalId)`):**
  - Immediately denies future gateway access lookups and ciphertext downloads
    for both current and historical versions, and increments the member's
    Read-ACL epoch to invalidate prior historical grants.
  - All subsequent file versions generate a **fresh random 256-bit DEK** and
    **fresh `EpochId`**, and omit the revoked member from the new version's
    `KeyEnvelopeSet`.
- **Documented Cryptographic Limit:**
  Revocation provides **forward secrecy for future versions** only. If a
  revoked member (or malware on their endpoint) already copied plaintext or a
  version's DEK/ciphertext prior to revocation, neither the blockchain nor the
  gateway can make them forget it.

## Append-Only Ransomware Recovery (Restore / Revert)

Suppose a compromised writer encrypts a file locally with ransomware and uploads
corrupted `V2` on top of clean `V1`:

1. **Contain the writer:** Suspend the compromised member (`emergencySuspendMember`)
   and/or revoke their `Write` ACL so no further bad versions can be appended.
2. **Identify a clean version:** On a **known-good endpoint**, inspect the
   immutable version history (`V1`, `V2`, authors, timestamps, incident window).
   RRDS does not claim a valid signature proves content is malware-free (no
   `trustedVersion` flag in MVP); human/operational review selects `V1`.
3. **Verify and decrypt `V1`:**
   - Authorize retrieval of `V1` (requires explicit historical Read grant if
     `V1 < head`).
   - Verify the canonical `KeyEnvelopeSet`, unwrap `V1`'s DEK via hardware key
     custody, verify the canonical `EncryptedFileManifest` and every chunk's
     SHA-256 CID, and authenticate every AES-256-GCM tag before accepting the
     recovered plaintext.
4. **Restore as a brand-new head version (`V3`):**
   - Run the recovered `V1` plaintext through the standard upload pipeline
     (`UploadService::restore_version`):
     - Generate a **fresh 256-bit DEK**, fresh `EpochId`, and fresh 64-bit
       `NoncePrefix`.
     - Wrap the new DEK only for the **current** active Read ACL (excluding any
       revoked/compromised members).
     - Upload and verify IPFS Cluster pin quorum (`MIN_PIN_REPLICAS`).
     - Append `V3` with `parentManifestHash = V2.manifestHash`.
5. **Preserve forensic history:** `V1` (clean source), `V2` (corrupted incident
   artifact), and `V3` (restored clean head) all remain permanently auditable in
   `FileRegistry`. History is never deleted or rolled back.
