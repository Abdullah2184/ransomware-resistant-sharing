# Incident & Ransomware Recovery Runbook

This runbook documents the operational procedure for containing a compromised
endpoint or ransomware upload and restoring clean file versions in RRDS
(`TECHNICAL_SPECIFICATION.md` §§2, 9.6–9.7, 14, 16 Phase 6).

See also [`docs/architecture/recovery-and-revocation.md`](../architecture/recovery-and-revocation.md)
and [`docs/architecture/historical-access.md`](../architecture/historical-access.md).

## 1. Immediate Containment (Minutes 0–15)

1. **Emergency Suspend the Compromised Member:**
   - Execute `AccessGovernance.emergencySuspendMember(memberId, reasonHash)`
     from the configured **Emergency Safe** (`EMERGENCY_SUSPENDER_ROLE`).
   - Effect: immediately blocks new login sessions, gateway access lookups,
     ciphertext/envelope downloads, and on-chain `createFile`, `appendVersion`,
     and `updateEnvelopeSet` transactions for that member.
2. **Revoke Active Gateway Sessions (Defense-in-Depth):**
   - Because the gateway checks authoritative Besu state at every protected
     route, on-chain suspension already blocks access. Operators can also
     revoke compromised sessions immediately in PostgreSQL or via
     `DELETE /v1/auth/session`.
3. **Revoke Write / Read ACLs if Scoped to Specific Files:**
   - Execute `AccessGovernance.setFilePermission(fileId, memberId, Write/Read, false, proposalId)`
     from the file's configured policy Safe.
   - Note: revoking file-level `Read` automatically increments
     `readPermissionEpochs[fileId][memberId]`, invalidating **all** historical
     read grants for that member on that file.

## 2. Forensic Inspection (Clean Endpoint Only)

1. Move to a **known-clean workstation** with an uncompromised hardware key
   custody token.
2. Authenticate and inspect immutable version history and audit records:

   ```shell
   cargo run --locked -p cli -- login --session-file ~/.rrds-session
   export RRDS_SESSION_FILE=~/.rrds-session
   cargo run --locked -p cli -- history <file-id>
   cargo run --locked -p cli -- audit --limit 100
   ```

3. Identify the last known-good version (`V_clean`, e.g., `V1`) before the
   corrupted version(s) (`V2`, ...).
   - Remember: RRDS has no `trustedVersion` flag on-chain; clean version
     selection is a human/operational decision backed by immutable author,
     block timestamp, and audit records.

## 3. Authorize Historical Version & Execute Append-Only Restore

1. If `V_clean < currentVersion`, grant explicit version-scoped historical Read
   access to the recovery operator via the file's `READ_ACL_POLICY` Safe:
   - `AccessGovernance.setHistoricalReadAccess(fileId, V_clean, recoveryMemberId, true, proposalId)`
   - Ensure the recovery operator has an envelope entry in `V_clean`'s
     `KeyEnvelopeSet` (if not, an existing authorized reader shares `V_clean`'s
     envelope via `rrds share <file-id> <V_clean> <recoveryMemberId>`).
2. Restore `V_clean` as a brand-new head version (`V_new = currentVersion + 1`),
   listing **only** currently authorized active readers (excluding the
   suspended/revoked member):

   ```shell
   cargo run --locked -p cli -- restore <file-id> <V_clean> \
     --reader <active-reader-1> --reader <active-reader-2>
   ```

3. What `rrds restore` guarantees:
   - Verifies the canonical `KeyEnvelopeSet`, unwraps `V_clean`'s DEK via key
     custody, verifies every CARv1 raw block SHA-256 CID, and authenticates
     every AES-256-GCM tag before accepting recovered bytes.
   - Generates a **fresh 256-bit DEK**, fresh `EpochId`, and fresh 64-bit
     `NoncePrefix`, wraps the new DEK only for active readers, pins to
     `MIN_PIN_REPLICAS` IPFS Cluster peers, and commits `V_new` parented to the
     current head (`V2`).
   - Preserves `V1` (clean source), `V2` (corrupted forensic evidence), and
     `V3` (restored clean head) immutably on-chain.

## 4. Infrastructure Recovery Procedures

### Indexer Projection Drift or Database Recovery

PostgreSQL projections are derived and never authoritative. Rebuild them safely:

- **Rebuild from persisted finalized events (no Besu archive scan needed):**
  ```shell
  cargo run --locked -p indexer -- --rebuild-projections
  ```
- **Full reindex from Besu `INDEXER_START_BLOCK` (clears derived projections only; preserves `gateway_audit_events`):**
  ```shell
  cargo run --locked -p indexer -- --reindex-from-chain
  ```

### Relayer Timeout Reconciliation

If a gateway write route returns `504 confirmation_timed_out` with a
`transactionHash`:

1. **Do NOT blindly resubmit** with a new nonce before checking status.
2. Query `eth_getTransactionReceipt(txHash)` (or `TransactionRelayer::reconcile_transaction(txHash)`):
   - If mined with `status == 0x1`: the operation succeeded on-chain.
   - If mined with `status == 0x0`: inspect revert reason (e.g., `StaleHead`,
     `ExpiredOperation`, `OperationNonceAlreadyConsumed`) and retry only after
     refreshing state.
   - If still unmined after Besu validator health is verified: investigate
     validator quorum (`sh infra/besu-qbft/verify.sh`).

### Orphaned IPFS Pin Handling

If `rrds upload` / `rrds modify` / `rrds restore` reports `OrphanedUpload`
(pinning succeeded on Cluster, but ledger commit failed), record the printed
`contentCid` / `envelopeSetCid` for scheduled offline orphan reconciliation
against finalized `FileRegistry` / `AccessGovernance` pointers. Never unpin any
CID referenced by a finalized version or pending transaction.

## 5. Post-Incident Key Rotation & Reinstatement

- **Permanent compromise:** Execute `AccessGovernance.setMemberStatus(memberId, Revoked, proposalId)` from the Organization Safe.
- **Key replacement:** Execute `AccessGovernance.supersedeMemberKeys` from the
  Organization Safe with a fresh `MemberKeyProof` signed by the replacement
  hardware key.
- **Reinstatement from suspension:** Only `RrdsTimelockController` (Consortium
  Safe + 24-hour delay) can execute `AccessGovernance.reinstateMember`.
- **Cryptographic limit:** Any plaintext or version DEK copied by the
  compromised endpoint *before* suspension cannot be retroactively erased;
  rotate any external secrets contained inside exposed files.
