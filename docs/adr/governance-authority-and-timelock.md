# ADR: Governance authorities and timelock

**Status:** Accepted by maintainer  
**Decision scope:** Threshold authority, organization policy scopes, consortium
timelock, and emergency suspension

## Context

Specification §§2, 7.1, 7.5, 12, 14 and Phase 2 require reviewed threshold
approval rather than custom multisig cryptography; consortium-level
membership, validator and system-wide permission-expanding changes require a
timelock; organization-level member and ACL changes use the relevant
organization's policy; emergency suspension must be narrow and separately
audited. Specification §17 leaves the exact threshold implementation,
threshold scopes and timelock durations for an ADR.

OpenZeppelin documents `TimelockController` as a scheduler/executor that
enforces a minimum delay and supports atomic batches. Its executor role may be
open to any address once an operation is ready. OpenZeppelin also warns that
default administrator authority is highly privileged. Safe accounts enforce
their configured owner threshold before executing a transaction; optional
Safe modules have separate execution paths and are excluded from this design.

References:

- [OpenZeppelin Contracts 5.x TimelockController](https://docs.openzeppelin.com/contracts/5.x/api/governance#TimelockController)
- [OpenZeppelin Contracts 5.x access control](https://docs.openzeppelin.com/contracts/5.x/access-control)
- [Safe smart-account concepts](https://docs.safe.global/advanced/smart-account-concepts)

## Decision

1. Use audited Safe threshold accounts as external authorities. Do not
   implement custom multisignature signature aggregation in `AccessGovernance`
   or `FileRegistry`.
2. Resolve authorization by policy scope to a configured Safe address. A
   scope may be consortium-wide, organization-wide, or a more specific policy
   scope, including a file policy. Safe itself enforces that scope's owners
   and threshold. The contracts authorize the configured Safe address, not
   its individual owners.
3. Use OpenZeppelin Contracts `TimelockController` version `5.6.1` for
   consortium-wide membership, validator, and system-wide
   permission-expanding operations. The minimum delay is 86,400 seconds
   (24 hours).
4. The consortium Safe receives proposer and canceller roles. The timelock
   holds its own admin role after construction; no deployer or EOA retains an
   administrative bypass. The executor role is open so anyone can execute an
   immutable scheduled operation after it is ready.
5. Organization-level member and ACL operations are executed directly by the
   relevant configured organization/policy Safe and do not incur the
   consortium delay unless the operation changes consortium-wide policy.
6. A separate emergency Safe may suspend a member only. It cannot grant
   permissions, append versions, update envelopes, change authorities, or
   reinstate members. Reinstatement is a governed operation through the
   configured consortium process.
7. Safe addresses and policy-scope mappings are explicit deployment
   configuration. Deployment must remove temporary setup authority before
   operational use. The project does not deploy user-owner Safe accounts as
   part of ordinary application transactions.
8. The implementation and tests must validate Safe and Timelock deployment
   and role behavior on the local Besu-compatible EVM before a production
   compatibility claim. This ADR alone does not establish Safe deployment
   support on the target Besu version.
9. Atomic file creation establishes the signed active creator's initial
   per-file Read and Write ACL grants in `AccessGovernance`. Later version
   appends require an existing Write ACL; the creator's initial grants are
   initialized with the file policy and first version in one transaction.
10. Deployment is timelock-only: deploy `AccessGovernance` and `FileRegistry`
    with the TimelockController address, but do not grant
    `FILE_REGISTRY_ROLE` during deployment. The consortium Safe schedules that
    grant through the timelock. File creation remains unavailable until the
    24-hour delay expires and the operation is executed; any account may
    execute the ready operation.
11. File metadata changes use the `FILE_METADATA_POLICY` authority, falling
    back to the file organization's Safe unless an explicit file-scoped Safe
    is configured. The timelock has no implicit metadata bypass.
12. Safe transactions are the canonical proposal approval and execution
    lifecycle for Safe-governed actions. Safe events and transaction records
    provide approval/execution evidence; TimelockController records scheduling
    and readiness for delayed consortium actions. An application `proposalId`
    is only a correlation reference carried in contract events, not a second
    approval credential or an on-chain proposal registry.

## Consequences

- Per-scope thresholds are configured in each external Safe. Changing an
  authority or policy-to-Safe mapping is itself a protected governance
  operation.
- The contract layer trusts the configured Safe address as the threshold
  boundary. It does not interpret Safe owners' signatures.
- An open executor improves liveness without granting authority to schedule
  or alter an operation; only the configured proposer can schedule it.
- The emergency authority is intentionally unable to reverse a suspension.
- File-scoped metadata policy overrides are governed by the organization Safe;
  without an override, the organization's Safe remains the authority.
- Do not duplicate Safe owner approvals or transaction status in custom
  contract proposal storage. Off-chain proposal systems must retain their
  mapping from application proposal IDs to Safe transactions and receipts.
- The 24-hour delay is an initial consortium policy and can only be changed
  through the existing timelock.
- Until integration tests exercise the selected Safe deployment and
  TimelockController on Besu, production deployment remains gated.

## Approval record

The maintainer approved:

- Safe threshold accounts per authority/policy scope.
- A 24-hour consortium timelock.
- Permissionless execution of ready timelock operations.
- A separate suspension-only emergency Safe.
- Per-policy Safe address selection, with each Safe enforcing its own
  threshold.
- Atomic initial Read and Write grants for the signed file creator.
- No deployer role-grant bypass during bootstrap; activate the file registry
  only through a delayed consortium-Safe timelock operation.
- Safe transaction lifecycle as the canonical proposal model, with application
  proposal IDs serving only as event correlation references.
