# ADR: Incremental CLI scope follows implemented use cases

**Status:** Accepted for Phase 5 development  
**Decision scope:** CLI behavior while application services and API routes are incomplete

## Context

The specification's Phase 5 requires identity registration and display,
file/folder listing, upload, download, modification, history, sharing,
revocation, and recovery/revert commands. The current `application` crate has
no use-case services. The gateway currently exposes health, login challenge
and session, access lookup, and encrypted content streaming; it does not
expose identity registration, listing, upload, sharing, revocation, or recovery
operations.

## Decision

- Implement CLI commands only when they can call an existing application
  service or documented gateway route.
- Start Phase 5 with a credential-free gateway health command as an operational
  baseline.
- Do not add placeholder commands that imply unsupported behavior, duplicate
  authorization rules in the CLI, or invent gateway endpoints.
- Add the remaining use-case services and routes incrementally, then connect
  thin CLI commands to them with understandable errors and receipts.

## Consequences

- The first CLI increment is intentionally limited and does not satisfy the
  full Phase 5 acceptance criteria.
- The health command verifies only that the HTTP gateway responds
  successfully; it does not establish database, chain, or storage health.
- Phase 5 remains in progress until the required use cases are available and
  exercised end-to-end.

## Specification references

- `TECHNICAL_SPECIFICATION.md` §§8, 9, 12, 15, and 16 Phase 5.
