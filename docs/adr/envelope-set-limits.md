# ADR: Envelope-set size limit

**Status:** Accepted by maintainer  
**Decision scope:** Maximum number of member envelopes in one serialized
envelope set

## Context

Specification §6.2 defines the versioned envelope-set structure but does not
set a maximum number of entries. The limit must be consistent across domain
validation, serialization, JSON Schema, and tests so that malformed or
unbounded inputs are rejected consistently.

## Decision

Limit a single envelope set to 1,024 entries. Enforce the same maximum in the
Rust validator and `schemas/key-envelope-set-v1.json`. Preserve deterministic
member ordering and reject duplicate members independently of the size limit.

## Consequences

- Envelope sets above 1,024 entries are invalid and must not be silently
  truncated.
- The maximum is a format constraint, not a claim that every deployment can
  operationally manage 1,024 members.
- A future change to this limit requires a versioned compatibility decision
  and coordinated updates to validators, schema, and boundary tests.

## Approval record

The maintainer approved a maximum of 1,024 entries.

## Specification reference

- `TECHNICAL_SPECIFICATION.md` §6.2.
