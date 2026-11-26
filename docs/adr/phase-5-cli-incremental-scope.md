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

- The initial `health` baseline has now been expanded (P4, 26 November 2026) to
  thin CLI commands backed by `crates/application` (`AuthService`,
  `UploadService`, `DownloadService`, `ShareService`) and `GatewayHttpClient`:
  `health`, `login`, `whoami`, `identity`, `ls`, `history`, `upload`, `modify`,
  `download`, `share`, `restore`, and `audit`.
- To preserve endpoint-to-storage isolation (never exposing Kubo/Cluster admin
  credentials to user endpoints), encrypted packages and canonical envelope sets
  are staged via authenticated ciphertext-only gateway routes
  (`POST /v1/blobs/content` using the `RRDSPKG1` frame in `crates/ports`, and
  `POST /v1/blobs/envelopes`).
- Multisig governance actions (member registration, Read/Write ACL grants and
  revocations, emergency suspension) remain executed through the configured
  Safe/Timelock governance workflow rather than unguarded CLI shortcuts.
- Production HSM integration and full end-to-end live-Besu acceptance tests
  remain tracked under P5–P7.

## Specification references

- `TECHNICAL_SPECIFICATION.md` §§8, 9, 12, 15, and 16 Phase 5.
