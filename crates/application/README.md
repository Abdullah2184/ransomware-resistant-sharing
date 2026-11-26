# Application Use Cases

This crate implements the infrastructure-independent RRDS client workflows
(`TECHNICAL_SPECIFICATION.md` §§9, 11–12). It depends only on `domain`,
`crypto`, and `ports`, allowing the CLI (`apps/cli`) and any future desktop GUI
to share identical business rules without embedding HTTP, SQL, or ABI details.

## Modules

- `auth`: EIP-712 login challenge validation and signing via `KeyCustodyProvider`.
- `upload`: Local AES-256-GCM chunk + chunk-0 private-metadata encryption, HPKE
  recipient envelope wrapping, IPFS pin-before-commit ordering, optimistic
  concurrency (`StaleHead`), append-only restore, and `OrphanedUpload` reporting.
- `download`: Signed EIP-712 `AccessLookup`, canonical envelope-set and manifest
  verification, DEK unwrap via key custody, per-chunk CID verification, and
  authenticated AES-256-GCM decryption.
- `share`: Authorized DEK unwrap and new immutable envelope-set publication for
  an added reader without re-encrypting file ciphertext.

## Verification

```shell
cargo test -p application --locked
```
