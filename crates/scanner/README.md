# Scanner (`crates/scanner`)

Client-side pre-upload scanning adapters implementing `ports::PreUploadScanner`
(`TECHNICAL_SPECIFICATION.md` §§12.1, 14).

## Contents

- `DisabledScanner` — default MVP adapter (`ScannerMode::Disabled`), which
  performs no inspection and returns `ScanOutcome::Skipped` /
  `ScanVerdict::Allow`.
- Re-exports `PreUploadScanner`, `ScannerMode` (`Disabled` default, `Warn`,
  `Enforce`), `ScanOutcome`, `ScanVerdict`, and `evaluate_scan_outcome`.

## Design Boundary

- Depends strictly on `domain` and `ports` (zero network, storage, database, or
  blockchain dependencies).
- Scanning, when an adapter is enabled post-MVP, runs strictly on the user
  endpoint prior to client-side encryption. The gateway, indexer, and storage
  nodes never inspect or receive plaintext. No `trustedVersion` flag exists
  on-chain.

## Verification

```shell
cargo test -p scanner --locked --offline
```
