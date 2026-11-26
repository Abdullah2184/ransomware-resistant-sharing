# Core ports

This crate defines infrastructure-facing interfaces and safe data types used
by application workflows:

- `KeyCustodyProvider`: registered public identity data, EIP-712 digest signing,
  HPKE DEK unwrap, and capability/health reporting without exposing private keys.
- `BlobStore`: ciphertext-only content package and envelope-set upload, Cluster
  pin-quorum verification, retrieval streams, and canonical `RRDSPKG1`
  encrypted-package framing (`encode_content_package_frame`,
  `decode_content_package_frame`).
- `GatewayAuthPort` and `LedgerPort`: challenge-response session establishment,
  authoritative identity/head queries, signed access lookup, and signed file,
  version, and envelope-set submission.
- `PreUploadScanner` (`ScannerMode`, `ScanOutcome`, `ScanVerdict`,
  `evaluate_scan_outcome`): optional endpoint pre-upload scanning boundary
  (disabled by default in MVP).
- `Clock` / `SystemClock`: deterministic time source for deadlines and TTL checks.

The traits are exercised through `ports`, `key-custody`, `ipfs-adapter`,
`scanner`, and `application` tests:

```sh
cargo test -p ports -p key-custody -p ipfs-adapter -p scanner -p application --locked
```
