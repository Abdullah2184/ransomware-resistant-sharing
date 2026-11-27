# Key custody

This crate implements the `ports::KeyCustodyProvider` boundary and startup
custody policy enforcement. Its `DevelopmentKeyCustody` holds
software-generated secp256k1 and X25519 keys in process memory and is explicitly
test/development only. It reports `test_only: true` and exportable private keys;
it is not an HSM adapter and must not be used in production.

`verify_provider_policy` enforces `CustodyStartupPolicy::Production` by
rejecting unhealthy, test-only, or exportable-key providers unless
`CustodyStartupPolicy::UnsafeDevelopment` is explicitly configured.
`DevelopmentKeyCustody` enforces signing/encryption key separation, EIP-2 low-`s`
canonical ECDSA signatures, key-version-bound `KeyId` derivation, and custody-side
`WrapContext` `(memberId, encryptionKeyVersion)` binding on `unwrap_dek`. A
hardware PKCS#11/HSM provider remains unimplemented.

Run its behavior tests with:

```sh
cargo test -p key-custody --locked
```
