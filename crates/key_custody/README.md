# Key custody

This crate implements the `ports::KeyCustodyProvider` boundary. Its
`DevelopmentKeyCustody` holds software-generated secp256k1 and X25519 keys in
process memory and is explicitly test/development only. It reports that
private keys are exportable; it is not an HSM adapter and must not be used in
production. A production startup guard and hardware provider remain
unimplemented.

Run its behavior tests with:

```sh
cargo test -p key-custody --locked
```
