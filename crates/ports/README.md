# Core ports

This crate defines infrastructure-facing interfaces and safe data types used
by application workflows. The initial `KeyCustodyProvider` port exposes
registered public identity data, EIP-712 digest signing, HPKE DEK unwrap, and
provider health/capability reporting without exposing private-key material.

The interface has no standalone behavior tests; it is exercised through the
`key-custody` implementation tests:

```sh
cargo test -p key-custody --locked
```
