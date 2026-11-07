# ADR: Member signing-key proof of possession

**Status:** Accepted by maintainer  
**Decision scope:** On-chain proof that a registered/rotated signing key is
controlled by the intended member

## Context

Specification §§5.3, 7.3 and 9.1 require approved member onboarding and
proof-of-possession for the signing key. Organization Safe approval alone
would allow a mistaken or malicious registration to bind a member ID to a
signing address the member does not control. The contract must also retain
atomic replay and expiry checks for the proof.

## Decision

- Require an EIP-712 `MemberKeyProof` signature from the proposed signing
  address for both member registration and signing/encryption key
  supersession. The organization Safe must separately call the corresponding
  governance function.
- Bind member ID, organization ID, proposed signing address, signing and
  encryption key versions, encryption public key, random nonzero operation
  nonce, and deadline under the `RRDS AccessGovernance` domain.
- Consume proof nonces in a dedicated per-member mapping to prevent replay
  without conflating them with envelope-update operation nonces.
- On-chain proof covers the signing key. Proof of X25519 encryption-key
  possession is not added because the selected custody interface has no
  challenge-decapsulation proof protocol; onboarding authority must validate
  that key out-of-band until that interface is specified.

## Consequences

- Registration and rotation require member and organization participation.
- The signed proof does not replace organization Safe approval or establish
  real-world identity.
- Existing deployments are not ABI-compatible with this change; Phase 2
  contracts have not been deployed to a persistent network.

## Specification references

- `TECHNICAL_SPECIFICATION.md` §§5.3, 7.3 and 9.1.
