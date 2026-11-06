
# Blockchain-Based Ransomware-Resistant Data Sharing

A consortium-based encrypted file-sharing and recovery system using
permissioned blockchain, IPFS and hardware-backed key custody.

## Project Overview

The system provides:
- Client-side file encryption.
- Distributed encrypted file storage through IPFS.
- File versioning and immutable audit history.
- Identity-based Read and Write access control.
- Multisignature governance.
- Historical file recovery.

## Technical Specification

See [TECHNICAL_SPECIFICATION.md](TECHNICAL_SPECIFICATION.md)
for the architecture, technology stack, module responsibilities,
cryptographic protocols, functional requirements and implementation plan.

## Technology Stack

- Rust — application core and off-chain services.
- Solidity — smart contracts.
- Hardhat — contract development and testing.
- Hyperledger Besu / QBFT — permissioned blockchain.
- IPFS / IPFS Cluster — encrypted file storage.
- PostgreSQL — indexer and gateway operational data.
- HSM — protected key custody.

## Development Status

Initial repository setup.

Implementation will follow the phases defined in
TECHNICAL_SPECIFICATION.md.
