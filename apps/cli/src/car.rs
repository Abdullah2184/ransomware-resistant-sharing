//! Thin CLI wrapper around `crypto::car` for extracting verified encrypted
//! content packages returned by `GET /v1/files/{id}/versions/{v}/content`.

use application::EncryptedPackageBytes;
use domain::{AccessReference, DomainError};

/// Parses a CARv1 byte stream, verifies its root header, block SHA-256 CIDs,
/// two-level UnixFS layout (`manifest.json` + `chunks/00000001..N`), and
/// `access.manifest_hash`, returning the verified package for decryption.
pub fn extract_package_from_car(
    car_bytes: &[u8],
    access: &AccessReference,
) -> Result<EncryptedPackageBytes, DomainError> {
    let verified = crypto::extract_verified_car_package(car_bytes, access)?;
    Ok(EncryptedPackageBytes {
        manifest_bytes: verified.manifest_bytes,
        chunks: verified.chunks,
    })
}

/// Encodes an [`EncryptedPackageBytes`] into a Kubo-compatible two-level UnixFS
/// `dag-pb` (`0x70`) directory-rooted CARv1 stream (`manifest.json` + `chunks/00000001..N`).
#[cfg(test)]
pub fn encode_unixfs_package_to_car(
    package: &EncryptedPackageBytes,
) -> (domain::ContentCid, Vec<u8>) {
    crypto::encode_unixfs_car_package(&package.manifest_bytes, &package.chunks)
        .expect("valid test package")
}
