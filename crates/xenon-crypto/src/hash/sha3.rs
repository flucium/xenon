use super::digest::message_digest;
use openssl::hash::MessageDigest;
use xenon_common::size::{SIZE_32_BYTE, SIZE_64_BYTE};
use xenon_common::Result;

/// Generate SHA3_512 digest
/// 
/// # Arguments
/// * `bytes` - Bytes to digest
/// 
/// # Errors
/// Internal error
pub fn sha3_512_digest(bytes: &[u8]) -> Result<[u8; SIZE_64_BYTE]> {
    message_digest::<SIZE_64_BYTE>(MessageDigest::sha3_512(), bytes)
}

/// Generate SHA3_256 digest
/// 
/// # Arguments
/// * `bytes` - Bytes to digest
/// 
/// # Errors
/// Internal error
pub fn sha3_256_digest(bytes: &[u8]) -> Result<[u8; SIZE_32_BYTE]> {
    message_digest::<SIZE_32_BYTE>(MessageDigest::sha3_256(), bytes)
}

/*
    Unit tests
    SHA3_512
    SHA3_256
*/

#[test]
fn test_sha3_512_digest() {
    assert_eq!(
        sha3_512_digest(&[]).unwrap(),
        [
            166, 159, 115, 204, 162, 58, 154, 197, 200, 181, 103, 220, 24, 90, 117, 110, 151, 201,
            130, 22, 79, 226, 88, 89, 224, 209, 220, 193, 71, 92, 128, 166, 21, 178, 18, 58, 241,
            245, 249, 76, 17, 227, 233, 64, 44, 58, 197, 88, 245, 0, 25, 157, 149, 182, 211, 227,
            1, 117, 133, 134, 40, 29, 205, 38
        ]
    );
}

#[test]
fn test_sha3_256_digest() {
    assert_eq!(
        sha3_256_digest(&[]).unwrap(),
        [
            167, 255, 198, 248, 191, 30, 215, 102, 81, 193, 71, 86, 160, 97, 214, 98, 245, 128,
            255, 77, 228, 59, 73, 250, 130, 216, 10, 75, 128, 248, 67, 74
        ]
    );
}
