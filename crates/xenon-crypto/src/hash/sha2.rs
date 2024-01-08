use openssl::hash::MessageDigest;
use xenon_common::size::{SIZE_32_BYTE, SIZE_64_BYTE};
use xenon_common::Result;
use super::digest::message_digest;


pub fn sha512_digest(bytes: &[u8]) -> Result<[u8; SIZE_64_BYTE]> {
    message_digest::<SIZE_64_BYTE>(MessageDigest::sha512(), bytes)
}

pub fn sha256_digest(bytes: &[u8]) -> Result<[u8; SIZE_32_BYTE]> {
    message_digest::<SIZE_32_BYTE>(MessageDigest::sha256(), bytes)
}



/*
    Unit tests
    SHA512
    SHA256
*/

#[test]
fn test_sha512_digest() {
    assert_eq!(
        sha512_digest(&[]).unwrap(),
        [
            207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214, 32, 228,
            5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208, 209, 60, 93, 133,
            242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49, 189, 71, 65, 122, 129,
            165, 56, 50, 122, 249, 39, 218, 62
        ]
    );
}

#[test]
fn test_sha256_digest() {
    assert_eq!(
        sha256_digest(&[]).unwrap(),
        [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85
        ]
    );
}