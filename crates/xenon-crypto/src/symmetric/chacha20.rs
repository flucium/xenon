use super::aead::*;
use core::result::Result;
use openssl::{error::ErrorStack, symm::Cipher};
use xenon_common::size::{SIZE_12_BYTE, SIZE_32_BYTE};

/// ChaCha20-Poly1305 decrypt
///
/// # Arguments
/// * `key` - Key
/// * `nonce` - Nonce
/// * `associated_data` - Associated data
/// * `message` - Message
///
/// # Error
/// In most cases, the error is due to a mistake in the message (cipher byte).
pub fn chacha20_poly1305_decrypt(
    key: &[u8; SIZE_32_BYTE],
    nonce: &[u8; SIZE_12_BYTE],
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    decrypt_aead(
        Cipher::chacha20_poly1305(),
        key,
        nonce,
        associated_data,
        message,
    )
}

/// ChaCha20-Poly1305 encrypt
///
/// # Arguments
/// * `key` - Key
/// * `nonce` - Nonce
/// * `associated_data` - Associated data
/// * `message` - Message
///
/// # Error
/// The error here is very likely to be an Internal error.
pub fn chacha20_poly1305_encrypt(
    key: &[u8; SIZE_32_BYTE],
    nonce: &[u8; SIZE_12_BYTE],
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    encrypt_aead(
        Cipher::chacha20_poly1305(),
        key,
        nonce,
        associated_data,
        message,
    )
}

/*
    Unit Tests
*/

/*
    ChaCha20-Poly1305
        test_chacha20_poly1305
        test_chacha20_poly1305_decrypt
        test_chacha20_poly1305_encrypt
*/

#[test]
fn test_symmetric_chacha20_poly1305() {
    let key = [0u8; SIZE_32_BYTE];
    let nonce = [0u8; SIZE_12_BYTE];
    let associated_data = [0u8; 0];
    let message = Vec::from("Hello, world! こんにちは、世界！");

    let cipher = chacha20_poly1305_encrypt(&key, &nonce, &associated_data, &message).unwrap();

    let plain = chacha20_poly1305_decrypt(&key, &nonce, &associated_data, &cipher).unwrap();

    assert_eq!(plain, message);
}

#[test]
fn test_symmetric_chacha20_poly1305_decrypt() {
    let key = [0u8; SIZE_32_BYTE];
    let nonce = [0u8; SIZE_12_BYTE];
    let associated_data = [0u8; 0];
    let message = Vec::from("Hello, world! こんにちは、世界！");

    let cipher = chacha20_poly1305_encrypt(&key, &nonce, &associated_data, &message).unwrap();

    let plain = chacha20_poly1305_decrypt(&key, &nonce, &associated_data, &cipher);
    
    assert!(plain.is_ok());
}

#[test]
fn test_symmetric_chacha20_poly1305_encrypt() {
    let key = [0u8; SIZE_32_BYTE];
    let nonce = [0u8; SIZE_12_BYTE];
    let associated_data = [0u8; 0];
    let message = Vec::from("Hello, world! こんにちは、世界！");

    let cipher = chacha20_poly1305_encrypt(&key, &nonce, &associated_data, &message).unwrap();

    assert_ne!(cipher, message);
}
