use super::aead::*;
use core::result::Result;
use openssl::error::ErrorStack;
use openssl::symm::Cipher;
use xenon_common::size::{SIZE_12_BYTE, SIZE_16_BYTE, SIZE_24_BYTE, SIZE_32_BYTE};

/// AES-128-GCM decrypt
/// 
/// # Arguments
/// * `key` - Key
/// * `nonce` - Nonce
/// * `associated_data` - Associated data
/// * `message` - Message
/// 
/// # Error
/// In most cases, the error is due to a mistake in the message (cipher byte).
pub fn aes_128_gcm_decrypt(
    key: &[u8; SIZE_16_BYTE],
    nonce: &[u8; SIZE_12_BYTE],
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    decrypt_aead::<SIZE_16_BYTE, SIZE_12_BYTE>(
        Cipher::aes_128_gcm(),
        key,
        nonce,
        associated_data,
        message,
    )
}

/// AES-192-GCM decrypt
/// 
/// # Arguments
/// * `key` - Key
/// * `nonce` - Nonce
/// * `associated_data` - Associated data
/// * `message` - Message
/// 
/// # Error
/// In most cases, the error is due to a mistake in the message (cipher byte).
pub fn aes_192_gcm_decrypt(
    key: &[u8; SIZE_24_BYTE],
    nonce: &[u8; SIZE_12_BYTE],
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    decrypt_aead::<SIZE_24_BYTE, SIZE_12_BYTE>(
        Cipher::aes_192_gcm(),
        key,
        nonce,
        associated_data,
        message,
    )
}

/// AES-256-GCM decrypt
/// 
/// # Arguments
/// * `key` - Key
/// * `nonce` - Nonce
/// * `associated_data` - Associated data
/// * `message` - Message
/// 
/// # Error
/// In most cases, the error is due to a mistake in the message (cipher byte).
pub fn aes_256_gcm_decrypt(
    key: &[u8; SIZE_32_BYTE],
    nonce: &[u8; SIZE_12_BYTE],
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    decrypt_aead::<SIZE_32_BYTE, SIZE_12_BYTE>(
        Cipher::aes_256_gcm(),
        key,
        nonce,
        associated_data,
        message,
    )
}

/// AES-128-GCM encrypt
/// 
/// # Arguments
/// * `key` - Key
/// * `nonce` - Nonce
/// * `associated_data` - Associated data
/// * `message` - Message
/// 
/// # Error
/// The error here is very likely to be an Internal error.
pub fn aes_128_gcm_encrypt(
    key: &[u8; SIZE_16_BYTE],
    nonce: &[u8; SIZE_12_BYTE],
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    encrypt_aead::<SIZE_16_BYTE, SIZE_12_BYTE>(
        Cipher::aes_128_gcm(),
        key,
        nonce,
        associated_data,
        message,
    )
}

/// AES-192-GCM encrypt
/// 
/// # Arguments
/// * `key` - Key
/// * `nonce` - Nonce
/// * `associated_data` - Associated data
/// * `message` - Message
/// 
/// # Error
/// The error here is very likely to be an Internal error.
pub fn aes_192_gcm_encrypt(
    key: &[u8; SIZE_24_BYTE],
    nonce: &[u8; SIZE_12_BYTE],
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    encrypt_aead::<SIZE_24_BYTE, SIZE_12_BYTE>(
        Cipher::aes_192_gcm(),
        key,
        nonce,
        associated_data,
        message,
    )
}

/// AES-256-GCM encrypt
/// 
/// # Arguments
/// * `key` - Key
/// * `nonce` - Nonce
/// * `associated_data` - Associated data
/// * `message` - Message
/// 
/// # Error
/// The error here is very likely to be an Internal error.
pub fn aes_256_gcm_encrypt(
    key: &[u8; SIZE_32_BYTE],
    nonce: &[u8; SIZE_12_BYTE],
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    encrypt_aead::<SIZE_32_BYTE, SIZE_12_BYTE>(
        Cipher::aes_256_gcm(),
        key,
        nonce,
        associated_data,
        message,
    )
}


/*
    Unit tests
*/

/*
    AES-128-GCM
    AES-192-GCM
    AES-256-GCM
*/

/*
    AES-128-GCM
        test_aes_128_gcm
        test_aes_128_gcm_decrypt
        test_aes_128_gcm_encrypt
*/

#[test]
fn test_aes_128_gcm() {
    let key = [0u8; SIZE_16_BYTE];
    let nonce = [0u8; SIZE_12_BYTE];
    let associated_data = [0u8; 0];
    let message = Vec::from("Hello, world! こんにちは、世界！");

    let cipher = aes_128_gcm_encrypt(&key, &nonce, &associated_data, &message).unwrap();

    let plain = aes_128_gcm_decrypt(&key, &nonce, &associated_data, &cipher).unwrap();

    assert_eq!(plain, message);
}

#[test]
fn test_aes_128_gcm_decrypt() {
    let key = [0u8; SIZE_16_BYTE];
    let nonce = [0u8; SIZE_12_BYTE];
    let associated_data = [0u8; 0];
    let message = Vec::from("Hello, world! こんにちは、世界！");

    let cipher = aes_128_gcm_encrypt(&key, &nonce, &associated_data, &message).unwrap();

    let plain = aes_128_gcm_decrypt(&key, &nonce, &associated_data, &cipher);

    assert!(plain.is_ok());
}

#[test]
fn test_aes_128_gcm_encrypt() {
    let key = [0u8; SIZE_16_BYTE];
    let nonce = [0u8; SIZE_12_BYTE];
    let associated_data = [0u8; 0];
    let message = Vec::from("Hello, world! こんにちは、世界！");

    let cipher = aes_128_gcm_encrypt(&key, &nonce, &associated_data, &message);

    assert!(cipher.is_ok());
}

/*
    AES-192-GCM
        test_aes_192_gcm
        test_aes_192_gcm_decrypt
        test_aes_192_gcm_encrypt
*/

#[test]
fn test_aes_192_gcm() {
    let key = [0u8; SIZE_24_BYTE];
    let nonce = [0u8; SIZE_12_BYTE];
    let associated_data = [0u8; 0];
    let message = Vec::from("Hello, world! こんにちは、世界！");

    let cipher = aes_192_gcm_encrypt(&key, &nonce, &associated_data, &message).unwrap();

    let plain = aes_192_gcm_decrypt(&key, &nonce, &associated_data, &cipher).unwrap();

    assert_eq!(plain, message);
}

#[test]
fn test_aes_192_gcm_decrypt() {
    let key = [0u8; SIZE_24_BYTE];
    let nonce = [0u8; SIZE_12_BYTE];
    let associated_data = [0u8; 0];
    let message = Vec::from("Hello, world! こんにちは、世界！");

    let cipher = aes_192_gcm_encrypt(&key, &nonce, &associated_data, &message).unwrap();

    let plain = aes_192_gcm_decrypt(&key, &nonce, &associated_data, &cipher);

    assert!(plain.is_ok());
}

#[test]
fn test_aes_192_gcm_encrypt() {
    let key = [0u8; SIZE_24_BYTE];
    let nonce = [0u8; SIZE_12_BYTE];
    let associated_data = [0u8; 0];
    let message = Vec::from("Hello, world! こんにちは、世界！");

    let cipher = aes_192_gcm_encrypt(&key, &nonce, &associated_data, &message);

    assert!(cipher.is_ok());
}

/*
    AES-256-GCM
        test_aes_256_gcm
        test_aes_256_gcm_decrypt
        test_aes_256_gcm_encrypt
*/

#[test]
fn test_aes_256_gcm() {
    let key = [0u8; SIZE_32_BYTE];
    let nonce = [0u8; SIZE_12_BYTE];
    let associated_data = [0u8; 0];
    let message = Vec::from("Hello, world! こんにちは、世界！");

    let cipher = aes_256_gcm_encrypt(&key, &nonce, &associated_data, &message).unwrap();

    let plain = aes_256_gcm_decrypt(&key, &nonce, &associated_data, &cipher).unwrap();

    assert_eq!(plain, message);
}

#[test]
fn test_aes_256_gcm_decrypt() {
    let key = [0u8; SIZE_32_BYTE];
    let nonce = [0u8; SIZE_12_BYTE];
    let associated_data = [0u8; 0];
    let message = Vec::from("Hello, world! こんにちは、世界！");

    let cipher = aes_256_gcm_encrypt(&key, &nonce, &associated_data, &message).unwrap();

    let plain = aes_256_gcm_decrypt(&key, &nonce, &associated_data, &cipher);

    assert!(plain.is_ok());
}

#[test]
fn test_aes_256_gcm_encrypt() {
    let key = [0u8; SIZE_32_BYTE];
    let nonce = [0u8; SIZE_12_BYTE];
    let associated_data = [0u8; 0];
    let message = Vec::from("Hello, world! こんにちは、世界！");

    let cipher = aes_256_gcm_encrypt(&key, &nonce, &associated_data, &message);

    assert!(cipher.is_ok());
}
