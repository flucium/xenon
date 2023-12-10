use super::aead::*;
use core::result::Result;
use openssl::{error::ErrorStack, symm::Cipher};
use xenon_common::size::{SIZE_12_BYTE, SIZE_16_BYTE, SIZE_32_BYTE};

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
