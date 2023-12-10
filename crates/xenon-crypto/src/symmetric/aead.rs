use core::result::Result;
use openssl::error::ErrorStack;
use xenon_common::size::SIZE_16_BYTE;


/// Decrypt aead
/// 
/// # Arguments
/// * `symm` - Symmetric cipher
/// * `key` - Key
/// * `iv` - IV
/// * `associated_data` - Associated data
/// * `message` - Message
pub(super) fn decrypt_aead<const T: usize, const U: usize>(
    symm: openssl::symm::Cipher,
    key: &[u8; T],
    iv: &[u8; U],
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let (message, tag) = message.split_at(message.len() - SIZE_16_BYTE);

    let plain = openssl::symm::decrypt_aead(symm, key, Some(iv), associated_data, message, &tag)?;

    Ok(plain)
}

/// Encrypt aead
///     
/// # Arguments
/// * `symm` - Symmetric cipher
/// * `key` - Key
/// * `iv` - IV
/// * `associated_data` - Associated data
/// * `message` - Message
pub(super) fn encrypt_aead<const T: usize, const U: usize>(
    symm: openssl::symm::Cipher,
    key: &[u8; T],
    iv: &[u8; U],
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let mut tag = [0u8; SIZE_16_BYTE];

    let mut cipher =
        openssl::symm::encrypt_aead(symm, key, Some(iv), associated_data, message, &mut tag)?;

    cipher.extend_from_slice(&tag);

    Ok(cipher)
}
