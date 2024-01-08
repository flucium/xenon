mod aead;
mod aes;
mod chacha20;

use self::aes::{
    aes_128_gcm_decrypt, aes_128_gcm_encrypt, aes_192_gcm_decrypt, aes_192_gcm_encrypt,
    aes_256_gcm_decrypt, aes_256_gcm_encrypt,
};
use self::chacha20::{chacha20_poly1305_decrypt, chacha20_poly1305_encrypt};
use crate::{algorithm::Symmetric, rand::gen, Key, SymmetricKey};
use xenon_common::size::{SIZE_12_BYTE, SIZE_16_BYTE};
use xenon_common::{Error, ErrorKind, Result};

/// Symmetric Decryption
///
/// # Arguments
/// * `symmetric_key` - Symmetric key
///
/// * `assosiated_data` - Associated data (optional: use with AEAD)
///
/// * `message` - Message
///
/// # Example
/// ```
/// use xenon_crypto::{Symmetric, SymmetricKey, encrypt,decrypt};
///
/// let symmetric_key = SymmetricKey::generate(Symmetric::Aes256Gcm).unwrap();
///
/// let cipher = encrypt(&symmetric_key, &[], b"Hello World").unwrap();
///
/// let plain = decrypt(&symmetric_key, &[], &cipher).unwrap();
/// ```
pub fn decrypt(
    symmetric_key: &SymmetricKey,
    assosiated_data: Option<&[u8]>,
    message: &[u8],
) -> Result<Vec<u8>> {
    let algorithm: Symmetric = symmetric_key.algorithm().try_into().unwrap();

    check_message_length(algorithm, message)?;

    let key_bytes = symmetric_key.as_bytes();

    let (cipher, iv) = split_message_and_iv(algorithm, message)?;

    let assosiated_data = match assosiated_data {
        Some(data) => data,
        None => &[],
    };

    let plain = match algorithm {
        Symmetric::Aes128Gcm => aes_128_gcm_decrypt(
            key_bytes.try_into().unwrap(),
            iv.try_into().unwrap(),
            assosiated_data,
            cipher,
        )
        .map_err(|_| {
            Error::new(
                ErrorKind::DecryptionFailed,
                String::from("AES-128-GCM Decryption failed"),
            )
        })?,
        Symmetric::Aes192Gcm => aes_192_gcm_decrypt(
            key_bytes.try_into().unwrap(),
            iv.try_into().unwrap(),
            assosiated_data,
            cipher,
        )
        .map_err(|_| {
            Error::new(
                ErrorKind::DecryptionFailed,
                String::from("AES-192-GCM Decryption failed"),
            )
        })?,
        Symmetric::Aes256Gcm => aes_256_gcm_decrypt(
            key_bytes.try_into().unwrap(),
            iv.try_into().unwrap(),
            assosiated_data,
            cipher,
        )
        .map_err(|_| {
            Error::new(
                ErrorKind::DecryptionFailed,
                String::from("AES-256-GCM Decryption failed"),
            )
        })?,
        Symmetric::ChaCha20Poly1305 => chacha20_poly1305_decrypt(
            key_bytes.try_into().unwrap(),
            iv.try_into().unwrap(),
            assosiated_data,
            cipher,
        )
        .map_err(|_| {
            Error::new(
                ErrorKind::DecryptionFailed,
                String::from("ChaCha20-Poly1305 Decryption failed"),
            )
        })?,
    };

    Ok(plain)
}

/// Symmetric Encryption
///
/// # Arguments
/// * `symmetric_key` - Symmetric key
///
/// * `assosiated_data` - Associated data (optional: use with AEAD)
///
/// * `message` - Message
///
/// # Example
/// ```
/// use xenon_crypto::{Symmetric, SymmetricKey, encrypt,decrypt};
///
/// let symmetric_key = SymmetricKey::generate(Symmetric::Aes256Gcm).unwrap();
///
/// let cipher = encrypt(&symmetric_key, &[], b"Hello World").unwrap();
///```
pub fn encrypt(
    symmetric_key: &SymmetricKey,
    assosiated_data: Option<&[u8]>,
    message: &[u8],
) -> Result<Vec<u8>> {
    check_symmetric_key_expired(symmetric_key)?;

    let algorithm: Symmetric = symmetric_key.algorithm().try_into().unwrap();

    let key_bytes = symmetric_key.as_bytes();

    let assosiated_data = match assosiated_data {
        Some(data) => data,
        None => &[],
    };

    let mut cipher_buffer = Vec::new();

    let (bytes, nonce) = match algorithm {
        Symmetric::Aes128Gcm => {
            let nonce = gen_iv::<SIZE_12_BYTE>()?;

            let cipher = aes_128_gcm_encrypt(
                key_bytes.try_into().unwrap(),
                &nonce,
                assosiated_data,
                message,
            )
            .map_err(|_| {
                Error::new(
                    ErrorKind::EncryptionFailed,
                    String::from("AES-128-GCM Encryption failed"),
                )
            })?;

            (cipher, nonce)
        }

        Symmetric::Aes192Gcm => {
            let nonce = gen_iv::<SIZE_12_BYTE>()?;

            let cipher = aes_192_gcm_encrypt(
                key_bytes.try_into().unwrap(),
                &nonce,
                assosiated_data,
                message,
            )
            .map_err(|_| {
                Error::new(
                    ErrorKind::EncryptionFailed,
                    String::from("AES-192-GCM Encryption failed"),
                )
            })?;

            (cipher, nonce)
        }

        Symmetric::Aes256Gcm => {
            let nonce = gen_iv::<SIZE_12_BYTE>()?;

            let cipher = aes_256_gcm_encrypt(
                key_bytes.try_into().unwrap(),
                &nonce,
                assosiated_data,
                message,
            )
            .map_err(|_| {
                Error::new(
                    ErrorKind::EncryptionFailed,
                    String::from("AES-256-GCM Encryption failed"),
                )
            })?;

            (cipher, nonce)
        }

        Symmetric::ChaCha20Poly1305 => {
            // generate nonce
            let nonce = gen_iv::<SIZE_12_BYTE>()?;

            let cipher = chacha20_poly1305_encrypt(
                key_bytes.try_into().unwrap(),
                &nonce,
                assosiated_data,
                message,
            )
            .map_err(|_| {
                Error::new(
                    ErrorKind::EncryptionFailed,
                    String::from("ChaCha20-Poly1305 Encryption failed"),
                )
            })?;

            (cipher, nonce)
        }
    };

    // extend from bytes (cipher)
    cipher_buffer.extend_from_slice(&bytes);

    // extend from nonce
    // append nonce to cipher
    cipher_buffer.extend_from_slice(&nonce);

    Ok(cipher_buffer)
}

// check message length
#[inline]
fn check_message_length(algorithm: Symmetric, message: &[u8]) -> Result<()> {
    let iv_len = match algorithm {
        // 12 bytes
        Symmetric::Aes128Gcm
        | Symmetric::Aes192Gcm
        | Symmetric::Aes256Gcm
        | Symmetric::ChaCha20Poly1305 => SIZE_12_BYTE,
        // 0 bytes
        // _ => return Ok(()),
    };

    let message_len = message.len();

    if message_len == 0 {
        Err(Error::new(
            ErrorKind::InvalidLength,
            String::from("Message length is zero"),
        ))?
    }

    if message_len <= iv_len {
        Err(Error::new(
            ErrorKind::InvalidLength,
            String::from("Message length is less than iv (nonce) length"),
        ))?
    } else {
        Ok(())
    }
}

// split message and iv (nonce)
#[inline]
fn split_message_and_iv(algorithm: Symmetric, message: &[u8]) -> Result<(&[u8], &[u8])> {
    let message_len = message.len();

    let iv_len = match algorithm {
        Symmetric::Aes128Gcm
        | Symmetric::Aes192Gcm
        | Symmetric::Aes256Gcm
        | Symmetric::ChaCha20Poly1305 => SIZE_12_BYTE,
        // _ => 0,
    };

    let cipher = &message[..message_len - iv_len];

    let nonce = &message[message_len - iv_len..];

    Ok((cipher, nonce))
}

// is symmetric key expired?
#[inline]
fn check_symmetric_key_expired(symmetric_key: &SymmetricKey) -> Result<()> {
    if symmetric_key.expiry().is_expired() == false {
        Err(Error::new(
            ErrorKind::Expired,
            String::from("Key is expired"),
        ))?
    } else {
        Ok(())
    }
}

// gen iv
#[inline]
fn gen_iv<const T: usize>() -> Result<[u8; T]> {
    match T {
        SIZE_12_BYTE | SIZE_16_BYTE => gen::<T>(),
        _ => Err(Error::new(
            ErrorKind::InvalidLength,
            String::from("IV (Nonce) length is invalid"),
        ))?,
    }
}
