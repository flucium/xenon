use crate::algorithm::Symmetric;
// use crate::Uuid;
use crate::{rand::gen_12, Key, SymmetricKey};
use xenon_common::{Error, ErrorKind, Result};

mod aead;
mod aes;

// ToDo...

pub fn decrypt(
    symmetric_key: &SymmetricKey,
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    let algorithm: Symmetric = symmetric_key.algorithm().try_into().unwrap();

    let cipher = &message[..message.len() - algorithm.iv_length().unwrap_or(0)];

    let nonce = &message[message.len() - algorithm.iv_length().unwrap_or(0)..];

    let plain = match algorithm {
        Symmetric::Aes128Gcm => aes::aes_128_gcm_decrypt(
            unsafe {
                symmetric_key
                    .as_bytes()
                    .get_unchecked(..symmetric_key.len())
            }
            .try_into()
            .unwrap(),
            nonce.try_into().unwrap(),
            associated_data,
            cipher,
        ),
        Symmetric::Aes192Gcm => aes::aes_192_gcm_decrypt(
            unsafe {
                symmetric_key
                    .as_bytes()
                    .get_unchecked(..symmetric_key.len())
            }
            .try_into()
            .unwrap(),
            nonce.try_into().unwrap(),
            associated_data,
            cipher,
        ),
        Symmetric::Aes256Gcm => aes::aes_256_gcm_decrypt(
            unsafe {
                symmetric_key
                    .as_bytes()
                    .get_unchecked(..symmetric_key.len())
            }
            .try_into()
            .unwrap(),
            nonce.try_into().unwrap(),
            associated_data,
            cipher,
        ),
    }
    .map_err(|_| {
        Error::new(
            ErrorKind::DecryptionFailed,
            String::from("Decryption failed"),
        )
    })?;

    Ok(plain)
}

pub fn encrypt(
    symmetric_key: &SymmetricKey,
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    // is expired
    if symmetric_key.expiry().is_expired() == false{
        Err(Error::new(
            ErrorKind::Expired,
            String::from("Symmetric key is expired"),
        ))?
    }

    let algorithm: Symmetric = symmetric_key.algorithm().try_into().unwrap();

    let nonce = gen_12()?;

    let mut cipher = match algorithm {
        Symmetric::Aes128Gcm => aes::aes_128_gcm_encrypt(
            unsafe {
                symmetric_key
                    .as_bytes()
                    .get_unchecked(..symmetric_key.len())
            }
            .try_into()
            .unwrap(),
            &nonce,
            associated_data,
            message,
        ),
        Symmetric::Aes192Gcm => aes::aes_192_gcm_encrypt(
            unsafe {
                symmetric_key
                    .as_bytes()
                    .get_unchecked(..symmetric_key.len())
            }
            .try_into()
            .unwrap(),
            &nonce,
            associated_data,
            message,
        ),
        Symmetric::Aes256Gcm => aes::aes_256_gcm_encrypt(
            unsafe {
                symmetric_key
                    .as_bytes()
                    .get_unchecked(..symmetric_key.len())
            }
            .try_into()
            .unwrap(),
            &nonce,
            associated_data,
            message,
        ),
    }
    .map_err(|_| {
        Error::new(
            ErrorKind::EncryptionFailed,
            String::from("Encryption failed"),
        )
    })?;

    cipher.extend_from_slice(&nonce);

    Ok(cipher)
}
