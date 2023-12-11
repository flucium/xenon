use crate::algorithm::Symmetric;
use crate::symmetric::aes::{aes_128_gcm_decrypt, aes_192_gcm_decrypt, aes_256_gcm_decrypt};
use crate::symmetric::chacha20::chacha20_poly1305_decrypt;
// use crate::Uuid;
use crate::{rand::gen_12, Key, SymmetricKey};
use xenon_common::{Error, ErrorKind, Result};

use self::aes::{aes_128_gcm_encrypt, aes_192_gcm_encrypt, aes_256_gcm_encrypt};
use self::chacha20::chacha20_poly1305_encrypt;

mod aead;
mod aes;
mod chacha20;

/*
    ToDo
        AES-128-CBC
        AES-192-CBC
        AES-256-CBC
        Assosiated Data
        Flexible nonce
*/

/// Symmetric Decryption
///
/// **!! Under development !!**
pub fn decrypt(symmetric_key: &SymmetricKey, message: &[u8]) -> Result<Vec<u8>> {
    // get algorithm
    let algorithm: Symmetric = symmetric_key.algorithm().try_into().unwrap();

    // get key bytes
    let key = symmetric_key.as_bytes();

    // get message length
    let message_len = message.len();

    // get iv (nonce) length
    let iv_len = algorithm.iv_length().unwrap_or(0);

    // check message length
    if message_len <= iv_len {
        Err(Error::new(
            ErrorKind::InvalidLength,
            String::from("Message length is less than iv (nonce) length"),
        ))?
    }

    // get cipher bytes
    let cipher = &message[..message_len - iv_len];

    // get iv (nonce) bytes
    let nonce = &message[message_len - iv_len..];

    let plain = match algorithm {
        Symmetric::Aes128Gcm => aes_128_gcm_decrypt(
            key.try_into().unwrap(),
            nonce.try_into().unwrap(),
            &[],
            cipher,
        )
        .map_err(|_| {
            Error::new(
                ErrorKind::DecryptionFailed,
                String::from("AES-128-GCM Decryption failed"),
            )
        })?,
        Symmetric::Aes192Gcm => aes_192_gcm_decrypt(
            key.try_into().unwrap(),
            nonce.try_into().unwrap(),
            &[],
            cipher,
        )
        .map_err(|_| {
            Error::new(
                ErrorKind::DecryptionFailed,
                String::from("AES-128-GCM Decryption failed"),
            )
        })?,
        Symmetric::Aes256Gcm => aes_256_gcm_decrypt(
            key.try_into().unwrap(),
            nonce.try_into().unwrap(),
            &[],
            cipher,
        )
        .map_err(|_| {
            Error::new(
                ErrorKind::DecryptionFailed,
                String::from("AES-128-GCM Decryption failed"),
            )
        })?,
        Symmetric::ChaCha20Poly1305 => chacha20_poly1305_decrypt(
            key.try_into().unwrap(),
            nonce.try_into().unwrap(),
            &[],
            cipher,
        )
        .map_err(|_| {
            Error::new(
                ErrorKind::DecryptionFailed,
                String::from("AES-128-GCM Decryption failed"),
            )
        })?,
    };

    Ok(plain)
}

/// Symmetric Encryption
///
/// **!! Under development !!**
pub fn encrypt(symmetric_key: &SymmetricKey, message: &[u8]) -> Result<Vec<u8>> {
    // is key expired?
    if symmetric_key.expiry().is_expired() == false {
        Err(Error::new(
            ErrorKind::Expired,
            String::from("Symmetric key is expired"),
        ))?
    }

    // get algorithm
    let algorithm: Symmetric = symmetric_key.algorithm().try_into().unwrap();

    // get key bytes
    let key_bytes = symmetric_key.as_bytes();

    // get iv (nonce)
    let nonce = gen_12()?;

    let mut cipher = Vec::new();

    // encrypt
    let bytes = match algorithm {
        Symmetric::Aes128Gcm => {
            aes_128_gcm_encrypt(key_bytes.try_into().unwrap(), &nonce, &[], message).map_err(
                |_| {
                    Error::new(
                        ErrorKind::EncryptionFailed,
                        String::from("AES-128-GCM Encryption failed"),
                    )
                },
            )?
        }

        Symmetric::Aes192Gcm => {
            aes_192_gcm_encrypt(key_bytes.try_into().unwrap(), &nonce, &[], message).map_err(
                |_| {
                    Error::new(
                        ErrorKind::EncryptionFailed,
                        String::from("AES-192-GCM Encryption failed"),
                    )
                },
            )?
        }

        Symmetric::Aes256Gcm => {
            aes_256_gcm_encrypt(key_bytes.try_into().unwrap(), &nonce, &[], message).map_err(
                |_| {
                    Error::new(
                        ErrorKind::EncryptionFailed,
                        String::from("AES-256-GCM Encryption failed"),
                    )
                },
            )?
        }

        Symmetric::ChaCha20Poly1305 => {
            chacha20_poly1305_encrypt(key_bytes.try_into().unwrap(), &nonce, &[], message).map_err(
                |_| {
                    Error::new(
                        ErrorKind::EncryptionFailed,
                        String::from("ChaCha20-Poly1305 Encryption failed"),
                    )
                },
            )?
        }
    };

    // extend from bytes (cipher)
    cipher.extend_from_slice(&bytes);

    // extend from nonce
    // append nonce to cipher
    cipher.extend_from_slice(&nonce);

    Ok(cipher)
}


/*
    
    !! Under development !!
        
        Unit tests
    
*/

/*

    Encrypt and Decrypt

    ChaCha20-Poly1305
    AES-256-GCM
    AES-192-GCM
    AES-128-GCM
    
*/

#[test]
fn test_symmetric_chacha20_poly1305() {
    // message
    let message = b"Hello World";

    // generate symmetric key
    let symmetric_key = SymmetricKey::generate(Symmetric::ChaCha20Poly1305).unwrap();

    let cipher = encrypt(&symmetric_key, message).unwrap();

    let plain = decrypt(&symmetric_key, &cipher).unwrap();

    // cipher != plain
    assert_ne!(cipher, plain);

    // message != cipher
    assert_ne!(message, cipher.as_slice());

    // message == plain
    assert_eq!(message, plain.as_slice());
}

#[test]
fn test_symmetric_aes_256_gcm() {
    // message
    let message = b"Hello World";

    // generate symmetric key
    let symmetric_key = SymmetricKey::generate(Symmetric::Aes256Gcm).unwrap();

    let cipher = encrypt(&symmetric_key, message).unwrap();

    let plain = decrypt(&symmetric_key, &cipher).unwrap();

    // cipher != plain
    assert_ne!(cipher, plain);

    // message != cipher
    assert_ne!(message, cipher.as_slice());

    // message == plain
    assert_eq!(message, plain.as_slice());
}

#[test]
fn test_symmetric_aes_192_gcm() {
    // message
    let message = b"Hello World";

    // generate symmetric key
    let symmetric_key = SymmetricKey::generate(Symmetric::Aes192Gcm).unwrap();

    let cipher = encrypt(&symmetric_key, message).unwrap();

    let plain = decrypt(&symmetric_key, &cipher).unwrap();

    // cipher != plain
    assert_ne!(cipher, plain);

    // message != cipher
    assert_ne!(message, cipher.as_slice());

    // message == plain
    assert_eq!(message, plain.as_slice());
}

#[test]
fn test_symmetric_aes_128_gcm() {
    // message
    let message = b"Hello World";

    // generate symmetric key
    let symmetric_key = SymmetricKey::generate(Symmetric::Aes128Gcm).unwrap();

    let cipher = encrypt(&symmetric_key, message).unwrap();

    let plain = decrypt(&symmetric_key, &cipher).unwrap();

    // cipher != plain
    assert_ne!(cipher, plain);

    // message != cipher
    assert_ne!(message, cipher.as_slice());

    // message == plain
    assert_eq!(message, plain.as_slice());
}
