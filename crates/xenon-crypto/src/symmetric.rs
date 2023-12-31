use self::aes::{
    aes_128_gcm_decrypt, aes_128_gcm_encrypt, aes_192_gcm_decrypt, aes_192_gcm_encrypt,
    aes_256_gcm_decrypt, aes_256_gcm_encrypt,
};
use self::chacha20::{chacha20_poly1305_decrypt, chacha20_poly1305_encrypt};
use crate::{algorithm::Symmetric, rand::gen, Key, SymmetricKey};

use xenon_common::size::{SIZE_12_BYTE, SIZE_16_BYTE};
use xenon_common::{Error, ErrorKind, Result};

mod aead;
mod aes;
mod chacha20;

/*
    ToDo
        AES-128-CBC
        AES-192-CBC
        AES-256-CBC
        Assosiated Data
*/

struct AssosiatedData<'a> {
    info: &'a [u8],
    algorithm: Symmetric,
}

/// Symmetric Decryption
///
/// **!! Under development !!**
pub fn decrypt(symmetric_key: &SymmetricKey, message: &[u8]) -> Result<Vec<u8>> {
    // get algorithm
    let algorithm: Symmetric = symmetric_key.algorithm().try_into().unwrap();

    // get key bytes
    let key_bytes = symmetric_key.as_bytes();

    // check message length
    check_message_length(algorithm, message)?;

    // get message, iv
    let (cipher, iv) = split_message_and_iv(algorithm, message)?;

    let plain = match algorithm {
        Symmetric::Aes128Gcm => aes_128_gcm_decrypt(
            key_bytes.try_into().unwrap(),
            iv.try_into().unwrap(),
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
            key_bytes.try_into().unwrap(),
            iv.try_into().unwrap(),
            &[],
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
            &[],
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
            &[],
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
/// **!! Under development !!**
pub fn encrypt(symmetric_key: &SymmetricKey, message: &[u8]) -> Result<Vec<u8>> {
    is_symmetric_key_expired(symmetric_key)?;

    // get algorithm
    let algorithm: Symmetric = symmetric_key.algorithm().try_into().unwrap();

    // get key bytes
    let key_bytes = symmetric_key.as_bytes();

    let mut cipher_buffer = Vec::new();

    // encrypt
    let (bytes, nonce) = match algorithm {
        Symmetric::Aes128Gcm => {
            // generate nonce
            let nonce = gen_iv::<SIZE_12_BYTE>()?;

            let cipher = aes_128_gcm_encrypt(key_bytes.try_into().unwrap(), &nonce, &[], message)
                .map_err(|_| {
                Error::new(
                    ErrorKind::EncryptionFailed,
                    String::from("AES-128-GCM Encryption failed"),
                )
            })?;

            (cipher, nonce)
        }

        Symmetric::Aes192Gcm => {
            // generate nonce
            let nonce = gen_iv::<SIZE_12_BYTE>()?;

            let cipher = aes_192_gcm_encrypt(key_bytes.try_into().unwrap(), &nonce, &[], message)
                .map_err(|_| {
                Error::new(
                    ErrorKind::EncryptionFailed,
                    String::from("AES-192-GCM Encryption failed"),
                )
            })?;

            (cipher, nonce)
        }

        Symmetric::Aes256Gcm => {
            // generate nonce
            let nonce = gen_iv::<SIZE_12_BYTE>()?;

            let cipher = aes_256_gcm_encrypt(key_bytes.try_into().unwrap(), &nonce, &[], message)
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

            let cipher =
                chacha20_poly1305_encrypt(key_bytes.try_into().unwrap(), &nonce, &[], message)
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
    // get iv (nonce) length
    // let iv_len = algorithm.iv_length().unwrap_or(0);
    let iv_len = match algorithm {
        // 12 bytes
        Symmetric::Aes128Gcm
        | Symmetric::Aes192Gcm
        | Symmetric::Aes256Gcm
        | Symmetric::ChaCha20Poly1305 => SIZE_12_BYTE,

        // 0 bytes
        _ => return Ok(()),
    };

    // get message length
    let message_len = message.len();

    // check message length
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

        _ => 0,
    };

    // get cipher bytes
    let cipher = &message[..message_len - iv_len];

    // get iv (nonce) bytes
    let nonce = &message[message_len - iv_len..];

    Ok((cipher, nonce))
}

// is symmetric key expired?
#[inline]
fn is_symmetric_key_expired(symmetric_key: &SymmetricKey) -> Result<()> {
    if symmetric_key.expiry().is_expired() == false {
        Err(Error::new(
            ErrorKind::Expired,
            String::from("Symmetric key is expired"),
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

/*
    !! Under development !!

    Unit tests
    e.g.
    cargo test --package xenon-crypto --lib -- symmetric::test_symmetric_aes_256_gcm --exact --nocapture

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
