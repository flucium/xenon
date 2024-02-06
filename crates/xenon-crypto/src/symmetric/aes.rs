use aead::KeyInit;
use xenon_common::result::Result;

use crate::key::SymmetricKey;

/// AES-256-GCM
///
/// Decrypts a message using AES-256-GCM.
///
/// # Arguments
/// * `aes_key` - The AES-256 key.
/// * `associated_data` - The associated data.
/// * `message` - The message to decrypt.
///
/// # Returns
/// The decrypted message.
///
/// # Example
/// ```
/// use xenon_crypto::aes::{aes_256_gcm_decrypt,aes_256_gcm_encrypt};
/// use xenon_crypto::key::SymmetricKey;
/// use xenon_crypto::key::Aes256Key;
/// use xenon_crypto::rand::gen_12;
/// use xenon_crypto::rand::thread_rng;
///
/// let aes_key = Aes256Key::generate(thread_rng());
///
/// let message = b"Hello, World!";
///
/// let nonce = gen_12();
///
/// let associated_data = b"associated_data";
///
/// let cipher = aes_256_gcm_encrypt(&aes_key, &nonce, associated_data, message).unwrap();
///
/// let plain = aes_256_gcm_decrypt(&aes_key, associated_data, &cipher).unwrap();
///
/// assert_eq!(plain,message);
/// ```
pub fn aes_256_gcm_decrypt(
    aes_key: &crate::key::Aes256Key,
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    super::aead_decrypt(
        &aes_gcm::Aes256Gcm::new_from_slice(&aes_key.bytes()).unwrap(),
        associated_data,
        message,
    )
}

/// AES-256-GCM
///
/// Encrypts a message using AES-256-GCM.
///
/// # Arguments
/// * `aes_key` - The AES-256 key.
/// * `nonce` - The nonce.
/// * `associated_data` - The associated data.
/// * `message` - The message to encrypt.
///
/// # Returns
/// The encrypted message.
///
/// # Example
/// ```
/// use xenon_crypto::aes::{aes_256_gcm_decrypt,aes_256_gcm_encrypt};
/// use xenon_crypto::key::SymmetricKey;
/// use xenon_crypto::key::Aes256Key;
/// use xenon_crypto::rand::gen_12;
/// use xenon_crypto::rand::thread_rng;
///
/// let aes_key = Aes256Key::generate(thread_rng());
///
/// let message = b"Hello, World!";
///
/// let nonce = gen_12();
///
/// let associated_data = b"associated_data";
///
/// let cipher = aes_256_gcm_encrypt(&aes_key, &nonce, associated_data, message).unwrap();
/// ```
pub fn aes_256_gcm_encrypt(
    aes_key: &crate::key::Aes256Key,
    nonce: &[u8; 12],
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    super::aead_encrypt(
        &aes_gcm::Aes256Gcm::new_from_slice(&aes_key.bytes()).unwrap(),
        nonce,
        associated_data,
        message,
    )
}

/// AES-192-GCM
///
/// Decrypts a message using AES-192-GCM.
///
/// # Arguments
/// * `aes_key` - The AES-192 key.
/// * `associated_data` - The associated data.
/// * `message` - The message to decrypt.
///     
/// # Returns
/// The decrypted message.
///
/// # Example
/// ```
/// use xenon_crypto::aes::{aes_192_gcm_decrypt,aes_192_gcm_encrypt};
/// use xenon_crypto::key::SymmetricKey;
/// use xenon_crypto::key::Aes192Key;
/// use xenon_crypto::rand::gen_12;
/// use xenon_crypto::rand::thread_rng;
///
/// let aes_key = Aes192Key::generate(thread_rng());
///
/// let message = b"Hello, World!";
///
/// let nonce = gen_12();
///
/// let associated_data = b"associated_data";
///
/// let cipher = aes_192_gcm_encrypt(&aes_key, &nonce, associated_data, message).unwrap();
///
/// let plain = aes_192_gcm_decrypt(&aes_key, associated_data, &cipher).unwrap();
///
/// assert_eq!(plain,message);
/// ```
pub fn aes_192_gcm_decrypt(
    aes_key: &crate::key::Aes192Key,
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    super::aead_decrypt(
        &aes_gcm::AesGcm::<aes_gcm::aes::Aes192, aes_gcm::aead::consts::U12>::new_from_slice(
            &aes_key.bytes(),
        )
        .unwrap(),
        associated_data,
        message,
    )
}

/// AES-192-GCM
///
/// Encrypts a message using AES-192-GCM.
///
/// # Arguments
/// * `aes_key` - The AES-192 key.
/// * `nonce` - The nonce.
/// * `associated_data` - The associated data.
/// * `message` - The message to encrypt.
///
/// # Returns
/// The encrypted message.
///
/// # Example
/// ```
/// use xenon_crypto::aes::{aes_192_gcm_decrypt,aes_192_gcm_encrypt};
/// use xenon_crypto::key::SymmetricKey;
/// use xenon_crypto::key::Aes192Key;
/// use xenon_crypto::rand::gen_12;
/// use xenon_crypto::rand::thread_rng;
///
/// let aes_key = Aes192Key::generate(thread_rng());
///
/// let message = b"Hello, World!";
///
/// let nonce = gen_12();
///
/// let associated_data = b"associated_data";
///
/// let cipher = aes_192_gcm_encrypt(&aes_key, &nonce, associated_data, message).unwrap();
/// ```
pub fn aes_192_gcm_encrypt(
    aes_key: &crate::key::Aes192Key,
    nonce: &[u8; 12],
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    super::aead_encrypt(
        &aes_gcm::AesGcm::<aes_gcm::aes::Aes192, aes_gcm::aead::consts::U12>::new_from_slice(
            &aes_key.bytes(),
        )
        .unwrap(),
        nonce,
        associated_data,
        message,
    )
}

/// AES-128-GCM
///
/// Decrypts a message using AES-128-GCM.
///
/// # Arguments
/// * `aes_key` - The AES-128 key.
/// * `associated_data` - The associated data.
/// * `message` - The message to decrypt.
///     
/// # Returns
/// The decrypted message.
///
/// # Example
/// ```
/// use xenon_crypto::aes::{aes_128_gcm_decrypt,aes_128_gcm_encrypt};
/// use xenon_crypto::key::SymmetricKey;
/// use xenon_crypto::key::Aes128Key;
/// use xenon_crypto::rand::gen_12;
/// use xenon_crypto::rand::thread_rng;
///
/// let aes_key = Aes128Key::generate(thread_rng());
///
/// let message = b"Hello, World!";
///
/// let nonce = gen_12();
///
/// let associated_data = b"associated_data";
///
/// let cipher = aes_128_gcm_encrypt(&aes_key, &nonce, associated_data, message).unwrap();
///
/// let plain = aes_128_gcm_decrypt(&aes_key, associated_data, &cipher).unwrap();
///
/// assert_eq!(plain,message);
/// ```
pub fn aes_128_gcm_decrypt(
    aes_key: &crate::key::Aes128Key,
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    super::aead_decrypt(
        &aes_gcm::Aes128Gcm::new_from_slice(&aes_key.bytes()).unwrap(),
        associated_data,
        message,
    )
}

/// AES-128-GCM
///
/// Encrypts a message using AES-128-GCM.
///
/// # Arguments
/// * `aes_key` - The AES-128 key.
/// * `nonce` - The nonce.
/// * `associated_data` - The associated data.
/// * `message` - The message to encrypt.
///
/// # Returns
/// The encrypted message.
///
/// # Example
/// ```
/// use xenon_crypto::aes::{aes_128_gcm_decrypt,aes_128_gcm_encrypt};
/// use xenon_crypto::key::SymmetricKey;
/// use xenon_crypto::key::Aes128Key;
/// use xenon_crypto::rand::gen_12;
/// use xenon_crypto::rand::thread_rng;
///
/// let aes_key = Aes128Key::generate(thread_rng());
///
/// let message = b"Hello, World!";
///
/// let nonce = gen_12();
///
/// let associated_data = b"associated_data";
///
/// let cipher = aes_128_gcm_encrypt(&aes_key, &nonce, associated_data, message).unwrap();
/// ```
pub fn aes_128_gcm_encrypt(
    aes_key: &crate::key::Aes128Key,
    nonce: &[u8; 12],
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    super::aead_encrypt(
        &aes_gcm::Aes128Gcm::new_from_slice(&aes_key.bytes()).unwrap(),
        nonce,
        associated_data,
        message,
    )
}
