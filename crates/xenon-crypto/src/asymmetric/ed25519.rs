use crate::key::AsymmetricKey;
use ed25519_dalek::{Signer, Verifier};
use xenon_common::error::Error;
use xenon_common::result::Result;


/// Ed25519 verify
/// 
/// # Arguments
/// * `public_key` - Public key
/// * `hasher` - Hasher
/// * `message` - Message
/// * `signature` - Signature
/// 
/// # Returns
/// True if the signature is valid, otherwise false.
/// 
/// # Example
/// ```
/// use xenon_crypto::thread_rng;
/// use xenon_crypto::key::PrivateKey;
/// use xenon_crypto::key::PublicKey;
/// use xenon_crypto::key::Ed25519PrivateKey;
/// use xenon_crypto::key::Ed25519PublicKey;
/// use xenon_crypto::hash::Hasher;
/// use xenon_crypto::hash::sha2::Sha512;
/// use xenon_crypto::ed25519::sign;
/// use xenon_crypto::ed25519::verify;
/// 
/// let private_key = Ed25519PrivateKey::generate(&mut thread_rng());
/// 
/// let public_key = Ed25519PublicKey::from_private(&private_key);
/// 
/// let s = sign(&private_key, Sha512::new(), b"hello").unwrap();
/// 
/// let is_ok = verify(&public_key, Sha512::new(), b"hello", &s).unwrap();
/// 
/// assert_eq!(is_ok, true);
/// ```
pub fn verify<const T: usize>(
    public_key: &crate::key::Ed25519PublicKey,
    mut hasher: impl crate::hash::Hasher<T>,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<bool> {
    hasher.update(message);

    let is_ok = ed25519_dalek::VerifyingKey::from_bytes(public_key.bytes().try_into().unwrap())
        .map_err(|_| Error::new_dummy())?
        .verify(
            &hasher.finalize(),
            &ed25519_dalek::Signature::from_bytes(signature),
        )
        .is_ok();

    Ok(is_ok)
}


/// Ed25519 sign
/// 
/// # Arguments
/// * `private_key` - Private key
/// * `hasher` - Hasher
/// * `message` - Message
/// 
/// # Returns
/// Signature of the message.
/// 
/// # Example
/// ```
/// use xenon_crypto::thread_rng;
/// use xenon_crypto::key::PrivateKey;
/// use xenon_crypto::key::Ed25519PrivateKey;
/// use xenon_crypto::hash::Hasher;
/// use xenon_crypto::hash::sha2::Sha512;
/// use xenon_crypto::ed25519::sign;
/// 
/// let private_key = Ed25519PrivateKey::generate(&mut thread_rng());
/// 
/// let s = sign(&private_key, Sha512::new(), b"hello").unwrap();
/// ```
pub fn sign<const T: usize>(
    private_key: &crate::key::Ed25519PrivateKey,
    mut hasher: impl crate::hash::Hasher<T>,
    message: &[u8],
) -> Result<[u8; 64]> {
    hasher.update(message);

    let signature = ed25519_dalek::SigningKey::from_bytes(private_key.bytes().try_into().unwrap())
        .try_sign(&hasher.finalize())
        .map_err(|_| Error::new_dummy())?
        .to_bytes();

    Ok(signature)
}
