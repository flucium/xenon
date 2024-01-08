pub(super) mod curve25519;
pub(super) mod curve448;

mod dh;
mod signer;
mod verifier;

use crate::algorithm::Hasher;
use crate::curve25519::{x25519_diffie_hellman, x25519_diffie_hellman_ephemeral};
use crate::curve448::{x448_diffie_hellman, x448_diffie_hellman_ephemeral};
use crate::hash::{sha2::*, sha3::*};
use crate::{
    algorithm::Asymmetric,
    curve25519::{ed25519_sign, ed25519_verify},
    curve448::{ed448_sign, ed448_verify},
    Key, PrivateKey, PublicKey, Symmetric, SymmetricKey, Utc, Uuid,
};

use xenon_common::size::{SIZE_16_BYTE, SIZE_24_BYTE, SIZE_32_BYTE};
use xenon_common::{Error, ErrorKind, Result};

#[derive(Debug, PartialEq, Eq)]
pub struct Signature {
    algorithm: Asymmetric,

    key_id: Uuid,

    hasher: Hasher,

    hash: Vec<u8>,

    bytes: Vec<u8>,

    timestamp: u64,
}

impl Signature {
    /// Algorithm name
    pub fn algorithm(&self) -> &Asymmetric {
        &self.algorithm
    }

    /// Key ID
    pub fn key_id(&self) -> &Uuid {
        &self.key_id
    }

    /// Hasher
    pub fn hasher(&self) -> &Hasher {
        &self.hasher
    }

    /// Hash
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    /// Signature bytes
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            &self
                .bytes
                .get_unchecked(..self.algorithm.signature_length().unwrap_or(0))
        }
    }

    /// Timestamp
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut buffer = Vec::new();

        buffer.extend_from_slice(self.algorithm.as_bytes());
        buffer.extend_from_slice(b"\n");
        buffer.extend_from_slice(self.key_id.as_bytes());
        buffer.extend_from_slice(b"\n");
        buffer.extend_from_slice(self.hasher.as_bytes());
        buffer.extend_from_slice(b"\n");
        buffer.extend_from_slice(&self.hash);
        buffer.extend_from_slice(b"\n");
        buffer.extend_from_slice(&self.timestamp.to_be_bytes());
        buffer.extend_from_slice(b"\n");
        buffer.extend_from_slice(&self.bytes);

        buffer
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let lines = bytes.split(|&byte| byte == b'\n').collect::<Vec<&[u8]>>();

        if lines.len() != 6 {
            Err(Error::new(
                ErrorKind::InvalidLength,
                String::from("Invalid signature length"),
            ))?;
        }

        // Algorithm
        let algorithm = Asymmetric::try_from(lines[0])?;

        // Key ID
        let key_id = Uuid::from_slice(lines[1])
            .map_err(|_| Error::new(ErrorKind::ParseFailed, String::from("Parse key id failed")))?;

        // Hasher
        let hasher = Hasher::try_from(lines[2])?;

        // Hash
        let hash = lines[3].to_vec();

        if hash.len() != hasher.output_length() {
            Err(Error::new(
                ErrorKind::InvalidLength,
                String::from("Invalid hash length"),
            ))?;
        }

        // Timestamp
        let timestamp = u64::from_be_bytes(lines[4].try_into().map_err(|_| {
            Error::new(
                ErrorKind::ParseFailed,
                String::from("Parse timestamp failed"),
            )
        })?);

        // Signature bytes
        let bytes = lines[5].to_vec();

        Ok(Self {
            algorithm,
            key_id,
            hasher,
            hash,
            bytes,
            timestamp,
        })
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        let lines = bytes.split(|&byte| byte == b'\n').collect::<Vec<&[u8]>>();

        if lines.len() != 6 {
            Err(Error::new(
                ErrorKind::InvalidLength,
                String::from("Invalid signature length"),
            ))?;
        }

        // Algorithm
        let algorithm = Asymmetric::try_from(lines[0])?;

        // Key ID
        let key_id = Uuid::from_slice(lines[1])
            .map_err(|_| Error::new(ErrorKind::ParseFailed, String::from("Parse key id failed")))?;

        // Hasher
        let hasher = Hasher::try_from(lines[2])?;

        // Hash
        let hash = lines[3].to_vec();

        if hash.len() != hasher.output_length() {
            Err(Error::new(
                ErrorKind::InvalidLength,
                String::from("Invalid hash length"),
            ))?;
        }

        // Timestamp
        let timestamp = u64::from_be_bytes(lines[4].try_into().map_err(|_| {
            Error::new(
                ErrorKind::ParseFailed,
                String::from("Parse timestamp failed"),
            )
        })?);

        // Signature bytes
        let bytes = lines[5].to_vec();

        Ok(Self {
            algorithm,
            key_id,
            hasher,
            hash,
            bytes,
            timestamp,
        })
    }
}

// ToDo
/// Verify
///
/// **!! Under development !!**
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<bool> {
    // check key expired
    if public_key.expiry().is_expired() == false {
        Err(Error::new(
            ErrorKind::Expired,
            String::from("Public key is expired"),
        ))?;
    }

    // get algorithm
    let algorithm = public_key.algorithm().try_into().unwrap();

    // Check algorithm
    if signature.algorithm() != &algorithm {
        Err(Error::new(
            ErrorKind::ToDo,
            String::from("Hash did not match"),
        ))?
    }

    // Check key id
    if signature.key_id() != public_key.id() {
        Err(Error::new(
            ErrorKind::ToDo,
            String::from("Hash did not match"),
        ))?
    }

    // hash
    let hash = match signature.hasher() {
        Hasher::Sha256 => sha256_digest(message)?.to_vec(),
        Hasher::Sha512 => sha512_digest(message)?.to_vec(),
        Hasher::Sha3_256 => sha3_256_digest(message)?.to_vec(),
        Hasher::Sha3_512 => sha3_512_digest(message)?.to_vec(),
    };

    // check hash
    if signature.hash() != hash {
        Err(Error::new(
            ErrorKind::ToDo,
            String::from("Hash did not match"),
        ))?
    }

    // verify
    let result = match algorithm {
        Asymmetric::Ed25519 => ed25519_verify(
            public_key.as_bytes().try_into().unwrap(),
            &hash,
            signature.as_bytes().try_into().unwrap(),
        )
        .map_err(|_| Error::new(ErrorKind::VerifyFailed, String::from("Verify failed")))?,
        Asymmetric::Ed448 => ed448_verify(
            public_key.as_bytes().try_into().unwrap(),
            &hash,
            signature.as_bytes().try_into().unwrap(),
        )
        .map_err(|_| Error::new(ErrorKind::VerifyFailed, String::from("Verify failed")))?,

        _ => Err(Error::new(
            ErrorKind::Unsupported,
            String::from("Unsupported algorithm"),
        ))?,
    };

    Ok(result)
}

/// Sign
///
/// **!! Under development !!**
pub fn sign(private_key: &PrivateKey, hasher: Hasher, message: &[u8]) -> Result<Signature> {
    // check key expired
    if private_key.expiry().is_expired() == false {
        Err(Error::new(
            ErrorKind::Expired,
            String::from("Private key is expired"),
        ))?;
    }

    // Algorithm
    let algorithm: Asymmetric = private_key.algorithm().try_into().unwrap();

    // Key ID
    let key_id = private_key.id().clone();

    // Hash
    let hash = match hasher {
        Hasher::Sha256 => sha256_digest(message)?.to_vec(),
        Hasher::Sha512 => sha512_digest(message)?.to_vec(),
        Hasher::Sha3_256 => sha3_256_digest(message)?.to_vec(),
        Hasher::Sha3_512 => sha3_512_digest(message)?.to_vec(),
    };

    // Signature
    let bytes = match algorithm {
        Asymmetric::Ed25519 => ed25519_sign(private_key.as_bytes().try_into().unwrap(), &hash)
            .map_err(|_| Error::new(ErrorKind::SignFailed, String::from("Sign failed")))?
            .to_vec(),
        Asymmetric::Ed448 => ed448_sign(private_key.as_bytes().try_into().unwrap(), &hash)
            .map_err(|_| Error::new(ErrorKind::SignFailed, String::from("Sign failed")))?
            .to_vec(),
        _ => Err(Error::new(
            ErrorKind::Unsupported,
            String::from("Unsupported algorithm"),
        ))?,
    };

    // Timestamp
    let timestamp = Utc::now().timestamp_millis() as u64;

    Ok(Signature {
        algorithm,
        key_id,
        hasher,
        hash,
        bytes,
        timestamp,
    })
}

/// Diffie-Hellman Key Exchange
///
/// **!! Under development !!**
pub fn diffie_hellma(
    private_key: &PrivateKey,
    public_key: &PublicKey,
    symmetric: Symmetric,
) -> Result<SymmetricKey> {
    is_private_key_expired(private_key)?;

    is_public_key_expired(public_key)?;

    is_match_algorithm(private_key, public_key)?;

    let algorithm = private_key.algorithm().try_into().unwrap();

    let shared_secret = match algorithm {
        Asymmetric::X25519 => {
            let private_key = private_key.as_bytes().try_into().unwrap();

            let public_key = public_key.as_bytes().try_into().unwrap();

            x25519_diffie_hellman(private_key, public_key)
                .map_err(|_| Error::internal_error())?
                .to_vec()
        }
        Asymmetric::X448 => {
            let private_key = private_key.as_bytes().try_into().unwrap();

            let public_key = public_key.as_bytes().try_into().unwrap();

            x448_diffie_hellman(private_key, public_key)
                .map_err(|_| Error::internal_error())?
                .to_vec()
        }
        _ => Err(Error::new(
            ErrorKind::Unsupported,
            String::from("Unsupported algorithm"),
        ))?,
    };

    to_symmetric_key(symmetric, &shared_secret)
}

/// Diffie-Hellman Key Exchange (Ephemeral)
///
/// **!! Under development !!**
pub fn diffie_hellma_ephemeral(
    their_public: &PublicKey,
    symmetric: Symmetric,
) -> Result<(PublicKey, SymmetricKey)> {
    is_public_key_expired(their_public)?;

    let algorithm = their_public.algorithm().try_into().unwrap();

    let (public_key, shared_secret) = match algorithm {
        Asymmetric::X25519 => {
            let public_key = their_public.as_bytes().try_into().unwrap();

            let (public_key, shared_secret) =
                x25519_diffie_hellman_ephemeral(public_key).map_err(|_| Error::internal_error())?;

            let public_key = PublicKey::new_from_slice(
                their_public.algorithm().try_into().unwrap(),
                &public_key,
            )?;

            (public_key, shared_secret.to_vec())
        }
        Asymmetric::X448 => {
            let public_key = their_public.as_bytes().try_into().unwrap();

            let (public_key, shared_secret) =
                x448_diffie_hellman_ephemeral(public_key).map_err(|_| Error::internal_error())?;

            let public_key = PublicKey::new_from_slice(
                their_public.algorithm().try_into().unwrap(),
                &public_key,
            )?;

            (public_key, shared_secret.to_vec())
        }
        _ => Err(Error::new(
            ErrorKind::Unsupported,
            String::from("Unsupported algorithm"),
        ))?,
    };

    let symmetric_key = to_symmetric_key(symmetric, &shared_secret)?;

    Ok((public_key, symmetric_key))
}

#[inline]
fn to_symmetric_key(symmetric: Symmetric, shared_secret: &[u8]) -> Result<SymmetricKey> {
    let key_length = match symmetric {
        Symmetric::Aes128Gcm => SIZE_16_BYTE,
        Symmetric::Aes192Gcm => SIZE_24_BYTE,
        Symmetric::Aes256Gcm => SIZE_32_BYTE,
        Symmetric::ChaCha20Poly1305 => SIZE_32_BYTE,
    };

    let key_bytes = &shared_secret[..key_length];

    SymmetricKey::new_from_slice(symmetric, key_bytes)
}

#[inline]
fn is_match_algorithm(private_key: &PrivateKey, public_key: &PublicKey) -> Result<()> {
    if private_key.algorithm() == public_key.algorithm() {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::Unsupported,
            String::from("Private key and public key must be the same algorithm"),
        ))?
    }
}

#[inline]
fn is_public_key_expired(public_key: &PublicKey) -> Result<()> {
    if public_key.expiry().is_expired() {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::Expired,
            String::from("Public key is expired"),
        ))
    }
}

#[inline]
fn is_private_key_expired(private_key: &PrivateKey) -> Result<()> {
    if private_key.expiry().is_expired() {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::Expired,
            String::from("Private key is expired"),
        ))
    }
}

/*
    Unit tests

    X25519
    X448

    e.g.
    cargo test --package xenon-crypto --lib -- asymmetric::test_x25519 --exact --nocapture
*/

#[test]
fn test_x25519() {
    let private_key = PrivateKey::generate(Asymmetric::X25519).unwrap();

    let public_key = PublicKey::from_private_key(&private_key).unwrap();

    assert_eq!(
        diffie_hellma(&private_key, &public_key, Symmetric::Aes128Gcm).is_ok(),
        true
    );

    assert_eq!(
        diffie_hellma(&private_key, &public_key, Symmetric::Aes192Gcm).is_ok(),
        true
    );

    assert_eq!(
        diffie_hellma(&private_key, &public_key, Symmetric::Aes256Gcm).is_ok(),
        true
    );

    assert_eq!(
        diffie_hellma(&private_key, &public_key, Symmetric::ChaCha20Poly1305).is_ok(),
        true
    );
}

#[test]
fn test_x448() {
    let private_key = PrivateKey::generate(Asymmetric::X448).unwrap();

    let public_key = PublicKey::from_private_key(&private_key).unwrap();

    assert_eq!(
        diffie_hellma(&private_key, &public_key, Symmetric::Aes128Gcm).is_ok(),
        true
    );

    assert_eq!(
        diffie_hellma(&private_key, &public_key, Symmetric::Aes192Gcm).is_ok(),
        true
    );

    assert_eq!(
        diffie_hellma(&private_key, &public_key, Symmetric::Aes256Gcm).is_ok(),
        true
    );

    assert_eq!(
        diffie_hellma(&private_key, &public_key, Symmetric::ChaCha20Poly1305).is_ok(),
        true
    );
}

#[test]
fn test_x25519_ephemeral() {
    let private_key = PrivateKey::generate(Asymmetric::X25519).unwrap();
    let their_public = PublicKey::from_private_key(&private_key).unwrap();

    assert_eq!(
        diffie_hellma_ephemeral(&their_public, Symmetric::Aes128Gcm).is_ok(),
        true
    );

    assert_eq!(
        diffie_hellma_ephemeral(&their_public, Symmetric::Aes192Gcm).is_ok(),
        true
    );
    
    assert_eq!(
        diffie_hellma_ephemeral(&their_public, Symmetric::Aes256Gcm).is_ok(),
        true
    );
    
    assert_eq!(
        diffie_hellma_ephemeral(&their_public, Symmetric::ChaCha20Poly1305).is_ok(),
        true
    );
}

#[test]
fn test_x448_ephemeral() {
    let private_key = PrivateKey::generate(Asymmetric::X448).unwrap();
    
    let their_public = PublicKey::from_private_key(&private_key).unwrap();
    
    assert_eq!(
        diffie_hellma_ephemeral(&their_public, Symmetric::Aes128Gcm).is_ok(),
        true
    );
    assert_eq!(
        diffie_hellma_ephemeral(&their_public, Symmetric::Aes192Gcm).is_ok(),
        true
    );
    assert_eq!(
        diffie_hellma_ephemeral(&their_public, Symmetric::Aes256Gcm).is_ok(),
        true
    );
    assert_eq!(
        diffie_hellma_ephemeral(&their_public, Symmetric::ChaCha20Poly1305).is_ok(),
        true
    );
}
