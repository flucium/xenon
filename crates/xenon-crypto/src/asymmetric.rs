mod dh;
mod signer;
mod verifier;

pub(super) mod curve25519;
pub(super) mod curve448;

use crate::{
    curve25519::{ed25519_sign, ed25519_verify, x25519_diffie_hellman},
    curve448::{ed448_sign, ed448_verify, x448_diffie_hellman, x448_diffie_hellman_ephemeral},
    hash::{
        sha2::{sha256_digest, sha512_digest},
        sha3::{sha3_256_digest, sha3_512_digest},
    },
    timestamp, Asymmetric, Hasher, Key, PrivateKey, PublicKey, Symmetric, SymmetricKey,
};

use xenon_common::{
    size::{SIZE_10_BYTE, SIZE_114_BYTE},
    Error, ErrorKind, Result,
};

use self::curve25519::x25519_diffie_hellman_ephemeral;

/// Diffie-Hellman
///
/// # Arguments
/// * `private_key` - The private key to perform the Diffie-Hellman with.
/// * `public_key` - The public key to perform the Diffie-Hellman with.
/// * `symmetric` - The symmetric algorithm to use.
///
/// # Returns
/// Shared Secret (SymmetricKey)
///
/// # Errors
/// The error here is very likely to be an Internal error.
///
/// An error will occur if there is a mistake in the key pair.
///
/// # Example
/// ```
/// let private_key = xenon_crypto::PrivateKey::generate(xenon_crypto::Asymmetric::X25519).unwrap();
///
/// let public_key = xenon_crypto::PublicKey::from_private_key(&private_key).unwrap();
///
/// let shared_secret = xenon_crypto::diffie_hellman(&private_key, &public_key, xenon_crypto::Symmetric::Aes128Gcm).unwrap();
/// ```
pub fn diffie_hellman(
    private_key: &PrivateKey,
    public_key: &PublicKey,
    symmetric: Symmetric,
) -> Result<SymmetricKey> {
    check_private_key_expired(private_key)?;

    check_public_key_expired(public_key)?;

    let algorithm: Asymmetric = private_key.algorithm().try_into().unwrap();

    let shared_secret = match algorithm {
        Asymmetric::X25519 => x25519_diffie_hellman(
            private_key.bytes().try_into().unwrap(),
            public_key.bytes().try_into().unwrap(),
        )
        .map_err(|_| Error::internal_error())?
        .to_vec(),

        Asymmetric::X448 => x448_diffie_hellman(
            private_key.bytes().try_into().unwrap(),
            public_key.bytes().try_into().unwrap(),
        )
        .map_err(|_| Error::internal_error())?
        .to_vec(),

        _ => Err(Error::new(
            ErrorKind::Unsupported,
            String::from("Unsupported algorithm"),
        ))?,
    };

    let symmetric_key =
        SymmetricKey::new_from_slice(symmetric, &shared_secret[..symmetric.key_length()])?;

    Ok(symmetric_key)
}

/// Diffie-Hellman Ephemeral
///
/// # Arguments
/// * `public_key` - The public key to perform the Diffie-Hellman Ephemeral with.
/// * `symmetric` - The symmetric algorithm to use.
///
/// # Returns
/// Public Key, Shared Secret (SymmetricKey)
///
/// # Errors
/// The error here is very likely to be an Internal error.
///
/// An error will occur if there is a mistake in the key pair.
///
/// # Example
/// ```
/// let private_key = xenon_crypto::PrivateKey::generate(xenon_crypto::Asymmetric::X25519).unwrap();
///
/// let public_key = xenon_crypto::PublicKey::from_private_key(&private_key).unwrap();
///
/// let (ephemeral_public_key, shared_secret) = xenon_crypto::diffie_hellman_ephemeral(&public_key, xenon_crypto::Symmetric::Aes128Gcm).unwrap();
/// ```
pub fn diffie_hellman_ephemeral(
    public_key: &PublicKey,
    symmetric: Symmetric,
) -> Result<(PublicKey, SymmetricKey)> {
    check_public_key_expired(public_key)?;

    let algorithm: Asymmetric = public_key.algorithm().try_into().unwrap();

    let (public_key, shared_secret) = match algorithm {
        Asymmetric::X25519 => {
            let (public_key, shared_secret) =
                x25519_diffie_hellman_ephemeral(public_key.bytes().try_into().unwrap())
                    .map_err(|_| Error::internal_error())?;

            (
                PublicKey::new_from_slice(Asymmetric::X25519, public_key.as_slice())?,
                SymmetricKey::new_from_slice(symmetric, &shared_secret[..symmetric.key_length()])?,
            )
        }

        Asymmetric::X448 => {
            let (public_key, shared_secret) =
                x448_diffie_hellman_ephemeral(public_key.bytes().try_into().unwrap())
                    .map_err(|_| Error::internal_error())?;

            (
                PublicKey::new_from_slice(Asymmetric::X448, public_key.as_slice())?,
                SymmetricKey::new_from_slice(symmetric, &shared_secret[..symmetric.key_length()])?,
            )
        }

        _ => Err(Error::new(
            ErrorKind::Unsupported,
            String::from("Unsupported algorithm"),
        ))?,
    };

    Ok((public_key, shared_secret))
}

/// Signature
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Signature {
    length: (usize, usize, usize, usize, usize),
    algorithm: [u8; SIZE_10_BYTE],
    hasher: [u8; SIZE_10_BYTE],
    key_id: [u8; 32],
    timestamp: [u8; 8],
    bytes: [u8; SIZE_114_BYTE],
}

impl Signature {
    /// Creates a new signature.
    pub fn new(
        algorithm: &[u8],
        hasher: &[u8],
        key_id: &[u8],
        timestamp: &[u8],
        bytes: &[u8],
    ) -> Self {
        let length = (
            algorithm.len(),
            hasher.len(),
            key_id.len(),
            timestamp.len(),
            bytes.len(),
        );

        let mut signature = Self {
            length,
            algorithm: [0u8; SIZE_10_BYTE],
            hasher: [0u8; SIZE_10_BYTE],
            key_id: [0u8; 32],
            timestamp: [0u8; 8],
            bytes: [0u8; SIZE_114_BYTE],
        };

        for i in 0..algorithm.len() {
            signature.algorithm[i] = algorithm[i];
        }

        for i in 0..hasher.len() {
            signature.hasher[i] = hasher[i];
        }

        for i in 0..key_id.len() {
            signature.key_id[i] = key_id[i];
        }

        for i in 0..timestamp.len() {
            signature.timestamp[i] = timestamp[i];
        }

        for i in 0..bytes.len() {
            signature.bytes[i] = bytes[i];
        }

        signature
    }

    /// Returns the algorithm of the signature.
    pub fn algorithm(&self) -> &[u8] {
        &self.algorithm[..self.algorithm_length()]
    }

    /// Returns the hasher of the signature.
    pub fn hasher(&self) -> &[u8] {
        &self.hasher[..self.hasher_length()]
    }

    /// Returns the key id of the signature.
    pub fn key_id(&self) -> &[u8] {
        &self.key_id[..self.key_id_length()]
    }

    /// Returns the timestamp of the signature.
    pub fn timestamp(&self) -> &[u8] {
        &self.timestamp[..self.timestamp_length()]
    }

    /// Returns the raw bytes of the signature.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.bytes_length()]
    }

    /// Signature to raw vector (bytes).
    pub fn to_vec(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(
            self.length.0
                + self.length.1
                + self.length.2
                + self.length.3
                + self.length.4
                + self.length.0.to_be_bytes().len()
                + self.length.1.to_be_bytes().len()
                + self.length.2.to_be_bytes().len()
                + self.length.3.to_be_bytes().len()
                + self.length.4.to_be_bytes().len()
                + 5,
        );

        buffer.extend_from_slice(&self.length.0.to_be_bytes());
        buffer.extend_from_slice(b":");
        buffer.extend_from_slice(&self.length.1.to_be_bytes());
        buffer.extend_from_slice(b":");
        buffer.extend_from_slice(&self.length.2.to_be_bytes());
        buffer.extend_from_slice(b":");
        buffer.extend_from_slice(&self.length.3.to_be_bytes());
        buffer.extend_from_slice(b":");
        buffer.extend_from_slice(&self.length.4.to_be_bytes());
        buffer.extend_from_slice(b"\n");
        buffer.extend_from_slice(&self.algorithm[..self.algorithm_length()]);
        buffer.extend_from_slice(&self.hasher[..self.hasher_length()]);
        buffer.extend_from_slice(&self.key_id[..self.key_id_length()]);
        buffer.extend_from_slice(&self.timestamp[..self.timestamp_length()]);
        buffer.extend_from_slice(&self.bytes[..self.bytes_length()]);

        buffer
    }

    fn algorithm_length(&self) -> usize {
        self.length.0
    }

    fn hasher_length(&self) -> usize {
        self.length.1
    }

    fn key_id_length(&self) -> usize {
        self.length.2
    }

    fn timestamp_length(&self) -> usize {
        self.length.3
    }

    fn bytes_length(&self) -> usize {
        self.length.4
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        let index = bytes
            .iter()
            .position(|&b| b == b'\n')
            .ok_or(Error::new(ErrorKind::ToDo, String::default()))?;

        let (length, data) = bytes.split_at(index);

        let length_bytes = length.split(|&b| b == b':').collect::<Vec<&[u8]>>();

        if length_bytes.len() != 5 {
            return Err(Error::new(ErrorKind::ToDo, String::default()));
        }

        let length = (
            usize::from_be_bytes(length_bytes[0].try_into().unwrap()),
            usize::from_be_bytes(length_bytes[1].try_into().unwrap()),
            usize::from_be_bytes(length_bytes[2].try_into().unwrap()),
            usize::from_be_bytes(length_bytes[3].try_into().unwrap()),
            usize::from_be_bytes(length_bytes[4].try_into().unwrap()),
        );

        // let length_sum = length.0 + length.1 + length.2 + length.3 + length.4;

        let (mut algorithm, mut hasher, mut key_id, mut timestamp, mut bytes) = (
            [0u8; SIZE_10_BYTE],
            [0u8; SIZE_10_BYTE],
            [0u8; 32],
            [0u8; 8],
            [0u8; SIZE_114_BYTE],
        );

        for i in 0..length.0 {
            // plus 1 to skip newline(\n)
            algorithm[i] = data[i + 1];
        }

        for i in 0..length.1 {
            // plus 1 to skip newline(\n)
            hasher[i] = data[length.0 + i + 1];
        }

        for i in 0..length.2 {
            // plus 1 to skip newline(\n)
            key_id[i] = data[length.0 + length.1 + i + 1];
        }

        for i in 0..length.3 {
            // plus 1 to skip newline(\n)
            timestamp[i] = data[length.0 + length.1 + length.2 + i + 1];
        }

        for i in 0..length.4 {
            // plus 1 to skip newline(\n)
            bytes[i] = data[length.0 + length.1 + length.2 + length.3 + i + 1];
        }

        Ok(Self {
            length,
            algorithm,
            hasher,
            key_id,
            timestamp,
            bytes,
        })
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::try_from(bytes.as_slice())
    }
}

/// Verifies a message with a public key.
///
/// # Arguments
/// * `public_key` - The public key to verify the message with.
/// * `message` - The message to verify.
/// * `signature` - The signature to verify the message with.
///
/// # Example
/// ```
/// let private_key = xenon_crypto::PrivateKey::generate(xenon_crypto::Asymmetric::Ed25519).unwrap();
///
/// let public_key = xenon_crypto::PublicKey::from_private_key(&private_key).unwrap();
///
/// let signature = xenon_crypto::sign(&private_key, xenon_crypto::Hasher::Sha256, b"Hello World").unwrap();
///
/// let is_ok = xenon_crypto::verify(&public_key, b"Hello World", &signature).unwrap();
/// ```
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<bool> {
    check_public_key_expired(public_key)?;

    let algorithm: Asymmetric = public_key.algorithm().try_into().unwrap();

    let id = public_key.id();

    let public_key_bytes = public_key.bytes();

    let md = hash_digest(Hasher::try_from(signature.hasher())?, message)?;

    if signature.algorithm() != algorithm.as_bytes() {
        Err(Error::new(ErrorKind::ToDo, String::from("")))?
    }

    if signature.key_id() != id {
        Err(Error::new(ErrorKind::ToDo, String::from("")))?
    }

    let result = match algorithm {
        Asymmetric::Ed25519 => ed25519_verify(
            public_key_bytes.try_into().unwrap(),
            &md,
            signature.bytes().try_into().unwrap(),
        )
        .map_err(|_| {
            Error::new(
                ErrorKind::VerifyFailed,
                String::from("Ed25519 Verification failed"),
            )
        })?,

        Asymmetric::Ed448 => ed448_verify(
            public_key_bytes.try_into().unwrap(),
            &md,
            signature.bytes().try_into().unwrap(),
        )
        .map_err(|_| {
            Error::new(
                ErrorKind::VerifyFailed,
                String::from("Ed448 Verification failed"),
            )
        })?,

        _ => Err(Error::new(
            ErrorKind::Unsupported,
            String::from("Unsupported algorithm"),
        ))?,
    };

    Ok(result)
}

/// Signs a message with a private key.
///
/// # Arguments
/// * `private_key` - The private key to sign the message with.
/// * `hasher` - The hasher to use.
/// * `message` - The message to sign.
///
/// # Example
/// ```
/// let private_key = xenon_crypto::PrivateKey::generate(xenon_crypto::Asymmetric::Ed25519).unwrap();
///
/// let public_key = xenon_crypto::PublicKey::from_private_key(&private_key).unwrap();
///
/// let signature = xenon_crypto::sign(&private_key, xenon_crypto::Hasher::Sha256, b"Hello World").unwrap();
/// ```
pub fn sign(private_key: &PrivateKey, hasher: Hasher, message: &[u8]) -> Result<Signature> {
    check_private_key_expired(private_key)?;

    let algorithm: Asymmetric = private_key.algorithm().try_into().unwrap();

    let id = private_key.id();

    let private_key_bytes = private_key.bytes();

    let md = hash_digest(hasher, message)?;

    let signature = match algorithm {
        Asymmetric::Ed25519 => ed25519_sign(private_key_bytes.try_into().unwrap(), &md)
            .map_err(|_| {
                Error::new(
                    ErrorKind::SignFailed,
                    String::from("Ed25519 Signing failed"),
                )
            })?
            .to_vec(),

        Asymmetric::Ed448 => ed448_sign(private_key_bytes.try_into().unwrap(), &md)
            .map_err(|_| Error::new(ErrorKind::SignFailed, String::from("Ed448 Signing failed")))?
            .to_vec(),

        _ => {
            return Err(Error::new(
                ErrorKind::Unsupported,
                String::from("Unsupported algorithm"),
            ))
        }
    };

    let timestampt = timestamp().to_be_bytes();

    Ok(Signature::new(
        private_key.algorithm().as_bytes(),
        hasher.as_bytes(),
        id,
        &timestampt,
        &signature,
    ))
}

#[inline]
fn hash_digest(hasher: Hasher, message: &[u8]) -> Result<Vec<u8>> {
    let bytes = match hasher {
        Hasher::Sha256 => sha256_digest(message)?.to_vec(),
        Hasher::Sha512 => sha512_digest(message)?.to_vec(),
        Hasher::Sha3_256 => sha3_256_digest(message)?.to_vec(),
        Hasher::Sha3_512 => sha3_512_digest(message)?.to_vec(),
    };

    Ok(bytes)
}

#[inline]
fn check_private_key_expired(private_key: &PrivateKey) -> Result<()> {
    if private_key.expiry().is_expired() {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::Expired,
            String::from("Private key is expired"),
        ))
    }
}

#[inline]
fn check_public_key_expired(public_key: &PublicKey) -> Result<()> {
    if public_key.expiry().is_expired() {
        Ok(())
    } else {
        Err(Error::new(
            ErrorKind::Expired,
            String::from("Public key is expired"),
        ))
    }
}
