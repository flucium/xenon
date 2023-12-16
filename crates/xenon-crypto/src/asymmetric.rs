use crate::algorithm::Hasher;
use crate::hash::{sha2::*, sha3::*};
use crate::{
    algorithm::Asymmetric,
    curve25519::{ed25519_sign, ed25519_verify},
    curve448::{ed448_sign, ed448_verify},
    Key, PrivateKey,
};
use crate::{PublicKey, Utc, Uuid};
use xenon_common::{Error, ErrorKind, Result};

pub(super) mod curve25519;
pub(super) mod curve448;
mod dh;
mod signer;
mod verifier;
// mod curve448;

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
