use crate::{
    algorithm::{Asymmetric, Symmetric},
    curve25519, curve448,
    hash::hkdf::{hkdf_sha256_derive, hkdf_sha512_derive},
    rand::gen_32,
    Expiry, Kdf, Uuid,
};
use xenon_common::{Error, ErrorKind, Result};

pub trait Key {
    fn id(&self) -> &Uuid;

    fn algorithm(&self) -> &str;

    fn expiry(&self) -> &Expiry;

    fn len(&self) -> usize;

    fn as_bytes(&self) -> &[u8];
}

pub trait AsymmetricKey: Key {
    fn signature(&self) -> Option<&[u8]>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymmetricKey {
    id: Uuid,
    algorithm: Symmetric,
    expiry: Expiry,
    bytes: Vec<u8>,
}

impl SymmetricKey {
    pub fn new_from_slice(algorithm: Symmetric, bytes: &[u8]) -> Result<Self> {
        let id = Uuid::new_v4();

        let expiry = Expiry::NO_EXPIRATION;

        if algorithm.key_length() != bytes.len() {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                format!(
                    "Invalid key length, expected {}, got {}",
                    algorithm.key_length(),
                    bytes.len()
                ),
            ));
        }

        Ok(Self {
            id,
            algorithm,
            expiry,
            bytes: bytes.to_vec(),
        })
    }

    pub fn generate(algorithm: Symmetric) -> Result<Self> {
        let id = Uuid::new_v4();

        let expiry = Expiry::NO_EXPIRATION;

        let bytes = gen_32()?.to_vec();

        Ok(Self {
            id,
            algorithm,
            expiry,
            bytes,
        })
    }

    pub fn derive(&self, algorithm: Symmetric, kdf: Kdf) -> Result<Self> {
        let symmetric = match kdf {
            Kdf::HkdfSha256 => Self::new_from_slice(
                algorithm,
                &hkdf_sha256_derive(&self.bytes, &gen_32()?, &[])?,
            ),
            Kdf::HkdfSha512 => Self::new_from_slice(
                algorithm,
                &hkdf_sha512_derive(&self.bytes, &gen_32()?, &[])?,
            ),
        }?;

        Ok(symmetric)
    }
}

impl Key for SymmetricKey {
    fn id(&self) -> &Uuid {
        &self.id
    }

    fn algorithm(&self) -> &str {
        self.algorithm.as_str()
    }

    fn expiry(&self) -> &Expiry {
        &self.expiry
    }

    fn len(&self) -> usize {
        self.algorithm.key_length()
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe { self.bytes.get_unchecked(..self.algorithm.key_length()) }
    }
}

impl ToString for SymmetricKey {
    fn to_string(&self) -> String {
        let mut string = String::new();

        string.push_str("Key id: ");
        string.push_str(&self.id.to_string());

        string.push('\n');

        string.push_str("Algorithm: ");
        string.push_str(&self.algorithm.to_string());

        string.push('\n');

        string.push_str("Expiry: ");
        string.push_str(&self.expiry.to_string());

        string.push('\n');

        string.push_str("Key: ");
        string.push_str(&openssl::base64::encode_block(&self.bytes));

        string
    }
}

impl TryFrom<String> for SymmetricKey {
    type Error = Error;

    fn try_from(string: String) -> Result<Self> {
        let mut lines = string.lines();

        let (key, value) = lines
            .next()
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?
            .split_once(":")
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?;

        if key != "Key id" {
            Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid Key id"),
            ))?;
        }

        let id = value
            .trim_start()
            .trim_end()
            .parse::<Uuid>()
            .map_err(|_| Error::new(ErrorKind::ParseFailed, String::from("Invalid Key id")))?;

        let (key, value) = lines
            .next()
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?
            .split_once(":")
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?;

        if key != "Algorithm" {
            Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid algorithm"),
            ))?;
        }

        let algorithm: Symmetric =
            value.trim_start().trim_end().try_into().map_err(|_| {
                Error::new(ErrorKind::ParseFailed, String::from("Invalid algorithm"))
            })?;

        let (key, value) = lines
            .next()
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?
            .split_once(":")
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?;

        if key != "Expiry" {
            Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid Key expiry"),
            ))?;
        }

        let expiry = Expiry::try_from(value.trim_start().trim_end())?;

        let (key, value) = lines
            .next()
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?
            .split_once(":")
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?;

        if key != "Key" {
            Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid Key"),
            ))?;
        }

        let key = openssl::base64::decode_block(value.trim_start().trim_end())
            .map_err(|_| Error::new(ErrorKind::ParseFailed, String::from("Invalid Key")))?;

        Ok(Self {
            id,
            algorithm,
            expiry,
            bytes: key,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateKey {
    id: Uuid,
    algorithm: Asymmetric,
    expiry: Expiry,
    bytes: Vec<u8>,
    signature: Option<Vec<u8>>,
}

impl PrivateKey {
    pub fn generate(algorithm: Asymmetric) -> Result<Self> {
        let id = Uuid::new_v4();

        let expiry = Expiry::new();

        let bytes = match algorithm {
            Asymmetric::Ed25519 => curve25519::ed25519_gen_private_key()
                .map_err(|_| Error::new(ErrorKind::Internal, String::default()))?
                .to_vec(),
            Asymmetric::X25519 => curve25519::x25519_gen_private_key()
                .map_err(|_| Error::new(ErrorKind::Internal, String::default()))?
                .to_vec(),

            Asymmetric::Ed448 => curve448::ed448_gen_private_key()
                .map_err(|_| Error::new(ErrorKind::Internal, String::default()))?
                .to_vec(),
            Asymmetric::X448 => curve448::x448_gen_private_key()
                .map_err(|_| Error::new(ErrorKind::Internal, String::default()))?
                .to_vec(),
        };

        Ok(Self {
            id,
            algorithm,
            expiry,
            bytes,
            signature: None,
        })
    }
}

impl Key for PrivateKey {
    fn id(&self) -> &Uuid {
        &self.id
    }

    fn algorithm(&self) -> &str {
        self.algorithm.as_str()
    }

    fn expiry(&self) -> &Expiry {
        &self.expiry
    }

    fn len(&self) -> usize {
        self.algorithm.key_length()
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe { self.bytes.get_unchecked(..self.algorithm.key_length()) }
    }
}

impl AsymmetricKey for PrivateKey {
    fn signature(&self) -> Option<&[u8]> {
        self.signature.as_deref()
    }
}

impl ToString for PrivateKey {
    fn to_string(&self) -> String {
        let mut string = String::new();

        string.push_str("Key id: ");
        string.push_str(&self.id.to_string());

        string.push('\n');

        string.push_str("Algorithm: ");
        string.push_str(&self.algorithm.to_string());

        string.push('\n');

        string.push_str("Expiry: ");
        string.push_str(&self.expiry.to_string());

        string.push('\n');

        string.push_str("Key: ");
        string.push_str(&openssl::base64::encode_block(&self.bytes));

        string.push('\n');

        string.push_str("Signature: ");
        match &self.signature {
            Some(signature) => string.push_str(&openssl::base64::encode_block(&signature)),
            None => string.push_str(&openssl::base64::encode_block(&[])),
        };

        string
    }
}

impl TryFrom<String> for PrivateKey {
    type Error = Error;

    fn try_from(string: String) -> Result<Self> {
        let mut lines = string.lines();

        let (key, value) = lines
            .next()
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?
            .split_once(":")
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?;

        if key != "Key id" {
            Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid Key id"),
            ))?;
        }

        let id = value
            .trim_start()
            .trim_end()
            .parse::<Uuid>()
            .map_err(|_| Error::new(ErrorKind::ParseFailed, String::from("Invalid Key id")))?;

        let (key, value) = lines
            .next()
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?
            .split_once(":")
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?;

        if key != "Algorithm" {
            Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid algorithm"),
            ))?;
        }

        let algorithm: Asymmetric =
            value.trim_start().trim_end().try_into().map_err(|_| {
                Error::new(ErrorKind::ParseFailed, String::from("Invalid algorithm"))
            })?;

        let (key, value) = lines
            .next()
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?
            .split_once(":")
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?;

        if key != "Expiry" {
            Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid Key expiry"),
            ))?;
        }

        let expiry = Expiry::try_from(value.trim_start().trim_end())?;

        let (key, value) = lines
            .next()
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?
            .split_once(":")
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?;

        if key != "Key" {
            Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid Key"),
            ))?;
        }

        let bytes = openssl::base64::decode_block(value.trim_start().trim_end())
            .map_err(|_| Error::new(ErrorKind::ParseFailed, String::from("Invalid Key")))?;

        let (key, value) = lines
            .next()
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?
            .split_once(":")
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?;

        if key != "Signature" {
            Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid Signature"),
            ))?;
        }

        let signature = openssl::base64::decode_block(value.trim_start().trim_end())
            .map_err(|_| Error::new(ErrorKind::ParseFailed, String::from("Invalid Signature")))?;

        let signature = match signature.len() > 0 {
            true => Some(signature),
            false => None,
        };

        Ok(Self {
            id,
            algorithm,
            expiry,
            bytes,
            signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    id: Uuid,
    algorithm: Asymmetric,
    expiry: Expiry,
    bytes: Vec<u8>,
    signature: Option<Vec<u8>>,
}

impl PublicKey {
    pub fn new_from_slice(algorithm: Asymmetric, bytes: &[u8]) -> Result<Self> {
        let id = Uuid::new_v4();

        let expiry = Expiry::NO_EXPIRATION;

        if algorithm.key_length() != bytes.len() {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                format!(
                    "Invalid key length, expected {}, got {}",
                    algorithm.key_length(),
                    bytes.len()
                ),
            ));
        }

        Ok(Self {
            id,
            algorithm,
            expiry,
            bytes: bytes.to_vec(),
            signature: None,
        })
    }

    pub fn from_private_key(priavte_key: &PrivateKey) -> Result<Self> {
        let bytes = match priavte_key.algorithm {
            Asymmetric::Ed25519 => curve25519::ed25519_gen_public_key(
                unsafe {
                    priavte_key
                        .as_bytes()
                        .get_unchecked(..priavte_key.algorithm.key_length())
                }
                .try_into()
                .unwrap(),
            )
            .map_err(|_| Error::new(ErrorKind::Internal, String::default()))?
            .to_vec(),

            Asymmetric::X25519 => curve25519::x25519_gen_public_key(
                unsafe {
                    priavte_key
                        .as_bytes()
                        .get_unchecked(..priavte_key.algorithm.key_length())
                }
                .try_into()
                .unwrap(),
            )
            .map_err(|_| Error::new(ErrorKind::Internal, String::default()))?
            .to_vec(),

            Asymmetric::Ed448 => curve448::ed448_gen_public_key(
                unsafe {
                    priavte_key
                        .as_bytes()
                        .get_unchecked(..priavte_key.algorithm.key_length())
                }
                .try_into()
                .unwrap(),
            )
            .map_err(|_| Error::new(ErrorKind::Internal, String::default()))?
            .to_vec(),

            Asymmetric::X448 => curve448::x448_gen_public_key(
                unsafe {
                    priavte_key
                        .as_bytes()
                        .get_unchecked(..priavte_key.algorithm.key_length())
                }
                .try_into()
                .unwrap(),
            )
            .map_err(|_| Error::new(ErrorKind::Internal, String::default()))?
            .to_vec(),
        };

        Ok(Self {
            id: priavte_key.id.clone(),
            algorithm: priavte_key.algorithm.clone(),
            expiry: priavte_key.expiry.clone(),
            bytes,
            signature: None,
        })
    }
}

impl Key for PublicKey {
    fn id(&self) -> &Uuid {
        &self.id
    }

    fn algorithm(&self) -> &str {
        self.algorithm.as_str()
    }

    fn expiry(&self) -> &Expiry {
        &self.expiry
    }

    fn len(&self) -> usize {
        self.algorithm.key_length()
    }

    fn as_bytes(&self) -> &[u8] {
        unsafe { self.bytes.get_unchecked(..self.algorithm.key_length()) }
    }
}

impl AsymmetricKey for PublicKey {
    fn signature(&self) -> Option<&[u8]> {
        self.signature.as_deref()
    }
}

impl ToString for PublicKey {
    fn to_string(&self) -> String {
        let mut string = String::new();

        string.push_str("Key id: ");
        string.push_str(&self.id.to_string());

        string.push('\n');

        string.push_str("Algorithm: ");
        string.push_str(&self.algorithm.to_string());

        string.push('\n');

        string.push_str("Expiry: ");
        string.push_str(&self.expiry.to_string());

        string.push('\n');

        string.push_str("Key: ");
        string.push_str(&openssl::base64::encode_block(&self.bytes));

        string.push('\n');

        string.push_str("Signature: ");
        match &self.signature {
            Some(signature) => string.push_str(&openssl::base64::encode_block(&signature)),
            None => string.push_str(&openssl::base64::encode_block(&[])),
        };

        string
    }
}

impl TryFrom<String> for PublicKey {
    type Error = Error;

    fn try_from(string: String) -> Result<Self> {
        let mut lines = string.lines();

        let (key, value) = lines
            .next()
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?
            .split_once(":")
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?;

        if key != "Key id" {
            Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid Key id"),
            ))?;
        }

        let id = value
            .trim_start()
            .trim_end()
            .parse::<Uuid>()
            .map_err(|_| Error::new(ErrorKind::ParseFailed, String::from("Invalid Key id")))?;

        let (key, value) = lines
            .next()
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?
            .split_once(":")
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?;

        if key != "Algorithm" {
            Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid algorithm"),
            ))?;
        }

        let algorithm: Asymmetric =
            value.trim_start().trim_end().try_into().map_err(|_| {
                Error::new(ErrorKind::ParseFailed, String::from("Invalid algorithm"))
            })?;

        let (key, value) = lines
            .next()
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?
            .split_once(":")
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?;

        if key != "Expiry" {
            Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid Key expiry"),
            ))?;
        }

        let expiry = Expiry::try_from(value.trim_start().trim_end())?;

        let (key, value) = lines
            .next()
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?
            .split_once(":")
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?;

        if key != "Key" {
            Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid Key"),
            ))?;
        }

        let bytes = openssl::base64::decode_block(value.trim_start().trim_end())
            .map_err(|_| Error::new(ErrorKind::ParseFailed, String::from("Invalid Key")))?;

        let (key, value) = lines
            .next()
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?
            .split_once(":")
            .ok_or(Error::new(ErrorKind::InvalidLength, String::default()))?;

        if key != "Signature" {
            Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid Signature"),
            ))?;
        }

        let signature = openssl::base64::decode_block(value.trim_start().trim_end())
            .map_err(|_| Error::new(ErrorKind::ParseFailed, String::from("Invalid Signature")))?;

        let signature = match signature.len() > 0 {
            true => Some(signature),
            false => None,
        };

        Ok(Self {
            id,
            algorithm,
            expiry,
            bytes,
            signature,
        })
    }
}
