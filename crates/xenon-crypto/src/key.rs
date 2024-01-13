use crate::{
    algorithm::{Asymmetric, Hasher, Symmetric},
    curve25519, curve448,
    hash::{
        hkdf::{hkdf_sha256_derive, hkdf_sha512_derive},
        sha2::sha256_digest,
    },
    rand::gen_32,
    sign, Expiry, Kdf, Signature,
};
use xenon_common::{
    format::{base64ct, hex},
    size::{SIZE_32_BYTE, SIZE_64_BYTE},
    Error, ErrorKind, Result,
};

pub trait Key {
    /// Returns the key id.
    fn id(&self) -> &[u8; SIZE_32_BYTE];

    /// Returns the key algorithm name.
    fn algorithm(&self) -> &str;

    /// Returns the key expiry.
    fn expiry(&self) -> &Expiry;

    /// Returns the key length.
    fn len(&self) -> usize;

    /// Returns the key bytes.
    fn as_bytes(&self) -> &[u8];
}

pub trait AsymmetricKey: Key {
    /// Returns the key signature.
    fn signature(&self) -> Option<&Signature>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymmetricKey {
    id: [u8; SIZE_32_BYTE],
    algorithm: Symmetric,
    expiry: Expiry,
    bytes: Vec<u8>,
}

impl SymmetricKey {
    /// Creates a new symmetric key from a slice.
    ///
    /// # Arguments
    /// * `algorithm` - The symmetric algorithm.
    /// * `bytes` - The key bytes.
    ///
    /// # Errors
    /// Returns an error if the key length is invalid.
    ///
    /// # Example
    /// ```
    /// use xenon_crypto::{Symmetric, SymmetricKey};
    ///
    /// let key = SymmetricKey::new_from_slice(Symmetric::Aes256Gcm, &[0; 32]).unwrap();
    /// ```
    pub fn new_from_slice(algorithm: Symmetric, bytes: &[u8]) -> Result<Self> {
        let id = generate_key_id()?;

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

    /// Generates a new symmetric key.
    ///
    /// # Arguments
    /// * `algorithm` - The symmetric algorithm.
    ///
    /// # Errors
    /// Returns an internal error if the key generation fails.
    ///
    /// # Example
    /// ```
    /// use xenon_crypto::{Symmetric, SymmetricKey};
    ///
    /// let key = SymmetricKey::generate(Symmetric::Aes256Gcm).unwrap();
    /// ```
    pub fn generate(algorithm: Symmetric) -> Result<Self> {
        let id = generate_key_id()?;

        let expiry = Expiry::NO_EXPIRATION;

        let bytes = gen_32()?.to_vec();

        Ok(Self {
            id,
            algorithm,
            expiry,
            bytes,
        })
    }

    /// Derives a new symmetric key from a key derivation function.
    ///
    /// # Arguments
    /// * `algorithm` - The symmetric algorithm.
    /// * `kdf` - The key derivation function.
    ///
    /// # Errors
    /// Returns an internal error if the key derivation fails.
    ///
    /// # Example
    /// ```
    /// use xenon_crypto::{Symmetric, SymmetricKey, Kdf};
    ///
    /// let key = SymmetricKey::generate(Symmetric::Aes256Gcm).unwrap();
    ///
    /// let derived_key = key.derive(Symmetric::Aes256Gcm, Kdf::HkdfSha256).unwrap();
    /// ```
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
    fn id(&self) -> &[u8; SIZE_32_BYTE] {
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
        string.push_str(&hex::encode(&self.id));

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

        let id = value.trim_start().trim_end();

        if id.len() != SIZE_64_BYTE {
            Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid Key id"),
            ))?;
        }

        let id = hex::decode(id)
            .map_err(|_| Error::new(ErrorKind::ParseFailed, String::from("Invalid Key id")))?
            .try_into()
            .unwrap();

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
    id: [u8; SIZE_32_BYTE],
    algorithm: Asymmetric,
    expiry: Expiry,
    bytes: Vec<u8>,
    signature: Option<Signature>,
}

impl PrivateKey {
    /// Creates a new private key from a slice.
    ///
    /// # Arguments
    /// * `algorithm` - The asymmetric algorithm.
    ///
    /// # Errors
    /// Returns an internal error if the key generation fails.
    ///
    /// # Example
    /// ```
    /// use xenon_crypto::{Asymmetric, PrivateKey};
    ///
    /// let private_key = PrivateKey::generate(Asymmetric::Ed25519).unwrap();
    /// ```
    pub fn generate(algorithm: Asymmetric) -> Result<Self> {
        let id = generate_key_id()?;

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

    // ToDo!()
    pub fn derive(&self, algorithm: Asymmetric, hasher: Hasher) -> Result<Self> {
        if !matches!(self.algorithm, Asymmetric::Ed25519 | Asymmetric::Ed448) {
            Err(Error::new(ErrorKind::ToDo, String::default()))?;
        }

        // PrivateKey::generate(algorithm);
        let mut private_key = Self::generate(algorithm)?;

        let signature = sign(self, hasher, &private_key.bytes)?;

        private_key.signature = Some(signature);

        Ok(private_key)
    }
}

impl Key for PrivateKey {
    fn id(&self) -> &[u8; SIZE_32_BYTE] {
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
    fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }
}

impl ToString for PrivateKey {
    fn to_string(&self) -> String {
        let mut string = String::new();

        string.push_str("Key id: ");
        string.push_str(&hex::encode(&self.id));

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

        let signature = match self.signature {
            Some(signature) => {
                let bytes = signature.to_vec();
                base64ct::encode(&bytes)
            }
            None => base64ct::encode(&[]),
        };
        string.push_str("Signature: ");
        string.push_str(&signature);

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

        let id = value.trim_start().trim_end();

        if id.len() != SIZE_64_BYTE {
            Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid Key id"),
            ))?;
        }

        let id = hex::decode(id)
            .map_err(|_| Error::new(ErrorKind::ParseFailed, String::from("Invalid Key id")))?
            .try_into()
            .unwrap();

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
            true => Some(Signature::try_from(signature)?),
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
    id: [u8; SIZE_32_BYTE],
    algorithm: Asymmetric,
    expiry: Expiry,
    bytes: Vec<u8>,
    signature: Option<Vec<u8>>,
}

impl PublicKey {
    /// Creates a new public key from a slice.
    ///
    /// # Arguments
    /// * `algorithm` - The asymmetric algorithm.
    /// * `bytes` - The key bytes.
    ///
    /// # Errors
    /// Returns an error if the key length is invalid.
    ///
    /// # Example
    /// ```
    /// use xenon_crypto::{Asymmetric, PublicKey};
    ///
    /// let public_key = PublicKey::new_from_slice(Asymmetric::Ed25519, &[0; 32]).unwrap();
    /// ```
    pub fn new_from_slice(algorithm: Asymmetric, bytes: &[u8]) -> Result<Self> {
        let id = generate_key_id()?;

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

    /// Generates a new public key from a private key.
    ///
    /// # Arguments
    /// * `priavte_key` - The private key.
    ///
    /// # Errors
    /// Returns an internal error if the key generation fails.
    ///
    /// # Example
    /// ```
    /// use xenon_crypto::{Asymmetric, PrivateKey, PublicKey};
    ///
    /// let private_key = PrivateKey::generate(Asymmetric::Ed25519).unwrap();
    ///
    /// let public_key = PublicKey::from_private_key(&private_key).unwrap();
    /// ```
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
    fn id(&self) -> &[u8; SIZE_32_BYTE] {
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
    fn signature(&self) -> Option<&Signature> {
        todo!()
    }
}

impl ToString for PublicKey {
    fn to_string(&self) -> String {
        let mut string = String::new();

        string.push_str("Key id: ");
        string.push_str(&hex::encode(&self.id));

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

        let id = value.trim_start().trim_end();

        if id.len() != SIZE_64_BYTE {
            Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid Key id"),
            ))?;
        }

        let id = hex::decode(id)
            .map_err(|_| Error::new(ErrorKind::ParseFailed, String::from("Invalid Key id")))?
            .try_into()
            .unwrap();

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

// generate a key id
fn generate_key_id() -> Result<[u8; SIZE_32_BYTE]> {
    let bytes = gen_32().map_err(|_| Error::new(ErrorKind::Internal, String::default()))?;

    let digest =
        sha256_digest(&bytes).map_err(|_| Error::new(ErrorKind::Internal, String::default()))?;

    Ok(digest)
}
