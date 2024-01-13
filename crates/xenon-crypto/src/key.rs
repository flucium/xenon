/*
    ToDo:
    parse_asymmetric_key_from_string / parse_symmetric_key_from_string: use a more efficient way to parse the string. And common code.
*/

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

    /// Returns the raw key bytes.
    fn bytes(&self) -> &[u8];

    /// Sets the key expiry.
    fn set_expiry(&mut self, expiry: Expiry) -> &mut Self;
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

    fn bytes(&self) -> &[u8] {
        unsafe { self.bytes.get_unchecked(..self.algorithm.key_length()) }
    }

    fn set_expiry(&mut self, expiry: Expiry) -> &mut Self {
        self.expiry = expiry;
        self
    }
}

impl ToString for SymmetricKey {
    fn to_string(&self) -> String {
        let mut string = String::new();

        string.push_str("ID: ");
        string.push_str(&hex::encode(&self.id));

        string.push('\n');

        string.push_str("Algorithm: ");
        string.push_str(&self.algorithm.to_string());

        string.push('\n');

        string.push_str("Expiry: ");
        string.push_str(&self.expiry.to_string());

        string.push('\n');

        // key raw bytes -> base64 string
        string.push_str("Key: ");
        string.push_str(&base64ct::encode(&self.bytes));

        string
    }
}

impl TryFrom<String> for SymmetricKey {
    type Error = Error;

    fn try_from(string: String) -> Result<Self> {
        let (id, algorithm, expiry, bytes) = parse_symmetric_key_from_string(string)?;

        Ok(Self {
            id,
            algorithm,
            expiry,
            bytes,
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
        gen_private_key(algorithm)
    }

    /// Derives a new private key from a key derivation function.
    ///
    /// # Arguments
    /// * `algorithm` - The asymmetric algorithm.
    /// * `hasher` - The hash algorithm.
    ///
    /// # Errors
    /// An error occurs if Self is other than Ed25519 or Ed448. Or internal error if the key generation fails.
    ///
    /// # Example
    /// ```
    /// use xenon_crypto::{Asymmetric, Hasher, PrivateKey};
    ///
    /// let private_key = PrivateKey::generate(Asymmetric::Ed25519).unwrap();
    ///
    /// let derived_key = private_key.derive(Asymmetric::X25519, Hasher::Sha256).unwrap();
    /// ```
    pub fn derive(&self, algorithm: Asymmetric, hasher: Hasher) -> Result<Self> {
        if !matches!(self.algorithm, Asymmetric::Ed25519 | Asymmetric::Ed448) {
            Err(Error::new(
                ErrorKind::Unsupported,
                String::from(
                    "A new Private Key can be derived only from the Ed25519 and Ed448 keys",
                ),
            ))?;
        }

        let mut private_key = gen_private_key(algorithm)?;

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

    fn bytes(&self) -> &[u8] {
        unsafe { self.bytes.get_unchecked(..self.algorithm.key_length()) }
    }

    fn set_expiry(&mut self, expiry: Expiry) -> &mut Self {
        self.expiry = expiry;
        self
    }
}

impl AsymmetricKey for PrivateKey {
    fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }
}

impl ToString for PrivateKey {
    fn to_string(&self) -> String {
        asymmetric_key_to_string(self)
    }
}

impl TryFrom<String> for PrivateKey {
    type Error = Error;

    fn try_from(string: String) -> Result<Self> {
        let (id, algorithm, expiry, bytes, signature) = parse_asymmetric_key_from_string(string)?;

        Ok(Self {
            id,
            algorithm,
            expiry,
            bytes,
            signature,
        })
    }
}

impl TryFrom<&str> for PrivateKey {
    type Error = Error;

    fn try_from(string: &str) -> Result<Self> {
        let (id, algorithm, expiry, bytes, signature) = parse_asymmetric_key_from_string(string)?;

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
    signature: Option<Signature>,
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
    pub fn from_private_key(private_key: &PrivateKey) -> Result<Self> {
        to_public_key(private_key)
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

    fn bytes(&self) -> &[u8] {
        unsafe { self.bytes.get_unchecked(..self.algorithm.key_length()) }
    }

    fn set_expiry(&mut self, expiry: Expiry) -> &mut Self {
        self.expiry = expiry;
        self
    }
}

impl AsymmetricKey for PublicKey {
    fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }
}

impl ToString for PublicKey {
    fn to_string(&self) -> String {
        asymmetric_key_to_string(self)
    }
}

impl TryFrom<String> for PublicKey {
    type Error = Error;

    fn try_from(string: String) -> Result<Self> {
        let (id, algorithm, expiry, bytes, signature) = parse_asymmetric_key_from_string(string)?;

        Ok(Self {
            id,
            algorithm,
            expiry,
            bytes,
            signature,
        })
    }
}

impl TryFrom<&str> for PublicKey {
    type Error = Error;

    fn try_from(string: &str) -> Result<Self> {
        let (id, algorithm, expiry, bytes, signature) = parse_asymmetric_key_from_string(string)?;

        Ok(Self {
            id,
            algorithm,
            expiry,
            bytes,
            signature,
        })
    }
}

fn gen_private_key(algorithm: Asymmetric) -> Result<PrivateKey> {
    let id = generate_key_id()?;

    let expiry = Expiry::new();

    let bytes = match algorithm {
        Asymmetric::Ed25519 => curve25519::ed25519_gen_private_key()
            .map_err(|_| Error::internal_error())?
            .to_vec(),

        Asymmetric::X25519 => curve25519::x25519_gen_private_key()
            .map_err(|_| Error::internal_error())?
            .to_vec(),

        Asymmetric::Ed448 => curve448::ed448_gen_private_key()
            .map_err(|_| Error::internal_error())?
            .to_vec(),

        Asymmetric::X448 => curve448::x448_gen_private_key()
            .map_err(|_| Error::internal_error())?
            .to_vec(),
    };

    Ok(PrivateKey {
        id,
        algorithm,
        expiry,
        bytes,
        signature: None,
    })
}

fn to_public_key(private_key: &PrivateKey) -> Result<PublicKey> {
    let bytes = match private_key.algorithm {
        Asymmetric::Ed25519 => curve25519::ed25519_gen_public_key(
            unsafe {
                private_key
                    .bytes()
                    .get_unchecked(..private_key.algorithm.key_length())
            }
            .try_into()
            .unwrap(),
        )
        .map_err(|_| Error::internal_error())?
        .to_vec(),

        Asymmetric::X25519 => curve25519::x25519_gen_public_key(
            unsafe {
                private_key
                    .bytes()
                    .get_unchecked(..private_key.algorithm.key_length())
            }
            .try_into()
            .unwrap(),
        )
        .map_err(|_| Error::internal_error())?
        .to_vec(),

        Asymmetric::Ed448 => curve448::ed448_gen_public_key(
            unsafe {
                private_key
                    .bytes()
                    .get_unchecked(..private_key.algorithm.key_length())
            }
            .try_into()
            .unwrap(),
        )
        .map_err(|_| Error::internal_error())?
        .to_vec(),

        Asymmetric::X448 => curve448::x448_gen_public_key(
            unsafe {
                private_key
                    .bytes()
                    .get_unchecked(..private_key.algorithm.key_length())
            }
            .try_into()
            .unwrap(),
        )
        .map_err(|_| Error::internal_error())?
        .to_vec(),
    };

    Ok(PublicKey {
        id: private_key.id.clone(),
        algorithm: private_key.algorithm.clone(),
        expiry: private_key.expiry.clone(),
        bytes,
        signature: None,
    })
}

fn asymmetric_key_to_string(asymmetric_key: &impl AsymmetricKey) -> String {
    let mut string = String::new();

    string.push_str("ID: ");
    string.push_str(&hex::encode(asymmetric_key.id()));

    string.push('\n');

    string.push_str("Algorithm: ");
    string.push_str(asymmetric_key.algorithm());

    string.push('\n');

    string.push_str("Expiry: ");
    string.push_str(asymmetric_key.expiry().to_string().as_str());

    string.push('\n');

    string.push_str("Key: ");
    string.push_str(&base64ct::encode(asymmetric_key.bytes()));

    string.push('\n');

    let signature = match asymmetric_key.signature() {
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

fn parse_asymmetric_key_from_string(
    string: impl Into<String>,
) -> Result<(
    [u8; SIZE_32_BYTE],
    Asymmetric,
    Expiry,
    Vec<u8>,
    Option<Signature>,
)> {
    const ERR_MSG_CORRUPT_INCORRECT_STRING_LENGTH: &str =
        "The key string is corrupt. Incorrect string length.";

    const ERR_MSG_CORRUPT_INCORRECT_STRING_FORMAT: &str =
        "The key string is corrupt. Incorrect string format.";

    const ERR_MSG_CORRUPT_INCORRECT_TOKEN: &str = "The key string is corrupt. Incorrect token.";

    const ERR_MSG_CORRUP_DATA_CORRUPTION: &str = "Could not parse correctly. Data corruption.";

    let string = string.into();

    let mut lines = string.lines();

    /*
        ID
    */
    let (key, value) = lines
        .next()
        .ok_or(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_LENGTH),
        ))?
        .split_once(":")
        .ok_or(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_FORMAT),
        ))?;

    if key != "ID" {
        Err(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_TOKEN),
        ))?;
    }

    let id = value.trim_start().trim_end();

    if id.len() != SIZE_64_BYTE {
        Err(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUP_DATA_CORRUPTION),
        ))?;
    }

    // overwrite the error message
    let id = hex::decode(id)
        .map_err(|_| {
            Error::new(
                ErrorKind::ParseFailed,
                String::from(ERR_MSG_CORRUP_DATA_CORRUPTION),
            )
        })?
        .try_into()
        .unwrap();

    /*
        Algorithm
    */
    let (key, value) = lines
        .next()
        .ok_or(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_LENGTH),
        ))?
        .split_once(":")
        .ok_or(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_FORMAT),
        ))?;

    if key != "Algorithm" {
        Err(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_TOKEN),
        ))?;
    }

    let algorithm: Asymmetric = value.trim_start().trim_end().try_into().map_err(|_| {
        Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUP_DATA_CORRUPTION),
        )
    })?;

    /*
        Expiry
    */
    let (key, value) = lines
        .next()
        .ok_or(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_LENGTH),
        ))?
        .split_once(":")
        .ok_or(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_FORMAT),
        ))?;

    if key != "Expiry" {
        Err(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_TOKEN),
        ))?;
    }

    // overwrite the error message
    let expiry = Expiry::try_from(value.trim_start().trim_end()).map_err(|_| {
        Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUP_DATA_CORRUPTION),
        )
    })?;

    /*
        Key raw bytes
    */
    let (key, value) = lines
        .next()
        .ok_or(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_LENGTH),
        ))?
        .split_once(":")
        .ok_or(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_FORMAT),
        ))?;

    if key != "Key" {
        Err(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_TOKEN),
        ))?;
    }

    // overwrite the error message
    let bytes = base64ct::decode(value.trim_start().trim_end()).map_err(|_| {
        Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUP_DATA_CORRUPTION),
        )
    })?;

    /*
        Signature
    */
    let (key, value) = lines
        .next()
        .ok_or(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_LENGTH),
        ))?
        .split_once(":")
        .ok_or(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_FORMAT),
        ))?;

    if key != "Signature" {
        Err(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_TOKEN),
        ))?;
    }

    // overwrite the error message
    let signature = base64ct::decode(value.trim_start().trim_end()).map_err(|_| {
        Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUP_DATA_CORRUPTION),
        )
    })?;

    // overwrite the error message
    let signature = match signature.len() > 0 {
        true => Some(Signature::try_from(signature).map_err(|_| {
            Error::new(
                ErrorKind::ParseFailed,
                String::from(ERR_MSG_CORRUP_DATA_CORRUPTION),
            )
        })?),
        false => None,
    };

    Ok((id, algorithm, expiry, bytes, signature))
}

fn parse_symmetric_key_from_string(
    string: impl Into<String>,
) -> Result<([u8; SIZE_32_BYTE], Symmetric, Expiry, Vec<u8>)> {
    const ERR_MSG_CORRUPT_INCORRECT_STRING_LENGTH: &str =
        "The key string is corrupt. Incorrect string length.";

    const ERR_MSG_CORRUPT_INCORRECT_STRING_FORMAT: &str =
        "The key string is corrupt. Incorrect string format.";

    const ERR_MSG_CORRUPT_INCORRECT_TOKEN: &str = "The key string is corrupt. Incorrect token.";

    const ERR_MSG_CORRUP_DATA_CORRUPTION: &str = "Could not parse correctly. Data corruption.";

    let string = string.into();

    let mut lines = string.lines();

    /*
        ID
    */
    let (key, value) = lines
        .next()
        .ok_or(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_LENGTH),
        ))?
        .split_once(":")
        .ok_or(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_FORMAT),
        ))?;

    if key != "ID" {
        Err(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_TOKEN),
        ))?;
    }

    let id = value.trim_start().trim_end();

    if id.len() != SIZE_64_BYTE {
        Err(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUP_DATA_CORRUPTION),
        ))?;
    }

    // overwrite the error message
    let id = hex::decode(id)
        .map_err(|_| {
            Error::new(
                ErrorKind::ParseFailed,
                String::from(ERR_MSG_CORRUP_DATA_CORRUPTION),
            )
        })?
        .try_into()
        .unwrap();

    /*
        Algorithm
    */
    let (key, value) = lines
        .next()
        .ok_or(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_LENGTH),
        ))?
        .split_once(":")
        .ok_or(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_FORMAT),
        ))?;

    if key != "Algorithm" {
        Err(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_TOKEN),
        ))?;
    }

    let algorithm: Symmetric = value.trim_start().trim_end().try_into().map_err(|_| {
        Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUP_DATA_CORRUPTION),
        )
    })?;

    /*
        Expiry
    */
    let (key, value) = lines
        .next()
        .ok_or(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_LENGTH),
        ))?
        .split_once(":")
        .ok_or(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_FORMAT),
        ))?;

    if key != "Expiry" {
        Err(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_TOKEN),
        ))?;
    }

    // overwrite the error message
    let expiry = Expiry::try_from(value.trim_start().trim_end()).map_err(|_| {
        Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUP_DATA_CORRUPTION),
        )
    })?;

    /*
        Key raw bytes
    */
    let (key, value) = lines
        .next()
        .ok_or(Error::new(
            ErrorKind::InvalidLength,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_LENGTH),
        ))?
        .split_once(":")
        .ok_or(Error::new(
            ErrorKind::InvalidLength,
            String::from(ERR_MSG_CORRUPT_INCORRECT_STRING_FORMAT),
        ))?;

    if key != "Key" {
        Err(Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUPT_INCORRECT_TOKEN),
        ))?;
    }

    // overwrite the error message
    let key = base64ct::decode(value.trim_start().trim_end()).map_err(|_| {
        Error::new(
            ErrorKind::ParseFailed,
            String::from(ERR_MSG_CORRUP_DATA_CORRUPTION),
        )
    })?;

    Ok((id, algorithm, expiry, key))
}

#[inline]
fn generate_key_id() -> Result<[u8; SIZE_32_BYTE]> {
    let bytes = gen_32()?;

    let digest = sha256_digest(&bytes)?;

    Ok(digest)
}
