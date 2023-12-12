use crate::{
    algorithm::Hasher,
    hash::{sha2::*,sha3::*},
    Key, PublicKey,
};
use xenon_common::{format::hex, Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    hasher: Hasher,
    bytes: Vec<u8>,
}

impl Fingerprint {
    pub fn new(hasher: Hasher, public_key: &PublicKey) -> Result<Self> {
        let bytes = match hasher {
            Hasher::Sha256 => sha256_digest(public_key.as_bytes())?.to_vec(),
            Hasher::Sha512 => sha512_digest(public_key.as_bytes())?.to_vec(),
            Hasher::Sha3_256 => sha3_256_digest(public_key.as_bytes())?.to_vec(),
            Hasher::Sha3_512 => sha3_512_digest(public_key.as_bytes())?.to_vec(),
        };

        Ok(Self { hasher, bytes })
    }

    pub fn new_sha256(public_key: &PublicKey) -> Result<Self> {
        Self::new(Hasher::Sha256, public_key)
    }

    pub fn new_sha512(public_key: &PublicKey) -> Result<Self> {
        Self::new(Hasher::Sha512, public_key)
    }

    pub fn new_sha3_256(public_key: &PublicKey) -> Result<Self> {
        Self::new(Hasher::Sha3_256, public_key)
    }

    pub fn new_sha3_512(public_key: &PublicKey) -> Result<Self> {
        Self::new(Hasher::Sha3_512, public_key)
    }

    /// Returns the hash algorithm name.
    pub fn hasher(&self) -> &Hasher {
        &self.hasher
    }

    /// Returns the fingerprint bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl ToString for Fingerprint {
    fn to_string(&self) -> String {
        format!("{}:{}", self.hasher.to_string(), hex::encode(&self.bytes)).to_string()
    }
}

impl TryFrom<String> for Fingerprint {
    type Error = Error;

    fn try_from(string: String) -> Result<Self> {
        let mut parts = string.split(':');

        let hasher = Hasher::try_from(parts.next().unwrap_or(&String::default()))?;

        let bytes = hex::decode(parts.next().unwrap_or(&String::default()))?;

        Ok(Self { hasher, bytes })
    }
}

impl TryFrom<&str> for Fingerprint {
    type Error = Error;

    fn try_from(string: &str) -> Result<Self> {
        Self::try_from(string.to_string())
    }
}
