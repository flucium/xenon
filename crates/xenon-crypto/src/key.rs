use crate::{
    algorithm::{Asymmetric, Symmetric},
    curve25519,
    rand::gen_32,
    Expiry, Uuid,
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
            Asymmetric::Ed25519 => curve25519::ed25519_gen_private_key(),
            Asymmetric::X25519 => curve25519::x25519_gen_private_key(),
        }
        .map_err(|_| Error::new(ErrorKind::Internal, String::default()))?
        .to_vec();

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    id: Uuid,
    algorithm: Asymmetric,
    expiry: Expiry,
    bytes: Vec<u8>,
    signature: Option<Vec<u8>>,
}

impl PublicKey {
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
            ),

            Asymmetric::X25519 => curve25519::x25519_gen_public_key(
                unsafe {
                    priavte_key
                        .as_bytes()
                        .get_unchecked(..priavte_key.algorithm.key_length())
                }
                .try_into()
                .unwrap(),
            ),
        }
        .map_err(|_| Error::new(ErrorKind::Internal, String::default()))?
        .to_vec();

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
