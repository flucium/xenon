use xenon_common::result::Result;

/// X25519 Private Key
#[derive(Debug, PartialEq, Eq)]
pub struct X25519PrivateKey {
    algorithm: crate::algorithm::Asymmetric,
    id: crate::Uuid,
    bytes: [u8; 32],
}

impl super::asymmetric::AsymmetricKey for X25519PrivateKey {
    fn algorithm(&self) -> crate::algorithm::Asymmetric {
        self.algorithm
    }

    fn id(&self) -> crate::Uuid {
        self.id
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn new(algorithm: &crate::algorithm::Asymmetric, id: &crate::Uuid, bytes: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            algorithm: *algorithm,
            id: *id,
            bytes: bytes.try_into().unwrap(),
        })
    }
}

impl super::asymmetric::PrivateKey for X25519PrivateKey {
    fn generate(r: impl crate::rand::RngCore + crate::rand::CryptoRng) -> Self {
        let bytes = *x25519_dalek::StaticSecret::random_from_rng(r).as_bytes();

        let id = crate::Uuid::new_v4();

        let algorithm = crate::algorithm::Asymmetric::X25519;

        Self {
            algorithm,
            id,
            bytes,
        }
    }
}

/// X25519 Public Key
#[derive(Debug, PartialEq, Eq)]
pub struct X25519PublicKey {
    algorithm: crate::algorithm::Asymmetric,
    id: crate::Uuid,
    bytes: [u8; 32],
}

impl super::asymmetric::AsymmetricKey for X25519PublicKey {
    fn algorithm(&self) -> crate::algorithm::Asymmetric {
        self.algorithm
    }

    fn id(&self) -> crate::Uuid {
        self.id
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn new(algorithm: &crate::algorithm::Asymmetric, id: &crate::Uuid, bytes: &[u8]) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            algorithm: *algorithm,
            id: *id,
            bytes: bytes.try_into().unwrap(),
        })
    }
}

impl super::asymmetric::PublicKey for X25519PublicKey {
    fn from_private(private_key: &impl super::PrivateKey) -> Self {
        let (algorithm, id, bytes) = (
            private_key.algorithm(),
            private_key.id(),
            public_key_from_private_key(private_key.bytes().try_into().unwrap()),
        );

        Self {
            algorithm,
            id,
            bytes,
        }
    }
}

#[inline]
fn public_key_from_private_key(private_key: [u8; 32]) -> [u8; 32] {
    *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key)).as_bytes()
}
