use xenon_common::result::Result;

/// Ed25519 Private Key
#[derive(Debug, PartialEq, Eq)]
pub struct Ed25519PrivateKey {
    algorithm: crate::algorithm::Asymmetric,
    id: crate::Uuid,
    bytes: [u8; 32],
}

impl super::asymmetric::AsymmetricKey for Ed25519PrivateKey {
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

impl super::asymmetric::PrivateKey for Ed25519PrivateKey {
    fn generate(mut r: impl crate::rand::RngCore + crate::rand::CryptoRng) -> Self {
        
        let bytes = *ed25519_dalek::SigningKey::generate(&mut r).as_bytes();

        let id = crate::Uuid::new_v4();

        let algorithm = crate::algorithm::Asymmetric::Ed25519;

        Ed25519PrivateKey {
            algorithm,
            id,
            bytes,
        }
    }
}

/// Ed25519 Public Key
#[derive(Debug, PartialEq, Eq)]
pub struct Ed25519PublicKey {
    algorithm: crate::algorithm::Asymmetric,
    id: crate::Uuid,
    bytes: [u8; 32],
}

impl super::asymmetric::AsymmetricKey for Ed25519PublicKey {
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

impl super::asymmetric::PublicKey for Ed25519PublicKey {
    fn from_private(private_key: &impl super::asymmetric::PrivateKey) -> Self {
        let (algorithm, id, bytes) = (
            private_key.algorithm(),
            private_key.id(),
            public_key_from_private_key(private_key.bytes().try_into().unwrap()),
        );

        Ed25519PublicKey {
            algorithm,
            id,
            bytes,
        }
    }
}

#[inline]
fn public_key_from_private_key(private_key: &[u8; 32]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(
        ed25519_dalek::SigningKey::from_bytes(private_key.try_into().unwrap())
            .verifying_key()
            .as_bytes(),
    );
    bytes
}
