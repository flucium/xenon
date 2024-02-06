use xenon_common::result::Result;

pub trait AsymmetricKey {

    /// Return the algorithm
    fn algorithm(&self) -> crate::algorithm::Asymmetric;

    /// Return the key id
    fn id(&self) -> crate::Uuid;

    /// Return the key length
    fn len(&self) -> usize;

    /// Return the key raw bytes
    fn bytes(&self) -> &[u8];

    /// Create a new key from the algorithm, id and bytes
    fn new(
        algorithm: &crate::algorithm::Asymmetric,
        id: &crate::Uuid,
        bytes: &[u8],
    ) -> Result<Self>
    where
        Self: Sized;
}

pub trait PrivateKey: AsymmetricKey {

    /// Generate a new key
    fn generate(r: impl crate::rand::RngCore + crate::rand::CryptoRng) -> Self;

    /// Convert to PEM
    fn to_pem(&self) -> String {
        private_key_to_pem(&self.algorithm(), &self.id(), self.bytes())
    }

    /// Create a new key from PEM
    fn from_pem(pem: &str) -> Result<Self>
    where
        Self: Sized,
    {
        let (algorithm, id, bytes) = private_key_from_pem::<32>(pem)?;

        Self::new(&algorithm, &id, &bytes)
    }
}

pub trait PublicKey: AsymmetricKey {

    /// Create a new key from the private key
    fn from_private(private_key: &impl PrivateKey) -> Self;

    /// Convert to PEM
    fn to_pem(&self) -> String {
        public_key_to_pem(&self.algorithm(), &self.id(), self.bytes())
    }
}

#[inline]
fn private_key_to_pem(
    algorithm: &crate::algorithm::Asymmetric,
    id: &crate::Uuid,
    bytes: &[u8],
) -> String {
    let mut v = Vec::new();

    v.push(algorithm.to_usize() as u8);

    id.as_bytes().iter().for_each(|b| v.push(*b));

    bytes.iter().for_each(|b| v.push(*b));

    crate::format::pem::encode(crate::format::pem::PEM_LABEL_PRIVATE_KEY, &v).unwrap()
}

#[inline]
fn public_key_to_pem(
    algorithm: &crate::algorithm::Asymmetric,
    id: &crate::Uuid,
    bytes: &[u8],
) -> String {
    let mut v = Vec::new();

    v.push(algorithm.to_usize() as u8);

    id.as_bytes().iter().for_each(|b| v.push(*b));

    bytes.iter().for_each(|b| v.push(*b));

    crate::format::pem::encode(crate::format::pem::PEM_LABEL_PUBLIC_KEY, &v).unwrap()
}

#[inline]
fn private_key_from_pem<const T: usize>(
    pem: &str,
) -> Result<(crate::algorithm::Asymmetric, crate::Uuid, [u8; T])> {
    let (label, v) = crate::format::pem::decode(pem).unwrap();

    if label != crate::format::pem::PEM_LABEL_PRIVATE_KEY {
        todo!()
    }

    let algorithm = crate::algorithm::Asymmetric::from_usize(v[0] as usize).unwrap();

    let id = crate::Uuid::from_slice(&v[1..17]).unwrap();

    let bytes = &v[17..];

    Ok((algorithm, id, bytes.try_into().unwrap()))
}
