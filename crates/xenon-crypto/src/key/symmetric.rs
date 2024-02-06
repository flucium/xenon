use xenon_common::result::Result;

pub trait SymmetricKey<T, const U: usize> {
    /// Generate a new key
    fn generate(r: impl crate::rand::RngCore + crate::rand::CryptoRng) -> Self
    where
        Self: Sized;

    /// Derive a new key from the current key
    fn derive(&self) -> Result<Self>
    where
        Self: Sized;

    /// Return the key length
    fn len(&self) -> usize {
        U
    }

    /// Return the key raw bytes
    fn bytes(&self) -> [u8; U];
}