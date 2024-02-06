use xenon_common::result::Result;

pub struct Aes128Key([u8; 16]);

impl super::SymmetricKey<Aes128Key,16> for Aes128Key {
    fn generate(r: impl crate::rand::RngCore + crate::rand::CryptoRng) -> Self
    where
        Self: Sized,
    {
        Self(gen_key::<16>(r))
    }

    fn derive(&self) -> Result<Self>
    where
        Self: Sized,
    {
        todo!()
    }

    fn bytes(&self) -> [u8;16] {
        self.0
    }
}

pub struct Aes192Key([u8; 24]);

impl super::SymmetricKey<Aes192Key,24> for Aes192Key {
    fn generate(r: impl crate::rand::RngCore + crate::rand::CryptoRng) -> Self
    where
        Self: Sized,
    {
        Self(gen_key::<24>(r))
    }

    fn derive(&self) -> Result<Self>
    where
        Self: Sized,
    {
        todo!()
    }

    fn bytes(&self) -> [u8;24] {
        self.0
    }
}

pub struct Aes256Key([u8; 32]);

impl super::SymmetricKey<Aes256Key,32> for Aes256Key {
    fn generate(r: impl crate::rand::RngCore + crate::rand::CryptoRng) -> Self
    where
        Self: Sized,
    {
        Self(gen_key::<32>(r))
    }

    fn derive(&self) -> Result<Self>
    where
        Self: Sized,
    {
        todo!()
    }

    fn bytes(&self) -> [u8;32] {
        self.0
    }
}

#[inline]
fn gen_key<const T: usize>(mut r: impl crate::rand::RngCore + crate::rand::CryptoRng) -> [u8; T] {
    let mut dst = [0u8; T];
    r.fill_bytes(&mut dst);
    dst
}
