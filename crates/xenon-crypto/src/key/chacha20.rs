// use xenon_common::result::Result;

// pub type XChaCha20Key = Chacha20Key;

// #[derive(Clone, Copy, Debug, Eq, PartialEq)]
// pub struct Chacha20Key([u8; 32]);

// impl super::SymmetricKey for Chacha20Key {
//     fn generate(mut r: impl crate::RngCore + crate::CryptoRng) -> Self
//     where
//         Self: Sized,
//     {
//         let mut bytes = [0u8; 32];
//         r.fill_bytes(&mut bytes);

//         Self(bytes)
//     }

//     fn derive(&self) -> Result<Self>
//     where
//         Self: Sized,
//     {
//         todo!()
//     }

//     fn bytes(&self) -> &[u8] {
//         &self.0
//     }
// }