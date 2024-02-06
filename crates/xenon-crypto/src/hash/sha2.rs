use digest::{Digest, FixedOutputReset};

/// SHA256
pub struct Sha256(sha2::Sha256);

impl Sha256 {
    /// Finalize the hash digest
    pub fn finalize(mut self) -> [u8; 32] {
        self.0.finalize_fixed_reset().into()
    }
}

impl super::Hasher<32> for Sha256 {
    fn new() -> Self {
        Sha256(sha2::Sha256::new())
    }

    fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data);
        self
    }

    fn finalize(mut self) -> [u8; 32] {
        self.0.finalize_fixed_reset().into()
    }
}

/// SHA512
pub struct Sha512(sha2::Sha512);

impl Sha512 {
    /// Finalize the hash digest
    pub fn finalize(mut self) -> [u8; 64] {
        self.0.finalize_fixed_reset().into()
    }
}

impl super::Hasher<64> for Sha512 {
    fn new() -> Self {
        Sha512(sha2::Sha512::new())
    }

    fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data);
        self
    }

    fn finalize(mut self) -> [u8; 64] {
        self.0.finalize_fixed_reset().into()
    }
}
