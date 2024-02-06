pub mod sha2;

pub trait Hasher<const T: usize> {

    /// Create a new hash digest
    fn new() -> Self;

    /// Update the hash digest, chaining the input data
    fn update(&mut self, data: &[u8]) -> &mut Self;


    /// Finalize the hash digest
    fn finalize(self) -> [u8; T];
}


pub trait Deriver{}