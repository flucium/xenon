pub use rand::{thread_rng, CryptoRng, RngCore};

/// Generate a 12 byte nonce.
pub fn gen_12() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Generate a 24 byte nonce.
pub fn gen_16() -> [u8; 16] {
    let mut nonce = [0u8; 16];
    thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Generate a 24 byte nonce.
pub fn gen_24() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Generate a 32 byte nonce.
pub fn gen_32() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    thread_rng().fill_bytes(&mut nonce);
    nonce
}