use crate::key::{AsymmetricKey, PrivateKey, PublicKey};

/// X25519 Diffie-Hellman
pub fn diffie_hellman(
    private_key: &crate::key::X25519PrivateKey,
    public_key: &crate::key::X25519PublicKey,
) -> [u8; 32] {
    let shared_secret = x25519_dalek::x25519(
        private_key.bytes().try_into().unwrap(),
        public_key.bytes().try_into().unwrap(),
    );

    shared_secret
}

/// X25519 Diffie-Hellman Ephemeral
pub fn diffie_hellman_ephemeral(
    r: impl crate::rand::RngCore + crate::rand::CryptoRng,
    public_key: &crate::key::X25519PublicKey,
) -> (crate::key::X25519PublicKey, [u8; 32]) {
    let privatekey = crate::key::X25519PrivateKey::generate(r);

    let my_public_key = crate::key::X25519PublicKey::from_private(&privatekey);

    let shared_secret = x25519_dalek::x25519(
        privatekey.bytes().try_into().unwrap(),
        public_key.bytes().try_into().unwrap(),
    );

    (my_public_key, shared_secret)
}
