/*
    Unit tests
    e.g.
    cargo test --package xenon-crypto --test symmetric -- test_symmetric_chacha20_poly1305 --exact --nocapture 
    
    Encrypt and Decrypt

    ChaCha20-Poly1305
    AES-256-GCM
    AES-192-GCM
    AES-128-GCM
*/

use xenon_crypto::{decrypt, encrypt, Symmetric, SymmetricKey};

#[test]
fn test_symmetric_chacha20_poly1305() {
    // message
    let message = b"Hello World";

    // generate symmetric key
    let symmetric_key = SymmetricKey::generate(Symmetric::ChaCha20Poly1305).unwrap();

    let cipher = encrypt(&symmetric_key, None, message).unwrap();

    let plain = decrypt(&symmetric_key, None, &cipher).unwrap();

    // cipher != plain
    assert_ne!(cipher, plain);

    // message != cipher
    assert_ne!(message, cipher.as_slice());

    // message == plain
    assert_eq!(message, plain.as_slice());
}

#[test]
fn test_symmetric_aes_256_gcm() {
    // message
    let message = b"Hello World";

    // generate symmetric key
    let symmetric_key = SymmetricKey::generate(Symmetric::Aes256Gcm).unwrap();

    let cipher = encrypt(&symmetric_key, None, message).unwrap();

    let plain = decrypt(&symmetric_key, None, &cipher).unwrap();

    // cipher != plain
    assert_ne!(cipher, plain);

    // message != cipher
    assert_ne!(message, cipher.as_slice());

    // message == plain
    assert_eq!(message, plain.as_slice());
}

#[test]
fn test_symmetric_aes_192_gcm() {
    // message
    let message = b"Hello World";

    // generate symmetric key
    let symmetric_key = SymmetricKey::generate(Symmetric::Aes192Gcm).unwrap();

    let cipher = encrypt(&symmetric_key, None, message).unwrap();

    let plain = decrypt(&symmetric_key, None, &cipher).unwrap();

    // cipher != plain
    assert_ne!(cipher, plain);

    // message != cipher
    assert_ne!(message, cipher.as_slice());

    // message == plain
    assert_eq!(message, plain.as_slice());
}

#[test]
fn test_symmetric_aes_128_gcm() {
    // message
    let message = b"Hello World";

    // generate symmetric key
    let symmetric_key = SymmetricKey::generate(Symmetric::Aes128Gcm).unwrap();

    let cipher = encrypt(&symmetric_key, None, message).unwrap();

    let plain = decrypt(&symmetric_key, None, &cipher).unwrap();

    // cipher != plain
    assert_ne!(cipher, plain);

    // message != cipher
    assert_ne!(message, cipher.as_slice());

    // message == plain
    assert_eq!(message, plain.as_slice());
}
