use xenon_crypto::{Asymmetric, Hasher};

#[test]
fn test_signature_to_vec_from_vec() {
    let algorithm = Asymmetric::Ed25519.as_bytes();
    let hasher = Hasher::Sha512.as_bytes();
    let key_id = [0u8; 32];
    let timestamp = [0u8; 8];
    let bytes = [0u8; 114];

    let signature = xenon_crypto::Signature::new(algorithm, hasher, &key_id, &timestamp, &bytes);

    let v = signature.to_vec();

    let signature2 = xenon_crypto::Signature::try_from(v);

    assert!(signature2.is_ok());

    assert_eq!(signature, signature2.unwrap());

    assert_eq!(signature.algorithm(), algorithm);

    assert_eq!(signature.hasher(), hasher);

    assert_eq!(signature.key_id(), key_id);

    assert_eq!(signature.timestamp(), timestamp);

    assert_eq!(signature.bytes(), bytes);
}

#[test]
fn test_ed25519_sign() {
    let private_key = xenon_crypto::PrivateKey::generate(Asymmetric::Ed25519).unwrap();

    let message = b"Hello World";

    let signature = xenon_crypto::sign(&private_key, Hasher::Sha512, message);

    assert!(signature.is_ok());
}

#[test]
fn test_ed448() {
    let private_key = xenon_crypto::PrivateKey::generate(Asymmetric::Ed448).unwrap();

    let message = b"Hello World";

    let signature = xenon_crypto::sign(&private_key, Hasher::Sha512, message);

    assert!(signature.is_ok());
}

#[test]
fn test_ed25519_verify() {
    let private_key = xenon_crypto::PrivateKey::generate(Asymmetric::Ed25519).unwrap();

    let public_key = xenon_crypto::PublicKey::from_private_key(&private_key).unwrap();

    let message = b"Hello World";

    let signature = xenon_crypto::sign(&private_key, Hasher::Sha512, message).unwrap();

    let verified = xenon_crypto::verify(&public_key, message, &signature);

    assert!(verified.is_ok());

    assert_eq!(verified.unwrap(), true);
}

#[test]
fn test_ed25519_verify_fail() {
    let private_key = xenon_crypto::PrivateKey::generate(Asymmetric::Ed25519).unwrap();

    let public_key = xenon_crypto::PublicKey::from_private_key(&private_key).unwrap();

    let signature = xenon_crypto::sign(&private_key, Hasher::Sha512, b"Hello World").unwrap();

    let verified = xenon_crypto::verify(&public_key, b"Hello World!", &signature);

    assert!(verified.is_ok());

    assert_eq!(verified.unwrap(), false);
}

#[test]
fn test_ed448_verify() {
    let private_key = xenon_crypto::PrivateKey::generate(Asymmetric::Ed448).unwrap();

    let public_key = xenon_crypto::PublicKey::from_private_key(&private_key).unwrap();

    let message = b"Hello World";

    let signature = xenon_crypto::sign(&private_key, Hasher::Sha512, message).unwrap();

    let verified = xenon_crypto::verify(&public_key, message, &signature);

    assert!(verified.is_ok());

    assert_eq!(verified.unwrap(), true);
}

#[test]
fn test_ed448_verify_fail() {
    let private_key = xenon_crypto::PrivateKey::generate(Asymmetric::Ed448).unwrap();

    let public_key = xenon_crypto::PublicKey::from_private_key(&private_key).unwrap();

    let signature = xenon_crypto::sign(&private_key, Hasher::Sha512, b"Hello World").unwrap();

    let verified = xenon_crypto::verify(&public_key, b"Hello World!", &signature);

    assert!(verified.is_ok());

    assert_eq!(verified.unwrap(), false);
}

#[test]
fn test_x25519() {
    let private_key = xenon_crypto::PrivateKey::generate(Asymmetric::X25519).unwrap();

    let public_key = xenon_crypto::PublicKey::from_private_key(&private_key).unwrap();

    let shared_secret = xenon_crypto::diffie_hellman(&private_key, &public_key, xenon_crypto::Symmetric::Aes128Gcm);

    assert!(shared_secret.is_ok());
}

#[test]
fn test_x448() {
    let private_key = xenon_crypto::PrivateKey::generate(Asymmetric::X448).unwrap();

    let public_key = xenon_crypto::PublicKey::from_private_key(&private_key).unwrap();

    let shared_secret = xenon_crypto::diffie_hellman(&private_key, &public_key, xenon_crypto::Symmetric::Aes128Gcm);

    assert!(shared_secret.is_ok());
}