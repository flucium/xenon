// e.g.
// cargo test --package xenon-crypto --test algorithm -- test_hasher_sha256 --exact --nocapture 

use xenon_crypto::{Hasher, Kdf, PasswordHasher, Symmetric, Asymmetric};


#[test]
fn test_hasher_sha256() {
    // from string
    assert_eq!(Hasher::Sha256, Hasher::try_from("Sha256").unwrap());

    // from string lowercase
    assert_eq!(Hasher::Sha256, Hasher::try_from("sha256").unwrap());

    // from string uppercase
    assert_eq!(Hasher::Sha256, Hasher::try_from("SHA256").unwrap());

    // to string
    assert_eq!("sha256", Hasher::Sha256.to_string());

    // to bytes
    assert_eq!(Hasher::Sha256.as_bytes(), &[115, 104, 97, 50, 53, 54]);
}

#[test]
fn test_hasher_kdf() {
    // from string
    assert_eq!(Kdf::HkdfSha256, Kdf::try_from("Hkdf-Sha256").unwrap());

    // from string lowercase
    assert_eq!(Kdf::HkdfSha256, Kdf::try_from("hkdf-sha256").unwrap());

    // from string uppercase
    assert_eq!(Kdf::HkdfSha256, Kdf::try_from("HKDF-SHA256").unwrap());

    // to string
    assert_eq!("hkdf-sha256", Kdf::HkdfSha256.to_string());

    // to bytes
    assert_eq!(
        Kdf::HkdfSha256.as_bytes(),
        &[104, 107, 100, 102, 45, 115, 104, 97, 50, 53, 54]
    );
}

#[test]
fn test_password_hasher() {
    // from string
    assert_eq!(
        PasswordHasher::Scrypt,
        PasswordHasher::try_from("Scrypt").unwrap()
    );

    // from string lowercase
    assert_eq!(
        PasswordHasher::Scrypt,
        PasswordHasher::try_from("scrypt").unwrap()
    );

    // from string uppercase
    assert_eq!(
        PasswordHasher::Scrypt,
        PasswordHasher::try_from("SCRYPT").unwrap()
    );

    // to string
    assert_eq!("scrypt", PasswordHasher::Scrypt.to_string());

    // to bytes
    assert_eq!(
        PasswordHasher::Scrypt.as_bytes(),
        &[115, 99, 114, 121, 112, 116]
    );
}

#[test]
fn test_symmetric() {
    // from string
    assert_eq!(
        Symmetric::Aes128Gcm,
        Symmetric::try_from("Aes128Gcm").unwrap()
    );

    // from string lowercase
    assert_eq!(
        Symmetric::Aes128Gcm,
        Symmetric::try_from("aes128gcm").unwrap()
    );

    // from string uppercase
    assert_eq!(
        Symmetric::Aes128Gcm,
        Symmetric::try_from("AES128GCM").unwrap()
    );

    // to string
    assert_eq!("aes128gcm", Symmetric::Aes128Gcm.to_string());

    // to bytes
    assert_eq!(
        Symmetric::Aes128Gcm.as_bytes(),
        &[97, 101, 115, 49, 50, 56, 103, 99, 109]
    );
}

#[test]
fn test_asymmetric() {
    // from string
    assert_eq!(
        Asymmetric::Ed25519,
        Asymmetric::try_from("Ed25519").unwrap()
    );

    // from string lowercase
    assert_eq!(
        Asymmetric::Ed25519,
        Asymmetric::try_from("ed25519").unwrap()
    );

    // from string uppercase
    assert_eq!(
        Asymmetric::Ed25519,
        Asymmetric::try_from("ED25519").unwrap()
    );

    // to string
    assert_eq!("ed25519", Asymmetric::Ed25519.to_string());

    // to bytes
    assert_eq!(
        Asymmetric::Ed25519.as_bytes(),
        &[101, 100, 50, 53, 53, 49, 57]
    );
}
