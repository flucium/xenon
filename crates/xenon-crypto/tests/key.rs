// e.g.
// cargo test --package xenon-crypto --test key -- test_gen_symmetric_key --exact --nocapture 

use xenon_crypto::{Asymmetric,  PrivateKey, Symmetric, SymmetricKey, PublicKey, Key};

#[test]
fn test_gen_symmetric_key() {
    assert_eq!(SymmetricKey::generate(Symmetric::Aes128Gcm).is_ok(), true);

    assert_eq!(SymmetricKey::generate(Symmetric::Aes192Gcm).is_ok(), true);

    assert_eq!(SymmetricKey::generate(Symmetric::Aes256Gcm).is_ok(), true);
}

#[test]
fn test_gen_private_key() {

    assert_eq!(PrivateKey::generate(Asymmetric::Ed25519).is_ok(), true);

    assert_eq!(PrivateKey::generate(Asymmetric::Ed448).is_ok(), true);

    assert_eq!(PrivateKey::generate(Asymmetric::X25519).is_ok(), true);

    assert_eq!(PrivateKey::generate(Asymmetric::X448).is_ok(), true);
}

#[test]
fn test_gen_public_key() {
    let private_key = PrivateKey::generate(Asymmetric::Ed25519).unwrap();
 
    assert_eq!(PublicKey::from_private_key(&private_key).is_ok(), true);
}


#[test]
fn test_gen_symmetric_key_and_set_expiry(){
    let mut symmetric_key = SymmetricKey::generate(Symmetric::Aes128Gcm).unwrap();


    symmetric_key.set_expiry(xenon_crypto::Expiry::try_from("2030/01/01").unwrap());
    assert_eq!(symmetric_key.expiry().is_expired(), true);

    symmetric_key.set_expiry(xenon_crypto::Expiry::try_from("1999/12/12").unwrap());
    assert_eq!(symmetric_key.expiry().is_expired(), false);
    assert_ne!(symmetric_key.expiry().is_expired(), true);
}


#[test]
fn test_gen_asymmetric_key_and_set_expiry(){
    let mut private_key = PrivateKey::generate(Asymmetric::Ed25519).unwrap();

    private_key.set_expiry(xenon_crypto::Expiry::try_from("2030/01/01").unwrap());
    assert_eq!(private_key.expiry().is_expired(), true);

    private_key.set_expiry(xenon_crypto::Expiry::try_from("1999/12/12").unwrap());
    assert_eq!(private_key.expiry().is_expired(), false);
    assert_ne!(private_key.expiry().is_expired(), true);
}