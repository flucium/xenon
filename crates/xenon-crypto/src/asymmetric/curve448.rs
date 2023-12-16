use core::result::Result;
use openssl::error::ErrorStack;
use openssl::pkey::{Id, PKey, Private, Public};
use xenon_common::size::{SIZE_114_BYTE, SIZE_56_BYTE, SIZE_57_BYTE};

use crate::asymmetric::{dh::diffie_hellman, signer::sign, verifier::verify};

const ED448: Id = Id::ED448;

const X448: Id = Id::X448;

/// Ed448 verify
///
/// # Arguments
/// * `public_key` - Public key
/// * `message` - Message
/// * `signature` - Signature
///
/// # Error
/// The error here is very likely to be an Internal error.
///
/// Normally, if the key is wrong and the validation fails, Ok(false) is returned.
pub fn ed448_verify(
    public_key: &[u8; SIZE_57_BYTE],
    message: &[u8],
    signature: &[u8; SIZE_114_BYTE],
) -> Result<bool, ErrorStack> {
    verify::<SIZE_114_BYTE>(
        &PKey::public_key_from_raw_bytes(public_key, ED448)?,
        message,
        signature,
    )
}

/// Ed448 sign
///
/// # Arguments
/// * `private_key` - Private key
/// * `message` - Message
///
/// # Error
/// The error here is very likely to be an Internal error.
pub fn ed448_sign(
    private_key: &[u8; SIZE_57_BYTE],
    message: &[u8],
) -> Result<[u8; SIZE_114_BYTE], ErrorStack> {
    sign::<SIZE_114_BYTE>(
        &PKey::private_key_from_raw_bytes(private_key, ED448)?,
        message,
    )
}

/// Ed448 generate private key
///
/// # Error
/// The error here is very likely to be an Internal error.
pub fn ed448_gen_private_key() -> Result<[u8; SIZE_57_BYTE], ErrorStack> {
    let pkey = PKey::generate_ed448()?;

    let bytes = pkey.raw_private_key()?;

    let private_key = unsafe { bytes.get_unchecked(..SIZE_57_BYTE) }
        .try_into()
        .unwrap();

    Ok(private_key)
}

/// Ed448 generate public key
///
/// # Arguments
/// * `private_key` - Private key
///
/// # Error
/// The error here is very likely to be an Internal error.
pub fn ed448_gen_public_key(
    private_key: &[u8; SIZE_57_BYTE],
) -> Result<[u8; SIZE_57_BYTE], ErrorStack> {
    let pkey = PKey::private_key_from_raw_bytes(private_key, ED448)?;

    let bytes = pkey.raw_public_key()?;

    let public_key = unsafe { bytes.get_unchecked(..SIZE_57_BYTE) }
        .try_into()
        .unwrap();

    Ok(public_key)
}

/// X448 Diffie-Hellman ephemeral
///
/// # Arguments
/// * `public_key` - Public key
///
/// # Returns
/// Result<(ephemeral_public_key, shared_secret), openssl:error::ErrorStack>
/// * `ephemeral_public_key` - Ephemeral public key
/// * `shared_secret` - Shared secret
///
/// # Error
/// The error here is very likely to be an Internal error.
///
/// If there is a mistake in the key pair, Shared Secret will be Eq false.
pub fn x448_diffie_hellman_ephemeral(
    public_key: &[u8; SIZE_56_BYTE],
) -> Result<([u8; SIZE_56_BYTE], [u8; SIZE_56_BYTE]), ErrorStack> {
    let ephemeral_private_key = x448_gen_private_key()?;

    let ephemeral_public_key = x448_gen_public_key(&ephemeral_private_key)?;

    let shared_secret = x448_diffie_hellman(&ephemeral_private_key, public_key)?;

    Ok((ephemeral_public_key, shared_secret))
}

/// X448 Diffie-Hellman
///
/// # Arguments
/// * `private_key` - Private key
/// * `public_key` - Public key
///
/// # Error
/// The error here is very likely to be an Internal error.
///
/// If there is a mistake in the key pair, Shared Secret will be Eq false.
pub fn x448_diffie_hellman(
    private_key: &[u8; SIZE_56_BYTE],
    public_key: &[u8; SIZE_56_BYTE],
) -> Result<[u8; SIZE_56_BYTE], ErrorStack> {
    diffie_hellman::<SIZE_56_BYTE>(
        &PKey::private_key_from_raw_bytes(private_key, X448)?,
        &PKey::public_key_from_raw_bytes(public_key, X448)?,
    )
}

/// X448 generate private key
///
/// # Error
/// The error here is very likely to be an Internal error.
pub fn x448_gen_private_key() -> Result<[u8; SIZE_56_BYTE], ErrorStack> {
    let pkey = PKey::generate_x448()?;

    let bytes = pkey.raw_private_key()?;

    let private_key = unsafe { bytes.get_unchecked(..SIZE_56_BYTE) }
        .try_into()
        .unwrap();

    Ok(private_key)
}

/// X448 generate public key
///
/// # Arguments
/// * `private_key` - Private key
///
/// # Error
/// The error here is very likely to be an Internal error.
pub fn x448_gen_public_key(
    private_key: &[u8; SIZE_56_BYTE],
) -> Result<[u8; SIZE_56_BYTE], ErrorStack> {
    let pkey = PKey::private_key_from_raw_bytes(private_key, X448)?;

    let bytes = pkey.raw_public_key()?;

    let public_key = unsafe { bytes.get_unchecked(..SIZE_56_BYTE) }
        .try_into()
        .unwrap();

    Ok(public_key)
}

/*
    Unit tests
*/

/*
    Ed448
    X448
*/

/*
    Ed448
        ed448_verify
        ed448_sign
        ed448_gen_private_key
        ed448_gen_public_key
*/

#[test]
fn test_ed448_verify() {
    let message = b"Hello World!";

    let private_key = ed448_gen_private_key().unwrap();

    let public_key = ed448_gen_public_key(&private_key).unwrap();

    let signature = ed448_sign(&private_key, message).unwrap();

    let result = ed448_verify(&public_key, message, &signature);

    assert!(result.is_ok());
}

#[test]
fn test_ed448_sign() {
    let message = b"Hello World!";

    let private_key = ed448_gen_private_key();

    let signature = ed448_sign(&private_key.unwrap(), message);

    assert!(signature.is_ok());
}

#[test]
fn test_ed448_gen_public_key() {
    let private_key = ed448_gen_private_key();

    assert!(private_key.is_ok());

    let public_key = ed448_gen_public_key(&private_key.unwrap());

    assert!(public_key.is_ok());
}

#[test]
fn test_ed448_gen_private_key() {
    let private_key = ed448_gen_private_key();

    assert!(private_key.is_ok());
}

/*
    X448
        x448_diffie_hellman_ephemeral
        x448_diffie_hellman
        x448_shared_secret
        x448_gen_private_key
        x448_gen_public_key
*/

#[test]
fn test_x448_diffie_hellman_ephemeral() {
    // alice
    let alice_private_key = x448_gen_private_key().unwrap();

    let alice_public_key = x448_gen_public_key(&alice_private_key).unwrap();

    // bob
    let (bob_ephemeral_public_key, bob_shared_secret) =
        x448_diffie_hellman_ephemeral(&alice_public_key).unwrap();

    // alice_private_key / bob_ephemeral_public_key
    let alice_shared_secret =
        x448_diffie_hellman(&alice_private_key, &bob_ephemeral_public_key).unwrap();

    assert_eq!(alice_shared_secret, bob_shared_secret);
}

#[test]
fn test_x448_diffie_hellman() {
    // alice
    let alice_private_key = x448_gen_private_key().unwrap();

    let alice_public_key = x448_gen_public_key(&alice_private_key).unwrap();

    // bob
    let bob_private_key = x448_gen_private_key().unwrap();

    let bob_public_key = x448_gen_public_key(&bob_private_key).unwrap();

    // alice_private_key / bob_public_key
    let alice_shared_secret = x448_diffie_hellman(&alice_private_key, &bob_public_key).unwrap();

    // bob_private_key / alice_public_key
    let bob_shared_secret = x448_diffie_hellman(&bob_private_key, &alice_public_key).unwrap();

    assert_eq!(alice_shared_secret, bob_shared_secret);
}


#[test]
fn test_x448_shared_secret() {
    let private_key = x448_gen_private_key().unwrap();

    let public_key = x448_gen_public_key(&private_key).unwrap();

    let shared_secret = x448_diffie_hellman(&private_key, &public_key);

    assert!(shared_secret.is_ok());
}


#[test]
fn test_x448_gen_private_key() {
    let private_key = x448_gen_private_key();

    assert!(private_key.is_ok());
}

#[test]
fn test_x448_gen_public_key() {
    let private_key = x448_gen_private_key().unwrap();

    let public_key = x448_gen_public_key(&private_key);

    assert!(public_key.is_ok());
}
