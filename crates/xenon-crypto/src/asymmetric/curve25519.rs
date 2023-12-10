use core::result::Result;
use openssl::error::ErrorStack;
use openssl::pkey::{Id, PKey, Private, Public};
use xenon_common::size::{SIZE_32_BYTE, SIZE_64_BYTE};

use crate::asymmetric::{dh::diffie_hellman, signer::sign, verifier::verify};

const ED25519: Id = Id::ED25519;

const X25519: Id = Id::X25519;

/// Ed25519 verify
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
pub fn ed25519_verify(
    public_key: &[u8; SIZE_32_BYTE],
    message: &[u8],
    signature: &[u8; SIZE_64_BYTE],
) -> Result<bool, ErrorStack> {
    verify::<SIZE_64_BYTE>(
        &PKey::public_key_from_raw_bytes(public_key, ED25519)?,
        message,
        signature,
    )
}

/// Ed25519 sign
///
/// # Arguments
/// * `private_key` - Private key
/// * `message` - Message
///
/// # Error
/// The error here is very likely to be an Internal error.
pub fn ed25519_sign(
    private_key: &[u8; SIZE_32_BYTE],
    message: &[u8],
) -> Result<[u8; SIZE_64_BYTE], ErrorStack> {
    sign::<SIZE_64_BYTE>(
        &PKey::private_key_from_raw_bytes(private_key, ED25519)?,
        message,
    )
}

/// Ed25519 generate private key
///
/// # Error
/// The error here is very likely to be an Internal error.
pub fn ed25519_gen_private_key() -> Result<[u8; SIZE_32_BYTE], ErrorStack> {
    let pkey = PKey::generate_ed25519()?;

    let bytes = pkey.raw_private_key()?;

    let private_key = unsafe { bytes.get_unchecked(..SIZE_32_BYTE) }
        .try_into()
        .unwrap();

    Ok(private_key)
}

/// Ed25519 generate public key
///
/// # Arguments
/// * `private_key` - Private key
///
/// # Error
/// The error here is very likely to be an Internal error.
pub fn ed25519_gen_public_key(
    private_key: &[u8; SIZE_32_BYTE],
) -> Result<[u8; SIZE_32_BYTE], ErrorStack> {
    let pkey = PKey::private_key_from_raw_bytes(private_key, ED25519)?;

    let bytes = pkey.raw_public_key()?;

    let public_key = unsafe { bytes.get_unchecked(..SIZE_32_BYTE) }
        .try_into()
        .unwrap();

    Ok(public_key)
}

/// X25519 diffie hellman ephemeral
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
pub fn x25519_diffie_hellman_ephemeral(
    public_key: &[u8; SIZE_32_BYTE],
) -> Result<([u8; SIZE_32_BYTE], [u8; SIZE_32_BYTE]), ErrorStack> {
    let ephemeral_private_key = x25519_gen_private_key()?;

    let ephemeral_public_key = x25519_gen_public_key(&ephemeral_private_key)?;

    let shared_secret = x25519_diffie_hellman(&ephemeral_private_key, public_key)?;

    Ok((ephemeral_public_key, shared_secret))
}

/// X25519 diffie hellman
///
/// # Arguments
/// * `private_key` - Private key
/// * `public_key` - Public key
///
/// # Error
/// The error here is very likely to be an Internal error.
///
/// If there is a mistake in the key pair, Shared Secret will be Eq false.
pub fn x25519_diffie_hellman(
    private_key: &[u8; SIZE_32_BYTE],
    public_key: &[u8; SIZE_32_BYTE],
) -> Result<[u8; SIZE_32_BYTE], ErrorStack> {
    let private_key = PKey::private_key_from_raw_bytes(private_key, X25519)?;

    let public_key = PKey::public_key_from_raw_bytes(public_key, X25519)?;

    diffie_hellman::<SIZE_32_BYTE>(&private_key, &public_key)
}

/// X25519 generate private key
///
/// # Error
/// The error here is very likely to be an Internal error.
pub fn x25519_gen_private_key() -> Result<[u8; SIZE_32_BYTE], ErrorStack> {
    let pkey = PKey::generate_x25519()?;

    let bytes = pkey.raw_private_key()?;

    let private_key = unsafe { bytes.get_unchecked(..SIZE_32_BYTE) }
        .try_into()
        .unwrap();

    Ok(private_key)
}

/// X25519 generate public key
///
/// # Arguments
/// * `private_key` - Private key
///
/// # Error
/// The error here is very likely to be an Internal error.
pub fn x25519_gen_public_key(
    private_key: &[u8; SIZE_32_BYTE],
) -> Result<[u8; SIZE_32_BYTE], ErrorStack> {
    let pkey = PKey::private_key_from_raw_bytes(private_key, X25519)?;

    let bytes = pkey.raw_public_key()?;

    let public_key = unsafe { bytes.get_unchecked(..SIZE_32_BYTE) }
        .try_into()
        .unwrap();

    Ok(public_key)
}

/*
    Unit tests
*/

/*
    ED25519
    X25519
*/

/*
    Ed25519
        ed25519_verify
        ed25519_sign
        ed25519_gen_private_key
        ed25519_gen_public_key
*/

#[test]
fn test_ed25519_verify() {
    let message = b"Hello World!";

    let private_key = ed25519_gen_private_key().unwrap();

    let public_key = ed25519_gen_public_key(&private_key).unwrap();

    let signature = ed25519_sign(&private_key, message).unwrap();

    let result = ed25519_verify(&public_key, message, &signature);

    assert!(result.is_ok());

    assert_eq!(result.unwrap(), true);
}

#[test]
fn test_ed25519_sign() {
    let message = b"Hello World!";

    let private_key = ed25519_gen_private_key();

    let signature = ed25519_sign(&private_key.unwrap(), message);

    assert!(signature.is_ok());
}

#[test]
fn test_ed25519_gen_private_key() {
    let private_key = ed25519_gen_private_key();

    assert!(private_key.is_ok());
}

#[test]
fn test_ed25519_gen_public_key() {
    let private_key = ed25519_gen_private_key().unwrap();

    let public_key = ed25519_gen_public_key(&private_key);

    assert!(public_key.is_ok());
}

/*
    X25519
        x25519_diffie_hellman_ephemeral
        x25519_diffie_hellman
        x25519_gen_shared_secret
        x25519_gen_private_key
        x25519_gen_public_key
*/

#[test]
fn test_x25519_diffie_hellman_ephemeral() {
    // alice
    let alice_private_key = x25519_gen_private_key().unwrap();

    let alice_public_key = x25519_gen_public_key(&alice_private_key).unwrap();

    // bob
    let (bob_ephemeral_public_key, bob_shared_secret) =
        x25519_diffie_hellman_ephemeral(&alice_public_key).unwrap();

    // alice_private_key / bob_ephemeral_public_key
    let alice_shared_secret =
        x25519_diffie_hellman(&alice_private_key, &bob_ephemeral_public_key).unwrap();

    assert_eq!(alice_shared_secret, bob_shared_secret);
}

#[test]
fn test_x25519_diffie_hellman() {
    // alice
    let alice_private_key = x25519_gen_private_key().unwrap();

    let alice_public_key = x25519_gen_public_key(&alice_private_key).unwrap();

    // bob
    let bob_private_key = x25519_gen_private_key().unwrap();

    let bob_public_key = x25519_gen_public_key(&bob_private_key).unwrap();

    // alice_private_key / bob_public_key
    let alice_shared_secret = x25519_diffie_hellman(&alice_private_key, &bob_public_key).unwrap();

    // bob_private_key / alice_public_key
    let bob_shared_secret = x25519_diffie_hellman(&bob_private_key, &alice_public_key).unwrap();

    assert_eq!(alice_shared_secret, bob_shared_secret);
}

#[test]
fn test_x25519_shared_secret() {
    let private_key = x25519_gen_private_key().unwrap();

    let public_key = x25519_gen_public_key(&private_key).unwrap();

    let shared_secret = x25519_diffie_hellman(&private_key, &public_key);

    assert!(shared_secret.is_ok());
}

#[test]
fn test_x25519_gen_private_key() {
    let private_key = x25519_gen_private_key();

    assert!(private_key.is_ok());
}

#[test]
fn test_x25519_gen_public_key() {
    let private_key = x25519_gen_private_key().unwrap();

    let public_key = x25519_gen_public_key(&private_key);

    assert!(public_key.is_ok());
}
