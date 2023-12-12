use openssl::md::Md;
use openssl::md::MdRef;
use openssl::pkey::Id;
use openssl::pkey_ctx::HkdfMode;
use openssl::pkey_ctx::PkeyCtx;

use xenon_common::{
    size::{SIZE_32_BYTE, SIZE_64_BYTE},
    Error, Result,
};

pub fn hkdf_sha512_derive(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; SIZE_64_BYTE]> {
    hkdf_extract_then_expand::<SIZE_64_BYTE>(Md::sha512(), ikm, salt, info)
}

pub fn hkdf_sha256_derive(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; SIZE_32_BYTE]> {
    hkdf_extract_then_expand::<SIZE_32_BYTE>(Md::sha256(), ikm, salt, info)
}

fn hkdf_extract_then_expand<const T: usize>(
    md: &MdRef,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<[u8; T]> {
    if ikm.len() == 0 {
        Err(Error::new(
            xenon_common::ErrorKind::InvalidLength,
            String::from("The key length must be at least 1 byte"),
        ))?
    }

    let mut ctx = PkeyCtx::new_id(Id::HKDF).map_err(|_| Error::internal_error())?;

    ctx.derive_init().map_err(|_| Error::internal_error())?;

    ctx.set_hkdf_mode(HkdfMode::EXTRACT_THEN_EXPAND)
        .map_err(|_| Error::internal_error())?;

    ctx.set_hkdf_md(md).map_err(|_| Error::internal_error())?;

    ctx.set_hkdf_key(ikm).map_err(|_| Error::internal_error())?;

    ctx.set_hkdf_salt(salt)
        .map_err(|_| Error::internal_error())?;

    ctx.add_hkdf_info(info)
        .map_err(|_| Error::internal_error())?;

    let mut okm = [0u8; T];

    ctx.derive(Some(&mut okm))
        .map_err(|_| Error::internal_error())?;

    Ok(okm)
}

/*
    Unit tests

    HKDF-SHA512 test
    HKDF-SHA256 test
*/
#[test]
fn test_hkdf_sha512_derive() {
    assert_eq!(
        hkdf_sha512_derive(&[0u8; 1], &[], &[]).unwrap(),
        [
            59, 228, 99, 41, 216, 71, 178, 136, 10, 34, 169, 45, 135, 71, 80, 227, 217, 146, 45,
            57, 145, 10, 166, 184, 182, 199, 151, 11, 128, 44, 200, 160, 165, 252, 240, 25, 133,
            253, 56, 52, 39, 40, 245, 166, 252, 213, 178, 227, 185, 212, 194, 238, 169, 166, 244,
            225, 189, 4, 168, 146, 182, 126, 12, 38
        ]
    )
}

#[test]
fn test_hkdf_sha512_derive_invalid_key_length() {
    // 0-byte key is invalid
    assert_eq!(hkdf_sha512_derive(&[], &[], &[]).is_err(), true);

    // error kind is InvalidKeyLength
    assert_eq!(
        hkdf_sha512_derive(&[], &[], &[]).err().unwrap().kind(),
        &xenon_common::ErrorKind::InvalidLength
    );
}

#[test]
fn test_hkdf_sha256_derive() {
    assert_eq!(
        hkdf_sha256_derive(&[0u8; 1], &[], &[]).unwrap(),
        [
            202, 13, 9, 82, 32, 25, 246, 98, 42, 39, 141, 181, 226, 162, 19, 26, 82, 166, 38, 167,
            71, 139, 37, 81, 189, 233, 164, 43, 9, 14, 2, 250
        ]
    )
}

#[test]
fn test_hkdf_sha256_derive_invalid_key_length() {
    // 0-byte key is invalid
    assert_eq!(hkdf_sha256_derive(&[], &[], &[]).is_err(), true);

    // error kind is InvalidKeyLength
    assert_eq!(
        hkdf_sha256_derive(&[], &[], &[]).err().unwrap().kind(),
        &xenon_common::ErrorKind::InvalidLength
    );
}
