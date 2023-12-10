use openssl::hash::{hash, MessageDigest};

use xenon_common::{
    size::{SIZE_32_BYTE, SIZE_64_BYTE},
    Error, Result,
};

pub fn sha3_512_digest(bytes: &[u8]) -> Result<[u8; SIZE_64_BYTE]> {
    let digest = hash(MessageDigest::sha3_512(), bytes).map_err(|_| Error::internal_error())?;

    let result = unsafe { digest.get_unchecked(..SIZE_64_BYTE) }
        .try_into()
        .unwrap();

    Ok(result)
}

pub fn sha3_256_digest(bytes: &[u8]) -> Result<[u8; SIZE_32_BYTE]> {
    let digest = hash(MessageDigest::sha3_256(), bytes).map_err(|_| Error::internal_error())?;

    let result = unsafe { digest.get_unchecked(..SIZE_32_BYTE) }
        .try_into()
        .unwrap();

    Ok(result)
}

pub fn sha512_digest(bytes: &[u8]) -> Result<[u8; SIZE_64_BYTE]> {
    let digest = hash(MessageDigest::sha512(), bytes).map_err(|_| Error::internal_error())?;

    let result = unsafe { digest.get_unchecked(..SIZE_64_BYTE) }
        .try_into()
        .unwrap();

    Ok(result)
}

pub fn sha256_digest(bytes: &[u8]) -> Result<[u8; SIZE_32_BYTE]> {
    let digest = hash(MessageDigest::sha256(), bytes).map_err(|_| Error::internal_error())?;

    let result = unsafe { digest.get_unchecked(..SIZE_32_BYTE) }
        .try_into()
        .unwrap();

    Ok(result)
}

/*
    Unit tests
*/

/*
    SHA3-512
    SHA3-256
    SHA512
    SHA256
*/

#[test]
fn test_sha3_512_digest() {
    assert_eq!(
        sha3_512_digest(&[]).unwrap(),
        [
            166, 159, 115, 204, 162, 58, 154, 197, 200, 181, 103, 220, 24, 90, 117, 110, 151, 201,
            130, 22, 79, 226, 88, 89, 224, 209, 220, 193, 71, 92, 128, 166, 21, 178, 18, 58, 241,
            245, 249, 76, 17, 227, 233, 64, 44, 58, 197, 88, 245, 0, 25, 157, 149, 182, 211, 227,
            1, 117, 133, 134, 40, 29, 205, 38
        ]
    );
}

#[test]
fn test_sha3_256_digest() {
    assert_eq!(
        sha3_256_digest(&[]).unwrap(),
        [
            167, 255, 198, 248, 191, 30, 215, 102, 81, 193, 71, 86, 160, 97, 214, 98, 245, 128,
            255, 77, 228, 59, 73, 250, 130, 216, 10, 75, 128, 248, 67, 74
        ]
    );
}

#[test]
fn test_sha512_digest() {
    assert_eq!(
        sha512_digest(&[]).unwrap(),
        [
            207, 131, 225, 53, 126, 239, 184, 189, 241, 84, 40, 80, 214, 109, 128, 7, 214, 32, 228,
            5, 11, 87, 21, 220, 131, 244, 169, 33, 211, 108, 233, 206, 71, 208, 209, 60, 93, 133,
            242, 176, 255, 131, 24, 210, 135, 126, 236, 47, 99, 185, 49, 189, 71, 65, 122, 129,
            165, 56, 50, 122, 249, 39, 218, 62
        ]
    );
}

#[test]
fn test_sha256_digest() {
    assert_eq!(
        sha256_digest(&[]).unwrap(),
        [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85
        ]
    );
}

pub mod kdf {
    use openssl::md::Md;
    use openssl::pkey::Id;
    use openssl::pkey_ctx::HkdfMode;
    use openssl::pkey_ctx::PkeyCtx;

    use xenon_common::{
        size::{SIZE_32_BYTE, SIZE_64_BYTE},
        Error, Result,
    };

    pub fn hkdf_sha512_derive(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; SIZE_64_BYTE]> {
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

        ctx.set_hkdf_md(Md::sha512())
            .map_err(|_| Error::internal_error())?;

        ctx.set_hkdf_key(ikm).map_err(|_| Error::internal_error())?;

        ctx.set_hkdf_salt(salt)
            .map_err(|_| Error::internal_error())?;

        ctx.add_hkdf_info(info)
            .map_err(|_| Error::internal_error())?;

        let mut okm = [0u8; SIZE_64_BYTE];

        ctx.derive(Some(&mut okm))
            .map_err(|_| Error::internal_error())?;

        Ok(okm)
    }

    pub fn hkdf_sha256_derive(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; SIZE_32_BYTE]> {
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

        ctx.set_hkdf_md(Md::sha256())
            .map_err(|_| Error::internal_error())?;

        ctx.set_hkdf_key(ikm).map_err(|_| Error::internal_error())?;

        ctx.set_hkdf_salt(salt)
            .map_err(|_| Error::internal_error())?;

        ctx.add_hkdf_info(info)
            .map_err(|_| Error::internal_error())?;

        let mut okm = [0u8; SIZE_32_BYTE];

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
                59, 228, 99, 41, 216, 71, 178, 136, 10, 34, 169, 45, 135, 71, 80, 227, 217, 146,
                45, 57, 145, 10, 166, 184, 182, 199, 151, 11, 128, 44, 200, 160, 165, 252, 240, 25,
                133, 253, 56, 52, 39, 40, 245, 166, 252, 213, 178, 227, 185, 212, 194, 238, 169,
                166, 244, 225, 189, 4, 168, 146, 182, 126, 12, 38
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
                202, 13, 9, 82, 32, 25, 246, 98, 42, 39, 141, 181, 226, 162, 19, 26, 82, 166, 38,
                167, 71, 139, 37, 81, 189, 233, 164, 43, 9, 14, 2, 250
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
}
