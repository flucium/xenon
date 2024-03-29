use xenon_common::{
    size::{SIZE_12_BYTE, SIZE_16_BYTE, SIZE_24_BYTE, SIZE_32_BYTE},
    Error, ErrorKind, Result,
};

/// Generate cryptographically strong pseudo-random bytes
/// 
/// # Errors
/// Internal error
pub fn gen_12() -> Result<[u8; SIZE_12_BYTE]> {
    let mut buffer = [0u8; SIZE_12_BYTE];

    openssl::rand::rand_bytes(&mut buffer).map_err(|_| Error::internal_error())?;

    Ok(buffer)
}

/// Generate cryptographically strong pseudo-random bytes
/// 
/// # Errors
/// Internal error
pub fn gen_16() -> Result<[u8; SIZE_16_BYTE]> {
    let mut buffer = [0u8; SIZE_16_BYTE];

    openssl::rand::rand_bytes(&mut buffer).map_err(|_| Error::internal_error())?;

    Ok(buffer)
}

/// Generate cryptographically strong pseudo-random bytes
/// 
/// # Errors
/// Internal error
pub fn gen_24() -> Result<[u8; SIZE_24_BYTE]> {
    let mut buffer = [0u8; SIZE_24_BYTE];

    openssl::rand::rand_bytes(&mut buffer).map_err(|_| Error::internal_error())?;

    Ok(buffer)
}

/// Generate cryptographically strong pseudo-random bytes
/// 
/// # Errors
/// Internal error
pub fn gen_32() -> Result<[u8; SIZE_32_BYTE]> {
    let mut buffer = [0u8; SIZE_32_BYTE];

    openssl::rand::rand_bytes(&mut buffer).map_err(|_| Error::internal_error())?;

    Ok(buffer)
}

pub fn gen<const T: usize>() -> Result<[u8; T]> {
    if T == 0 {
        Err(Error::new(
            ErrorKind::InvalidLength,
            String::from("The minimum size is 1-byte"),
        ))?;
    }

    if T > SIZE_32_BYTE {
        Err(Error::new(
            ErrorKind::InvalidLength,
            String::from("The maximum size is 32-bytes"),
        ))?;
    }

    let mut buffer = [0u8; T];

    openssl::rand::rand_bytes(&mut buffer).map_err(|_| Error::internal_error())?;

    Ok(buffer)
}