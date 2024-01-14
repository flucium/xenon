use openssl::hash::{hash, MessageDigest};
use xenon_common::{Error, Result};

/// Generate a message digest
/// 
/// # Errors
/// Internal error
pub(super) fn message_digest<const T: usize>(md: MessageDigest, bytes: &[u8]) -> Result<[u8; T]> {
    if md.size() != T {
        Err(Error::internal_error())?
    }

    let digest = hash(md, bytes).map_err(|_| Error::internal_error())?;

    Ok(unsafe { digest.get_unchecked(..T) }.try_into().unwrap())
}
