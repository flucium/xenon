use core::result::Result;
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;

/// Sign
/// 
/// const T: usize - Size of the output buffer
/// 
/// # Arguments
/// * `private_key` - Private key
/// * `message` - Message
pub(super) fn sign<const T: usize>(
    private_key: &PKey<Private>,
    message: &[u8],
) -> Result<[u8; T], ErrorStack> {
    let mut buffer = [0u8; T];

    let mut signer = Signer::new_without_digest(private_key)?;

    signer.sign_oneshot(&mut buffer, message)?;

    Ok(buffer)
}
