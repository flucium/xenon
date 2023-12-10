use core::result::Result;
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Public};
use openssl::sign::Verifier;

/// Verify
/// 
/// const T: usize - Size of the signature
/// 
/// # Arguments
/// * `public_key` - Public key
/// * `message` - Message
/// * `signature` - Signature
pub(super) fn verify<const T: usize>(
    public_key: &PKey<Public>,
    message: &[u8],
    signature: &[u8; T],
) -> Result<bool, ErrorStack> {
    let mut verifier = Verifier::new_without_digest(public_key)?;

    verifier.verify_oneshot(signature, message)
}
