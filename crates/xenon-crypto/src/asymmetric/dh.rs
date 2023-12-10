use core::result::Result;
use openssl::derive::Deriver;
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private, Public};

/// Diffie-Hellman
/// 
/// const T: usize - Size of the output buffer
/// 
/// # Arguments
/// * `private_key` - Private key
/// * `public_key` - Public key
pub(super) fn diffie_hellman<const T: usize>(
    private_key: &PKey<Private>,
    public_key: &PKey<Public>,
) -> Result<[u8; T], ErrorStack> {
    let mut buffer = [0u8; T];

    let mut deriver = Deriver::new(private_key)?;

    deriver.set_peer(public_key)?;

    deriver.derive(&mut buffer)?;

    Ok(buffer)
}
