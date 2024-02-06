use aead::{Aead, Payload};
use xenon_common::error::Error;
use xenon_common::result::Result;

pub mod aes;

#[inline]
pub(super) fn aead_decrypt(
    aead: &impl Aead,
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    let message_len = message.len();

    let nonce_len = message[message_len - 8..][7..][0] as u32;

    let nonce = &message[message_len - nonce_len as usize - 8..][..nonce_len as usize];

    let message = &message[..message_len - nonce_len as usize - 8];

    let plain = aead
        .decrypt(
            nonce.into(),
            Payload {
                msg: message,
                aad: associated_data,
            },
        )
        .map_err(|_| Error::new_dummy())?;

    Ok(plain)
}

#[inline]
pub(super) fn aead_encrypt(
    aead: &impl Aead,
    nonce: &[u8],
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    let mut cipher = aead
        .encrypt(
            nonce.into(),
            Payload {
                msg: message,
                aad: associated_data,
            },
        )
        .map_err(|_| Error::new_dummy())?;

    cipher.extend_from_slice(nonce);

    cipher.extend_from_slice(nonce.len().to_be_bytes().as_ref());

    Ok(cipher.to_vec())
}
