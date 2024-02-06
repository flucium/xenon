extern crate alloc;

use alloc::{string::String, vec::Vec};
use xenon_common::error::Error;
use xenon_common::result::Result;

type Label<'a> = &'a str;

pub const PEM_LABEL_PRIVATE_KEY: Label = "PRIVATE KEY";

pub const PEM_LABEL_PUBLIC_KEY: Label = "PUBLIC KEY";

#[cfg(target_os = "macos")]
const LINE_ENDING: pem_rfc7468::LineEnding = pem_rfc7468::LineEnding::LF;

#[cfg(target_os = "linux")]
const LINE_ENDING: pem_rfc7468::LineEnding = pem_rfc7468::LineEnding::LF;

#[cfg(target_os = "windows")]
const LINE_ENDING: pem_rfc7468::LineEnding = pem_rfc7468::LineEnding::CRLF;

/// Decode PEM
///
/// # Arguments
/// * `pem` - PEM to decode
///
/// # Returns
/// Label and Decoded data.
///
/// # Errors
/// If the PEM cannot be decoded.
///
/// # Example
/// ```
/// use xenon_crypto::format::pem;
///
/// let (label, data) = pem::decode("-----BEGIN PRIVATE KEY-----\nAQIDBAUGBwg=\n-----END PRIVATE KEY-----").unwrap();
/// ```
pub fn decode(pem: &str) -> Result<(String, Vec<u8>)> {
    let (label, v) = pem_rfc7468::decode_vec(pem.as_bytes()).map_err(|_| Error::new_dummy())?;

    let label = label.to_string();

    Ok((label, v))
}

/// Encode PEM
///
/// # Arguments
/// * `label` - PEM label
/// * `data` - Data to encode
///
/// # Returns
/// Encoded PEM.
///
/// # Errors
/// If the data cannot be encoded.
///
/// # Example
/// ```
/// use xenon_crypto::format::pem::{self, PEM_LABEL_PRIVATE_KEY};
///
/// let pem = pem::encode(PEM_LABEL_PRIVATE_KEY, &[0u8;32]).unwrap();
/// ```
pub fn encode(label: Label, data: &[u8]) -> Result<String> {
    pem_rfc7468::encode_string(label, LINE_ENDING, data).map_err(|_| Error::new_dummy())
}
