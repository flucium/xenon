extern crate alloc;

use alloc::{string::String, vec::Vec};
use base64ct::Encoding;
use xenon_common::error::Error;
use xenon_common::result::Result;

/// Decode base64
/// 
/// # Arguments
/// * `string` - Base64 to decode
/// 
/// # Returns
/// Decoded data.
/// 
/// # Errors
/// If the base64 cannot be decoded.
/// 
/// # Example
/// ```
/// use xenon_crypto::format::base64ct;
/// 
/// let data = base64ct::decode("AQIDBAUGBwg=").unwrap();
/// ```
pub fn decode(string: &str) -> Result<Vec<u8>> {
    base64ct::Base64::decode_vec(string).map_err(|_| Error::new_dummy())
}


/// Encode base64
/// 
/// # Arguments
/// * `data` - Data to encode
/// 
/// # Returns
/// Encoded base64.
/// 
/// # Example
/// ```
/// use xenon_crypto::format::base64ct;
/// 
/// let string = base64ct::encode(b"Hello, World!");
/// ```
pub fn encode(data: &[u8]) -> String {
    base64ct::Base64::encode_string(data)
}
