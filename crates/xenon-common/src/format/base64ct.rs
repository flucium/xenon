use openssl::base64::{decode_block, encode_block};

use crate::{Error, ErrorKind, Result};

pub fn decode(s: &str) -> Result<Vec<u8>> {
    decode_block(s)
        .map_err(|_| Error::new(ErrorKind::ParseFailed, String::from("Base64 decode failed")))
}

pub fn encode(bytes: &[u8]) -> String {
    encode_block(bytes)
}