use crate::{Error, ErrorKind, Result};
extern crate alloc;

use alloc::{string::String, vec::Vec};

const TABLE: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

pub fn encode(bytes: &[u8]) -> String {
    let mut buffer = String::with_capacity(bytes.len() * 2 + 1);

    for &byte in bytes {
        buffer.push(TABLE[(byte >> 4) as usize]);
        buffer.push(TABLE[(byte & 0x0F) as usize]);
    }

    buffer
}

// todo: きたない...
// なんて汚いんだ...
pub fn decode(hex: impl Into<String>) -> Result<Vec<u8>> {
    let hex = hex.into();

    if hex.len() % 2 != 0 {
        return Err(Error::new(
            ErrorKind::InvalidLength,
            String::from("Invalid hex length"),
        ));
    }

    let mut buffer = Vec::new();

    let mut chars = hex.chars();

    while let Some(ch) = chars.next() {
        let byte = (match ch.to_digit(16) {
            Some(n) => n as u8,
            None => Err(Error::new(
                ErrorKind::ParseFailed,
                String::from("Invalid hex character"),
            ))?,
        } << 4)
            | match match chars.next() {
                Some(c) => c,
                None => Err(Error::new(
                    ErrorKind::ParseFailed,
                    String::from("Invalid hex character"),
                ))?,
            }
            .to_digit(16)
            {
                Some(n) => n as u8,
                None => Err(Error::new(
                    ErrorKind::ParseFailed,
                    String::from("Invalid hex character"),
                ))?,
            };

        buffer.push(byte);
    }

    Ok(buffer)
}

#[test]
fn test_encode() {
    assert_eq!(encode(b"Hello, world!"), "48656c6c6f2c20776f726c6421");
}

#[test]
fn test_decode() {
    assert_eq!(
        decode("48656c6c6f2c20776f726c6421").unwrap(),
        b"Hello, world!"
    );
}

#[test]
fn test_decode_error() {
    // Ok
    // assert_eq!(decode("48656c6c6f2c20776f726c6421").unwrap(), b"Hello, world!");

    // Err
    assert!(decode("48656c6c6f2c20776f726c642").is_err());
}
