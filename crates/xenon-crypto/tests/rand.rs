// e.g.
// cargo test --package xenon-crypto --test rand -- test_gen_12 --exact --nocapture 

use xenon_common::size::{SIZE_12_BYTE, SIZE_16_BYTE, SIZE_24_BYTE, SIZE_32_BYTE};
use xenon_crypto::rand::{gen_12, gen_16, gen_24, gen_32};

#[test]
fn test_gen_12() {
    let buffer = gen_12().unwrap();
    assert_eq!(buffer.len(), SIZE_12_BYTE);
}

#[test]
fn test_gen_16() {
    let buffer = gen_16().unwrap();
    assert_eq!(buffer.len(), SIZE_16_BYTE);
}

#[test]
fn test_gen_24() {
    let buffer = gen_24().unwrap();
    assert_eq!(buffer.len(), SIZE_24_BYTE);
}

#[test]
fn test_gen_32() {
    let buffer = gen_32().unwrap();
    assert_eq!(buffer.len(), SIZE_32_BYTE);
}

pub mod chacha_rng {
    // todo!()
}
