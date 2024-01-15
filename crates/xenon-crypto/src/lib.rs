mod algorithm;
mod asymmetric;
mod expiry;
mod fingerprint;
mod hash;
mod key;
mod symmetric;
// pub mod
pub mod rand;

// pub use
pub use algorithm::*;
pub use asymmetric::*;
pub use expiry::*;
pub use fingerprint::*;
pub use key::*;
pub use symmetric::*;

// Re-export
pub use chrono::{NaiveDate as Date, Utc};
pub use openssl;

/// Compare two byte slices in constant time.
///
/// # Example
/// ```
/// use xenon_crypto::eq;
///
/// let a = b"Hello";
///
/// let b = b"Hello";
///
/// assert!(eq(a, b));
/// ```
pub fn eq(a: impl AsRef<[u8]>, b: impl AsRef<[u8]>) -> bool {
    let a = a.as_ref();

    let b = b.as_ref();

    if a.len() != b.len() {
        return false;
    }

    openssl::memcmp::eq(a, b)
}

/// Get the current timestamp in milliseconds.
pub fn timestamp() -> u64 {
    Utc::now().timestamp_millis() as u64
}
