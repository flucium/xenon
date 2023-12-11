mod asymmetric;
mod expiry;
mod fingerprint;
mod hybrid;
mod key;
mod symmetric;

// pub mod
pub mod algorithm;
pub mod hash;
pub mod rand;

// pub use
pub use asymmetric::*;
pub use expiry::*;
pub use fingerprint::*;
pub use hybrid::*;
pub use key::*;
pub use symmetric::*;

// Re-export
pub use chrono::{NaiveDate as Date, Utc};
pub use openssl;
pub use uuid::Uuid;


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
