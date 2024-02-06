use xenon_common::error::Error;
use xenon_common::result::Result;

/// Asymmetric Algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asymmetric {
    Ed25519 = 1,
    X25519 = 2,
    Ed448 = 3,
    X448 = 4,
}

impl Asymmetric {

    /// Convert to usize
    /// 
    /// # Example
    /// ```
    /// use xenon_crypto::algorithm::Asymmetric;
    /// 
    /// let value = Asymmetric::Ed25519.to_usize();
    /// 
    /// assert_eq!(value, 1);
    /// ```
    pub fn to_usize(&self) -> usize {
        *self as usize
    }

    /// Convert from usize
    /// 
    /// # Arguments
    /// * `value` - usize
    /// 
    /// # Errors
    /// Returns an error if the value is not a valid Asymmetric.
    /// 
    /// # Example
    /// ```
    /// use xenon_crypto::algorithm::Asymmetric;
    /// 
    /// let value = Asymmetric::from_usize(1);
    /// 
    /// assert_eq!(value.unwrap(), Asymmetric::Ed25519);
    /// ```
    pub fn from_usize(value: usize) -> Result<Asymmetric> {
        match value {
            1 => Ok(Asymmetric::Ed25519),
            2 => Ok(Asymmetric::X25519),
            3 => Ok(Asymmetric::Ed448),
            4 => Ok(Asymmetric::X448),
            _ => Err(Error::new_dummy()),
        }
    }
}