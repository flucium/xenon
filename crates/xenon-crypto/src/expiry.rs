use crate::{Date, Utc};
use xenon_common::{size::SIZE_10_BYTE, Error, ErrorKind, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expiry(Option<Date>);

impl Expiry {
    /// No expiration date.
    pub const NO_EXPIRATION: Self = Self(None);

    /// Create a new expiry
    ///
    /// This is the same as NO_EXPIRATION. No expiration date.
    ///
    /// # Example
    /// ```
    /// let expiry = xenon_crypto::Expiry::new();
    /// ```
    pub const fn new() -> Self {
        Self(None)
    }

    /// Returns true if the key is expired.
    ///
    /// # Example
    /// ```
    /// let expiry = xenon_crypto::Expiry::try_from("2021/12/31".to_string()).unwrap();
    ///
    /// assert_eq!(expiry.is_expired(), false);
    /// ```
    pub fn is_expired(&self) -> bool {
        if self.0.is_none() {
            return true;
        }

        match self.0 {
            None => return true,
            Some(date) => {
                let current_date = Utc::now().naive_utc().date();

                date >= current_date
            }
        }
    }

    pub fn len(&self) -> usize {
        SIZE_10_BYTE
    }
}

impl ToString for Expiry {
    fn to_string(&self) -> String {
        match self.0 {
            None => String::from("0000/00/00"),
            Some(date) => date.format("%Y/%m/%d").to_string(),
        }
    }
}

impl TryFrom<String> for Expiry {
    type Error = Error;

    fn try_from(string: String) -> Result<Self> {
        if is_no_expiration(string.as_bytes()) {
            return Ok(Self(None));
        }

        let date = Date::parse_from_str(&string, "%Y/%m/%d")
            .map_err(|err| Error::new(ErrorKind::ParseFailed, String::from(err.to_string())))?;

        Ok(Self(Some(date)))
    }
}

impl TryFrom<&str> for Expiry {
    type Error = Error;

    fn try_from(string: &str) -> Result<Self> {
        if is_no_expiration(string) {
            return Ok(Self(None));
        }

        let date = Date::parse_from_str(&string, "%Y/%m/%d")
            .map_err(|err| Error::new(ErrorKind::ParseFailed, String::from(err.to_string())))?;

        Ok(Self(Some(date)))
    }
}

impl TryFrom<&[u8]> for Expiry {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if is_no_expiration(bytes) {
            return Ok(Self(None));
        }

        let string = String::from_utf8(bytes.to_vec())
            .map_err(|err| Error::new(ErrorKind::ParseFailed, String::from(err.to_string())))?;

        let date = Date::parse_from_str(&string, "%Y/%m/%d")
            .map_err(|err| Error::new(ErrorKind::ParseFailed, String::from(err.to_string())))?;

        Ok(Self(Some(date)))
    }
}

fn is_no_expiration(date: impl AsRef<[u8]>) -> bool {
    date.as_ref() == b"0000/00/00"
}
