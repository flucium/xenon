

// pub mod
pub mod size;
pub mod format;



pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, PartialEq, Eq)]
pub struct Error(ErrorKind, String);

impl Error {
    pub fn new(kind: ErrorKind, message: String) -> Self {
        Self(kind, message)
    }

    pub fn internal_error() -> Self {
        Self(ErrorKind::Internal, String::default())
    }

    pub fn kind(&self) -> &ErrorKind {
        &self.0
    }

    pub fn message(&self) -> &str {
        &self.1
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Dummy,
    Internal,
    Other,

    Unsupported,

    ParseFailed,

    Expired,

    InvalidLength,

    EncryptFailed,
    DecryptFailed,
}

impl ToString for ErrorKind {
    fn to_string(&self) -> String {
        match self {
            ErrorKind::Dummy => String::from("Dummy"),
            ErrorKind::Internal => String::from("Internal"),
            ErrorKind::Other => String::from("Other"),
            ErrorKind::Unsupported => String::from("Unsupported"),
            ErrorKind::ParseFailed => String::from("ParseFailed"),
            ErrorKind::Expired => String::from("Expired"),
            ErrorKind::InvalidLength => String::from("InvalidLength"),
            ErrorKind::EncryptFailed => String::from("EncryptFailed"),
            ErrorKind::DecryptFailed => String::from("DecryptFailed"),
        }
    }
}
