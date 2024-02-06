#[derive(Debug)]
pub enum ErrorKind {
    Dummy,
    Internal,
    Other,
}

#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: &'static str,
}

impl Error {
    pub const fn new_dummy() -> Self {
        Self {
            kind: ErrorKind::Dummy,
            message: "Dummy error",
        }
    }

 
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    pub fn message(&self) -> &str {
        self.message
    }
}
