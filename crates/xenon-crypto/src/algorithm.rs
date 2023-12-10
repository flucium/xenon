use xenon_common::{
    size::{SIZE_12_BYTE, SIZE_16_BYTE, SIZE_24_BYTE, SIZE_32_BYTE, SIZE_64_BYTE},
    Error, ErrorKind, Result,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hasher {
    Sha256,
    Sha512,
    Sha3_256,
    Sha3_512,
}

impl Hasher {
    pub fn as_str(&self) -> &str {
        match self {
            Hasher::Sha256 => "sha256",
            Hasher::Sha512 => "sha512",
            Hasher::Sha3_256 => "sha3-256",
            Hasher::Sha3_512 => "sha3-512",
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Hasher::Sha256 => &[0x73, 0x68, 0x61, 0x32, 0x35, 0x36],
            Hasher::Sha512 => &[0x73, 0x68, 0x61, 0x35, 0x31, 0x32],
            Hasher::Sha3_256 => &[0x73, 0x68, 0x61, 0x33, 0x2d, 0x32, 0x35, 0x36],
            Hasher::Sha3_512 => &[0x73, 0x68, 0x61, 0x33, 0x2d, 0x35, 0x31, 0x32],
        }
    }

    pub fn output_length(&self) -> usize {
        match self {
            Hasher::Sha256 => SIZE_32_BYTE,
            Hasher::Sha512 => SIZE_64_BYTE,
            Hasher::Sha3_256 => SIZE_32_BYTE,
            Hasher::Sha3_512 => SIZE_64_BYTE,
        }
    }
}

impl ToString for Hasher {
    fn to_string(&self) -> String {
        match self {
            Hasher::Sha256 => String::from("sha256"),
            Hasher::Sha512 => String::from("sha512"),
            Hasher::Sha3_256 => String::from("sha3-256"),
            Hasher::Sha3_512 => String::from("sha3-512"),
        }
    }
}

impl TryFrom<String> for Hasher {
    type Error = Error;

    fn try_from(string: String) -> Result<Self> {
        match string {
            string if string.eq_ignore_ascii_case("sha256") => Ok(Self::Sha256),
            string if string.eq_ignore_ascii_case("sha512") => Ok(Self::Sha512),
            string if string.eq_ignore_ascii_case("sha3-256") => Ok(Self::Sha3_256),
            string if string.eq_ignore_ascii_case("sha3-512") => Ok(Self::Sha3_512),

            _ => Err(Error::new(
                ErrorKind::Unsupported,
                String::from("Unsupported hash algorithm"),
            )),
        }
    }
}

impl TryFrom<&str> for Hasher {
    type Error = Error;

    fn try_from(string: &str) -> Result<Self> {
        match string {
            string if string.eq_ignore_ascii_case("sha256") => Ok(Self::Sha256),
            string if string.eq_ignore_ascii_case("sha512") => Ok(Self::Sha512),
            string if string.eq_ignore_ascii_case("sha3-256") => Ok(Self::Sha3_256),
            string if string.eq_ignore_ascii_case("sha3-512") => Ok(Self::Sha3_512),

            _ => Err(Error::new(
                ErrorKind::Unsupported,
                String::from("Unsupported hash algorithm"),
            )),
        }
    }
}

impl TryFrom<&[u8]> for Hasher {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        match bytes {
            bytes if bytes.eq_ignore_ascii_case(&[0x73, 0x68, 0x61, 0x32, 0x35, 0x36]) => {
                Ok(Self::Sha256)
            }
            bytes if bytes.eq_ignore_ascii_case(&[0x73, 0x68, 0x61, 0x35, 0x31, 0x32]) => {
                Ok(Self::Sha512)
            }
            bytes
                if bytes
                    .eq_ignore_ascii_case(&[0x73, 0x68, 0x61, 0x33, 0x2d, 0x32, 0x35, 0x36]) =>
            {
                Ok(Self::Sha3_256)
            }
            bytes
                if bytes
                    .eq_ignore_ascii_case(&[0x73, 0x68, 0x61, 0x33, 0x2d, 0x35, 0x31, 0x32]) =>
            {
                Ok(Self::Sha3_512)
            }

            _ => Err(Error::new(
                ErrorKind::Unsupported,
                String::from("Unsupported hash algorithm"),
            )),
        }
    }
}

impl TryInto<String> for Hasher {
    type Error = Error;

    fn try_into(self) -> Result<String> {
        Ok(self.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    HkdfSha256,
    HkdfSha512,
}

impl Kdf {
    pub fn as_str(&self) -> &str {
        match self {
            Kdf::HkdfSha256 => "hkdf-sha256",
            Kdf::HkdfSha512 => "hkdf-sha512",
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Kdf::HkdfSha256 => &[
                0x68, 0x6b, 0x64, 0x66, 0x2d, 0x73, 0x68, 0x61, 0x32, 0x35, 0x36,
            ],
            Kdf::HkdfSha512 => &[
                0x68, 0x6b, 0x64, 0x66, 0x2d, 0x73, 0x68, 0x61, 0x35, 0x31, 0x32,
            ],
        }
    }
}

impl ToString for Kdf {
    fn to_string(&self) -> String {
        match self {
            Kdf::HkdfSha256 => String::from("hkdf-sha256"),
            Kdf::HkdfSha512 => String::from("hkdf-sha512"),
        }
    }
}

impl TryFrom<String> for Kdf {
    type Error = Error;

    fn try_from(string: String) -> Result<Self> {
        match string {
            string if string.eq_ignore_ascii_case("hkdf-sha256") => Ok(Self::HkdfSha256),
            string if string.eq_ignore_ascii_case("hkdf-sha512") => Ok(Self::HkdfSha512),

            _ => Err(Error::new(
                ErrorKind::Unsupported,
                String::from("Unsupported key derivation function"),
            )),
        }
    }
}

impl TryFrom<&str> for Kdf {
    type Error = Error;

    fn try_from(string: &str) -> Result<Self> {
        match string {
            string if string.eq_ignore_ascii_case("hkdf-sha256") => Ok(Self::HkdfSha256),
            string if string.eq_ignore_ascii_case("hkdf-sha512") => Ok(Self::HkdfSha512),

            _ => Err(Error::new(
                ErrorKind::Unsupported,
                String::from("Unsupported key derivation function"),
            )),
        }
    }
}

impl TryFrom<&[u8]> for Kdf {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        match bytes {
            bytes
                if bytes.eq_ignore_ascii_case(&[
                    0x68, 0x6b, 0x64, 0x66, 0x2d, 0x73, 0x68, 0x61, 0x32, 0x35, 0x36,
                ]) =>
            {
                Ok(Self::HkdfSha256)
            }
            bytes
                if bytes.eq_ignore_ascii_case(&[
                    0x68, 0x6b, 0x64, 0x66, 0x2d, 0x73, 0x68, 0x61, 0x35, 0x31, 0x32,
                ]) =>
            {
                Ok(Self::HkdfSha512)
            }

            _ => Err(Error::new(
                ErrorKind::Unsupported,
                String::from("Unsupported key derivation function"),
            )),
        }
    }
}

impl TryInto<String> for Kdf {
    type Error = Error;

    fn try_into(self) -> Result<String> {
        Ok(self.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordHasher {
    Scrypt,
    // Argon2i,
    // Argon2d,
    // Argon2id,
}

impl PasswordHasher {
    pub fn as_str(&self) -> &str {
        match self {
            PasswordHasher::Scrypt => "scrypt",
            // PasswordHasher::Argon2i => "argon2i",
            // PasswordHasher::Argon2d => "argon2d",
            // PasswordHasher::Argon2id => "argon2id",
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PasswordHasher::Scrypt => &[0x73, 0x63, 0x72, 0x79, 0x70, 0x74],
            // PasswordHasher::Argon2i => &[0x61, 0x72, 0x67, 0x6f, 0x6e, 0x32, 0x69],
            // PasswordHasher::Argon2d => &[0x61, 0x72, 0x67, 0x6f, 0x6e, 0x32, 0x64],
            // PasswordHasher::Argon2id => &[0x61, 0x72, 0x67, 0x6f, 0x6e, 0x32, 0x69, 0x64],
        }
    }
}

impl ToString for PasswordHasher {
    fn to_string(&self) -> String {
        match self {
            PasswordHasher::Scrypt => String::from("scrypt"),
            // PasswordHasher::Argon2i => String::from("argon2i"),
            // PasswordHasher::Argon2d => String::from("argon2d"),
            // PasswordHasher::Argon2id => String::from("argon2id"),
        }
    }
}

impl TryFrom<String> for PasswordHasher {
    type Error = Error;

    fn try_from(string: String) -> Result<Self> {
        match string {
            string if string.eq_ignore_ascii_case("scrypt") => Ok(Self::Scrypt),
            // string if string.eq_ignore_ascii_case("argon2i") => Ok(Self::Argon2i),
            // string if string.eq_ignore_ascii_case("argon2d") => Ok(Self::Argon2d),
            // string if string.eq_ignore_ascii_case("argon2id") => Ok(Self::Argon2id),
            _ => Err(Error::new(
                ErrorKind::Unsupported,
                String::from("Unsupported password hash algorithm"),
            )),
        }
    }
}

impl TryFrom<&str> for PasswordHasher {
    type Error = Error;

    fn try_from(string: &str) -> Result<Self> {
        match string {
            string if string.eq_ignore_ascii_case("scrypt") => Ok(Self::Scrypt),
            // string if string.eq_ignore_ascii_case("argon2i") => Ok(Self::Argon2i),
            // string if string.eq_ignore_ascii_case("argon2d") => Ok(Self::Argon2d),
            // string if string.eq_ignore_ascii_case("argon2id") => Ok(Self::Argon2id),
            _ => Err(Error::new(
                ErrorKind::Unsupported,
                String::from("Unsupported password hash algorithm"),
            )),
        }
    }
}

impl TryFrom<&[u8]> for PasswordHasher {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        match bytes {
            bytes if bytes.eq_ignore_ascii_case(&[0x73, 0x63, 0x72, 0x79, 0x70, 0x74]) => {
                Ok(Self::Scrypt)
            }
            // bytes if bytes.eq_ignore_ascii_case(&[0x61, 0x72, 0x67, 0x6f, 0x6e, 0x32, 0x69]) => {
            //     Ok(Self::Argon2i)
            // }
            // bytes if bytes.eq_ignore_ascii_case(&[0x61, 0x72, 0x67, 0x6f, 0x6e, 0x32, 0x64]) => {
            //     Ok(Self::Argon2d)
            // }
            // bytes
            //     if bytes.eq_ignore_ascii_case(&[0x61, 0x72, 0x67, 0x6f, 0x6e, 0x32, 0x69, 0x64]) =>
            // {
            //     Ok(Self::Argon2id)
            // }
            _ => Err(Error::new(
                ErrorKind::Unsupported,
                String::from("Unsupported password hash algorithm"),
            )),
        }
    }
}

impl TryInto<String> for PasswordHasher {
    type Error = Error;

    fn try_into(self) -> Result<String> {
        Ok(self.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symmetric {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
}

impl Symmetric {
    pub fn key_length(&self) -> usize {
        match self {
            Symmetric::Aes128Gcm => SIZE_16_BYTE,
            Symmetric::Aes192Gcm => SIZE_24_BYTE,
            Symmetric::Aes256Gcm => SIZE_32_BYTE,
        }
    }

    pub fn nonce_length(&self) -> Option<usize> {
        self.iv_length()
    }

    pub fn iv_length(&self) -> Option<usize> {
        match self {
            Symmetric::Aes128Gcm => Some(SIZE_12_BYTE),
            Symmetric::Aes192Gcm => Some(SIZE_12_BYTE),
            Symmetric::Aes256Gcm => Some(SIZE_12_BYTE),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Symmetric::Aes128Gcm => "aes128gcm",
            Symmetric::Aes192Gcm => "aes192gcm",
            Symmetric::Aes256Gcm => "aes256gcm",
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Symmetric::Aes128Gcm => &[0x61, 0x65, 0x73, 0x31, 0x32, 0x38, 0x67, 0x63, 0x6d],
            Symmetric::Aes192Gcm => &[0x61, 0x65, 0x73, 0x31, 0x39, 0x32, 0x67, 0x63, 0x6d],
            Symmetric::Aes256Gcm => &[0x61, 0x65, 0x73, 0x32, 0x35, 0x36, 0x67, 0x63, 0x6d],
        }
    }
}

impl ToString for Symmetric {
    fn to_string(&self) -> String {
        match self {
            Symmetric::Aes128Gcm => String::from("aes128gcm"),
            Symmetric::Aes192Gcm => String::from("aes192gcm"),
            Symmetric::Aes256Gcm => String::from("aes256gcm"),
        }
    }
}

impl TryFrom<String> for Symmetric {
    type Error = Error;

    fn try_from(string: String) -> Result<Self> {
        match string {
            string if string.eq_ignore_ascii_case("aes128gcm") => Ok(Self::Aes128Gcm),
            string if string.eq_ignore_ascii_case("aes192gcm") => Ok(Self::Aes192Gcm),
            string if string.eq_ignore_ascii_case("aes256gcm") => Ok(Self::Aes256Gcm),

            _ => Err(Error::new(
                ErrorKind::Unsupported,
                String::from("Unsupported symmetric algorithm"),
            )),
        }
    }
}

impl TryFrom<&str> for Symmetric {
    type Error = Error;

    fn try_from(string: &str) -> Result<Self> {
        match string {
            string if string.eq_ignore_ascii_case("aes128gcm") => Ok(Self::Aes128Gcm),
            string if string.eq_ignore_ascii_case("aes192gcm") => Ok(Self::Aes192Gcm),
            string if string.eq_ignore_ascii_case("aes256gcm") => Ok(Self::Aes256Gcm),

            _ => Err(Error::new(
                ErrorKind::Unsupported,
                String::from("Unsupported symmetric algorithm"),
            )),
        }
    }
}

impl TryFrom<&[u8]> for Symmetric {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        match bytes {
            bytes
                if bytes.eq_ignore_ascii_case(&[
                    0x61, 0x65, 0x73, 0x31, 0x32, 0x38, 0x67, 0x63, 0x6d,
                ]) =>
            {
                Ok(Self::Aes128Gcm)
            }
            bytes
                if bytes.eq_ignore_ascii_case(&[
                    0x61, 0x65, 0x73, 0x31, 0x39, 0x32, 0x67, 0x63, 0x6d,
                ]) =>
            {
                Ok(Self::Aes192Gcm)
            }
            bytes
                if bytes.eq_ignore_ascii_case(&[
                    0x61, 0x65, 0x73, 0x32, 0x35, 0x36, 0x67, 0x63, 0x6d,
                ]) =>
            {
                Ok(Self::Aes256Gcm)
            }

            _ => Err(Error::new(
                ErrorKind::Unsupported,
                String::from("Unsupported symmetric algorithm"),
            )),
        }
    }
}

impl TryInto<String> for Symmetric {
    type Error = Error;

    fn try_into(self) -> Result<String> {
        Ok(self.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asymmetric {
    Ed25519,
    X25519,
}

impl Asymmetric {
    pub fn as_str(&self) -> &str {
        match self {
            Asymmetric::Ed25519 => "ed25519",
            Asymmetric::X25519 => "x25519",
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Asymmetric::Ed25519 => &[0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39],
            Asymmetric::X25519 => &[0x78, 0x32, 0x35, 0x35, 0x31, 0x39],
        }
    }

    pub fn key_length(&self) -> usize {
        match self {
            Asymmetric::Ed25519 => SIZE_32_BYTE,
            Asymmetric::X25519 => SIZE_32_BYTE,
        }
    }

    pub fn signature_length(&self) -> Result<usize> {
        match self {
            Asymmetric::Ed25519 => Ok(SIZE_64_BYTE),
            _ => Err(Error::new(
                ErrorKind::Unsupported,
                String::from("Unsupported signer"),
            )),
        }
    }
}

impl ToString for Asymmetric {
    fn to_string(&self) -> String {
        match self {
            Asymmetric::Ed25519 => String::from("ed25519"),
            Asymmetric::X25519 => String::from("x25519"),
        }
    }
}

impl TryFrom<String> for Asymmetric {
    type Error = Error;

    fn try_from(string: String) -> Result<Self> {
        match string {
            string if string.eq_ignore_ascii_case("Ed25519") => Ok(Self::Ed25519),
            string if string.eq_ignore_ascii_case("X25519") => Ok(Self::X25519),

            _ => Err(Error::new(
                ErrorKind::Unsupported,
                String::from("Unsupported asymmetric algorithm"),
            )),
        }
    }
}

impl TryFrom<&str> for Asymmetric {
    type Error = Error;

    fn try_from(string: &str) -> Result<Self> {
        match string {
            string if string.eq_ignore_ascii_case("Ed25519") => Ok(Self::Ed25519),
            string if string.eq_ignore_ascii_case("X25519") => Ok(Self::X25519),
            _ => Err(Error::new(
                ErrorKind::Unsupported,
                String::from("Unsupported asymmetric algorithm"),
            )),
        }
    }
}

impl TryFrom<&[u8]> for Asymmetric {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        match bytes {
            bytes if bytes.eq_ignore_ascii_case(&[0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39]) => {
                Ok(Self::Ed25519)
            }
            bytes if bytes.eq_ignore_ascii_case(&[0x78, 0x32, 0x35, 0x35, 0x31, 0x39]) => {
                Ok(Self::X25519)
            }

            _ => Err(Error::new(
                ErrorKind::Unsupported,
                String::from("Unsupported asymmetric algorithm"),
            )),
        }
    }
}

impl TryInto<String> for Asymmetric {
    type Error = Error;

    fn try_into(self) -> Result<String> {
        Ok(self.to_string())
    }
}

/*
    Unit tests
*/

/*
    Hasher (SHA256)
    Kdf (HKDF-SHA256)
    PasswordHasher (Scrypt)
    Symmetric (AES128GCM)
    Asymmetric (Ed25519)
*/

#[test]
fn test_hasher_sha256() {
    // from string
    assert_eq!(Hasher::Sha256, Hasher::try_from("Sha256").unwrap());

    // from string lowercase
    assert_eq!(Hasher::Sha256, Hasher::try_from("sha256").unwrap());

    // from string uppercase
    assert_eq!(Hasher::Sha256, Hasher::try_from("SHA256").unwrap());

    // to string
    assert_eq!("sha256", Hasher::Sha256.to_string());

    // to bytes
    assert_eq!(Hasher::Sha256.as_bytes(), &[115, 104, 97, 50, 53, 54]);
}

#[test]
fn test_hasher_kdf() {
    // from string
    assert_eq!(Kdf::HkdfSha256, Kdf::try_from("Hkdf-Sha256").unwrap());

    // from string lowercase
    assert_eq!(Kdf::HkdfSha256, Kdf::try_from("hkdf-sha256").unwrap());

    // from string uppercase
    assert_eq!(Kdf::HkdfSha256, Kdf::try_from("HKDF-SHA256").unwrap());

    // to string
    assert_eq!("hkdf-sha256", Kdf::HkdfSha256.to_string());

    // to bytes
    assert_eq!(
        Kdf::HkdfSha256.as_bytes(),
        &[104, 107, 100, 102, 45, 115, 104, 97, 50, 53, 54]
    );
}

#[test]
fn test_password_hasher() {
    // from string
    assert_eq!(
        PasswordHasher::Scrypt,
        PasswordHasher::try_from("Scrypt").unwrap()
    );

    // from string lowercase
    assert_eq!(
        PasswordHasher::Scrypt,
        PasswordHasher::try_from("scrypt").unwrap()
    );

    // from string uppercase
    assert_eq!(
        PasswordHasher::Scrypt,
        PasswordHasher::try_from("SCRYPT").unwrap()
    );

    // to string
    assert_eq!("scrypt", PasswordHasher::Scrypt.to_string());

    // to bytes
    assert_eq!(
        PasswordHasher::Scrypt.as_bytes(),
        &[115, 99, 114, 121, 112, 116]
    );
}

#[test]
fn test_symmetric() {
    // from string
    assert_eq!(
        Symmetric::Aes128Gcm,
        Symmetric::try_from("Aes128Gcm").unwrap()
    );

    // from string lowercase
    assert_eq!(
        Symmetric::Aes128Gcm,
        Symmetric::try_from("aes128gcm").unwrap()
    );

    // from string uppercase
    assert_eq!(
        Symmetric::Aes128Gcm,
        Symmetric::try_from("AES128GCM").unwrap()
    );

    // to string
    assert_eq!("aes128gcm", Symmetric::Aes128Gcm.to_string());

    // to bytes
    assert_eq!(
        Symmetric::Aes128Gcm.as_bytes(),
        &[97, 101, 115, 49, 50, 56, 103, 99, 109]
    );
}

#[test]
fn test_asymmetric() {
    // from string
    assert_eq!(
        Asymmetric::Ed25519,
        Asymmetric::try_from("Ed25519").unwrap()
    );

    // from string lowercase
    assert_eq!(
        Asymmetric::Ed25519,
        Asymmetric::try_from("ed25519").unwrap()
    );

    // from string uppercase
    assert_eq!(
        Asymmetric::Ed25519,
        Asymmetric::try_from("ED25519").unwrap()
    );

    // to string
    assert_eq!("ed25519", Asymmetric::Ed25519.to_string());

    // to bytes
    assert_eq!(
        Asymmetric::Ed25519.as_bytes(),
        &[101, 100, 50, 53, 53, 49, 57]
    );
}
