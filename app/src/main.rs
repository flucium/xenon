mod manifest;
use clap::{Parser, ValueEnum};
use std::{fs::File, path::Path};

#[derive(Debug, Parser)]
#[clap(name = manifest::NAME, version = manifest::VERSION, about = manifest::ABOUT, author = manifest::AUTHOR)]
enum App {
    #[clap(name = "keygen", alias = "keygenerate", about = "Generate a key")]
    KeyGen {
        /// Algorithm to use.
        #[clap(long = "algorithm", alias = "alg", default_value = "ed25519")]
        algorithm: KeyGenAlgorithm,

        /// Output the key to a file.
        #[clap(long = "output", alias = "out")]
        output: Option<String>,

        /// Expiry date of the key.
        #[clap(long = "expiry", alias = "exp", default_value = "0000/00/00")]
        expiry: String,

        /// Length of the key.
        #[clap(long = "length", alias = "len")]
        length: Option<usize>,
    },

    #[clap(name = "sign", about = "Sign a message")]
    Sign {
        /// Sign with an algorithm.
        #[clap(long = "algorithm", alias = "alg", default_value = "ed25519")]
        algorithm: SignatureAlgorithm,

        /// Sign with a private key.
        #[clap(long = "privatekey", alias = "priv", alias = "key")]
        private_key: String,

        /// Message to sign.
        #[clap(long = "message", alias = "msg")]
        message: String,

        /// Hasher to use.
        #[clap(long = "hasher", alias = "hash", default_value = "sha512")]
        hasher: String,
    },

    #[clap(name = "verify", about = "Verify a message")]
    Verify {
        /// Sign with an algorithm.
        #[clap(long = "algorithm", alias = "alg", default_value = "ed25519")]
        algorithm: SignatureAlgorithm,

        /// Verify with a public key.
        #[clap(long = "publickey", alias = "pub", alias = "key")]
        public_key: String,

        /// Message to verify.
        #[clap(long = "message", alias = "msg")]
        message: String,

        /// Signature to verify.
        #[clap(long = "signature", alias = "sig")]
        signature: String,
    },

    #[clap(name = "encrypt", about = "Encrypt a message")]
    Encrypt {
        /// Encrypt with an algorithm.
        #[clap(long = "algorithm", alias = "alg", default_value = "aes256gcm")]
        algorithm: SymmetricAlgorithm,

        /// Encrypt with a public key.
        #[clap(long = "key")]
        symmetric_key: String,

        /// Associated data.
        #[clap(long = "associateddata", alias = "aad")]
        associated_data: Option<String>,

        /// Message to encrypt.
        #[clap(long = "message", alias = "msg")]
        message: String,
    },

    #[clap(name = "decrypt", about = "Decrypt a message")]
    Decrypt {
        /// Encrypt with an algorithm.
        #[clap(long = "algorithm", alias = "alg", default_value = "aes256gcm")]
        algorithm: SymmetricAlgorithm,

        /// Decrypt with a private key.
        #[clap(long = "key")]
        symmetric_key: String,

        /// Associated data.
        #[clap(long = "associateddata", alias = "aad")]
        associated_data: Option<String>,

        /// Message to decrypt.
        #[clap(long = "message", alias = "msg")]
        message: String,
    },
}

#[derive(Debug, Clone, Parser, ValueEnum)]
enum KeyGenAlgorithm {
    #[clap(name = "symmetric", alias = "sym")]
    Symmetric,

    #[clap(name = "ed25519")]
    Ed25519,

    #[clap(name = "ed448")]
    Ed448,
}

#[derive(Debug, Clone, Parser, ValueEnum)]
enum SignatureAlgorithm {
    #[clap(name = "ed25519")]
    Ed25519,

    #[clap(name = "ed448")]
    Ed448,
}

#[derive(Debug, Clone, Parser, ValueEnum)]
enum SymmetricAlgorithm {
    #[clap(name = "aes128gcm")]
    Aes128Gcm,

    #[clap(name = "aes192gcm")]
    Aes192Gcm,

    #[clap(name = "aes256gcm")]
    Aes256Gcm,

    #[clap(name = "chacha20poly1305")]
    ChaCha20Poly1305,
}

fn open(path: impl AsRef<Path>) -> File {
    let path = path.as_ref();

    match File::options()
        .create_new(true)
        .write(true)
        .read(true)
        .append(false)
        .open(path)
    {
        Ok(file) => file,
        Err(err) => panic!("Failed to open file {:?}: {:?}", path, err),
    }
}

fn main() {
    let app = App::parse();

    match app {
        App::KeyGen {
            algorithm,
            output,
            expiry,
            length,
        } => {}

        App::Sign {
            algorithm,
            private_key,
            message,
            hasher,
        } => {}

        App::Verify {
            algorithm,
            public_key,
            message,
            signature,
        } => {}

        App::Encrypt {
            algorithm,
            symmetric_key,
            associated_data,
            message,
        } => {}

        App::Decrypt {
            algorithm,
            symmetric_key,
            associated_data,
            message,
        } => {}
    }
}
