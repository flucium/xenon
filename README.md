# XENON
XENON is a hybrid cryptographic library and program.

In addition to encryption and digital signature of files, e-mails, etc., it provides a key database.

The goal is to develop a program that can easily perform digital signature and encryption. And that is XENON.

OpenPGP/GPG is large in scale; XENON is a small project and program compared to them. 

I want an encryption program that is smaller in scale than OpenPGP/GPG.

## Build
cargo and build.sh.

build.sh generates a compressed file for distribution after building.

### cargo
```bash
# debug
$ cargo build

# release
$ cargo build --release
```

### build.sh
```bash
# debug
$ zsh ./build.sh

# release
$ zsh ./build.sh release

# extract
# $ tar -zxvf *.tar.gz && rm *.tar.gz
```

## Usage
*(As of December 17, 2023)*
The XENON CLI app can be used on Unix-like systems. Can be called from Bash or ZSH.

The most basic usage example.

### Key generation
```bash
# keygen ed25519
...

# keygen x25519
...

# through pipe
...
```

### Encrypt/Decrypt
```bash
# encryption
...

# decryption
...

# through pipe
...
```

### Sign/Verify
```bash
# sign
...

# verify
...

# through pipe
...
```

### Keyring
```bash
# building
...

# add keyring (local)
...

# add keyring (remote host)
...

# import
...

# export
...
```

# Key revocation
```bash
...
```

# ToDo
[ToDo](./todo.md)


# Dependencies
- OpenSSL 3.0.12

# Sponsors
- [Kemo0513](https://github.com/Kemo0513)