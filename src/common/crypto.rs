use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey};

use crate::Error;

#[derive(Debug)]
pub enum PrivateKey {
    Rsa(RsaPrivateKey),
    Ed25519(ed25519_dalek::Keypair),
}

impl PrivateKey {
    /// Creates a new RSA private key from a PKCS1 PEM string.
    pub fn from_rsa_pkcs1_pem(private_key_pem: &str) -> crate::Result<Self> {
        Ok(PrivateKey::Rsa(
            RsaPrivateKey::from_pkcs1_pem(private_key_pem)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        ))
    }

    /// Creates a new RSA private key from a PKCS1 binary slice.
    pub fn from_rsa_pkcs1_der(private_key_bytes: &[u8]) -> crate::Result<Self> {
        Ok(PrivateKey::Rsa(
            RsaPrivateKey::from_pkcs1_der(private_key_bytes)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        ))
    }

    /// Creates an Ed25519 private key
    pub fn from_ed25519(public_key_bytes: &[u8], private_key_bytes: &[u8]) -> crate::Result<Self> {
        Ok(PrivateKey::Ed25519(ed25519_dalek::Keypair {
            public: ed25519_dalek::PublicKey::from_bytes(public_key_bytes)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
            secret: ed25519_dalek::SecretKey::from_bytes(private_key_bytes)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum HashAlgorithm {
    Sha1 = R_HASH_SHA1,
    Sha256 = R_HASH_SHA256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    RsaSha1,
    RsaSha256,
    Ed25519Sha256,
}

pub(crate) const R_HASH_SHA1: u64 = 0x01;
pub(crate) const R_HASH_SHA256: u64 = 0x02;
