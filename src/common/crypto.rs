use std::{io, marker::PhantomData};

use ed25519_dalek::Signer;
use rsa::{
    pkcs1::DecodeRsaPrivateKey,
    pkcs8::{AssociatedOid, ObjectIdentifier},
    PaddingScheme, RsaPrivateKey,
};
use sha1::{digest::Output, Sha1};
use sha2::{digest::Digest, Sha256};

use crate::{Error, Result};

pub trait SigningKey {
    type Hasher: Digest + AssociatedOid + io::Write;

    fn sign(&self, data: &Output<Self::Hasher>) -> Result<Vec<u8>>;

    fn hasher(&self) -> Self::Hasher {
        Self::Hasher::new()
    }

    fn algorithm(&self) -> Algorithm;
}

#[derive(Debug)]
pub struct RsaKey<T> {
    inner: RsaPrivateKey,
    padding: PhantomData<T>,
}

impl<T: Digest + AssociatedOid + io::Write> RsaKey<T> {
    /// Creates a new RSA private key from a PKCS1 PEM string.
    pub fn from_rsa_pkcs1_pem(private_key_pem: &str) -> Result<Self> {
        let inner = RsaPrivateKey::from_pkcs1_pem(private_key_pem)
            .map_err(|err| Error::CryptoError(err.to_string()))?;

        Ok(RsaKey {
            inner,
            padding: PhantomData,
        })
    }

    /// Creates a new RSA private key from a PKCS1 binary slice.
    pub fn from_rsa_pkcs1_der(private_key_bytes: &[u8]) -> Result<Self> {
        let inner = RsaPrivateKey::from_pkcs1_der(private_key_bytes)
            .map_err(|err| Error::CryptoError(err.to_string()))?;

        Ok(RsaKey {
            inner,
            padding: PhantomData,
        })
    }
}

impl SigningKey for RsaKey<Sha1> {
    type Hasher = Sha1;

    fn sign(&self, data: &Output<Self::Hasher>) -> Result<Vec<u8>> {
        self.inner
            .sign(PaddingScheme::new_pkcs1v15_sign::<Self::Hasher>(), data)
            .map_err(|err| Error::CryptoError(err.to_string()))
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::RsaSha1
    }
}

impl SigningKey for RsaKey<Sha256> {
    type Hasher = Sha256;

    fn sign(&self, data: &Output<Self::Hasher>) -> Result<Vec<u8>> {
        self.inner
            .sign(PaddingScheme::new_pkcs1v15_sign::<Self::Hasher>(), data)
            .map_err(|err| Error::CryptoError(err.to_string()))
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::RsaSha256
    }
}

pub struct Ed25519Key {
    inner: ed25519_dalek::Keypair,
}

impl Ed25519Key {
    /// Creates an Ed25519 private key
    pub fn from_bytes(public_key_bytes: &[u8], private_key_bytes: &[u8]) -> crate::Result<Self> {
        Ok(Self {
            inner: ed25519_dalek::Keypair {
                public: ed25519_dalek::PublicKey::from_bytes(public_key_bytes)
                    .map_err(|err| Error::CryptoError(err.to_string()))?,
                secret: ed25519_dalek::SecretKey::from_bytes(private_key_bytes)
                    .map_err(|err| Error::CryptoError(err.to_string()))?,
            },
        })
    }
}

impl SigningKey for Ed25519Key {
    type Hasher = Sha256;

    fn sign(&self, data: &Output<Self::Hasher>) -> Result<Vec<u8>> {
        Ok(self.inner.sign(data.as_ref()).to_bytes().to_vec())
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519Sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum HashAlgorithm {
    Sha1 = R_HASH_SHA1,
    Sha256 = R_HASH_SHA256,
}

impl TryFrom<&ObjectIdentifier> for HashAlgorithm {
    type Error = Error;

    fn try_from(oid: &ObjectIdentifier) -> Result<Self> {
        match oid {
            oid if oid == &Sha256::OID => Ok(HashAlgorithm::Sha256),
            oid if oid == &Sha1::OID => Ok(HashAlgorithm::Sha1),
            _ => Err(Error::CryptoError("Unsupported hash algorithm".to_string())),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    RsaSha1,
    RsaSha256,
    Ed25519Sha256,
}

pub(crate) const R_HASH_SHA1: u64 = 0x01;
pub(crate) const R_HASH_SHA256: u64 = 0x02;
