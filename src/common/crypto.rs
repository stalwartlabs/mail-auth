use std::{io, marker::PhantomData};

use ed25519_dalek::Signer;
use rsa::{
    pkcs1::DecodeRsaPrivateKey,
    pkcs8::{AssociatedOid, ObjectIdentifier},
    PaddingScheme, PublicKey as _, RsaPrivateKey,
};
use sha1::{digest::Output, Sha1};
use sha2::{digest::Digest, Sha256};

use crate::{dkim::Canonicalization, Error, Result};

use super::headers::Writer;

pub trait SigningKey {
    type Hasher: HashContext;

    fn sign(&self, data: HashOutput) -> Result<Vec<u8>>;

    fn hasher(&self) -> Self::Hasher {
        Self::Hasher::new()
    }

    fn algorithm(&self) -> Algorithm;
}

#[derive(Debug, Clone)]
pub struct RsaKey<T> {
    inner: RsaPrivateKey,
    padding: PhantomData<T>,
}

impl<T: Digest + AssociatedOid + io::Write> RsaKey<T> {
    /// Creates a new RSA private key from a PKCS1 PEM string.
    pub fn from_pkcs1_pem(private_key_pem: &str) -> Result<Self> {
        let inner = RsaPrivateKey::from_pkcs1_pem(private_key_pem)
            .map_err(|err| Error::CryptoError(err.to_string()))?;

        Ok(RsaKey {
            inner,
            padding: PhantomData,
        })
    }

    /// Creates a new RSA private key from a PKCS1 binary slice.
    pub fn from_pkcs1_der(private_key_bytes: &[u8]) -> Result<Self> {
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

    fn sign(&self, data: HashOutput) -> Result<Vec<u8>> {
        self.inner
            .sign(
                PaddingScheme::new_pkcs1v15_sign::<Self::Hasher>(),
                data.as_ref(),
            )
            .map_err(|err| Error::CryptoError(err.to_string()))
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::RsaSha1
    }
}

impl SigningKey for RsaKey<Sha256> {
    type Hasher = Sha256;

    fn sign(&self, data: HashOutput) -> Result<Vec<u8>> {
        self.inner
            .sign(
                PaddingScheme::new_pkcs1v15_sign::<Self::Hasher>(),
                data.as_ref(),
            )
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

    fn sign(&self, data: HashOutput) -> Result<Vec<u8>> {
        Ok(self.inner.sign(data.as_ref()).to_bytes().to_vec())
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519Sha256
    }
}

pub trait VerifyingKey {
    fn verify<'a>(
        &self,
        headers: &mut dyn Iterator<Item = (&'a [u8], &'a [u8])>,
        signature: &[u8],
        canonicalication: Canonicalization,
        algorithm: Algorithm,
    ) -> Result<()>;
}

pub(crate) enum VerifyingKeyType {
    Rsa,
    Ed25519,
}

impl VerifyingKeyType {
    pub(crate) fn verifying_key(
        &self,
        bytes: &[u8],
    ) -> Result<Box<dyn VerifyingKey + Sync + Send>> {
        Ok(match self {
            Self::Rsa => {
                let inner =
                    <rsa::RsaPublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_der(bytes)
                        .or_else(|_| rsa::pkcs1::DecodeRsaPublicKey::from_pkcs1_der(bytes))
                        .map_err(|err| Error::CryptoError(err.to_string()))?;

                Box::new(RsaPublicKey { inner }) as Box<dyn VerifyingKey + Sync + Send>
            }
            Self::Ed25519 => Box::new(Ed25519PublicKey {
                inner: ed25519_dalek::PublicKey::from_bytes(bytes)
                    .map_err(|err| Error::CryptoError(err.to_string()))?,
            }),
        })
    }
}

pub(crate) struct RsaPublicKey {
    inner: rsa::RsaPublicKey,
}

impl VerifyingKey for RsaPublicKey {
    fn verify<'a>(
        &self,
        headers: &mut dyn Iterator<Item = (&'a [u8], &'a [u8])>,
        signature: &[u8],
        canonicalization: Canonicalization,
        algorithm: Algorithm,
    ) -> Result<()> {
        match algorithm {
            Algorithm::RsaSha256 => {
                let hash = canonicalization.hash_headers::<Sha256>(headers);
                self.inner
                    .verify(
                        PaddingScheme::new_pkcs1v15_sign::<Sha256>(),
                        hash.as_ref(),
                        signature,
                    )
                    .map_err(|_| Error::FailedVerification)
            }
            Algorithm::RsaSha1 => {
                let hash = canonicalization.hash_headers::<Sha1>(headers);
                self.inner
                    .verify(
                        PaddingScheme::new_pkcs1v15_sign::<Sha1>(),
                        hash.as_ref(),
                        signature,
                    )
                    .map_err(|_| Error::FailedVerification)
            }
            Algorithm::Ed25519Sha256 => Err(Error::IncompatibleAlgorithms),
        }
    }
}

pub(crate) struct Ed25519PublicKey {
    inner: ed25519_dalek::PublicKey,
}

impl VerifyingKey for Ed25519PublicKey {
    fn verify<'a>(
        &self,
        headers: &mut dyn Iterator<Item = (&'a [u8], &'a [u8])>,
        signature: &[u8],
        canonicalization: Canonicalization,
        algorithm: Algorithm,
    ) -> Result<()> {
        if !matches!(algorithm, Algorithm::Ed25519Sha256) {
            return Err(Error::IncompatibleAlgorithms);
        }

        let hash = canonicalization.hash_headers::<Sha256>(headers);
        self.inner
            .verify_strict(
                hash.as_ref(),
                &ed25519_dalek::Signature::from_bytes(signature)
                    .map_err(|err| Error::CryptoError(err.to_string()))?,
            )
            .map_err(|_| Error::FailedVerification)
    }
}

impl Writer for Sha1 {
    fn write(&mut self, buf: &[u8]) {
        self.update(buf);
    }
}

impl Writer for Sha256 {
    fn write(&mut self, buf: &[u8]) {
        self.update(buf);
    }
}

pub trait HashContext: Writer + Sized {
    fn new() -> Self;
    fn finish(self) -> HashOutput;
}

impl HashContext for Sha1 {
    fn new() -> Self {
        <Self as Digest>::new()
    }

    fn finish(self) -> HashOutput {
        HashOutput::Sha1(self.finalize())
    }
}

impl HashContext for Sha256 {
    fn new() -> Self {
        <Self as Digest>::new()
    }

    fn finish(self) -> HashOutput {
        HashOutput::Sha256(self.finalize())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum HashAlgorithm {
    Sha1 = R_HASH_SHA1,
    Sha256 = R_HASH_SHA256,
}

impl HashAlgorithm {
    pub fn hash(&self, data: &[u8]) -> HashOutput {
        match self {
            Self::Sha1 => HashOutput::Sha1(Sha1::digest(data)),
            Self::Sha256 => HashOutput::Sha256(Sha256::digest(data)),
        }
    }
}

pub enum HashOutput {
    Sha1(Output<Sha1>),
    Sha256(Output<Sha256>),
}

impl AsRef<[u8]> for HashOutput {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Sha1(output) => output.as_ref(),
            Self::Sha256(output) => output.as_ref(),
        }
    }
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
