/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::array::TryFromSliceError;
use std::marker::PhantomData;

use ed25519_dalek::Signer;
use rsa::{pkcs1::DecodeRsaPrivateKey, Pkcs1v15Sign, RsaPrivateKey};
use sha2::digest::Digest;

use crate::{
    common::headers::{Writable, Writer},
    dkim::Canonicalization,
    Error, Result,
};

use super::{Algorithm, HashContext, HashImpl, HashOutput, Sha1, Sha256, SigningKey, VerifyingKey};

#[derive(Debug)]
pub struct RsaKey<T> {
    inner: RsaPrivateKey,
    padding: PhantomData<T>,
}

impl<T: HashImpl> RsaKey<T> {
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

    fn sign(&self, input: impl Writable) -> Result<Vec<u8>> {
        let hash = self.hash(input);
        self.inner
            .sign(
                Pkcs1v15Sign::new::<<Self::Hasher as HashImpl>::Context>(),
                hash.as_ref(),
            )
            .map_err(|err| Error::CryptoError(err.to_string()))
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::RsaSha1
    }
}

impl SigningKey for RsaKey<Sha256> {
    type Hasher = Sha256;

    fn sign(&self, input: impl Writable) -> Result<Vec<u8>> {
        let hash = self.hash(input);
        self.inner
            .sign(
                Pkcs1v15Sign::new::<<Self::Hasher as HashImpl>::Context>(),
                hash.as_ref(),
            )
            .map_err(|err| Error::CryptoError(err.to_string()))
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::RsaSha256
    }
}

pub struct Ed25519Key {
    inner: ed25519_dalek::SigningKey,
}

impl Ed25519Key {
    /// Creates an Ed25519 private key
    pub fn from_bytes(private_key_bytes: &[u8]) -> crate::Result<Self> {
        Ok(Self {
            inner: ed25519_dalek::SigningKey::from_bytes(
                private_key_bytes
                    .try_into()
                    .map_err(|err: TryFromSliceError| Error::CryptoError(err.to_string()))?,
            ),
        })
    }
}

impl SigningKey for Ed25519Key {
    type Hasher = Sha256;

    fn sign(&self, input: impl Writable) -> Result<Vec<u8>> {
        let hash = self.hash(input);
        Ok(self.inner.sign(hash.as_ref()).to_bytes().to_vec())
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519Sha256
    }
}

pub(crate) struct RsaPublicKey {
    inner: rsa::RsaPublicKey,
}

impl RsaPublicKey {
    pub(crate) fn verifying_key_from_bytes(
        bytes: &[u8],
    ) -> Result<Box<dyn VerifyingKey + Send + Sync>> {
        Ok(Box::new(RsaPublicKey {
            inner: <rsa::RsaPublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_der(bytes)
                .or_else(|_| rsa::pkcs1::DecodeRsaPublicKey::from_pkcs1_der(bytes))
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        }))
    }
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
                let mut hasher = sha2::Sha256::new();
                canonicalization.canonicalize_headers(headers, &mut hasher);
                let hash = hasher.finalize();

                self.inner
                    .verify(
                        Pkcs1v15Sign::new::<sha2::Sha256>(),
                        hash.as_ref(),
                        signature,
                    )
                    .map_err(|_| Error::FailedVerification)
            }
            Algorithm::RsaSha1 => {
                let mut hasher = sha1::Sha1::new();
                canonicalization.canonicalize_headers(headers, &mut hasher);
                let hash = hasher.finalize();

                self.inner
                    .verify(Pkcs1v15Sign::new::<sha1::Sha1>(), hash.as_ref(), signature)
                    .map_err(|_| Error::FailedVerification)
            }
            Algorithm::Ed25519Sha256 => Err(Error::IncompatibleAlgorithms),
        }
    }
}

pub(crate) struct Ed25519PublicKey {
    inner: ed25519_dalek::VerifyingKey,
}

impl Ed25519PublicKey {
    pub(crate) fn verifying_key_from_bytes(
        bytes: &[u8],
    ) -> Result<Box<dyn VerifyingKey + Send + Sync>> {
        Ok(Box::new(Ed25519PublicKey {
            inner: ed25519_dalek::VerifyingKey::from_bytes(
                bytes
                    .try_into()
                    .map_err(|err: TryFromSliceError| Error::CryptoError(err.to_string()))?,
            )
            .map_err(|err| Error::CryptoError(err.to_string()))?,
        }))
    }
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

        let mut hasher = sha2::Sha256::new();
        canonicalization.canonicalize_headers(headers, &mut hasher);
        let hash = hasher.finalize();

        self.inner
            .verify_strict(
                hash.as_ref(),
                &ed25519_dalek::Signature::from_bytes(
                    signature
                        .try_into()
                        .map_err(|err: TryFromSliceError| Error::CryptoError(err.to_string()))?,
                ),
            )
            .map_err(|_| Error::FailedVerification)
    }
}

impl Writer for sha1::Sha1 {
    fn write(&mut self, buf: &[u8]) {
        self.update(buf);
    }
}

impl Writer for sha2::Sha256 {
    fn write(&mut self, buf: &[u8]) {
        self.update(buf);
    }
}

impl HashImpl for Sha1 {
    type Context = sha1::Sha1;

    fn hasher() -> Self::Context {
        <Self::Context as Digest>::new()
    }
}

impl HashImpl for Sha256 {
    type Context = sha2::Sha256;

    fn hasher() -> Self::Context {
        <Self::Context as Digest>::new()
    }
}

impl HashContext for sha1::Sha1 {
    fn complete(self) -> HashOutput {
        HashOutput::RustCryptoSha1(self.finalize())
    }
}

impl HashContext for sha2::Sha256 {
    fn complete(self) -> HashOutput {
        HashOutput::RustCryptoSha256(self.finalize())
    }
}
