/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{
    Algorithm, CryptoError, HashContext, HashImpl, HashOutput, Sha1, Sha256, SigningKey,
    VerifyingKey,
};
use crate::{
    Error, Result,
    common::headers::{Writable, Writer},
    dkim::Canonicalization,
};
use ed25519_dalek::Signer;
use rsa::{
    BigUint, Pkcs1v15Sign, RsaPrivateKey,
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey, der::Decode},
    pkcs8::DecodePrivateKey,
    traits::PublicKeyParts,
};
use rustls_pki_types::PrivateKeyDer;
use sha2::Digest;
use std::array::TryFromSliceError;
use std::marker::PhantomData;

const SHA256_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
const SHA1_DIGEST_INFO_PREFIX: &[u8] = &[
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];

fn pkcs1v15_sha256() -> Pkcs1v15Sign {
    Pkcs1v15Sign {
        hash_len: Some(32),
        prefix: SHA256_DIGEST_INFO_PREFIX.into(),
    }
}

fn pkcs1v15_sha1() -> Pkcs1v15Sign {
    Pkcs1v15Sign {
        hash_len: Some(20),
        prefix: SHA1_DIGEST_INFO_PREFIX.into(),
    }
}

#[derive(Debug)]
pub struct RsaKey<T> {
    inner: RsaPrivateKey,
    padding: PhantomData<T>,
}

impl<T: HashImpl> RsaKey<T> {
    /// Creates a new RSA private key from various DER-encoded key formats.
    ///
    /// Only supports PKCS1 and PKCS8 formats -- will yield an error for other formats.
    pub fn from_key_der(key_der: PrivateKeyDer<'_>) -> Result<Self> {
        let inner = match key_der {
            PrivateKeyDer::Pkcs1(der) => RsaPrivateKey::from_pkcs1_der(der.secret_pkcs1_der())
                .map_err(|err| Error::Crypto(CryptoError::Library(err.to_string())))?,
            PrivateKeyDer::Pkcs8(der) => RsaPrivateKey::from_pkcs8_der(der.secret_pkcs8_der())
                .map_err(|err| Error::Crypto(CryptoError::Library(err.to_string())))?,
            _ => {
                return Err(Error::Crypto(CryptoError::Library(
                    "Unsupported RSA key format".to_string(),
                )));
            }
        };

        Ok(RsaKey {
            inner,
            padding: PhantomData,
        })
    }

    /// Returns the public key of the RSA key pair, encoded as a PKCS1 RSAPublicKey.
    pub fn public_key(&self) -> Vec<u8> {
        rsa::RsaPublicKey::from(&self.inner)
            .to_pkcs1_der()
            .map(|der| der.as_bytes().to_vec())
            .unwrap_or_default()
    }
}

impl SigningKey for RsaKey<Sha256> {
    type Hasher = Sha256;

    fn sign(&self, input: impl Writable) -> Result<Vec<u8>> {
        let hash = self.hash(input);
        self.inner
            .sign(pkcs1v15_sha256(), hash.as_ref())
            .map_err(|err| Error::Crypto(CryptoError::Library(err.to_string())))
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::RsaSha256
    }
}

pub struct Ed25519Key {
    inner: ed25519_dalek::SigningKey,
}

impl Ed25519Key {
    /// Generates a new Ed25519 key pair encoded in PKCS#8 DER format.
    pub fn generate_pkcs8() -> Result<Vec<u8>> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use rand::RngCore;

        let mut seed = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
        rand::rngs::OsRng.fill_bytes(&mut seed);

        Ok(ed25519_dalek::SigningKey::from_bytes(&seed)
            .to_pkcs8_der()
            .map_err(|err| Error::Crypto(CryptoError::Library(err.to_string())))?
            .as_bytes()
            .to_vec())
    }

    pub fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;

        Ok(Self {
            inner: ed25519_dalek::SigningKey::from_pkcs8_der(pkcs8_der)
                .map_err(|err| Error::Crypto(CryptoError::Library(err.to_string())))?,
        })
    }

    pub fn from_pkcs8_maybe_unchecked_der(pkcs8_der: &[u8]) -> Result<Self> {
        Self::from_pkcs8_der(pkcs8_der)
    }

    pub fn from_seed_and_public_key(seed: &[u8], public_key: &[u8]) -> Result<Self> {
        let inner = ed25519_dalek::SigningKey::from_bytes(seed.try_into().map_err(
            |err: TryFromSliceError| Error::Crypto(CryptoError::Library(err.to_string())),
        )?);

        if inner.verifying_key().as_bytes().as_slice() != public_key {
            return Err(Error::Crypto(CryptoError::Library(
                "Ed25519 public key does not match the provided seed".to_string(),
            )));
        }

        Ok(Self { inner })
    }

    /// Returns the public key of the Ed25519 key pair.
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.verifying_key().to_bytes().to_vec()
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

/// Largest RSA modulus accepted.
const RSA_MAX_MODULUS_BITS: usize = 8192;

impl RsaPublicKey {
    pub(crate) fn verifying_key_from_bytes(
        bytes: &[u8],
    ) -> Result<Box<dyn VerifyingKey + Send + Sync>> {
        let pkcs1 = match rsa::pkcs8::SubjectPublicKeyInfoRef::try_from(bytes) {
            Ok(spki) => {
                rsa::pkcs1::RsaPublicKey::from_der(spki.subject_public_key.as_bytes().ok_or_else(
                    || Error::Crypto(CryptoError::Library("Malformed RSA key".into())),
                )?)
            }
            Err(_) => rsa::pkcs1::RsaPublicKey::from_der(bytes),
        }
        .map_err(|err| Error::Crypto(CryptoError::Library(err.to_string())))?;

        let n = BigUint::from_bytes_be(pkcs1.modulus.as_bytes());
        let e = BigUint::from_bytes_be(pkcs1.public_exponent.as_bytes());

        Ok(Box::new(RsaPublicKey {
            inner: rsa::RsaPublicKey::new_with_max_size(n, e, RSA_MAX_MODULUS_BITS)
                .map_err(|err| Error::Crypto(CryptoError::Library(err.to_string())))?,
        }))
    }

    fn verify_digest(&self, data: &[u8], signature: &[u8], algorithm: Algorithm) -> Result<()> {
        match algorithm {
            Algorithm::RsaSha256 => self
                .inner
                .verify(
                    pkcs1v15_sha256(),
                    sha2::Sha256::digest(data).as_slice(),
                    signature,
                )
                .map_err(|_| Error::Crypto(CryptoError::FailedVerification)),
            Algorithm::RsaSha1 => self
                .inner
                .verify(
                    pkcs1v15_sha1(),
                    sha1::Sha1::digest(data).as_slice(),
                    signature,
                )
                .map_err(|_| Error::Crypto(CryptoError::FailedVerification)),
            Algorithm::Ed25519Sha256 => Err(Error::Crypto(CryptoError::IncompatibleAlgorithms)),
        }
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
        let mut data = Vec::with_capacity(256);
        canonicalization.canonicalize_headers(headers, &mut data);
        self.verify_digest(&data, signature, algorithm)
    }

    fn verify_bytes(&self, input: &[u8], signature: &[u8], algorithm: Algorithm) -> Result<()> {
        self.verify_digest(input, signature, algorithm)
    }

    fn public_key_bits(&self) -> usize {
        self.inner.n().bits()
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
            inner: ed25519_dalek::VerifyingKey::from_bytes(bytes.try_into().map_err(
                |err: TryFromSliceError| Error::Crypto(CryptoError::Library(err.to_string())),
            )?)
            .map_err(|err| Error::Crypto(CryptoError::Library(err.to_string())))?,
        }))
    }

    fn verify_digest(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        let signature = ed25519_dalek::Signature::from_bytes(signature.try_into().map_err(
            |err: TryFromSliceError| Error::Crypto(CryptoError::Library(err.to_string())),
        )?);

        self.inner
            .verify_strict(sha2::Sha256::digest(data).as_slice(), &signature)
            .map_err(|_| Error::Crypto(CryptoError::FailedVerification))
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
            return Err(Error::Crypto(CryptoError::IncompatibleAlgorithms));
        }

        let mut data = Vec::with_capacity(256);
        canonicalization.canonicalize_headers(headers, &mut data);
        self.verify_digest(&data, signature)
    }

    fn verify_bytes(&self, input: &[u8], signature: &[u8], algorithm: Algorithm) -> Result<()> {
        if !matches!(algorithm, Algorithm::Ed25519Sha256) {
            return Err(Error::Crypto(CryptoError::IncompatibleAlgorithms));
        }

        self.verify_digest(input, signature)
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
