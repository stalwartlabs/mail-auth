/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Signing and verification keys backed by the pure Rust `rsa`, `ed25519-dalek`,
//! `ml-dsa`, `sha1` and `sha2` crates, used when `aws-lc-rs` is not enabled.

use super::{
    Algorithm, CryptoError, HashContext, HashImpl, HashOutput, Sha1, Sha256, Sha512, SigningKey,
    VerifyingKey,
    composite::{
        self, LABEL, PUBLIC_KEY_LEN, PrivateKey, PublicKey, SIGNATURE_LEN, Seed, library_error,
        message_representative,
    },
    rsa_private_key_heap_size,
};
use crate::{
    Error, Result,
    dkim::Canonicalization,
    headers::{Writable, Writer},
};
use ed25519_dalek::Signer;
use ml_dsa::{EncodedVerifyingKey, ExpandedSigningKey, MlDsa44};
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

/// An RSA private key for `rsa-sha256` signing (RFC 6376 Section 3.3.2).
///
/// `T` selects the hash function; only `RsaKey<Sha256>` implements
/// [`SigningKey`]. Load a key with [`from_key_der`](Self::from_key_der).
#[derive(Debug)]
pub struct RsaKey<T> {
    inner: RsaPrivateKey,
    padding: PhantomData<T>,
}

impl<T: HashImpl> RsaKey<T> {
    /// Loads an RSA private key from DER, in PKCS #1 (`RSAPrivateKey`) or
    /// PKCS #8 (`PrivateKeyInfo`) form. Parse PEM input first with
    /// [`PrivateKeyDer::from_pem_slice`](rustls_pki_types::pem::PemObject::from_pem_slice).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] with [`CryptoError::Library`] if the key is
    /// in another format (such as SEC1) or cannot be decoded.
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

    /// Returns the public key of the RSA key pair, encoded as a DER PKCS #1
    /// `RSAPublicKey`. Returns an empty vector if encoding fails.
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

    fn heap_size(&self) -> usize {
        rsa_private_key_heap_size(self.inner.size())
    }
}

/// An Ed25519 private key for `ed25519-sha256` signing (RFC 8463).
///
/// The signature is computed over the SHA-256 hash of the signed data, as
/// RFC 8463 Section 3 requires.
pub struct Ed25519Key {
    inner: ed25519_dalek::SigningKey,
}

impl Ed25519Key {
    /// Generates a new random Ed25519 key pair and returns it as PKCS #8 DER
    /// bytes, ready for [`from_pkcs8_der`](Self::from_pkcs8_der).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] with [`CryptoError::Library`] if key
    /// generation or encoding fails.
    pub fn generate_pkcs8() -> Result<Vec<u8>> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use rand::Rng;

        let mut seed = [0u8; ed25519_dalek::SECRET_KEY_LENGTH];
        rand::rng().fill_bytes(&mut seed);

        Ok(ed25519_dalek::SigningKey::from_bytes(&seed)
            .to_pkcs8_der()
            .map_err(|err| Error::Crypto(CryptoError::Library(err.to_string())))?
            .as_bytes()
            .to_vec())
    }

    /// Loads an Ed25519 key pair from PKCS #8 DER bytes (v1 or v2), checking
    /// that the embedded public key, when present, matches the private key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] with [`CryptoError::Library`] if the key
    /// cannot be decoded.
    pub fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;

        Ok(Self {
            inner: ed25519_dalek::SigningKey::from_pkcs8_der(pkcs8_der)
                .map_err(|err| Error::Crypto(CryptoError::Library(err.to_string())))?,
        })
    }

    /// Loads an Ed25519 key pair from PKCS #8 v1 or v2 DER bytes. On this
    /// backend it is identical to [`from_pkcs8_der`](Self::from_pkcs8_der).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] with [`CryptoError::Library`] if the key
    /// cannot be decoded.
    pub fn from_pkcs8_maybe_unchecked_der(pkcs8_der: &[u8]) -> Result<Self> {
        Self::from_pkcs8_der(pkcs8_der)
    }

    /// Builds an Ed25519 key pair from its 32-byte seed (private key) and
    /// 32-byte public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] with [`CryptoError::Library`] if either
    /// value has the wrong length or the public key does not match the seed.
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

    /// Returns the 32-byte raw Ed25519 public key, as published in the `p=`
    /// tag of a DKIM key record.
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
            Algorithm::Ed25519Sha256 | Algorithm::MlDsa44Ed25519Sha512 => {
                Err(Error::Crypto(CryptoError::IncompatibleAlgorithms))
            }
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

    fn heap_size(&self) -> usize {
        self.inner.n().bits().div_ceil(8) + self.inner.e().bits().div_ceil(8)
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

/// An ML-DSA-44/Ed25519 composite private key for `mldsa44-ed25519-sha512`
/// signing (DKIM2 only), the `id-MLDSA44-Ed25519-SHA512` algorithm of
/// draft-ietf-lamps-pq-composite-sigs.
///
/// The private key is the 32-byte ML-DSA-44 seed followed by the 32-byte
/// Ed25519 seed. ML-DSA-44 signatures are hedged (randomized), as FIPS 204
/// recommends, so signing the same input twice gives different signatures.
pub struct MlDsa44Ed25519Key {
    mldsa: ExpandedSigningKey<MlDsa44>,
    ed25519: ed25519_dalek::SigningKey,
}

impl MlDsa44Ed25519Key {
    /// Generates a new random key and returns it as PKCS #8 DER bytes (the
    /// `id-MLDSA44-Ed25519-SHA512` private key encoding), ready for
    /// [`from_pkcs8_der`](Self::from_pkcs8_der).
    ///
    /// # Errors
    ///
    /// Never fails on this backend; the signature matches the other backends.
    pub fn generate_pkcs8() -> Result<Vec<u8>> {
        use rand::Rng;

        let mut mldsa = Seed::default();
        let mut ed25519 = Seed::default();
        let mut rng = rand::rng();
        rng.fill_bytes(&mut mldsa);
        rng.fill_bytes(&mut ed25519);
        Ok(composite::pkcs8_der(&mldsa, &ed25519))
    }

    /// Loads a key from PKCS #8 DER bytes holding an
    /// `id-MLDSA44-Ed25519-SHA512` private key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] with [`CryptoError::Library`] if the key
    /// cannot be decoded.
    pub fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self> {
        Ok(Self::from_private_key(PrivateKey::from_pkcs8_der(
            pkcs8_der,
        )?))
    }

    /// Loads a key from its 64-byte raw form: the ML-DSA-44 seed followed by
    /// the Ed25519 seed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] with [`CryptoError::Library`] if the key has
    /// the wrong length.
    pub fn from_raw_private_key(raw: &[u8]) -> Result<Self> {
        Ok(Self::from_private_key(PrivateKey::from_raw(raw)?))
    }

    fn from_private_key(key: PrivateKey<'_>) -> Self {
        Self {
            mldsa: ExpandedSigningKey::from_seed(&(*key.mldsa).into()),
            ed25519: ed25519_dalek::SigningKey::from_bytes(key.ed25519),
        }
    }

    /// Returns the 1344-byte composite public key (the ML-DSA-44 public key
    /// followed by the Ed25519 public key), as published in the `p=` tag of
    /// a `k=mldsa44-ed25519-sha512` key record.
    ///
    /// # Errors
    ///
    /// Never fails on this backend; the signature matches the other backends.
    pub fn public_key(&self) -> Result<Vec<u8>> {
        let mut key = Vec::with_capacity(PUBLIC_KEY_LEN);
        key.extend_from_slice(&self.mldsa.verifying_key().encode());
        key.extend_from_slice(self.ed25519.verifying_key().as_bytes());
        Ok(key)
    }
}

impl SigningKey for MlDsa44Ed25519Key {
    type Hasher = Sha512;

    fn sign(&self, input: impl Writable) -> Result<Vec<u8>> {
        let representative = message_representative(input);
        let mldsa = self
            .mldsa
            .sign_randomized(&representative, LABEL, &mut rand::rng())
            .map_err(|_| library_error("ML-DSA-44 signing failed"))?;
        let mut signature = Vec::with_capacity(SIGNATURE_LEN);
        signature.extend_from_slice(&mldsa.encode());
        signature.extend_from_slice(&self.ed25519.sign(&representative).to_bytes());
        Ok(signature)
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::MlDsa44Ed25519Sha512
    }

    fn heap_size(&self) -> usize {
        MLDSA44_PRIVATE_KEY_HEAP_SIZE
    }
}

pub(crate) struct MlDsa44Ed25519PublicKey {
    mldsa: ml_dsa::VerifyingKey<MlDsa44>,
    ed25519: ed25519_dalek::VerifyingKey,
}

const MLDSA44_PRIVATE_KEY_HEAP_SIZE: usize = 20480;
const MLDSA44_PUBLIC_KEY_HEAP_SIZE: usize = 18432;

impl MlDsa44Ed25519PublicKey {
    pub(crate) fn verifying_key_from_bytes(
        bytes: &[u8],
    ) -> Result<Box<dyn VerifyingKey + Send + Sync>> {
        let key = PublicKey::from_bytes(bytes)?;
        Ok(Box::new(Self {
            mldsa: ml_dsa::VerifyingKey::decode(&EncodedVerifyingKey::<MlDsa44>::from(*key.mldsa)),
            ed25519: ed25519_dalek::VerifyingKey::from_bytes(key.ed25519)
                .map_err(|err| Error::Crypto(CryptoError::Library(err.to_string())))?,
        }))
    }
}

impl VerifyingKey for MlDsa44Ed25519PublicKey {
    fn verify<'a>(
        &self,
        _: &mut dyn Iterator<Item = (&'a [u8], &'a [u8])>,
        _: &[u8],
        _: Canonicalization,
        _: Algorithm,
    ) -> Result<()> {
        Err(Error::Crypto(CryptoError::IncompatibleAlgorithms))
    }

    fn verify_bytes(&self, input: &[u8], signature: &[u8], algorithm: Algorithm) -> Result<()> {
        if !matches!(algorithm, Algorithm::MlDsa44Ed25519Sha512) {
            return Err(Error::Crypto(CryptoError::IncompatibleAlgorithms));
        }
        let signature = composite::Signature::from_bytes(signature)
            .ok_or(Error::Crypto(CryptoError::FailedVerification))?;
        let mldsa = ml_dsa::Signature::<MlDsa44>::try_from(signature.mldsa.as_slice())
            .map_err(|_| Error::Crypto(CryptoError::FailedVerification))?;
        let representative = message_representative(input);
        if self
            .mldsa
            .verify_with_context(&representative, LABEL, &mldsa)
            && self
                .ed25519
                .verify_strict(
                    &representative,
                    &ed25519_dalek::Signature::from_bytes(signature.ed25519),
                )
                .is_ok()
        {
            Ok(())
        } else {
            Err(Error::Crypto(CryptoError::FailedVerification))
        }
    }

    fn heap_size(&self) -> usize {
        MLDSA44_PUBLIC_KEY_HEAP_SIZE
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

impl Writer for sha2::Sha512 {
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

impl HashImpl for Sha512 {
    type Context = sha2::Sha512;

    fn hasher() -> Self::Context {
        <Self::Context as Digest>::new()
    }
}

impl HashContext for sha2::Sha512 {
    fn complete(self) -> HashOutput {
        HashOutput::RustCryptoSha512(self.finalize())
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
