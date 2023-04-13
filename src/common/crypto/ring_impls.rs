use std::marker::PhantomData;

use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{
    Ed25519KeyPair, RsaKeyPair, UnparsedPublicKey, ED25519,
    RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY, RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_SHA256,
};

use crate::{
    common::headers::{Writable, Writer},
    dkim::Canonicalization,
    Error, Result,
};

use super::{Algorithm, HashContext, HashImpl, HashOutput, Sha1, Sha256, SigningKey, VerifyingKey};

#[derive(Debug)]
pub struct RsaKey<T> {
    inner: RsaKeyPair,
    rng: SystemRandom,
    padding: PhantomData<T>,
}

impl<T: HashImpl> RsaKey<T> {
    #[cfg(feature = "rustls-pemfile")]
    pub fn from_pkcs8_pem(pkcs8_pem: &str) -> Result<Self> {
        let item = rustls_pemfile::read_one(&mut pkcs8_pem.as_bytes())
            .map_err(|err| Error::CryptoError(err.to_string()))?;

        let pkcs8_der = match item {
            Some(rustls_pemfile::Item::PKCS8Key(key)) => key,
            _ => return Err(Error::CryptoError("No PKCS8 key found in PEM".to_string())),
        };

        Self::from_pkcs8_der(&pkcs8_der)
    }

    /// Creates a new RSA private key from PKCS8 DER-encoded bytes.
    pub fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: RsaKeyPair::from_pkcs8(pkcs8_der)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
            rng: SystemRandom::new(),
            padding: PhantomData,
        })
    }

    #[cfg(feature = "rustls-pemfile")]
    pub fn from_rsa_pem(rsa_pem: &str) -> Result<Self> {
        let item = rustls_pemfile::read_one(&mut rsa_pem.as_bytes())
            .map_err(|err| Error::CryptoError(err.to_string()))?;

        let rsa_der = match item {
            Some(rustls_pemfile::Item::RSAKey(key)) => key,
            _ => return Err(Error::CryptoError("No RSA key found in PEM".to_string())),
        };

        Self::from_der(&rsa_der)
    }

    /// Creates a new RSA private key from a PKCS1 binary slice.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: RsaKeyPair::from_der(der).map_err(|err| Error::CryptoError(err.to_string()))?,
            rng: SystemRandom::new(),
            padding: PhantomData,
        })
    }
}

impl SigningKey for RsaKey<Sha256> {
    type Hasher = Sha256;

    fn sign(&self, input: impl Writable) -> Result<Vec<u8>> {
        let mut data = Vec::with_capacity(256);
        input.write(&mut data);

        let mut signature = vec![0; self.inner.public_modulus_len()];
        self.inner
            .sign(&RSA_PKCS1_SHA256, &self.rng, &data, &mut signature)
            .map_err(|err| Error::CryptoError(err.to_string()))?;
        Ok(signature)
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::RsaSha256
    }
}

pub struct Ed25519Key {
    inner: Ed25519KeyPair,
}

impl Ed25519Key {
    pub fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: Ed25519KeyPair::from_pkcs8(pkcs8_der)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        })
    }

    pub fn from_pkcs8_maybe_unchecked_der(pkcs8_der: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8_der)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        })
    }

    pub fn from_seed_and_public_key(seed: &[u8], public_key: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: Ed25519KeyPair::from_seed_and_public_key(seed, public_key)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        })
    }
}

impl SigningKey for Ed25519Key {
    type Hasher = Sha256;

    fn sign(&self, input: impl Writable) -> Result<Vec<u8>> {
        let mut data = Sha256::hasher();
        input.write(&mut data);
        Ok(self.inner.sign(data.complete().as_ref()).as_ref().to_vec())
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519Sha256
    }
}

pub(crate) struct RsaPublicKey {
    sha1: UnparsedPublicKey<Vec<u8>>,
    sha2: UnparsedPublicKey<Vec<u8>>,
}

impl RsaPublicKey {
    pub(crate) fn verifying_key_from_bytes(
        bytes: &[u8],
    ) -> Result<Box<dyn VerifyingKey + Send + Sync>> {
        let key = try_strip_rsa_prefix(bytes);
        Ok(Box::new(Self {
            sha1: UnparsedPublicKey::new(
                &RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
                key.to_vec(),
            ),
            sha2: UnparsedPublicKey::new(
                &RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                key.to_vec(),
            ),
        }))
    }
}

/// Try to strip an ASN.1 DER-encoded RSA public key prefix
///
/// Returns the original slice if the prefix is not found.
fn try_strip_rsa_prefix(bytes: &[u8]) -> &[u8] {
    let orig = bytes;

    if !bytes
        .first()
        .map(|val| *val == DER_SEQUENCE_TAG)
        .unwrap_or_default()
    {
        return orig;
    };

    let (_, bytes) = match bytes.get(1..) {
        Some(val) => decode_multi_byte_len(val),
        None => return orig,
    };

    if !bytes
        .first()
        .map(|val| *val == DER_SEQUENCE_TAG)
        .unwrap_or_default()
    {
        return orig;
    };

    let (byte_len, bytes) = match bytes.get(1..) {
        Some(val) => decode_multi_byte_len(val),
        None => return orig,
    };

    if bytes.len() <= 13 || bytes[0] != DER_OBJECT_ID_TAG || byte_len != 13 {
        return orig;
    }

    let bytes = &bytes[13..]; // skip the RSA encryption OID

    if !bytes
        .first()
        .map(|val| *val == DER_BIT_STRING_TAG)
        .unwrap_or_default()
    {
        return orig;
    };

    let (_, bytes) = decode_multi_byte_len(&bytes[1..]);
    bytes.get(1..).unwrap_or(orig) // skip the unused bits byte
}

fn decode_multi_byte_len(bytes: &[u8]) -> (usize, &[u8]) {
    let first_byte = match bytes.first() {
        Some(val) => val,
        None => return (0, bytes),
    };

    if first_byte & 0x80 == 0 {
        if let Some(val) = bytes.get(1..) {
            return (*first_byte as usize, val);
        }
        return (0, bytes);
    }

    let len_len = (first_byte & 0x7f) as usize;
    let mut len = 0;
    for i in 0..len_len {
        if let Some(val) = bytes.get(1 + i) {
            len = (len << 8) | *val as usize;
        } else {
            return (0, bytes);
        }
    }

    if let Some(val) = bytes.get(len_len + 1..) {
        return (len, val);
    }

    (0, bytes)
}

const DER_OBJECT_ID_TAG: u8 = 0x06;
const DER_BIT_STRING_TAG: u8 = 0x03;
const DER_SEQUENCE_TAG: u8 = 0x30;

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

        match algorithm {
            Algorithm::RsaSha256 => self
                .sha2
                .verify(&data, signature)
                .map_err(|_| Error::FailedVerification),
            Algorithm::RsaSha1 => self
                .sha1
                .verify(&data, signature)
                .map_err(|_| Error::FailedVerification),
            Algorithm::Ed25519Sha256 => Err(Error::IncompatibleAlgorithms),
        }
    }
}

pub(crate) struct Ed25519PublicKey {
    inner: UnparsedPublicKey<Vec<u8>>,
}

impl Ed25519PublicKey {
    pub(crate) fn verifying_key_from_bytes(
        bytes: &[u8],
    ) -> Result<Box<dyn VerifyingKey + Send + Sync>> {
        Ok(Box::new(Self {
            inner: UnparsedPublicKey::new(&ED25519, bytes.to_vec()),
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

        let mut hasher = Sha256::hasher();
        canonicalization.canonicalize_headers(headers, &mut hasher);
        self.inner
            .verify(hasher.complete().as_ref(), signature)
            .map_err(|err| Error::CryptoError(err.to_string()))
    }
}

impl HashImpl for Sha1 {
    type Context = Context;

    fn hasher() -> Self::Context {
        Context::new(&SHA1_FOR_LEGACY_USE_ONLY)
    }
}

impl HashImpl for Sha256 {
    type Context = Context;

    fn hasher() -> Self::Context {
        Context::new(&SHA256)
    }
}

impl HashContext for Context {
    fn complete(self) -> HashOutput {
        HashOutput::Ring(self.finish())
    }
}

impl Writer for Context {
    fn write(&mut self, data: &[u8]) {
        self.update(data);
    }
}
