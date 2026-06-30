/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::headers::{Writable, Writer};
use crate::{Result, dkim::Canonicalization};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CryptoError {
    Library(String),
    FailedVerification,
    IncompatibleAlgorithms,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Library(err) => write!(f, "Cryptography layer error: {err}"),
            CryptoError::FailedVerification => write!(f, "Signature verification failed"),
            CryptoError::IncompatibleAlgorithms => write!(
                f,
                "Incompatible algorithms used in signature and DKIM DNS record"
            ),
        }
    }
}

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
mod ring_impls;
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
pub use ring_impls::{Ed25519Key, RsaKey};
#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
pub(crate) use ring_impls::{Ed25519PublicKey, RsaPublicKey};

#[cfg(all(feature = "rust-crypto", not(any(feature = "ring", feature = "aws-lc-rs"))))]
mod rust_crypto;
#[cfg(all(feature = "rust-crypto", not(any(feature = "ring", feature = "aws-lc-rs"))))]
pub use rust_crypto::{Ed25519Key, RsaKey};
#[cfg(all(feature = "rust-crypto", not(any(feature = "ring", feature = "aws-lc-rs"))))]
pub(crate) use rust_crypto::{Ed25519PublicKey, RsaPublicKey};

pub trait SigningKey {
    type Hasher: HashImpl;

    fn sign(&self, input: impl Writable) -> Result<Vec<u8>>;

    fn hash(&self, data: impl Writable) -> HashOutput {
        let mut hasher = <Self::Hasher as HashImpl>::hasher();
        data.write(&mut hasher);
        hasher.complete()
    }

    fn algorithm(&self) -> Algorithm;
}

/// A concrete DKIM signing key, holding either an RSA or an Ed25519 key.
#[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rust-crypto"))]
pub enum DkimKey {
    Rsa(RsaKey<Sha256>),
    Ed25519(Ed25519Key),
}

#[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rust-crypto"))]
impl SigningKey for DkimKey {
    type Hasher = Sha256;

    fn sign(&self, input: impl Writable) -> Result<Vec<u8>> {
        match self {
            DkimKey::Rsa(key) => key.sign(input),
            DkimKey::Ed25519(key) => key.sign(input),
        }
    }

    fn algorithm(&self) -> Algorithm {
        match self {
            DkimKey::Rsa(key) => key.algorithm(),
            DkimKey::Ed25519(key) => key.algorithm(),
        }
    }
}

#[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rust-crypto"))]
impl From<RsaKey<Sha256>> for DkimKey {
    fn from(key: RsaKey<Sha256>) -> Self {
        DkimKey::Rsa(key)
    }
}

#[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rust-crypto"))]
impl From<Ed25519Key> for DkimKey {
    fn from(key: Ed25519Key) -> Self {
        DkimKey::Ed25519(key)
    }
}

pub trait VerifyingKey {
    fn verify<'a>(
        &self,
        headers: &mut dyn Iterator<Item = (&'a [u8], &'a [u8])>,
        signature: &[u8],
        canonicalization: Canonicalization,
        algorithm: Algorithm,
    ) -> Result<()>;

    /// Verifies a signature computed over an already-canonicalized byte string
    fn verify_bytes(&self, input: &[u8], signature: &[u8], algorithm: Algorithm) -> Result<()>;

    /// Size in bits of the public key.
    fn public_key_bits(&self) -> usize {
        usize::MAX
    }
}

pub(crate) enum VerifyingKeyType {
    Rsa,
    Ed25519,
}

impl VerifyingKeyType {
    pub(crate) fn verifying_key(
        &self,
        bytes: &[u8],
    ) -> Result<Box<dyn VerifyingKey + Send + Sync>> {
        match self {
            #[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rust-crypto"))]
            Self::Rsa => RsaPublicKey::verifying_key_from_bytes(bytes),
            #[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rust-crypto"))]
            Self::Ed25519 => Ed25519PublicKey::verifying_key_from_bytes(bytes),
        }
    }
}

pub trait HashContext: Writer + Sized {
    fn complete(self) -> HashOutput;
}

pub trait HashImpl {
    type Context: HashContext;

    fn hasher() -> Self::Context;
}

#[derive(Clone, Copy)]
pub struct Sha1;

#[derive(Clone, Copy)]
pub struct Sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum HashAlgorithm {
    Sha1 = R_HASH_SHA1,
    Sha256 = R_HASH_SHA256,
}

#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs as crypto_backend;
#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
use ring as crypto_backend;

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
impl HashAlgorithm {
    pub fn hash(&self, data: impl Writable) -> HashOutput {
        match self {
            Self::Sha1 => {
                let mut hasher = crypto_backend::digest::Context::new(
                    &crypto_backend::digest::SHA1_FOR_LEGACY_USE_ONLY,
                );
                data.write(&mut hasher);
                HashOutput::Digest(hasher.finish())
            }
            Self::Sha256 => {
                let mut hasher =
                    crypto_backend::digest::Context::new(&crypto_backend::digest::SHA256);
                data.write(&mut hasher);
                HashOutput::Digest(hasher.finish())
            }
        }
    }
}

#[cfg(all(feature = "rust-crypto", not(any(feature = "ring", feature = "aws-lc-rs"))))]
impl HashAlgorithm {
    pub fn hash(&self, data: impl Writable) -> HashOutput {
        use sha2::Digest as _;
        match self {
            Self::Sha1 => {
                let mut hasher = sha1::Sha1::new();
                data.write(&mut hasher);
                HashOutput::RustCryptoSha1(hasher.finalize())
            }
            Self::Sha256 => {
                let mut hasher = sha2::Sha256::new();
                data.write(&mut hasher);
                HashOutput::RustCryptoSha256(hasher.finalize())
            }
        }
    }
}

impl HashAlgorithm {
    pub fn parse(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("sha256") {
            Some(HashAlgorithm::Sha256)
        } else if name.eq_ignore_ascii_case("sha1") {
            Some(HashAlgorithm::Sha1)
        } else {
            None
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha1 => "sha1",
            HashAlgorithm::Sha256 => "sha256",
        }
    }
}

#[derive(Clone)]
#[non_exhaustive]
pub enum HashOutput {
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    Digest(crypto_backend::digest::Digest),
    #[cfg(all(feature = "rust-crypto", not(any(feature = "ring", feature = "aws-lc-rs"))))]
    RustCryptoSha1(sha1::digest::Output<sha1::Sha1>),
    #[cfg(all(feature = "rust-crypto", not(any(feature = "ring", feature = "aws-lc-rs"))))]
    RustCryptoSha256(sha2::digest::Output<sha2::Sha256>),
}

impl AsRef<[u8]> for HashOutput {
    fn as_ref(&self) -> &[u8] {
        match self {
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            Self::Digest(output) => output.as_ref(),
            #[cfg(all(feature = "rust-crypto", not(any(feature = "ring", feature = "aws-lc-rs"))))]
            Self::RustCryptoSha1(output) => output.as_ref(),
            #[cfg(all(feature = "rust-crypto", not(any(feature = "ring", feature = "aws-lc-rs"))))]
            Self::RustCryptoSha256(output) => output.as_ref(),
        }
    }
}

impl PartialEq for HashOutput {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for HashOutput {}

impl std::fmt::Debug for HashOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_ref().fmt(f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Algorithm {
    RsaSha1,
    #[default]
    RsaSha256,
    Ed25519Sha256,
}

pub(crate) const R_HASH_SHA1: u64 = 0x01;
pub(crate) const R_HASH_SHA256: u64 = 0x02;

impl Algorithm {
    pub fn parse(name: &[u8]) -> Option<Self> {
        hashify::tiny_map_ignore_case!(name,
            b"rsa-sha1" => Algorithm::RsaSha1,
            b"rsa-sha256" => Algorithm::RsaSha256,
            b"ed25519-sha256" => Algorithm::Ed25519Sha256,
        )
    }

    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::RsaSha1 => "rsa-sha1",
            Algorithm::RsaSha256 => "rsa-sha256",
            Algorithm::Ed25519Sha256 => "ed25519-sha256",
        }
    }
}
