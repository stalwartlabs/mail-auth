/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Signing keys, verification keys and hash functions.
//!
//! Implements the signature algorithms used by DKIM (RFC 6376 Section 3.3),
//! ARC (RFC 8617) and DKIM2 (draft-ietf-dkim-dkim2-spec): `rsa-sha256`,
//! `rsa-sha1` (verification only; deprecated by RFC 8301) and `ed25519-sha256` (RFC 8463,
//! built on the EdDSA scheme of RFC 8032).
//!
//! The backend is chosen at compile time: `aws-lc-rs` or `ring`, or
//! `rust-crypto` (the pure Rust `rsa`, `ed25519-dalek`, `sha1` and `sha2`
//! crates) when neither is enabled. [`RsaKey`] and [`Ed25519Key`] have the
//! same interface on every backend.

use super::headers::{Writable, Writer};
use crate::{Result, dkim::Canonicalization};

/// A failure reported by the cryptography layer, carried by
/// [`Error::Crypto`](crate::Error::Crypto).
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CryptoError {
    /// The backend rejected an operation (malformed or unsupported key,
    /// signing failure). The string holds the backend's error message.
    Library(String),
    /// The signature does not match the signed data.
    FailedVerification,
    /// The signature algorithm does not match the public key type (for
    /// example, an `ed25519-sha256` signature checked against an RSA key
    /// published with `k=rsa`).
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

#[cfg(all(
    feature = "rust-crypto",
    not(any(feature = "ring", feature = "aws-lc-rs"))
))]
mod rust_crypto;
#[cfg(all(
    feature = "rust-crypto",
    not(any(feature = "ring", feature = "aws-lc-rs"))
))]
pub use rust_crypto::{Ed25519Key, RsaKey};
#[cfg(all(
    feature = "rust-crypto",
    not(any(feature = "ring", feature = "aws-lc-rs"))
))]
pub(crate) use rust_crypto::{Ed25519PublicKey, RsaPublicKey};

/// A private key that can produce DKIM, ARC and DKIM2 signatures.
///
/// Implemented by [`RsaKey<Sha256>`](RsaKey), [`Ed25519Key`] and [`DkimKey`].
/// Signers such as [`DkimSigner`](crate::dkim::DkimSigner) are generic over
/// this trait.
pub trait SigningKey {
    /// The hash function used by the signature algorithm.
    type Hasher: HashImpl;

    /// Signs the bytes written by `input` and returns the raw signature.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`](crate::Error::Crypto) with
    /// [`CryptoError::Library`] if the backend fails to sign.
    fn sign(&self, input: impl Writable) -> Result<Vec<u8>>;

    /// Hashes the bytes written by `data` with [`Self::Hasher`].
    fn hash(&self, data: impl Writable) -> HashOutput {
        let mut hasher = <Self::Hasher as HashImpl>::hasher();
        data.write(&mut hasher);
        hasher.complete()
    }

    /// Returns the signature algorithm written to the `a=` tag.
    fn algorithm(&self) -> Algorithm;
}

/// A concrete DKIM signing key, holding either an RSA or an Ed25519 key.
///
/// Lets a single signer type hold keys of either algorithm.
/// [`Dkim2Signer`](crate::dkim2::Dkim2Signer) requires it. Both key types
/// convert into it with `From`.
#[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rust-crypto"))]
pub enum DkimKey {
    /// An RSA key producing `rsa-sha256` signatures.
    Rsa(RsaKey<Sha256>),
    /// An Ed25519 key producing `ed25519-sha256` signatures (RFC 8463).
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

/// A public key that can verify signatures, parsed from the `p=` tag of a
/// DKIM key record (RFC 6376 Section 3.6.1).
pub trait VerifyingKey {
    /// Canonicalizes `headers` with `canonicalization` and verifies
    /// `signature` over the result, using `algorithm`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`](crate::Error::Crypto) with
    /// [`CryptoError::IncompatibleAlgorithms`] if `algorithm` does not match
    /// the key type, or with [`CryptoError::FailedVerification`] or
    /// [`CryptoError::Library`] if the signature does not verify.
    fn verify<'a>(
        &self,
        headers: &mut dyn Iterator<Item = (&'a [u8], &'a [u8])>,
        signature: &[u8],
        canonicalization: Canonicalization,
        algorithm: Algorithm,
    ) -> Result<()>;

    /// Verifies `signature` over `input`, an already canonicalized byte
    /// string, using `algorithm`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`](crate::Error::Crypto) with
    /// [`CryptoError::IncompatibleAlgorithms`] if `algorithm` does not match
    /// the key type, or with [`CryptoError::FailedVerification`] if the
    /// signature does not verify.
    fn verify_bytes(&self, input: &[u8], signature: &[u8], algorithm: Algorithm) -> Result<()>;

    /// Size in bits of the public key (the RSA modulus length). The default
    /// implementation returns `usize::MAX`, which Ed25519 keys keep, so that
    /// minimum key size checks apply to RSA keys only.
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

/// An incremental hash computation. Data is fed through [`Writer`].
pub trait HashContext: Writer + Sized {
    /// Finishes the computation and returns the digest.
    fn complete(self) -> HashOutput;
}

/// A hash function, selected at the type level.
pub trait HashImpl {
    /// The incremental hashing state for this function.
    type Context: HashContext;

    /// Starts a new hash computation.
    fn hasher() -> Self::Context;
}

/// The SHA-1 hash function, used by the `rsa-sha1` algorithm (RFC 6376
/// Section 3.3.1). Deprecated by RFC 8301; kept for verifying legacy
/// signatures.
#[derive(Clone, Copy)]
pub struct Sha1;

/// The SHA-256 hash function, used by `rsa-sha256` and `ed25519-sha256`.
#[derive(Clone, Copy)]
pub struct Sha256;

/// A hash algorithm selected at run time, as named in DKIM tags (the hash
/// part of `a=`, and the `h=` tag of DKIM key records).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum HashAlgorithm {
    /// SHA-1 (`sha1`).
    Sha1 = R_HASH_SHA1,
    /// SHA-256 (`sha256`).
    Sha256 = R_HASH_SHA256,
}

#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs as crypto_backend;
#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
use ring as crypto_backend;

#[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
impl HashAlgorithm {
    /// Hashes the bytes written by `data` with this algorithm.
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

#[cfg(all(
    feature = "rust-crypto",
    not(any(feature = "ring", feature = "aws-lc-rs"))
))]
impl HashAlgorithm {
    /// Hashes the bytes written by `data` with this algorithm.
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
    /// Parses a hash algorithm name (`sha1` or `sha256`), ignoring ASCII
    /// case. Returns `None` for any other name.
    pub fn parse(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("sha256") {
            Some(HashAlgorithm::Sha256)
        } else if name.eq_ignore_ascii_case("sha1") {
            Some(HashAlgorithm::Sha1)
        } else {
            None
        }
    }

    /// Returns the lowercase algorithm name (`sha1` or `sha256`).
    pub fn name(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha1 => "sha1",
            HashAlgorithm::Sha256 => "sha256",
        }
    }
}

/// A hash digest produced by the active cryptography backend.
///
/// Read the digest bytes through [`AsRef<[u8]>`](AsRef). Two outputs compare
/// equal when their bytes are equal, whatever the variant.
#[derive(Clone)]
#[non_exhaustive]
pub enum HashOutput {
    /// A digest computed by `aws-lc-rs` or `ring`.
    #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
    Digest(crypto_backend::digest::Digest),
    /// A SHA-1 digest computed by the `sha1` crate.
    #[cfg(all(
        feature = "rust-crypto",
        not(any(feature = "ring", feature = "aws-lc-rs"))
    ))]
    RustCryptoSha1(sha1::digest::Output<sha1::Sha1>),
    /// A SHA-256 digest computed by the `sha2` crate.
    #[cfg(all(
        feature = "rust-crypto",
        not(any(feature = "ring", feature = "aws-lc-rs"))
    ))]
    RustCryptoSha256(sha2::digest::Output<sha2::Sha256>),
}

impl AsRef<[u8]> for HashOutput {
    fn as_ref(&self) -> &[u8] {
        match self {
            #[cfg(any(feature = "ring", feature = "aws-lc-rs"))]
            Self::Digest(output) => output.as_ref(),
            #[cfg(all(
                feature = "rust-crypto",
                not(any(feature = "ring", feature = "aws-lc-rs"))
            ))]
            Self::RustCryptoSha1(output) => output.as_ref(),
            #[cfg(all(
                feature = "rust-crypto",
                not(any(feature = "ring", feature = "aws-lc-rs"))
            ))]
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

/// A signature algorithm, as named in the `a=` tag of DKIM (RFC 6376
/// Section 3.5), ARC and DKIM2 signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Algorithm {
    /// `rsa-sha1` (RFC 6376 Section 3.3.1). This crate only verifies it;
    /// RFC 8301 deprecates it for both signing and verifying.
    RsaSha1,
    /// `rsa-sha256` (RFC 6376 Section 3.3.2). This is the default.
    #[default]
    RsaSha256,
    /// `ed25519-sha256` (RFC 8463).
    Ed25519Sha256,
}

pub(crate) const R_HASH_SHA1: u64 = 0x01;
pub(crate) const R_HASH_SHA256: u64 = 0x02;

impl Algorithm {
    /// Parses an algorithm name (`rsa-sha1`, `rsa-sha256` or
    /// `ed25519-sha256`), ignoring ASCII case. Returns `None` for any other
    /// name.
    pub fn parse(name: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(name, Algorithm,
            b"rsa-sha1" => Algorithm::RsaSha1,
            b"rsa-sha256" => Algorithm::RsaSha256,
            b"ed25519-sha256" => Algorithm::Ed25519Sha256,
        )
        .copied()
    }

    /// Returns the lowercase algorithm name used in the `a=` tag.
    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::RsaSha1 => "rsa-sha1",
            Algorithm::RsaSha256 => "rsa-sha256",
            Algorithm::Ed25519Sha256 => "ed25519-sha256",
        }
    }
}
