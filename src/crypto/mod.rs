/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Signing keys, verification keys and hash functions.
//!
//! Implements the signature algorithms used by DKIM (RFC 6376 Section 3.3),
//! ARC (RFC 8617) and DKIM2 (draft-ietf-dkim-dkim2-spec): `rsa-sha256`,
//! `rsa-sha1` (verification only; deprecated by RFC 8301), `ed25519-sha256`
//! (RFC 8463, built on the EdDSA scheme of RFC 8032) and, for DKIM2 only,
//! the post-quantum composite `mldsa44-ed25519-sha512`
//! (draft-ietf-lamps-pq-composite-sigs).
//!
//! The backend is chosen at compile time: `aws-lc-rs`, or `rust-crypto` (the
//! pure Rust `rsa`, `ed25519-dalek`, `ml-dsa`, `sha1` and `sha2` crates) when
//! `aws-lc-rs` is not enabled. [`RsaKey`], [`Ed25519Key`] and
//! [`MlDsa44Ed25519Key`] have the same interface on every backend.

use super::headers::{Writable, Writer};
use crate::{Result, dkim::Canonicalization};

#[cfg(any(feature = "aws-lc-rs", feature = "rust-crypto"))]
pub(crate) mod composite;

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

#[cfg(feature = "aws-lc-rs")]
mod aws_lc;
#[cfg(feature = "aws-lc-rs")]
mod aws_lc_mldsa;
#[cfg(feature = "aws-lc-rs")]
pub use aws_lc::{Ed25519Key, MlDsa44Ed25519Key, RsaKey};
#[cfg(feature = "aws-lc-rs")]
pub(crate) use aws_lc::{Ed25519PublicKey, MlDsa44Ed25519PublicKey, RsaPublicKey};

#[cfg(all(feature = "rust-crypto", not(feature = "aws-lc-rs")))]
mod rust_crypto;
#[cfg(all(feature = "rust-crypto", not(feature = "aws-lc-rs")))]
pub use rust_crypto::{Ed25519Key, MlDsa44Ed25519Key, RsaKey};
#[cfg(all(feature = "rust-crypto", not(feature = "aws-lc-rs")))]
pub(crate) use rust_crypto::{Ed25519PublicKey, MlDsa44Ed25519PublicKey, RsaPublicKey};

/// A private key that can produce DKIM, ARC and DKIM2 signatures.
///
/// Implemented by [`RsaKey<Sha256>`](RsaKey), [`Ed25519Key`],
/// [`MlDsa44Ed25519Key`] and [`DkimKey`]. Signers such as
/// [`DkimSigner`](crate::dkim::DkimSigner) are generic over this trait.
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

    /// Approximate heap memory owned by the key, in bytes, for weighing
    /// cache entries that hold it.
    fn heap_size(&self) -> usize {
        0
    }
}

/// A concrete DKIM signing key, holding an RSA, an Ed25519 or an
/// ML-DSA-44/Ed25519 composite key.
///
/// Lets a single signer type hold keys of any algorithm.
/// [`Dkim2Signer`](crate::dkim2::Dkim2Signer) requires it. Every key type
/// converts into it with `From`. The composite variant is defined for DKIM2
/// only; the DKIM and ARC signers reject it.
#[cfg(any(feature = "aws-lc-rs", feature = "rust-crypto"))]
pub enum DkimKey {
    /// An RSA key producing `rsa-sha256` signatures.
    Rsa(RsaKey<Sha256>),
    /// An Ed25519 key producing `ed25519-sha256` signatures (RFC 8463).
    Ed25519(Ed25519Key),
    /// An ML-DSA-44/Ed25519 composite key producing `mldsa44-ed25519-sha512`
    /// signatures (DKIM2 only).
    MlDsa44Ed25519(Box<MlDsa44Ed25519Key>),
}

#[cfg(any(feature = "aws-lc-rs", feature = "rust-crypto"))]
impl SigningKey for DkimKey {
    type Hasher = Sha256;

    fn sign(&self, input: impl Writable) -> Result<Vec<u8>> {
        match self {
            DkimKey::Rsa(key) => key.sign(input),
            DkimKey::Ed25519(key) => key.sign(input),
            DkimKey::MlDsa44Ed25519(key) => key.sign(input),
        }
    }

    fn algorithm(&self) -> Algorithm {
        match self {
            DkimKey::Rsa(key) => key.algorithm(),
            DkimKey::Ed25519(key) => key.algorithm(),
            DkimKey::MlDsa44Ed25519(key) => key.algorithm(),
        }
    }

    fn heap_size(&self) -> usize {
        match self {
            DkimKey::Rsa(key) => key.heap_size(),
            DkimKey::Ed25519(key) => key.heap_size(),
            DkimKey::MlDsa44Ed25519(key) => size_of::<MlDsa44Ed25519Key>() + key.heap_size(),
        }
    }
}

#[cfg(any(feature = "aws-lc-rs", feature = "rust-crypto"))]
pub(crate) const fn rsa_private_key_heap_size(modulus_len: usize) -> usize {
    const BASE: usize = 768;
    const PER_MODULUS_BYTE: usize = 8;
    BASE + PER_MODULUS_BYTE * modulus_len
}

#[cfg(any(feature = "aws-lc-rs", feature = "rust-crypto"))]
impl From<RsaKey<Sha256>> for DkimKey {
    fn from(key: RsaKey<Sha256>) -> Self {
        DkimKey::Rsa(key)
    }
}

#[cfg(any(feature = "aws-lc-rs", feature = "rust-crypto"))]
impl From<Ed25519Key> for DkimKey {
    fn from(key: Ed25519Key) -> Self {
        DkimKey::Ed25519(key)
    }
}

#[cfg(any(feature = "aws-lc-rs", feature = "rust-crypto"))]
impl From<MlDsa44Ed25519Key> for DkimKey {
    fn from(key: MlDsa44Ed25519Key) -> Self {
        DkimKey::MlDsa44Ed25519(Box::new(key))
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
    /// implementation returns `usize::MAX`, which Ed25519 and composite keys
    /// keep, so that minimum key size checks apply to RSA keys only.
    fn public_key_bits(&self) -> usize {
        usize::MAX
    }

    /// Approximate heap memory owned by the key, in bytes, for weighing
    /// cache entries that hold it.
    fn heap_size(&self) -> usize {
        0
    }
}

pub(crate) enum VerifyingKeyType {
    Rsa,
    Ed25519,
    MlDsa44Ed25519,
}

impl VerifyingKeyType {
    pub(crate) fn verifying_key(
        &self,
        bytes: &[u8],
    ) -> Result<Box<dyn VerifyingKey + Send + Sync>> {
        match self {
            #[cfg(any(feature = "aws-lc-rs", feature = "rust-crypto"))]
            Self::Rsa => RsaPublicKey::verifying_key_from_bytes(bytes),
            #[cfg(any(feature = "aws-lc-rs", feature = "rust-crypto"))]
            Self::Ed25519 => Ed25519PublicKey::verifying_key_from_bytes(bytes),
            #[cfg(any(feature = "aws-lc-rs", feature = "rust-crypto"))]
            Self::MlDsa44Ed25519 => MlDsa44Ed25519PublicKey::verifying_key_from_bytes(bytes),
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

    /// Hashes the bytes written by `data`.
    fn digest(data: impl Writable) -> HashOutput {
        let mut hasher = Self::hasher();
        data.write(&mut hasher);
        hasher.complete()
    }
}

/// The SHA-1 hash function, used by the `rsa-sha1` algorithm (RFC 6376
/// Section 3.3.1). Deprecated by RFC 8301; kept for verifying legacy
/// signatures.
#[derive(Clone, Copy)]
pub struct Sha1;

/// The SHA-256 hash function, used by `rsa-sha256` and `ed25519-sha256`.
#[derive(Clone, Copy)]
pub struct Sha256;

/// The SHA-512 hash function, used by `mldsa44-ed25519-sha512` and by DKIM2
/// `sha512` message hashes.
#[derive(Clone, Copy)]
pub struct Sha512;

/// A hash algorithm selected at run time, as named in DKIM tags (the hash
/// part of `a=`, and the `h=` tag of DKIM key records) and in the `h=` tag
/// of DKIM2 `Message-Instance` header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum HashAlgorithm {
    /// SHA-1 (`sha1`).
    Sha1 = R_HASH_SHA1,
    /// SHA-256 (`sha256`).
    Sha256 = R_HASH_SHA256,
    /// SHA-512 (`sha512`). Used by DKIM2 only.
    Sha512 = R_HASH_SHA512,
}

#[cfg(feature = "aws-lc-rs")]
impl HashAlgorithm {
    /// Hashes the bytes written by `data` with this algorithm.
    pub fn hash(&self, data: impl Writable) -> HashOutput {
        let mut hasher = aws_lc_rs::digest::Context::new(match self {
            Self::Sha1 => &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => &aws_lc_rs::digest::SHA256,
            Self::Sha512 => &aws_lc_rs::digest::SHA512,
        });
        data.write(&mut hasher);
        HashOutput::Digest(hasher.finish())
    }
}

#[cfg(all(feature = "rust-crypto", not(feature = "aws-lc-rs")))]
impl HashAlgorithm {
    /// Hashes the bytes written by `data` with this algorithm.
    pub fn hash(&self, data: impl Writable) -> HashOutput {
        match self {
            Self::Sha1 => Sha1::digest(data),
            Self::Sha256 => Sha256::digest(data),
            Self::Sha512 => Sha512::digest(data),
        }
    }
}

impl HashAlgorithm {
    /// Parses a DKIM hash algorithm name (`sha1` or `sha256`), ignoring
    /// ASCII case. Returns `None` for any other name, including `sha512`,
    /// which DKIM does not define.
    pub fn parse(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("sha256") {
            Some(HashAlgorithm::Sha256)
        } else if name.eq_ignore_ascii_case("sha1") {
            Some(HashAlgorithm::Sha1)
        } else {
            None
        }
    }

    /// Returns the lowercase algorithm name (`sha1`, `sha256` or `sha512`).
    pub fn name(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha1 => "sha1",
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha512 => "sha512",
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
    /// A digest computed by `aws-lc-rs`.
    #[cfg(feature = "aws-lc-rs")]
    Digest(aws_lc_rs::digest::Digest),
    /// A SHA-1 digest computed by the `sha1` crate.
    #[cfg(all(feature = "rust-crypto", not(feature = "aws-lc-rs")))]
    RustCryptoSha1(sha1::digest::Output<sha1::Sha1>),
    /// A SHA-256 digest computed by the `sha2` crate.
    #[cfg(all(feature = "rust-crypto", not(feature = "aws-lc-rs")))]
    RustCryptoSha256(sha2::digest::Output<sha2::Sha256>),
    /// A SHA-512 digest computed by the `sha2` crate.
    #[cfg(all(feature = "rust-crypto", not(feature = "aws-lc-rs")))]
    RustCryptoSha512(sha2::digest::Output<sha2::Sha512>),
}

impl AsRef<[u8]> for HashOutput {
    fn as_ref(&self) -> &[u8] {
        match self {
            #[cfg(feature = "aws-lc-rs")]
            Self::Digest(output) => output.as_ref(),
            #[cfg(all(feature = "rust-crypto", not(feature = "aws-lc-rs")))]
            Self::RustCryptoSha1(output) => output.as_ref(),
            #[cfg(all(feature = "rust-crypto", not(feature = "aws-lc-rs")))]
            Self::RustCryptoSha256(output) => output.as_ref(),
            #[cfg(all(feature = "rust-crypto", not(feature = "aws-lc-rs")))]
            Self::RustCryptoSha512(output) => output.as_ref(),
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
/// Section 3.5) and ARC signatures and in the `s=` tag of DKIM2 signatures.
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
    /// `mldsa44-ed25519-sha512`: the composite of ML-DSA-44 (FIPS 204) and
    /// Ed25519 (RFC 8032) defined as `id-MLDSA44-Ed25519-SHA512` by
    /// draft-ietf-lamps-pq-composite-sigs, with an empty application
    /// context. The composite message `M` is the DKIM2 signature input
    /// (draft-ietf-dkim-dkim2-spec Section 12.8), so its SHA-512 pre-hash is
    /// the only SHA-512 computation. DKIM2 only.
    MlDsa44Ed25519Sha512,
}

pub(crate) const R_HASH_SHA1: u64 = 0x01;
pub(crate) const R_HASH_SHA256: u64 = 0x02;
pub(crate) const R_HASH_SHA512: u64 = 0x40;

impl Algorithm {
    /// Parses a DKIM or ARC algorithm name (`rsa-sha1`, `rsa-sha256` or
    /// `ed25519-sha256`), ignoring ASCII case. Returns `None` for any other
    /// name, including the DKIM2-only `mldsa44-ed25519-sha512`.
    pub fn parse(name: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(name, Algorithm,
            b"rsa-sha1" => Algorithm::RsaSha1,
            b"rsa-sha256" => Algorithm::RsaSha256,
            b"ed25519-sha256" => Algorithm::Ed25519Sha256,
        )
        .copied()
    }

    /// Parses a DKIM2 signature algorithm name (`rsa-sha256`,
    /// `ed25519-sha256` or `mldsa44-ed25519-sha512`). Names are
    /// case-sensitive (draft-ietf-dkim-dkim2-spec Section 2.14), and
    /// `rsa-sha1` is not a DKIM2 algorithm.
    pub fn parse_dkim2(name: &[u8]) -> Option<Self> {
        hashify::map!(name, Algorithm,
            b"rsa-sha256" => Algorithm::RsaSha256,
            b"ed25519-sha256" => Algorithm::Ed25519Sha256,
            b"mldsa44-ed25519-sha512" => Algorithm::MlDsa44Ed25519Sha512,
        )
        .copied()
    }

    /// Returns the lowercase algorithm name used in the `a=` or `s=` tag.
    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::RsaSha1 => "rsa-sha1",
            Algorithm::RsaSha256 => "rsa-sha256",
            Algorithm::Ed25519Sha256 => "ed25519-sha256",
            Algorithm::MlDsa44Ed25519Sha512 => "mldsa44-ed25519-sha512",
        }
    }

    pub(crate) fn is_dkim1(&self) -> bool {
        !matches!(self, Algorithm::MlDsa44Ed25519Sha512)
    }
}
