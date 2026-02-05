/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::headers::{Writable, Writer};
use crate::{Result, dkim::Canonicalization};

#[cfg(feature = "ring")]
mod ring_impls;
#[cfg(feature = "ring")]
pub use ring_impls::{Ed25519Key, RsaKey};
#[cfg(feature = "ring")]
pub(crate) use ring_impls::{Ed25519PublicKey, RsaPublicKey};

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
    ) -> Result<Box<dyn VerifyingKey + Send + Sync>> {
        match self {
            #[cfg(feature = "ring")]
            Self::Rsa => RsaPublicKey::verifying_key_from_bytes(bytes),
            #[cfg(feature = "ring")]
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

impl HashAlgorithm {
    pub fn hash(&self, data: impl Writable) -> HashOutput {
        match self {
            Self::Sha1 => {
                let mut hasher =
                    ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
                data.write(&mut hasher);
                HashOutput::Ring(hasher.finish())
            }
            Self::Sha256 => {
                let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
                data.write(&mut hasher);
                HashOutput::Ring(hasher.finish())
            }
        }
    }
}

#[non_exhaustive]
pub enum HashOutput {
    #[cfg(feature = "ring")]
    Ring(ring::digest::Digest),
}

impl AsRef<[u8]> for HashOutput {
    fn as_ref(&self) -> &[u8] {
        match self {
            #[cfg(feature = "ring")]
            Self::Ring(output) => output.as_ref(),
        }
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
