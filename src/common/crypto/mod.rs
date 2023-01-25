use sha1::{digest::Output, Digest};

use crate::{dkim::Canonicalization, Result};

use super::headers::{Writable, Writer};

mod rust_crypto;
pub use rust_crypto::{Ed25519Key, RsaKey};
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
            Self::Rsa => RsaPublicKey::verifying_key_from_bytes(bytes),
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
                let mut hasher = sha1::Sha1::new();
                data.write(&mut hasher);
                HashOutput::Sha1(hasher.finalize())
            }
            Self::Sha256 => {
                let mut hasher = sha2::Sha256::new();
                data.write(&mut hasher);
                HashOutput::Sha256(hasher.finalize())
            }
        }
    }
}

pub enum HashOutput {
    Sha1(Output<sha1::Sha1>),
    Sha256(Output<sha2::Sha256>),
}

impl AsRef<[u8]> for HashOutput {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Sha1(output) => output.as_ref(),
            Self::Sha256(output) => output.as_ref(),
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
