/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Backend independent parts of the `id-MLDSA44-Ed25519-SHA512` composite
//! signature (draft-ietf-lamps-pq-composite-sigs): key and signature layouts,
//! the PKCS #8 encoding and the message representative `M'`.

use super::{CryptoError, HashImpl, HashOutput, Sha512};
use crate::{Error, headers::Writable};

pub(crate) const SEED_LEN: usize = 32;
pub(crate) const MLDSA44_PUBLIC_KEY_LEN: usize = 1312;
pub(crate) const MLDSA44_SIGNATURE_LEN: usize = 2420;
pub(crate) const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub(crate) const ED25519_SIGNATURE_LEN: usize = 64;
pub(crate) const PUBLIC_KEY_LEN: usize = MLDSA44_PUBLIC_KEY_LEN + ED25519_PUBLIC_KEY_LEN;
pub(crate) const SIGNATURE_LEN: usize = MLDSA44_SIGNATURE_LEN + ED25519_SIGNATURE_LEN;
pub(crate) const PRIVATE_KEY_LEN: usize = 2 * SEED_LEN;

pub(crate) const LABEL: &[u8; 30] = b"COMPSIG-MLDSA44-Ed25519-SHA512";
const PREFIX: &[u8; 32] = b"CompositeAlgorithmSignatures2025";
const EMPTY_CONTEXT_LEN: u8 = 0;
const SHA512_LEN: usize = 64;
pub(crate) const REPRESENTATIVE_LEN: usize = PREFIX.len() + LABEL.len() + 1 + SHA512_LEN;

const PKCS8_PREFIX: &[u8; 19] = &[
    0x30, 0x51, 0x02, 0x01, 0x00, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06,
    0x27, 0x04, 0x40,
];

pub(crate) type Seed = [u8; SEED_LEN];

pub(crate) struct PrivateKey<'x> {
    pub(crate) mldsa: &'x Seed,
    pub(crate) ed25519: &'x Seed,
}

impl<'x> PrivateKey<'x> {
    pub(crate) fn from_raw(raw: &'x [u8]) -> crate::Result<Self> {
        raw.split_first_chunk::<SEED_LEN>()
            .and_then(|(mldsa, rest)| {
                rest.try_into()
                    .ok()
                    .map(|ed25519| PrivateKey { mldsa, ed25519 })
            })
            .ok_or_else(|| library_error("Invalid ML-DSA-44/Ed25519 private key length"))
    }

    pub(crate) fn from_pkcs8_der(der: &'x [u8]) -> crate::Result<Self> {
        der.strip_prefix(PKCS8_PREFIX.as_slice())
            .ok_or_else(|| library_error("Not an id-MLDSA44-Ed25519-SHA512 PKCS #8 key"))
            .and_then(Self::from_raw)
    }
}

pub(crate) fn pkcs8_der(mldsa: &Seed, ed25519: &Seed) -> Vec<u8> {
    let mut der = Vec::with_capacity(PKCS8_PREFIX.len() + PRIVATE_KEY_LEN);
    der.extend_from_slice(PKCS8_PREFIX);
    der.extend_from_slice(mldsa);
    der.extend_from_slice(ed25519);
    der
}

pub(crate) struct PublicKey<'x> {
    pub(crate) mldsa: &'x [u8; MLDSA44_PUBLIC_KEY_LEN],
    pub(crate) ed25519: &'x [u8; ED25519_PUBLIC_KEY_LEN],
}

impl<'x> PublicKey<'x> {
    pub(crate) fn from_bytes(bytes: &'x [u8]) -> crate::Result<Self> {
        bytes
            .split_first_chunk::<MLDSA44_PUBLIC_KEY_LEN>()
            .and_then(|(mldsa, rest)| {
                rest.try_into()
                    .ok()
                    .map(|ed25519| PublicKey { mldsa, ed25519 })
            })
            .ok_or_else(|| library_error("Invalid ML-DSA-44/Ed25519 public key length"))
    }
}

pub(crate) struct Signature<'x> {
    pub(crate) mldsa: &'x [u8; MLDSA44_SIGNATURE_LEN],
    pub(crate) ed25519: &'x [u8; ED25519_SIGNATURE_LEN],
}

impl<'x> Signature<'x> {
    pub(crate) fn from_bytes(bytes: &'x [u8]) -> Option<Self> {
        bytes
            .split_first_chunk::<MLDSA44_SIGNATURE_LEN>()
            .and_then(|(mldsa, rest)| {
                rest.try_into()
                    .ok()
                    .map(|ed25519| Signature { mldsa, ed25519 })
            })
    }
}

pub(crate) fn message_representative(message: impl Writable) -> [u8; REPRESENTATIVE_LEN] {
    representative_from_digest(&Sha512::digest(message))
}

fn representative_from_digest(digest: &HashOutput) -> [u8; REPRESENTATIVE_LEN] {
    let mut representative = [0u8; REPRESENTATIVE_LEN];
    for (slot, byte) in representative.iter_mut().zip(
        PREFIX
            .iter()
            .chain(LABEL)
            .chain(&[EMPTY_CONTEXT_LEN])
            .chain(digest.as_ref()),
    ) {
        *slot = *byte;
    }
    representative
}

#[cold]
pub(crate) fn library_error(message: &str) -> Error {
    Error::Crypto(CryptoError::Library(message.to_string()))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::{Algorithm, MlDsa44Ed25519Key, SigningKey, VerifyingKeyType};
    use encodify::base64;

    const VECTORS: &str = include_str!("../../resources/dkim2/lamps-mldsa44-ed25519.json");

    struct Vector {
        message: Vec<u8>,
        context: Vec<u8>,
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        pkcs8: Vec<u8>,
        signature: Vec<u8>,
        signature_with_context: Vec<u8>,
    }

    fn vector() -> Vector {
        let json: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        let field = |name: &str| {
            base64::STANDARD
                .decode(json[name].as_str().unwrap())
                .unwrap()
        };
        Vector {
            message: field("m"),
            context: field("ctx"),
            public_key: field("pk"),
            private_key: field("sk"),
            pkcs8: field("sk_pkcs8"),
            signature: field("s"),
            signature_with_context: field("sWithContext"),
        }
    }

    // LAMPS Appendix E: the published signature over m verifies with pk.
    #[test]
    fn lamps_vector_verifies() {
        let vector = vector();
        assert_eq!(vector.public_key.len(), PUBLIC_KEY_LEN);
        assert_eq!(vector.signature.len(), SIGNATURE_LEN);
        let key = VerifyingKeyType::MlDsa44Ed25519
            .verifying_key(&vector.public_key)
            .unwrap();
        key.verify_bytes(
            &vector.message,
            &vector.signature,
            Algorithm::MlDsa44Ed25519Sha512,
        )
        .unwrap();

        let mut tampered = vector.message.clone();
        tampered.push(b'!');
        assert!(
            key.verify_bytes(
                &tampered,
                &vector.signature,
                Algorithm::MlDsa44Ed25519Sha512
            )
            .is_err()
        );
        assert!(
            key.verify_bytes(&vector.message, &vector.signature, Algorithm::Ed25519Sha256)
                .is_err()
        );
    }

    // DKIM2 uses an empty application context, so the vector's ctx signature must not verify.
    #[test]
    fn lamps_vector_context_signature_is_rejected() {
        let vector = vector();
        assert!(!vector.context.is_empty());
        let key = VerifyingKeyType::MlDsa44Ed25519
            .verifying_key(&vector.public_key)
            .unwrap();
        assert!(
            key.verify_bytes(
                &vector.message,
                &vector.signature_with_context,
                Algorithm::MlDsa44Ed25519Sha512
            )
            .is_err()
        );
    }

    // The vector's private key derives its public key and produces verifiable signatures.
    #[test]
    fn lamps_vector_private_key_signs() {
        let vector = vector();
        let raw = MlDsa44Ed25519Key::from_raw_private_key(&vector.private_key).unwrap();
        let pkcs8 = MlDsa44Ed25519Key::from_pkcs8_der(&vector.pkcs8).unwrap();
        assert_eq!(raw.public_key().unwrap(), vector.public_key);
        assert_eq!(pkcs8.public_key().unwrap(), vector.public_key);
        assert_eq!(raw.algorithm(), Algorithm::MlDsa44Ed25519Sha512);

        let signature = raw.sign(vector.message.as_slice()).unwrap();
        assert_eq!(signature.len(), SIGNATURE_LEN);
        let key = VerifyingKeyType::MlDsa44Ed25519
            .verifying_key(&vector.public_key)
            .unwrap();
        key.verify_bytes(&vector.message, &signature, Algorithm::MlDsa44Ed25519Sha512)
            .unwrap();
    }

    #[test]
    fn generated_key_round_trips() {
        let pkcs8 = MlDsa44Ed25519Key::generate_pkcs8().unwrap();
        let key = MlDsa44Ed25519Key::from_pkcs8_der(&pkcs8).unwrap();
        let signature = key.sign(b"message".as_slice()).unwrap();
        VerifyingKeyType::MlDsa44Ed25519
            .verifying_key(&key.public_key().unwrap())
            .unwrap()
            .verify_bytes(b"message", &signature, Algorithm::MlDsa44Ed25519Sha512)
            .unwrap();
    }

    #[test]
    fn malformed_keys_and_signatures_are_rejected() {
        assert!(MlDsa44Ed25519Key::from_raw_private_key(&[0u8; 63]).is_err());
        assert!(MlDsa44Ed25519Key::from_pkcs8_der(&[0u8; 83]).is_err());
        assert!(
            VerifyingKeyType::MlDsa44Ed25519
                .verifying_key(&[0u8; PUBLIC_KEY_LEN - 1])
                .is_err()
        );
        let vector = vector();
        let key = VerifyingKeyType::MlDsa44Ed25519
            .verifying_key(&vector.public_key)
            .unwrap();
        let short = vector.signature.get(..SIGNATURE_LEN - 1).unwrap();
        assert!(
            key.verify_bytes(&vector.message, short, Algorithm::MlDsa44Ed25519Sha512)
                .is_err()
        );
        let mut broken = vector.signature.clone();
        if let Some(byte) = broken.last_mut() {
            *byte ^= 1;
        }
        assert!(
            key.verify_bytes(&vector.message, &broken, Algorithm::MlDsa44Ed25519Sha512)
                .is_err()
        );
    }
}
