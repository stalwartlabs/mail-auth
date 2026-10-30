/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Backend independent parts of the DKIM2 `mldsa44` algorithm
//! (draft-ietf-dkim-dkim2-spec Section 3.4): "pure" ML-DSA-44 (FIPS 204)
//! with the `DKIM2` context string, and the RFC 9881 PKCS #8 private key
//! encoding.

use super::CryptoError;
use crate::Error;

pub(crate) const SEED_LEN: usize = 32;
pub(crate) const PUBLIC_KEY_LEN: usize = 1312;
pub(crate) const SIGNATURE_LEN: usize = 2420;
pub(crate) const CONTEXT: &[u8; 5] = b"DKIM2";

const PKCS8_SEED_PREFIX: &[u8; 22] = &[
    0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x03, 0x11, 0x04, 0x22, 0x80, 0x20,
];
const PKCS8_BOTH_PREFIX: &[u8; 30] = &[
    0x30, 0x82, 0x0a, 0x3e, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x03, 0x11, 0x04, 0x82, 0x0a, 0x2a, 0x30, 0x82, 0x0a, 0x26, 0x04, 0x20,
];
const PKCS8_BOTH_EXPANDED_PREFIX: &[u8; 4] = &[0x04, 0x82, 0x0a, 0x00];
const EXPANDED_KEY_LEN: usize = 2560;

pub(crate) type Seed = [u8; SEED_LEN];

pub(crate) fn seed_from_raw(raw: &[u8]) -> crate::Result<&Seed> {
    raw.try_into()
        .map_err(|_| library_error("Invalid ML-DSA-44 seed length"))
}

pub(crate) fn seed_from_pkcs8_der(der: &[u8]) -> crate::Result<&Seed> {
    if let Some(seed) = der.strip_prefix(PKCS8_SEED_PREFIX.as_slice()) {
        return seed_from_raw(seed);
    }
    der.strip_prefix(PKCS8_BOTH_PREFIX.as_slice())
        .and_then(|rest| rest.split_first_chunk::<SEED_LEN>())
        .filter(|(_, expanded)| {
            expanded
                .strip_prefix(PKCS8_BOTH_EXPANDED_PREFIX.as_slice())
                .is_some_and(|expanded| expanded.len() == EXPANDED_KEY_LEN)
        })
        .map(|(seed, _)| seed)
        .ok_or_else(|| library_error("Not an ML-DSA-44 PKCS #8 key with a seed"))
}

pub(crate) fn pkcs8_der(seed: &Seed) -> Vec<u8> {
    let mut der = Vec::with_capacity(PKCS8_SEED_PREFIX.len() + SEED_LEN);
    der.extend_from_slice(PKCS8_SEED_PREFIX);
    der.extend_from_slice(seed);
    der
}

pub(crate) fn public_key_from_bytes(bytes: &[u8]) -> crate::Result<&[u8; PUBLIC_KEY_LEN]> {
    bytes
        .try_into()
        .map_err(|_| Error::Crypto(CryptoError::MalformedPublicKey))
}

#[cold]
pub(crate) fn library_error(message: &str) -> Error {
    Error::Crypto(CryptoError::Library(message.to_string()))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::{Algorithm, MlDsa44Key, SigningKey, VerifyingKeyType};
    use encodify::base64;

    const VECTOR: &str = include_str!("../../resources/dkim2/mldsa44.json");

    struct Vector {
        message: Vec<u8>,
        public_key: Vec<u8>,
        pkcs8_seed: Vec<u8>,
        pkcs8_both: Vec<u8>,
        signature: Vec<u8>,
        signature_empty_context: Vec<u8>,
    }

    fn vector() -> Vector {
        let json: serde_json::Value = serde_json::from_str(VECTOR).unwrap();
        let field = |name: &str| {
            base64::STANDARD
                .decode(json[name].as_str().unwrap())
                .unwrap()
        };
        Vector {
            message: field("m"),
            public_key: field("pk"),
            pkcs8_seed: field("pkcs8_seed"),
            pkcs8_both: field("pkcs8_both"),
            signature: field("s"),
            signature_empty_context: field("s_empty_context"),
        }
    }

    // An OpenSSL signature made with the DKIM2 context verifies; one made with an empty context does not.
    #[test]
    fn openssl_vector_verifies_with_dkim2_context() {
        let vector = vector();
        assert_eq!(vector.public_key.len(), PUBLIC_KEY_LEN);
        assert_eq!(vector.signature.len(), SIGNATURE_LEN);
        let key = VerifyingKeyType::MlDsa44
            .verifying_key(&vector.public_key)
            .unwrap();
        key.verify_bytes(&vector.message, &vector.signature, Algorithm::MlDsa44)
            .unwrap();
        assert!(
            key.verify_bytes(
                &vector.message,
                &vector.signature_empty_context,
                Algorithm::MlDsa44
            )
            .is_err()
        );
        let mut tampered = vector.message.clone();
        tampered.push(b'!');
        assert!(
            key.verify_bytes(&tampered, &vector.signature, Algorithm::MlDsa44)
                .is_err()
        );
        assert!(
            key.verify_bytes(&vector.message, &vector.signature, Algorithm::Ed25519Sha256)
                .is_err()
        );
    }

    // Both RFC 9881 private key forms written by OpenSSL load and derive the published public key.
    #[test]
    fn openssl_private_keys_load_and_sign() {
        let vector = vector();
        for der in [&vector.pkcs8_seed, &vector.pkcs8_both] {
            let key = MlDsa44Key::from_pkcs8_der(der).unwrap();
            assert_eq!(key.public_key().unwrap(), vector.public_key);
            assert_eq!(key.algorithm(), Algorithm::MlDsa44);
            let signature = key.sign(vector.message.as_slice()).unwrap();
            assert_eq!(signature.len(), SIGNATURE_LEN);
            VerifyingKeyType::MlDsa44
                .verifying_key(&vector.public_key)
                .unwrap()
                .verify_bytes(&vector.message, &signature, Algorithm::MlDsa44)
                .unwrap();
        }
        let seed = vector.pkcs8_seed.get(PKCS8_SEED_PREFIX.len()..).unwrap();
        assert_eq!(
            MlDsa44Key::from_raw_private_key(seed)
                .unwrap()
                .public_key()
                .unwrap(),
            vector.public_key
        );
    }

    #[test]
    fn generated_key_round_trips() {
        let pkcs8 = MlDsa44Key::generate_pkcs8().unwrap();
        assert_eq!(pkcs8.len(), PKCS8_SEED_PREFIX.len() + SEED_LEN);
        let key = MlDsa44Key::from_pkcs8_der(&pkcs8).unwrap();
        let signature = key.sign(b"message".as_slice()).unwrap();
        VerifyingKeyType::MlDsa44
            .verifying_key(&key.public_key().unwrap())
            .unwrap()
            .verify_bytes(b"message", &signature, Algorithm::MlDsa44)
            .unwrap();
    }

    #[test]
    fn malformed_keys_and_signatures_are_rejected() {
        let vector = vector();
        assert!(MlDsa44Key::from_raw_private_key(&[0u8; 31]).is_err());
        assert!(MlDsa44Key::from_pkcs8_der(&[0u8; 54]).is_err());
        assert!(
            MlDsa44Key::from_pkcs8_der(
                vector
                    .pkcs8_both
                    .get(..vector.pkcs8_both.len() - 1)
                    .unwrap()
            )
            .is_err()
        );
        assert!(matches!(
            VerifyingKeyType::MlDsa44.verifying_key(&[0u8; PUBLIC_KEY_LEN - 1]),
            Err(Error::Crypto(CryptoError::MalformedPublicKey))
        ));
        let key = VerifyingKeyType::MlDsa44
            .verifying_key(&vector.public_key)
            .unwrap();
        let short = vector.signature.get(..SIGNATURE_LEN - 1).unwrap();
        assert!(
            key.verify_bytes(&vector.message, short, Algorithm::MlDsa44)
                .is_err()
        );
        let mut broken = vector.signature.clone();
        if let Some(byte) = broken.last_mut() {
            *byte ^= 1;
        }
        assert!(
            key.verify_bytes(&vector.message, &broken, Algorithm::MlDsa44)
                .is_err()
        );
    }
}
