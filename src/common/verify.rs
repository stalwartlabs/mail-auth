/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use rsa::PaddingScheme;
use sha1::Sha1;
use sha2::Sha256;

use crate::{
    dkim::{Algorithm, DomainKey, PublicKey},
    Error,
};

pub(crate) trait VerifySignature {
    fn s(&self) -> &str;

    fn d(&self) -> &str;

    fn b(&self) -> &[u8];

    fn a(&self) -> Algorithm;

    fn domain_key(&self) -> String {
        let s = self.s();
        let d = self.d();
        let mut key = String::with_capacity(s.len() + d.len() + 13);
        key.push_str(s);
        key.push_str("._domainkey.");
        key.push_str(d);
        key.push('.');
        key
    }

    fn verify(&self, record: &DomainKey, hh: &[u8]) -> crate::Result<()> {
        match (&self.a(), &record.p) {
            (Algorithm::RsaSha256, PublicKey::Rsa(public_key)) => rsa::PublicKey::verify(
                public_key,
                PaddingScheme::new_pkcs1v15_sign::<Sha256>(),
                hh,
                self.b(),
            )
            .map_err(|_| Error::FailedVerification),

            (Algorithm::RsaSha1, PublicKey::Rsa(public_key)) => rsa::PublicKey::verify(
                public_key,
                PaddingScheme::new_pkcs1v15_sign::<Sha1>(),
                hh,
                self.b(),
            )
            .map_err(|_| Error::FailedVerification),

            (Algorithm::Ed25519Sha256, PublicKey::Ed25519(public_key)) => public_key
                .verify_strict(
                    hh,
                    &ed25519_dalek::Signature::from_bytes(self.b())
                        .map_err(|err| Error::CryptoError(err.to_string()))?,
                )
                .map_err(|_| Error::FailedVerification),

            (_, PublicKey::Revoked) => Err(Error::RevokedPublicKey),

            (_, _) => Err(Error::IncompatibleAlgorithms),
        }
    }
}
