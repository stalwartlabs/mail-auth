/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! DKIM1 key pair generation (feature `generate`).

use crate::crypto::CryptoError;
use crate::{Error, crypto::Ed25519Key};
use encodify::base64;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
};

/// A freshly generated DKIM1 signing key pair.
///
/// The private key is loaded into a signing key such as
/// [`RsaKey`](crate::crypto::RsaKey) or [`Ed25519Key`]; the public key is
/// published, base64 encoded, in the `p=` tag of the
/// `<selector>._domainkey.<domain>` TXT record (RFC 6376, Section 3.6.1).
pub struct DkimKeyPair {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl DkimKeyPair {
    /// Generates an RSA key pair of `bits` bits; both keys are encoded as
    /// PKCS#1 DER.
    ///
    /// RFC 8301, Section 3.2 requires at least 1024 bits and recommends 2048.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] when key generation or encoding fails.
    pub fn generate_rsa(bits: usize) -> crate::Result<Self> {
        let priv_key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, bits)
            .map_err(|err| Error::Crypto(CryptoError::Library(err.to_string())))?;
        let pub_key = RsaPublicKey::from(&priv_key);

        Ok(DkimKeyPair {
            private_key: priv_key
                .to_pkcs1_der()
                .map_err(|err| Error::Crypto(CryptoError::Library(err.to_string())))?
                .as_bytes()
                .to_vec(),
            public_key: pub_key
                .to_pkcs1_der()
                .map_err(|err| Error::Crypto(CryptoError::Library(err.to_string())))?
                .as_bytes()
                .to_vec(),
        })
    }

    /// Generates an Ed25519 key pair (RFC 8463). The private key is encoded
    /// as PKCS#8 DER; the public key is the raw 32 byte key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] when key generation fails.
    pub fn generate_ed25519() -> crate::Result<Self> {
        let pkcs8_der = Ed25519Key::generate_pkcs8()
            .map_err(|err| Error::Crypto(CryptoError::Library(err.to_string())))?;
        let key = Ed25519Key::from_pkcs8_der(&pkcs8_der).unwrap();

        Ok(DkimKeyPair {
            private_key: pkcs8_der,
            public_key: key.public_key(),
        })
    }

    /// Returns the public key: PKCS#1 DER for RSA, raw 32 bytes for Ed25519.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Returns the private key: PKCS#1 DER for RSA, PKCS#8 DER for Ed25519.
    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }

    /// Consumes the pair and returns `(private_key, public_key)`.
    pub fn into_inner(self) -> (Vec<u8>, Vec<u8>) {
        (self.private_key, self.public_key)
    }

    /// Returns the public key base64 encoded, ready for the `p=` tag of the
    /// key record.
    pub fn encoded_public_key(&self) -> String {
        base64::STANDARD.encode(&self.public_key)
    }
}

#[cfg(test)]
mod test {
    use crate::dkim::sign::test::verify;
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer};
    use std::time::{Duration, Instant};

    use crate::{
        MessageAuthenticator,
        crypto::{Ed25519Key, RsaKey, Sha256},
        dkim::DomainKey,
        dkim::{DkimReportRecord, DkimSigner, generate::DkimKeyPair},
        dns::cache::test::DummyCaches,
        parse::TxtRecordParser,
    };

    #[tokio::test]
    async fn dkim_generate_verify() {
        let rsa_pkcs = DkimKeyPair::generate_rsa(2048).unwrap();
        let ed_pkcs = DkimKeyPair::generate_ed25519().unwrap();

        let rsa_public = format!("v=DKIM1; t=s; p={}", rsa_pkcs.encoded_public_key());
        let ed_public = format!("v=DKIM1; k=ed25519; p={}", ed_pkcs.encoded_public_key());

        let pk_ed = Ed25519Key::from_pkcs8_der(&ed_pkcs.private_key).unwrap();
        let pk_rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from(rsa_pkcs.private_key.as_slice()),
        ))
        .unwrap();

        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        let caches = DummyCaches::new();
        caches.txt_add(
            "default._domainkey.example.com.".to_string(),
            DomainKey::parse(rsa_public.as_bytes()).unwrap(),
            Instant::now() + Duration::new(3600, 0),
        );
        caches.txt_add(
            "ed._domainkey.example.com.".to_string(),
            DomainKey::parse(ed_public.as_bytes()).unwrap(),
            Instant::now() + Duration::new(3600, 0),
        );
        caches.txt_add(
            "_report._domainkey.example.com.".to_string(),
            DkimReportRecord::parse("ra=dkim-failures; rp=100; rr=x".as_bytes()).unwrap(),
            Instant::now() + Duration::new(3600, 0),
        );

        let message = concat!(
            "From: bill@example.com\r\n",
            "To: jdoe@example.com\r\n",
            "Subject: TPS Report\r\n",
            "\r\n",
            "I'm going to need those TPS reports ASAP. ",
            "So, if you could do that, that'd be great.\r\n"
        );

        dbg!("Test generated RSA key");
        verify(
            &resolver,
            &caches,
            DkimSigner::from_key(pk_rsa)
                .domain("example.com")
                .selector("default")
                .headers(["From", "To", "Subject"])
                .identity("\"John Doe\"@example.com")
                .sign(message.as_bytes())
                .unwrap(),
            message,
            Ok(()),
        )
        .await;

        dbg!("Test ED25519 generated key");
        verify(
            &resolver,
            &caches,
            DkimSigner::from_key(pk_ed)
                .domain("example.com")
                .selector("ed")
                .headers(["From", "To", "Subject"])
                .sign(message.as_bytes())
                .unwrap(),
            message,
            Ok(()),
        )
        .await;
    }
}
