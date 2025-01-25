/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_builder::encoders::base64::base64_encode;
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
    RsaPrivateKey, RsaPublicKey,
};

use crate::{common::crypto::Ed25519Key, Error};

pub struct DkimKeyPair {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl DkimKeyPair {
    /// Generates a new RSA key pair encoded in PKCS#1 DER format with the given number of bits
    pub fn generate_rsa(bits: usize) -> crate::Result<Self> {
        //TODO: Use `ring` once it supports RSA key generation
        let priv_key = RsaPrivateKey::new(&mut rand::thread_rng(), bits)
            .map_err(|err| Error::CryptoError(err.to_string()))?;
        let pub_key = RsaPublicKey::from(&priv_key);

        Ok(DkimKeyPair {
            private_key: priv_key
                .to_pkcs1_der()
                .map_err(|err| Error::CryptoError(err.to_string()))?
                .as_bytes()
                .to_vec(),
            public_key: pub_key
                .to_pkcs1_der()
                .map_err(|err| Error::CryptoError(err.to_string()))?
                .as_bytes()
                .to_vec(),
        })
    }

    /// Generates a new Ed25519 key pair encoded in PKCS#8 DER format
    pub fn generate_ed25519() -> crate::Result<Self> {
        let pkcs8_der =
            Ed25519Key::generate_pkcs8().map_err(|err| Error::CryptoError(err.to_string()))?;
        let key = Ed25519Key::from_pkcs8_der(&pkcs8_der).unwrap();

        Ok(DkimKeyPair {
            private_key: pkcs8_der,
            public_key: key.public_key(),
        })
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn private_key(&self) -> &[u8] {
        &self.private_key
    }

    pub fn into_inner(self) -> (Vec<u8>, Vec<u8>) {
        (self.private_key, self.public_key)
    }

    pub fn encoded_public_key(&self) -> String {
        String::from_utf8(base64_encode(&self.public_key).unwrap_or_default()).unwrap_or_default()
    }
}

#[cfg(test)]
mod test {
    use crate::dkim::sign::test::verify;
    use std::time::{Duration, Instant};

    use crate::{
        common::{
            crypto::{Ed25519Key, RsaKey, Sha256},
            parse::TxtRecordParser,
            verify::DomainKey,
        },
        dkim::{generate::DkimKeyPair, DkimSigner, DomainKeyReport},
        MessageAuthenticator,
    };

    #[tokio::test]
    async fn dkim_generate_verify() {
        let rsa_pkcs = DkimKeyPair::generate_rsa(2048).unwrap();
        let ed_pkcs = DkimKeyPair::generate_ed25519().unwrap();

        let rsa_public = format!("v=DKIM1; t=s; p={}", rsa_pkcs.encoded_public_key());
        let ed_public = format!("v=DKIM1; k=ed25519; p={}", ed_pkcs.encoded_public_key());

        let pk_ed = Ed25519Key::from_pkcs8_der(&ed_pkcs.private_key).unwrap();
        let pk_rsa = RsaKey::<Sha256>::from_der(&rsa_pkcs.private_key).unwrap();

        // Create resolver
        let resolver = MessageAuthenticator::new_system_conf().unwrap();
        #[cfg(any(test, feature = "test"))]
        {
            resolver.txt_add(
                "default._domainkey.example.com.".to_string(),
                DomainKey::parse(rsa_public.as_bytes()).unwrap(),
                Instant::now() + Duration::new(3600, 0),
            );
            resolver.txt_add(
                "ed._domainkey.example.com.".to_string(),
                DomainKey::parse(ed_public.as_bytes()).unwrap(),
                Instant::now() + Duration::new(3600, 0),
            );
            resolver.txt_add(
                "_report._domainkey.example.com.".to_string(),
                DomainKeyReport::parse("ra=dkim-failures; rp=100; rr=x".as_bytes()).unwrap(),
                Instant::now() + Duration::new(3600, 0),
            );
        }

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
            DkimSigner::from_key(pk_rsa)
                .domain("example.com")
                .selector("default")
                .headers(["From", "To", "Subject"])
                .agent_user_identifier("\"John Doe\" <jdoe@example.com>")
                .sign(message.as_bytes())
                .unwrap(),
            message,
            Ok(()),
        )
        .await;

        dbg!("Test ED25519 generated key");
        verify(
            &resolver,
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
