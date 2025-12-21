/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{Algorithm, HashContext, HashImpl, HashOutput, Sha1, Sha256, SigningKey, VerifyingKey};
use crate::{
    Error, Result,
    common::headers::{Writable, Writer},
    dkim::Canonicalization,
};
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{
    ED25519, Ed25519KeyPair, KeyPair, RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY, RSA_PKCS1_SHA256, RsaKeyPair,
    UnparsedPublicKey,
};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, pem::PemObject};
use std::marker::PhantomData;

#[derive(Debug)]
pub struct RsaKey<T> {
    inner: RsaKeyPair,
    rng: SystemRandom,
    padding: PhantomData<T>,
}

impl<T: HashImpl> RsaKey<T> {
    #[deprecated(since = "0.7.4", note = "use `from_key_der()` instead")]
    pub fn from_pkcs8_pem(pkcs8_pem: &str) -> Result<Self> {
        Self::from_key_der(PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from_pem_slice(pkcs8_pem.as_bytes())
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        ))
    }

    /// Creates a new RSA private key from PKCS8 DER-encoded bytes.
    #[deprecated(since = "0.7.4", note = "use `from_key_der()` instead")]
    pub fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self> {
        Self::from_key_der(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der)))
    }

    #[deprecated(since = "0.7.4", note = "use `from_key_der()` instead")]
    pub fn from_rsa_pem(rsa_pem: &str) -> Result<Self> {
        Self::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(rsa_pem.as_bytes())
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        ))
    }

    /// Creates a new RSA private key from a PKCS1 binary slice.
    #[deprecated(since = "0.7.4", note = "use `from_key_der()` instead")]
    pub fn from_der(der: &[u8]) -> Result<Self> {
        Self::from_key_der(PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)))
    }

    /// Creates a new RSA private key from various DER-encoded key formats.
    ///
    /// Only supports PKCS1 and PKCS8 formats -- will yield an error for other formats.
    pub fn from_key_der(key_der: PrivateKeyDer<'_>) -> Result<Self> {
        let inner = match key_der {
            PrivateKeyDer::Pkcs1(der) => RsaKeyPair::from_der(der.secret_pkcs1_der())
                .map_err(|err| Error::CryptoError(err.to_string()))?,
            PrivateKeyDer::Pkcs8(der) => RsaKeyPair::from_pkcs8(der.secret_pkcs8_der())
                .map_err(|err| Error::CryptoError(err.to_string()))?,
            _ => return Err(Error::CryptoError("Unsupported RSA key format".to_string())),
        };

        Ok(Self {
            inner,
            rng: SystemRandom::new(),
            padding: PhantomData,
        })
    }

    /// Returns the public key of the RSA key pair.
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public().as_ref().to_vec()
    }
}

impl SigningKey for RsaKey<Sha256> {
    type Hasher = Sha256;

    fn sign(&self, input: impl Writable) -> Result<Vec<u8>> {
        let mut data = Vec::with_capacity(256);
        input.write(&mut data);

        let mut signature = vec![0; self.inner.public().modulus_len()];
        self.inner
            .sign(&RSA_PKCS1_SHA256, &self.rng, &data, &mut signature)
            .map_err(|err| Error::CryptoError(err.to_string()))?;
        Ok(signature)
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::RsaSha256
    }
}

pub struct Ed25519Key {
    inner: Ed25519KeyPair,
}

impl Ed25519Key {
    pub fn generate_pkcs8() -> Result<Vec<u8>> {
        Ok(Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|err| Error::CryptoError(err.to_string()))?
            .as_ref()
            .to_vec())
    }

    pub fn from_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: Ed25519KeyPair::from_pkcs8(pkcs8_der)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        })
    }

    pub fn from_pkcs8_maybe_unchecked_der(pkcs8_der: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8_der)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        })
    }

    pub fn from_seed_and_public_key(seed: &[u8], public_key: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: Ed25519KeyPair::from_seed_and_public_key(seed, public_key)
                .map_err(|err| Error::CryptoError(err.to_string()))?,
        })
    }

    // Returns the public key of the Ed25519 key pair.
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public_key().as_ref().to_vec()
    }
}

impl SigningKey for Ed25519Key {
    type Hasher = Sha256;

    fn sign(&self, input: impl Writable) -> Result<Vec<u8>> {
        let mut data = Sha256::hasher();
        input.write(&mut data);
        Ok(self.inner.sign(data.complete().as_ref()).as_ref().to_vec())
    }

    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519Sha256
    }
}

pub(crate) struct RsaPublicKey {
    sha1: UnparsedPublicKey<Vec<u8>>,
    sha2: UnparsedPublicKey<Vec<u8>>,
}

impl RsaPublicKey {
    pub(crate) fn verifying_key_from_bytes(
        bytes: &[u8],
    ) -> Result<Box<dyn VerifyingKey + Send + Sync>> {
        let key = try_strip_rsa_prefix(bytes).unwrap_or(bytes);
        Ok(Box::new(Self {
            sha1: UnparsedPublicKey::new(
                &RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
                key.to_vec(),
            ),
            sha2: UnparsedPublicKey::new(
                &RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                key.to_vec(),
            ),
        }))
    }
}

/// Try to strip an ASN.1 DER-encoded RSA public key prefix
///
/// Returns the original slice if the prefix is not found.
fn try_strip_rsa_prefix(bytes: &[u8]) -> Option<&[u8]> {
    if *bytes.first()? != DER_SEQUENCE_TAG {
        return None;
    }

    let (_, bytes) = decode_multi_byte_len(&bytes[1..])?;
    if *bytes.first()? != DER_SEQUENCE_TAG {
        return None;
    }

    let (byte_len, bytes) = decode_multi_byte_len(&bytes[1..])?;
    if *bytes.first()? != DER_OBJECT_ID_TAG || byte_len != 13 {
        return None;
    }

    let bytes = bytes.get(13..)?; // skip the RSA encryption OID
    if *bytes.first()? != DER_BIT_STRING_TAG {
        return None;
    }

    decode_multi_byte_len(&bytes[1..]).and_then(|(_, bytes)| bytes.get(1..)) // skip the unused bits byte
}

fn decode_multi_byte_len(bytes: &[u8]) -> Option<(usize, &[u8])> {
    if bytes.first()? & 0x80 == 0 {
        return Some((bytes[0] as usize, &bytes[1..]));
    }

    let len_len = (bytes[0] & 0x7f) as usize;
    if bytes.len() < len_len + 1 {
        return None;
    }

    let mut len = 0;
    for i in 0..len_len {
        len = (len << 8) | bytes[1 + i] as usize;
    }

    Some((len, &bytes[len_len + 1..]))
}

const DER_OBJECT_ID_TAG: u8 = 0x06;
const DER_BIT_STRING_TAG: u8 = 0x03;
const DER_SEQUENCE_TAG: u8 = 0x30;

impl VerifyingKey for RsaPublicKey {
    fn verify<'a>(
        &self,
        headers: &mut dyn Iterator<Item = (&'a [u8], &'a [u8])>,
        signature: &[u8],
        canonicalization: Canonicalization,
        algorithm: Algorithm,
    ) -> Result<()> {
        let mut data = Vec::with_capacity(256);
        canonicalization.canonicalize_headers(headers, &mut data);

        match algorithm {
            Algorithm::RsaSha256 => self
                .sha2
                .verify(&data, signature)
                .map_err(|_| Error::FailedVerification),
            Algorithm::RsaSha1 => self
                .sha1
                .verify(&data, signature)
                .map_err(|_| Error::FailedVerification),
            Algorithm::Ed25519Sha256 => Err(Error::IncompatibleAlgorithms),
        }
    }
}

pub(crate) struct Ed25519PublicKey {
    inner: UnparsedPublicKey<Vec<u8>>,
}

impl Ed25519PublicKey {
    pub(crate) fn verifying_key_from_bytes(
        bytes: &[u8],
    ) -> Result<Box<dyn VerifyingKey + Send + Sync>> {
        Ok(Box::new(Self {
            inner: UnparsedPublicKey::new(&ED25519, bytes.to_vec()),
        }))
    }
}

impl VerifyingKey for Ed25519PublicKey {
    fn verify<'a>(
        &self,
        headers: &mut dyn Iterator<Item = (&'a [u8], &'a [u8])>,
        signature: &[u8],
        canonicalization: Canonicalization,
        algorithm: Algorithm,
    ) -> Result<()> {
        if !matches!(algorithm, Algorithm::Ed25519Sha256) {
            return Err(Error::IncompatibleAlgorithms);
        }

        let mut hasher = Sha256::hasher();
        canonicalization.canonicalize_headers(headers, &mut hasher);
        self.inner
            .verify(hasher.complete().as_ref(), signature)
            .map_err(|err| Error::CryptoError(err.to_string()))
    }
}

impl HashImpl for Sha1 {
    type Context = Context;

    fn hasher() -> Self::Context {
        Context::new(&SHA1_FOR_LEGACY_USE_ONLY)
    }
}

impl HashImpl for Sha256 {
    type Context = Context;

    fn hasher() -> Self::Context {
        Context::new(&SHA256)
    }
}

impl HashContext for Context {
    fn complete(self) -> HashOutput {
        HashOutput::Ring(self.finish())
    }
}

impl Writer for Context {
    fn write(&mut self, data: &[u8]) {
        self.update(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_key_der_pkcs1() {
        let key_der = PrivateKeyDer::from_pem_slice(PKCS1_PEM.as_bytes()).unwrap();
        assert!(matches!(key_der, PrivateKeyDer::Pkcs1(_)));
        RsaKey::<Sha256>::from_key_der(key_der).unwrap();
    }

    #[test]
    fn from_key_der_pkcs8() {
        let key_der = PrivateKeyDer::from_pem_slice(PKCS8_PEM.as_bytes()).unwrap();
        assert!(matches!(key_der, PrivateKeyDer::Pkcs8(_)));
        RsaKey::<Sha256>::from_key_der(key_der).unwrap();
    }

    const PKCS1_PEM: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEoAIBAAKCAQEAplSshLNG7gYj7LckWBQ5Gg1mrFGj2soo3VuMKSbvfR6tMrnj
khKUSl3TWQyKdkuOOf4EzAyxhJdq/hWGvMdwfwH2q4UzjjcaRHDP54oBH6WHxyAn
UUkJTFfJo2i8jFE/um09igLr5sEaKMiHgjQIdUScuQRGqKhqS9e4tPpTnfP4ayvM
zVvD1ptUnaV4O9+GkpEwx/vLVXItMO2KNXXKADYBuWcY9g+Dlpp637radmLJjnvj
bCJipWjuVzUEQvIvf3x1dZ4b899Bycp4uScmdz5brfxkhLaA9vchnmr+F7aAuwwK
N5X2Ep6n5d1M0XjA02Z9Zi2W4NkZiNBBmb/f6QIDAQABAoIBAAPzPANNGv4L98jx
+C3o/F/YbyE1sXmV9lP8I1nr1+FbETvEleQSHGL1aPpIVbZ6/gugXdP3E4qFqmUS
ik1hQtRFWJVuDPwk5ghiPHxwIYLd+cRFHiHsT96isWzNJTiDinWpN/5XKkE5QfTe
KaJc4tGJebEG1LhsgtUTxbTImCPxYvKUItDlApOusVvhARjqCnXunNEu5iDiADHH
Wsv3eSPdWkdF5Jjgt/bI4I9XmagX3e1z6ZQiGvdBwCc8ccwkU6yTswXgWCPqyw/t
lbTFqE19lEoHGTYYElKaHUo9hCmI3HZS69ShYKG7dMT9dVLhzRlNx7AzZcYWh8Mx
Ptc8OY0CgYEA1LJe5EpfJ/XvzbiVtNiq07CGhlQj62DAH+XpyqtWHHrUNgMbnBZS
29had9h2NyfIFDIZAKPGWRuSB6PSyDR6w5Sugh5nRoXshzaFr1pAHmo18s+QELjj
XyccwivxRXurwmdDL5Bx0YCKII4LJyE3CBlJzq0/wOxvi+iKDRG+TIUCgYEAyDG8
DXk+E6f9Vd4phaN3sLVDd228U/NNuEr+K74AFHwomgEv//KdK2i/EjFq0zGf31jE
QMoVbnTDmmzVPfKRDlD3tk5XIz2TDzgGxOYBIWJLUiOlkXxckbLVJBR3NxKn561n
id7vMR8ik+hAhEp9yZishZr+QrS/4AyHR3ahBRUCgYBYgoGKboh6kJVh/lYOE7vC
q8rPS2RHJtPMclh/xhznbRWyBEkRAxkn8zhydtl6ykswXEibQ4veuOJj24BzX6NW
kCCudQh1CHYNLlsjRWM5ROl+SXGiA85aYmRNSQv15ijrlR0YRfuXOu4/7dwmRGQq
MpvMLbxCBCHHDtWj6qZOIQKBgF+3F7hBbaKsQP2bGLMicwlzwOwK9W4V9+TTRi7X
yuYAbtEjHDX9Y5Prot8p7W9IXK3GnR51AEYtYZAl1NancR8tKyJo1lStDfDK0sG1
TnkNrAF7tZ+XnBK1NB7qAg28x7aHO+e5RRdxUXDyLFaT3wxSCLpgXoy6KrsOgmdy
mo35An9pYQ3Ik9ghh3PJsQ0r/TywuKIzmSvLJZfI/cuBOFkPDoWCleQGdzyQcxuc
PSCtw8eXUj/Oc09qo5dRWXQkt5uW8sJB0k5fNnfCDqNReUXavDNXOHq31J5USy5R
8ts1bmtZtK0oRci6A8PcgWChUvSfFUT5IrQM/x4rxabn8qIK
-----END RSA PRIVATE KEY-----
"#;

    const PKCS8_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDXxo5+n7aZ0psn
dNjs53za9Af657AuG3sVnvWEBf24OvwwWClJ5vN+cWA7V2yIuuVvd40RxX1N4HLX
QewaUBVw+XlHanskcYA8WTVuMTI6XNY6hIAtU1ETSWAPke5sH6DyrAzxIoC2R+IH
ejqwjtdWdQ0MNVudqY3BO6mAH+zYblRzytMmcols+aqYNgZeAYuEie+EiJiTT65v
y0mG24k0ALF5XLPahxhoUK/xuhjjG/Y/InD8s6C4BksO29bStnyqhMToSGMtUyOT
PTyh1XgrUB4dlfEnpfX9F/wU8a7ijrD38Qtg935c08Qg9YcwVXzpFHWRw/ZF/auq
lcazbMaHAgMBAAECggEAOKmhncrfLsHJkLD0jjGz7eOLfO3+q/z3c5QMsSDJoemL
dD6SiR+m7ZtkQ/EPRVCfE4h3eSU9ZIf+YFylXbuOBd7dZE2oDMfpfu+GQmuU3xKm
BzPoXP62GbR5D12pGKetokxgEaqX1kZGKuSEKP05uzB9vqj8aAiwev/p4QWBMsw6
2stumeWMuZortwL9PZpXgzpJPHXDnFdsn3OIINBMFYFdqda8RhL3rWWsbV5nL1oR
Q2/SMPLc1dQ8ZQKdPmbVhdfnPitVKVEkn8xIiFPWNS3SfYIi+wQj0lWdJbvUUJ1i
7BIXvnXeeVLyYhekTpE5ZnGeGI4A5lix4PN+GIao8QKBgQDtuPW8BaXWfPHb93Kl
mWBQNHz0I71p8GL9/+xRpA9SMuUtYS0jJ1whNgcwoSI4cOKo1UsIMDPAPpTU47Ul
0D+vXr/GyiONL6+IsXAf5xhaQnUWRWKs4G9obadyGkT8aH6y8W+ddKD1JWQKUf4t
Bmpeim+Ck0I8POhDbNNfThTLwwKBgQDoXZ70Pb6HViZAbzf+rEznNycgG8IqtTSc
V7YoSMZe17u0AQjE9XZizBrhpz47N6/JvyYTBIh6VPQe880FTnHdUjvbqn8bmLE7
QEYwvgF5hmHVXlWXUsyKbfMH5Dp8Uy74FV2VTd1hJ7UMSke7LQT41Hgyaz32x7Lm
r0P63fgh7QKBgQDMrnCGz6YWo8XrS4efJgxTgp4D57HzQVM6t9xV/xhiAghppj4j
AoTE46wVJug8CJZgICZWiopEgJ3NH7KdOE1dRguBshIiQmi1HXIZRfUl4grGfj+T
8jp6g8+k4xF68s4EbPVZcU4VRXh5mldrlRaJCFEy8HAbRaYGR/FHIget2QKBgGd/
o9h4VBAmAD29DDzkdBCc0VGM66xoL/nfW6SP3cPK5bFksIpCJywUa3jNLHvl7ue2
u3fHEh8jDeVnhI9zhGYnRcAvLhSVq4OPunPlffSqNZN7RDZ1y+Nw28pNDvvndUlN
AvUIzK2EqTDDOTYW9Fr9EFisydnM01PLB0WLbwV1AoGAGmaWcbNfPyPnJU1nIHGG
fPlEpGn+3Oxr1ja02FPwexk/bg6CRVIqP2x7RtR1cH9fOqiDOoIqyfKswuZkwVj3
EMeos/WHHrw+UzXem+IswmwG9rnUBMlMRCkJ9GhXk98bqoWeJpMhlj1L+oBQ3Spj
j8T1spkdY4jj3CvmzQ0ha0U=
-----END PRIVATE KEY-----
"#;
}
