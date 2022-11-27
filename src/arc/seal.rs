use std::{borrow::Cow, io::Write, time::SystemTime};

use ed25519_dalek::Signer;
use mail_builder::encoders::base64::base64_encode;
use rsa::PaddingScheme;
use sha1::Digest;
use sha2::Sha256;

use crate::{
    dkim::{Algorithm, Canonicalization},
    ARCOutput, AuthenticatedMessage, AuthenticationResults, DKIMResult, Error, PrivateKey,
};

use super::{ChainValidation, Seal, Signature, ARC};

impl<'x> ARC<'x> {
    pub fn new(results: &'x AuthenticationResults) -> Self {
        ARC {
            signature: Signature::default(),
            seal: Seal::default(),
            results,
        }
    }

    pub fn seal(
        mut self,
        message: &'x AuthenticatedMessage<'x>,
        arc_output: &ARCOutput,
        with_key: &PrivateKey,
    ) -> crate::Result<Self> {
        if !arc_output.can_be_sealed() {
            return Err(Error::ARCInvalidCV);
        }

        // Set a=
        if let PrivateKey::Ed25519(_) = with_key {
            self.signature.a = Algorithm::Ed25519Sha256;
            self.seal.a = Algorithm::Ed25519Sha256;
        } else {
            self.signature.a = Algorithm::RsaSha256;
            self.seal.a = Algorithm::RsaSha256;
        }

        // Set i= and cv=
        if arc_output.set.is_empty() {
            self.signature.i = 1;
            self.seal.i = 1;
            self.seal.cv = ChainValidation::None;
        } else {
            let i = arc_output.set.last().unwrap().seal.header.i + 1;
            self.signature.i = i;
            self.seal.i = i;
            self.seal.cv = match &arc_output.result {
                DKIMResult::Pass => ChainValidation::Pass,
                _ => ChainValidation::Fail,
            };
        }

        // Create hashes
        let mut body_hasher = Sha256::new();
        let mut header_hasher = Sha256::new();

        // Canonicalize headers and body
        let (body_len, signed_headers) =
            self.signature
                .canonicalize(message, &mut header_hasher, &mut body_hasher)?;

        if signed_headers.is_empty() {
            return Err(Error::NoHeadersFound);
        }

        // Create Signature
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.signature.bh = base64_encode(&body_hasher.finalize())?;
        self.signature.t = now;
        self.signature.x = if self.signature.x > 0 {
            now + self.signature.x
        } else {
            0
        };
        self.signature.h = signed_headers;
        if self.signature.l > 0 {
            self.signature.l = body_len as u64;
        }

        // Add signature to hash
        self.signature.write(&mut header_hasher, false)?;

        // Sign
        let b = match with_key {
            PrivateKey::Rsa(private_key) => private_key
                .sign(
                    PaddingScheme::new_pkcs1v15_sign::<Sha256>(),
                    &header_hasher.finalize(),
                )
                .map_err(|err| Error::CryptoError(err.to_string()))?,
            PrivateKey::Ed25519(key_pair) => {
                key_pair.sign(&header_hasher.finalize()).to_bytes().to_vec()
            }
            PrivateKey::None => return Err(Error::MissingParameters),
        };
        self.signature.b = base64_encode(&b)?;

        // Hash ARC chain
        let mut header_hasher = Sha256::new();
        if !arc_output.set.is_empty() {
            Canonicalization::Relaxed.canonicalize_headers(
                arc_output.set.iter().flat_map(|set| {
                    [
                        (set.results.name, set.results.value),
                        (set.signature.name, set.signature.value),
                        (set.seal.name, set.seal.value),
                    ]
                }),
                &mut header_hasher,
            )?;
        }

        // Hash ARC headers for the current instance
        self.results.write(&mut header_hasher, self.seal.i, false)?;
        self.signature.write(&mut header_hasher, false)?;
        self.seal.write(&mut header_hasher, false)?;

        // Seal
        let b = match with_key {
            PrivateKey::Rsa(private_key) => private_key
                .sign(
                    PaddingScheme::new_pkcs1v15_sign::<Sha256>(),
                    &header_hasher.finalize(),
                )
                .map_err(|err| Error::CryptoError(err.to_string()))?,
            PrivateKey::Ed25519(key_pair) => {
                key_pair.sign(&header_hasher.finalize()).to_bytes().to_vec()
            }
            PrivateKey::None => return Err(Error::MissingParameters),
        };
        self.seal.b = base64_encode(&b)?;

        Ok(self)
    }

    /// Sets the headers to sign.
    pub fn headers(mut self, headers: impl IntoIterator<Item = impl Into<Cow<'x, str>>>) -> Self {
        self.signature.h = headers.into_iter().map(|h| h.into()).collect();
        self
    }

    /// Sets the domain to use for signing.
    pub fn domain(mut self, domain: &'x str) -> Self {
        self.signature.d = domain.into();
        self.seal.d = domain.into();
        self
    }

    /// Sets the selector to use for signing.
    pub fn selector(mut self, selector: &'x str) -> Self {
        self.signature.s = selector.into();
        self.seal.s = selector.into();
        self
    }

    /// Sets the number of seconds from now to use for the signature expiration.
    pub fn expiration(mut self, expiration: u64) -> Self {
        self.signature.x = expiration;
        self
    }

    /// Include the body length in the signature.
    pub fn body_length(mut self, body_length: bool) -> Self {
        self.signature.l = u64::from(body_length);
        self
    }

    /// Sets header canonicalization algorithm.
    pub fn header_canonicalization(mut self, ch: Canonicalization) -> Self {
        self.signature.ch = ch;
        self
    }

    /// Sets header canonicalization algorithm.
    pub fn body_canonicalization(mut self, cb: Canonicalization) -> Self {
        self.signature.cb = cb;
        self
    }
}

impl<'x> Signature<'x> {
    #[allow(clippy::while_let_on_iterator)]
    pub(crate) fn canonicalize(
        &self,
        message: &'x AuthenticatedMessage<'x>,
        header_hasher: impl Write,
        body_hasher: impl Write,
    ) -> crate::Result<(usize, Vec<Cow<'x, str>>)> {
        let mut headers = Vec::with_capacity(self.h.len());
        let mut found_headers = vec![false; self.h.len()];
        let mut signed_headers = Vec::with_capacity(self.h.len());

        for (name, value) in &message.headers {
            if let Some(pos) = self
                .h
                .iter()
                .position(|header| name.eq_ignore_ascii_case(header.as_bytes()))
            {
                headers.push((*name, *value));
                found_headers[pos] = true;
                signed_headers.push(std::str::from_utf8(name).unwrap().into());
            }
        }

        let body_len = message.body.len();
        self.ch
            .canonicalize_headers(headers.into_iter().rev(), header_hasher)?;
        self.cb.canonicalize_body(message.body, body_hasher)?;

        // Add any missing headers
        signed_headers.reverse();
        for (header, found) in self.h.iter().zip(found_headers) {
            if !found {
                signed_headers.push(header.to_string().into());
            }
        }

        Ok((body_len, signed_headers))
    }
}
