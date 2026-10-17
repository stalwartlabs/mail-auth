/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::{
    DnsError, Error,
    crypto::{CryptoError, SigningKey},
    dkim::{AtpsRecord, DkimReportRecord, DkimSigner, DomainKey, Signature},
    dmarc::{DmarcRecord, Uri},
    dns::TxtRecord,
    mta_sts::{MtaStsRecord, ReportUri, TlsRptRecord},
    spf::{Directive, Macro, Mechanism, SpfRecord},
};
use std::{mem::size_of, sync::Arc};

#[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rust-crypto"))]
use crate::dkim2::{Dkim2Signer, Flag, KeyEntry};

pub(crate) trait HeapSize {
    fn heap_size(&self) -> usize;
}

impl HeapSize for String {
    fn heap_size(&self) -> usize {
        self.capacity()
    }
}

impl<T: HeapSize> HeapSize for Vec<T> {
    fn heap_size(&self) -> usize {
        self.capacity() * size_of::<T>() + self.iter().map(HeapSize::heap_size).sum::<usize>()
    }
}

impl<T: HeapSize> HeapSize for Box<[T]> {
    fn heap_size(&self) -> usize {
        self.len() * size_of::<T>() + self.iter().map(HeapSize::heap_size).sum::<usize>()
    }
}

impl<T: HeapSize> HeapSize for Option<T> {
    fn heap_size(&self) -> usize {
        self.as_ref().map_or(0, HeapSize::heap_size)
    }
}

impl<T: HeapSize> HeapSize for Arc<T> {
    fn heap_size(&self) -> usize {
        2 * size_of::<usize>() + size_of::<T>() + self.as_ref().heap_size()
    }
}

impl HeapSize for u8 {
    fn heap_size(&self) -> usize {
        0
    }
}

impl HeapSize for Macro {
    fn heap_size(&self) -> usize {
        match self {
            Macro::Literal(bytes) => bytes.len(),
            Macro::List(items) => items.heap_size(),
            Macro::Variable { .. } | Macro::None => 0,
        }
    }
}

impl HeapSize for Mechanism {
    fn heap_size(&self) -> usize {
        match self {
            Mechanism::Include { macro_string }
            | Mechanism::A { macro_string, .. }
            | Mechanism::Mx { macro_string, .. }
            | Mechanism::Ptr { macro_string }
            | Mechanism::Exists { macro_string } => macro_string.heap_size(),
            Mechanism::All | Mechanism::Ip4 { .. } | Mechanism::Ip6 { .. } => 0,
        }
    }
}

impl HeapSize for Directive {
    fn heap_size(&self) -> usize {
        self.mechanism.heap_size()
    }
}

impl HeapSize for SpfRecord {
    fn heap_size(&self) -> usize {
        self.directives.heap_size()
            + self.exp.heap_size()
            + self.redirect.heap_size()
            + self.ra.as_ref().map_or(0, |ra| ra.len())
    }
}

impl HeapSize for Uri {
    fn heap_size(&self) -> usize {
        self.uri.heap_size()
    }
}

impl HeapSize for DmarcRecord {
    fn heap_size(&self) -> usize {
        self.rua.heap_size() + self.ruf.heap_size()
    }
}

impl HeapSize for DomainKey {
    fn heap_size(&self) -> usize {
        size_of_val(self.p.as_ref()) + self.p.heap_size()
    }
}

impl HeapSize for DkimReportRecord {
    fn heap_size(&self) -> usize {
        self.ra.heap_size() + self.rs.heap_size()
    }
}

impl HeapSize for AtpsRecord {
    fn heap_size(&self) -> usize {
        self.d.heap_size()
    }
}

impl HeapSize for MtaStsRecord {
    fn heap_size(&self) -> usize {
        self.id.heap_size()
    }
}

impl HeapSize for ReportUri {
    fn heap_size(&self) -> usize {
        match self {
            ReportUri::Mail(uri) | ReportUri::Http(uri) => uri.heap_size(),
        }
    }
}

impl HeapSize for TlsRptRecord {
    fn heap_size(&self) -> usize {
        self.rua.heap_size()
    }
}

impl HeapSize for Error {
    fn heap_size(&self) -> usize {
        match self {
            Error::Io(text)
            | Error::Dns(DnsError::Resolver(text))
            | Error::Crypto(CryptoError::Library(text)) => text.heap_size(),
            _ => 0,
        }
    }
}

impl HeapSize for Signature {
    fn heap_size(&self) -> usize {
        self.d.heap_size()
            + self.s.heap_size()
            + self.b.capacity()
            + self.bh.capacity()
            + self.h.heap_size()
            + self.z.heap_size()
            + self.i.heap_size()
            + self.atps.heap_size()
    }
}

impl TxtRecord {
    /// Approximate heap memory owned by this record, in bytes, including the
    /// shared allocation of the parsed record. Walks the record once, so cache
    /// implementations should compute it when the entry is inserted.
    pub fn heap_size(&self) -> usize {
        match self {
            TxtRecord::Spf(record) => record.heap_size(),
            TxtRecord::SpfExplanation(record) => record.heap_size(),
            TxtRecord::DomainKey(record) => record.heap_size(),
            TxtRecord::DkimReport(record) => record.heap_size(),
            TxtRecord::Dmarc(record) => record.heap_size(),
            TxtRecord::Atps(record) => record.heap_size(),
            TxtRecord::MtaSts(record) => record.heap_size(),
            TxtRecord::TlsRpt(record) => record.heap_size(),
            TxtRecord::Error(err) => err.heap_size(),
        }
    }
}

impl<T: SigningKey, State> DkimSigner<T, State> {
    /// Approximate heap memory owned by this signer, in bytes: the signature
    /// template and the private key material.
    pub fn heap_size(&self) -> usize {
        self.key.heap_size() + self.template.heap_size()
    }
}

#[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rust-crypto"))]
impl<State> Dkim2Signer<State> {
    /// Approximate heap memory owned by this signer, in bytes: the domain,
    /// selectors, flags, nonce and private key material.
    pub fn heap_size(&self) -> usize {
        self.keys.capacity() * size_of::<KeyEntry>()
            + self
                .keys
                .iter()
                .map(|entry| entry.key.heap_size() + entry.selector.heap_size())
                .sum::<usize>()
            + self.domain.heap_size()
            + self.flags.capacity() * size_of::<Flag>()
            + self.nonce.heap_size()
    }
}

#[cfg(test)]
#[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rust-crypto"))]
mod test {
    use crate::{
        Error,
        crypto::{Ed25519Key, RsaKey, Sha256, SigningKey},
        dkim::{DkimSigner, DomainKey},
        dmarc::DmarcRecord,
        dns::{TxtRecord, TxtRecordParser},
        spf::SpfRecord,
    };
    use encodify::base64;
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, pem::PemObject};
    use std::{mem::size_of, sync::Arc};

    const ARC_HEADER: usize = 2 * size_of::<usize>();

    fn spf(record: &str) -> TxtRecord {
        TxtRecord::Spf(Arc::new(SpfRecord::parse(record.as_bytes()).unwrap()))
    }

    #[test]
    fn txt_record_heap_size() {
        // Every parsed record counts its shared allocation and grows with its content
        let small = spf("v=spf1 include:_spf.google.com ~all").heap_size();
        let large = spf(concat!(
            "v=spf1 ip4:192.0.2.0/24 include:_spf.google.com ",
            "include:spf.protection.outlook.com include:sendgrid.net a mx -all"
        ))
        .heap_size();
        assert!(small > ARC_HEADER + size_of::<SpfRecord>() + "_spf.google.com".len());
        assert!(large > small + "spf.protection.outlook.com".len() + "sendgrid.net".len());

        let dmarc = TxtRecord::Dmarc(Arc::new(
            DmarcRecord::parse(b"v=DMARC1; p=reject; rua=mailto:dmarc@example.org").unwrap(),
        ))
        .heap_size();
        assert!(dmarc >= ARC_HEADER + size_of::<DmarcRecord>() + "dmarc@example.org".len());

        let key = TxtRecord::DomainKey(Arc::new(
            DomainKey::parse(b"v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")
                .unwrap(),
        ))
        .heap_size();
        assert!(key >= ARC_HEADER + size_of::<DomainKey>() + 32);

        assert_eq!(TxtRecord::Error(Error::Parse).heap_size(), 0);
        assert_eq!(
            TxtRecord::Error(Error::Io("timeout".to_string())).heap_size(),
            "timeout".len()
        );
    }

    #[test]
    fn signer_heap_size() {
        // A signer counts its template strings and its private key material
        let rsa = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            PrivatePkcs1KeyDer::from_pem_slice(
                include_str!("../resources/rsa-private.pem").as_bytes(),
            )
            .unwrap(),
        ))
        .unwrap();
        let rsa_key = rsa.heap_size();
        assert!(rsa_key >= 2048 / 8 * 4);
        let signer = DkimSigner::from_key(rsa)
            .domain("example.org")
            .selector("default")
            .headers(["From", "To", "Subject"]);
        assert!(signer.heap_size() >= rsa_key + "example.org".len() + "default".len());

        let ed = Ed25519Key::from_seed_and_public_key(
            &base64::LENIENT
                .decode("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=")
                .unwrap(),
            &base64::LENIENT
                .decode("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")
                .unwrap(),
        )
        .unwrap();
        assert!(ed.heap_size() < rsa_key);
    }
}
