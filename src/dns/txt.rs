/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! The parsed TXT record type stored in DNS caches.

use crate::{
    Error,
    dkim::{AtpsRecord, DkimReportRecord, DomainKey},
    dmarc::DmarcRecord,
    mta_sts::{MtaStsRecord, TlsRptRecord},
    spf::{Macro, SpfRecord},
};
use std::sync::Arc;

/// A parsed DNS TXT record, as stored in the TXT [`ResolverCache`] of a
/// [`DnsCache`].
///
/// [`MessageAuthenticator::txt_lookup`](crate::MessageAuthenticator::txt_lookup)
/// parses the TXT answer into the record type the caller asked for and caches
/// the outcome as a `TxtRecord`, so a cache hit skips both the query and the
/// parse. When no TXT record of the requested type parses, the error is
/// cached as [`TxtRecord::Error`]; DNS query failures are not cached. Each record type converts into its variant with
/// `From`, which lets cache implementations pre-populate entries.
///
/// [`ResolverCache`]: super::ResolverCache
/// [`DnsCache`]: super::DnsCache
#[derive(Clone)]
pub enum TxtRecord {
    /// An SPF record (RFC 7208 Section 4.5).
    Spf(Arc<SpfRecord>),
    /// The explanation string fetched from the target of an SPF `exp=`
    /// modifier (RFC 7208 Section 6.2), kept unexpanded.
    SpfExplanation(Arc<Macro>),
    /// A DKIM public key record (RFC 6376 Section 3.6.1).
    DomainKey(Arc<DomainKey>),
    /// A DKIM failure reporting record (RFC 6651 Section 3).
    DkimReport(Arc<DkimReportRecord>),
    /// A DMARC policy record (RFC 9989).
    Dmarc(Arc<DmarcRecord>),
    /// A DKIM Authorized Third-Party Signatures record (RFC 6541 Section 4).
    Atps(Arc<AtpsRecord>),
    /// An MTA-STS record (RFC 8461 Section 3.1).
    MtaSts(Arc<MtaStsRecord>),
    /// An SMTP TLS Reporting record (RFC 8460 Section 3).
    TlsRpt(Arc<TlsRptRecord>),
    /// No TXT record at the name parsed as the requested type. Holds the
    /// error returned to the caller.
    Error(Error),
}

/// Parser for a record type published in DNS TXT records.
///
/// Implemented by every record type that
/// [`MessageAuthenticator::txt_lookup`](crate::MessageAuthenticator::txt_lookup)
/// can fetch.
pub trait TxtRecordParser: Sized {
    /// Parses the contents of one TXT record, with its character strings
    /// already concatenated.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] with [`DnsError::InvalidRecordType`](crate::DnsError::InvalidRecordType)
    /// when the record is not of this type (for example, a missing or wrong
    /// version tag), or another [`Error`] when the record is of this type but
    /// malformed.
    fn parse(record: &[u8]) -> crate::Result<Self>;
}

mod private {
    pub trait Sealed {}
}

#[doc(hidden)]
pub trait UnwrapTxtRecord: private::Sealed + Sized {
    fn unwrap_txt(txt: TxtRecord) -> crate::Result<Arc<Self>>;
}

impl<T: Into<TxtRecord>> From<crate::Result<T>> for TxtRecord {
    fn from(v: crate::Result<T>) -> Self {
        match v {
            Ok(v) => v.into(),
            Err(err) => TxtRecord::Error(err),
        }
    }
}

macro_rules! txt_record {
    ($($record:ty => $variant:ident),+ $(,)?) => {
        $(
            impl From<$record> for TxtRecord {
                fn from(v: $record) -> Self {
                    TxtRecord::$variant(v.into())
                }
            }

            impl private::Sealed for $record {}

            impl UnwrapTxtRecord for $record {
                fn unwrap_txt(txt: TxtRecord) -> crate::Result<Arc<Self>> {
                    match txt {
                        TxtRecord::$variant(a) => Ok(a),
                        TxtRecord::Error(err) => Err(err),
                        _ => Err(Error::Io("Invalid record type".to_string())),
                    }
                }
            }
        )+
    };
}

txt_record!(
    DomainKey => DomainKey,
    DkimReportRecord => DkimReport,
    AtpsRecord => Atps,
    SpfRecord => Spf,
    Macro => SpfExplanation,
    DmarcRecord => Dmarc,
    MtaStsRecord => MtaSts,
    TlsRptRecord => TlsRpt,
);
