/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! The parsed TXT record type stored in DNS caches.

use crate::{
    Error,
    dkim::{AtpsRecord, DkimReportRecord, DomainKey},
    dkim2::DomainPolicy,
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
/// cached as [`TxtRecord::Invalid`], tagged with the requested type. A
/// negative answer (`NXDOMAIN` or NODATA) that carries an SOA record is
/// cached as [`TxtRecord::Error`], which applies to every type; resolver
/// failures are not cached. The cache is keyed by name only, so a lookup
/// treats an entry parsed as another type (a record or an
/// [`TxtRecord::Invalid`] of another kind) as a miss and queries again: a
/// lookup made for one purpose, such as an SPF `include:` of a `_dmarc` name,
/// cannot decide the outcome of another. Each record type converts into its
/// variant with `From` (and a `Result` of it into the variant or
/// [`TxtRecord::Invalid`]), which lets cache implementations pre-populate
/// entries.
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
    /// A DKIM2 Domain Policy Record (draft-ietf-dkim-dkim2-dns Section 5).
    Dkim2Policy(Arc<DomainPolicy>),
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
    /// No TXT record at the name parsed as the record type `kind`. Holds the
    /// error returned to lookups of that type; lookups of other types ignore
    /// the entry.
    Invalid {
        /// The record type whose parse failed.
        kind: TxtRecordKind,
        /// The parse error, boxed in an [`Arc`] to keep `TxtRecord` small.
        error: Arc<Error>,
    },
    /// The name has no TXT records (a negative answer), whatever the record
    /// type. Holds the error returned to the caller.
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

    /// Parses the TXT records found at one name, each with its character
    /// strings already concatenated. The default implementation returns the
    /// first record that [`parse`](Self::parse) accepts, or the error of the
    /// last one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Dns`] with [`DnsError::InvalidRecordType`](crate::DnsError::InvalidRecordType)
    /// when `records` is empty, or the error of the last record otherwise.
    fn parse_records(records: &[Vec<u8>]) -> crate::Result<Self> {
        let mut result = Err(Error::Dns(crate::DnsError::InvalidRecordType));
        for record in records {
            result = Self::parse(record);
            if result.is_ok() {
                break;
            }
        }
        result
    }
}

const _: () = assert!(size_of::<TxtRecord>() <= 32);

mod private {
    pub trait Sealed {}
}

#[doc(hidden)]
pub trait UnwrapTxtRecord: private::Sealed + Sized {
    const KIND: TxtRecordKind;

    fn unwrap_txt(txt: TxtRecord) -> Option<crate::Result<Arc<Self>>>;
}

impl<T: Into<TxtRecord> + UnwrapTxtRecord> From<crate::Result<T>> for TxtRecord {
    fn from(v: crate::Result<T>) -> Self {
        match v {
            Ok(v) => v.into(),
            Err(error) => TxtRecord::Invalid {
                kind: T::KIND,
                error: Arc::new(error),
            },
        }
    }
}

macro_rules! txt_record {
    ($($record:ty => $variant:ident),+ $(,)?) => {
        /// The record type of a [`TxtRecord`], used to tag
        /// [`TxtRecord::Invalid`] entries.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum TxtRecordKind {
            $(
                #[doc = concat!("[`", stringify!($record), "`] (`TxtRecord::", stringify!($variant), "`).")]
                $variant,
            )+
        }

        $(
            impl From<$record> for TxtRecord {
                fn from(v: $record) -> Self {
                    TxtRecord::$variant(v.into())
                }
            }

            impl private::Sealed for $record {}

            impl UnwrapTxtRecord for $record {
                const KIND: TxtRecordKind = TxtRecordKind::$variant;

                fn unwrap_txt(txt: TxtRecord) -> Option<crate::Result<Arc<Self>>> {
                    match txt {
                        TxtRecord::$variant(record) => Some(Ok(record)),
                        TxtRecord::Error(error) => Some(Err(error)),
                        TxtRecord::Invalid {
                            kind: TxtRecordKind::$variant,
                            error,
                        } => Some(Err(Arc::unwrap_or_clone(error))),
                        _ => None,
                    }
                }
            }
        )+
    };
}

txt_record!(
    DomainKey => DomainKey,
    DomainPolicy => Dkim2Policy,
    DkimReportRecord => DkimReport,
    AtpsRecord => Atps,
    SpfRecord => Spf,
    Macro => SpfExplanation,
    DmarcRecord => Dmarc,
    MtaStsRecord => MtaSts,
    TlsRptRecord => TlsRpt,
);
