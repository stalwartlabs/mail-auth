/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Domain-based Message Authentication, Reporting, and Conformance (DMARC).
//!
//! Implements DMARC policy discovery and evaluation as specified in
//! [RFC 9989](https://datatracker.ietf.org/doc/html/rfc9989), including the
//! DNS Tree Walk, Public Suffix Domain (`psd=`) handling and the external
//! reporting destination check. Reports themselves are covered by
//! [RFC 9990](https://datatracker.ietf.org/doc/html/rfc9990) (aggregate) and
//! [RFC 9991](https://datatracker.ietf.org/doc/html/rfc9991) (failure); see
//! the `report` module. Indirect mail flows are discussed in
//! [RFC 7960](https://datatracker.ietf.org/doc/html/rfc7960).
//!
//! The entry point is
//! [`MessageAuthenticator::verify_dmarc`](crate::MessageAuthenticator::verify_dmarc),
//! which takes the results of DKIM (and optionally DKIM2) and SPF
//! verification in [`DmarcParameters`](verify::DmarcParameters) and returns
//! a [`DmarcOutput`].

use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// Verification result types: [`DmarcOutput`] and [`DmarcResult`].
pub mod output;
/// Parser for `v=DMARC1` TXT records.
pub mod parse;
/// DMARC evaluation (RFC 9989, Section 4.10) and reporting address
/// authorization.
pub mod verify;

pub use output::{DmarcOutput, DmarcResult};

/// A DMARC Policy Record (RFC 9989, Section 4.7).
///
/// Parsed from a `v=DMARC1` DNS TXT record published at `_dmarc.<domain>`
/// and found by the DNS Tree Walk of
/// [`MessageAuthenticator::verify_dmarc`](crate::MessageAuthenticator::verify_dmarc),
/// which exposes the applied record through [`DmarcOutput::record`]. Each
/// field is named after its tag.
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub struct DmarcRecord {
    /// `adkim=`: DKIM identifier alignment mode (default relaxed).
    pub adkim: Alignment,
    /// `aspf=`: SPF identifier alignment mode (default relaxed).
    pub aspf: Alignment,
    /// `fo=`: failure reporting options (default `0`, [`FailureOptions::All`]).
    pub fo: FailureOptions,
    /// `np=`: policy for non-existent subdomains; defaults to `sp`.
    pub np: Policy,
    /// `p=`: policy for the domain itself; [`Policy::Unspecified`] when the
    /// tag is missing.
    pub p: Policy,
    /// `psd=`: whether the domain is a Public Suffix Domain.
    pub psd: Psd,
    /// `rua=`: destinations for aggregate reports (RFC 9990).
    pub rua: Vec<Uri>,
    /// `ruf=`: destinations for failure reports (RFC 9991).
    pub ruf: Vec<Uri>,
    /// `sp=`: policy for existing subdomains; defaults to `p`.
    pub sp: Policy,
    /// `t=`: test mode (`t=y`); the policy is applied one level less strictly.
    pub t: bool,
}

#[derive(Debug, Hash, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// A reporting destination from the `rua=` or `ruf=` tag of a DMARC record.
///
/// Only `mailto:` URIs are kept; the scheme is stripped and the address is
/// lowercased.
pub struct Uri {
    /// The destination email address, without the `mailto:` prefix.
    pub uri: String,
    /// Maximum report size in bytes from the `!size` suffix (`k`, `m`, `g`
    /// and `t` units are expanded); `0` when no limit was given.
    pub max_size: usize,
}

#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Identifier alignment mode, the `adkim=` and `aspf=` tags (checked as
/// described in RFC 9989, Section 4.10.2). Displays as `r` or `s`.
pub enum Alignment {
    /// `r`: the identifier's Organizational Domain must match the Author
    /// Domain's.
    Relaxed,
    /// `s`: the identifier must match the Author Domain exactly.
    Strict,
}

/// The `psd=` tag of a DMARC record (RFC 9989, Section 4.7).
///
/// Both `Yes` and `No` stop the DNS Tree Walk and fix the Organizational
/// Domain.
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub enum Psd {
    /// `psd=y`: the domain is a Public Suffix Domain; the Organizational
    /// Domain is one label below it.
    Yes,
    /// `psd=n`: the domain is not a PSD; it is the Organizational Domain.
    No,
    /// `psd=u` or no tag: determined by the Tree Walk.
    Default,
}

/// The `fo=` tag of a DMARC record: when to generate failure reports
/// (RFC 9991).
#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub enum FailureOptions {
    /// `0`: report when all mechanisms fail to produce an aligned pass
    /// (default).
    All,
    /// `1`: report when any mechanism fails to produce an aligned pass.
    Any,
    /// `d`: report when DKIM does not produce an aligned pass.
    Dkim,
    /// `s`: report when SPF does not produce an aligned pass.
    Spf,
    /// `d:s`: report when either DKIM or SPF does not produce an aligned
    /// pass.
    DkimSpf,
}

#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
/// A requested handling policy, the `p=`, `sp=` and `np=` tags (RFC 9989,
/// Section 4.7). Displays as `none`, `quarantine` or `reject`.
pub enum Policy {
    /// `none`: no specific action requested.
    None,
    /// `quarantine`: treat failing mail as suspicious.
    Quarantine,
    /// `reject`: reject failing mail.
    Reject,
    /// The tag is absent. Displays as `none`.
    #[default]
    Unspecified,
}

impl Uri {
    /// Creates a destination (test helper).
    #[cfg(test)]
    pub fn new(uri: impl Into<String>, max_size: usize) -> Self {
        Uri {
            uri: uri.into(),
            max_size,
        }
    }

    /// Returns the destination email address.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Returns the maximum report size in bytes, or `0` for no limit.
    pub fn max_size(&self) -> usize {
        self.max_size
    }
}

impl DmarcRecord {
    /// Returns the failure report destinations (`ruf=`).
    pub fn ruf(&self) -> &[Uri] {
        &self.ruf
    }

    /// Returns the aggregate report destinations (`rua=`).
    pub fn rua(&self) -> &[Uri] {
        &self.rua
    }
}

impl Display for Alignment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Alignment::Relaxed => "r",
            Alignment::Strict => "s",
        })
    }
}

impl Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Policy::Quarantine => "quarantine",
            Policy::Reject => "reject",
            Policy::None | Policy::Unspecified => "none",
        })
    }
}

impl AsRef<str> for Uri {
    fn as_ref(&self) -> &str {
        &self.uri
    }
}
