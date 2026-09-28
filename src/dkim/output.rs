/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! DKIM1 verification results: [`DkimResult`] and [`DkimOutput`].

use super::Signature;
use crate::{DnsError, Error};
use std::fmt::Display;

/// The outcome of verifying one DKIM1 signature, using the result names of
/// RFC 8601, Section 2.7.1.
///
/// Produced by [`MessageAuthenticator::verify_dkim`](crate::MessageAuthenticator::verify_dkim)
/// inside each [`DkimOutput`]. Every variant other than `Pass` and `None`
/// carries the error that caused it.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DkimResult {
    /// The signature verified.
    Pass,
    /// The signature could not be evaluated: it is malformed, uses an
    /// unsupported version, algorithm or canonicalization, was ignored for
    /// carrying `l=` in strict mode, has expired, or its body hash does not
    /// match the message.
    Neutral(crate::Error),
    /// The signature was evaluated and is invalid: the cryptographic check
    /// failed or the `i=` domain does not match `d=`.
    Fail(crate::Error),
    /// A permanent error while fetching the key: the key record does not
    /// exist, is invalid, has been revoked or uses an unsupported key type.
    PermError(crate::Error),
    /// A transient DNS error while fetching the key; retrying later may
    /// succeed.
    TempError(crate::Error),
    /// No signature was evaluated. `verify_dkim` never returns it (a message
    /// without signatures yields an empty vector); it appears in other
    /// outputs, such as ARC, when there is nothing to verify.
    None,
}

/// The verification result of one DKIM1 signature.
///
/// [`MessageAuthenticator::verify_dkim`](crate::MessageAuthenticator::verify_dkim)
/// returns one output per parsed `DKIM-Signature` header, plus a `neutral`
/// output without a signature for each header rejected with an
/// [`Error::Dkim`] error (such as an unsupported algorithm
/// or version). Headers that fail to parse for other reasons, such as a
/// missing tag or invalid base64, produce no output. Besides the
/// [`DkimResult`], it records the parsed signature (when the header could be
/// parsed), the RFC 6651 failure report address and whether the result comes
/// from an RFC 6541 ATPS check. Use `From<DkimResult>` and
/// [`with_signature`](Self::with_signature) to synthesize an output, for
/// example in tests or when feeding DMARC, which needs the signature's `d=`
/// domain for alignment.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DkimOutput<'x> {
    pub(crate) result: DkimResult,
    pub(crate) signature: Option<&'x Signature>,
    pub(crate) report: Option<String>,
    pub(crate) is_atps: bool,
}

impl<'x> DkimOutput<'x> {
    pub(crate) fn pass() -> Self {
        DkimOutput {
            result: DkimResult::Pass,
            signature: None,
            report: None,
            is_atps: false,
        }
    }

    pub(crate) fn perm_err(err: Error) -> Self {
        DkimOutput {
            result: DkimResult::PermError(err),
            signature: None,
            report: None,
            is_atps: false,
        }
    }

    pub(crate) fn temp_err(err: Error) -> Self {
        DkimOutput {
            result: DkimResult::TempError(err),
            signature: None,
            report: None,
            is_atps: false,
        }
    }

    pub(crate) fn fail(err: Error) -> Self {
        DkimOutput {
            result: DkimResult::Fail(err),
            signature: None,
            report: None,
            is_atps: false,
        }
    }

    pub(crate) fn neutral(err: Error) -> Self {
        DkimOutput {
            result: DkimResult::Neutral(err),
            signature: None,
            report: None,
            is_atps: false,
        }
    }

    pub(crate) fn dns_error(err: Error) -> Self {
        if matches!(&err, Error::Dns(DnsError::Resolver(_))) {
            DkimOutput::temp_err(err)
        } else {
            DkimOutput::perm_err(err)
        }
    }

    /// Attaches the signature this result refers to.
    ///
    /// Used to build an output outside the verifier, for example from a
    /// cached result, so that DMARC can check its `d=` domain for alignment.
    pub fn with_signature(mut self, signature: &'x Signature) -> Self {
        self.signature = signature.into();
        self
    }

    pub(crate) fn with_atps(mut self) -> Self {
        self.is_atps = true;
        self
    }

    /// Returns the verification result.
    pub fn result(&self) -> &DkimResult {
        &self.result
    }

    /// Returns the parsed signature this result refers to, or `None` when the
    /// `DKIM-Signature` header could not be parsed.
    pub fn signature(&self) -> Option<&Signature> {
        self.signature
    }

    /// Returns the address to send an RFC 6651 failure report to.
    ///
    /// Set only when the signature has `r=y`, did not pass, the signer's
    /// `_report._domainkey.<d>` record exists, the `rp=` sampling percentage
    /// selected this failure and the `rr=` tag requests reports for this kind
    /// of failure. The address is `<ra>@<d>`.
    pub fn report_address(&self) -> Option<&str> {
        self.report.as_deref()
    }

    /// Returns `true` when the result comes from an RFC 6541 ATPS check: the
    /// signature verified, its `atps=` domain matched the `From` domain and
    /// the ATPS record lookup determined the result.
    pub fn is_atps(&self) -> bool {
        self.is_atps
    }
}

impl From<DkimResult> for DkimOutput<'_> {
    fn from(result: DkimResult) -> Self {
        DkimOutput {
            result,
            signature: None,
            report: None,
            is_atps: false,
        }
    }
}

impl From<Error> for DkimResult {
    fn from(err: Error) -> Self {
        if matches!(&err, Error::Dns(DnsError::Resolver(_))) {
            DkimResult::TempError(err)
        } else {
            DkimResult::PermError(err)
        }
    }
}

impl Display for DkimResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DkimResult::Pass => f.write_str("pass"),
            DkimResult::Fail(err) => write!(f, "fail; {err}"),
            DkimResult::Neutral(err) => write!(f, "neutral; {err}"),
            DkimResult::TempError(err) => write!(f, "temp error; {err}"),
            DkimResult::PermError(err) => write!(f, "perm error; {err}"),
            DkimResult::None => f.write_str("none"),
        }
    }
}
