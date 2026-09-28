/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{DmarcRecord, FailureOptions, Policy};
use crate::{DnsError, Error};
use std::{fmt::Display, sync::Arc};

/// The outcome of DMARC evaluation.
///
/// Returned by
/// [`MessageAuthenticator::verify_dmarc`](crate::MessageAuthenticator::verify_dmarc).
/// It holds the Author Domain, the policy to apply, the aligned SPF and DKIM
/// results and the DMARC Policy Record that was applied, if any.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DmarcOutput {
    pub(crate) spf_result: DmarcResult,
    pub(crate) dkim_result: DmarcResult,
    pub(crate) domain: String,
    pub(crate) policy: Policy,
    pub(crate) record: Option<Arc<DmarcRecord>>,
}

/// A DMARC result (RFC 9989, Section 4.10), either for one mechanism
/// ([`DmarcOutput::spf_result`], [`DmarcOutput::dkim_result`]) or overall
/// ([`DmarcOutput::result`]).
///
/// Displays as `pass`, `none`, or the variant name followed by the error
/// (for example `fail; <error>`).
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DmarcResult {
    /// The mechanism passed with an identifier aligned with the Author
    /// Domain.
    Pass,
    /// The mechanism did not produce an aligned pass; usually carries
    /// [`Error::NotAligned`].
    Fail(crate::Error),
    /// A transient DNS error prevented evaluation (RFC 9989, Section 5.3.6):
    /// DMARC can neither pass nor fail.
    TempError(crate::Error),
    /// A permanent error while discovering the DMARC record.
    PermError(crate::Error),
    /// DMARC does not apply: no usable RFC5322.From domain, no DMARC record,
    /// or no result for this mechanism.
    None,
}

impl From<Error> for DmarcResult {
    fn from(err: Error) -> Self {
        if matches!(&err, Error::Dns(DnsError::Resolver(_))) {
            DmarcResult::TempError(err)
        } else {
            DmarcResult::PermError(err)
        }
    }
}

impl Default for DmarcOutput {
    fn default() -> Self {
        Self {
            domain: String::new(),
            policy: Policy::None,
            record: None,
            spf_result: DmarcResult::None,
            dkim_result: DmarcResult::None,
        }
    }
}

impl DmarcOutput {
    pub(crate) fn with_domain(mut self, domain: &str) -> Self {
        self.domain = domain.to_string();
        self
    }

    pub(crate) fn with_spf_result(mut self, result: DmarcResult) -> Self {
        self.spf_result = result;
        self
    }

    pub(crate) fn with_dkim_result(mut self, result: DmarcResult) -> Self {
        self.dkim_result = result;
        self
    }

    pub(crate) fn with_record(mut self, record: Arc<DmarcRecord>) -> Self {
        self.record = record.into();
        self
    }

    /// Returns the Author Domain (the RFC5322.From domain, as an A-label), or
    /// an empty string when none could be determined.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Consumes the output and returns the Author Domain.
    pub fn into_domain(self) -> String {
        self.domain
    }

    /// Returns the policy to apply to a failing message: `p`, `sp` or `np`
    /// of the applied record depending on where it was found, lowered by one
    /// level in test mode (`t=y`). [`Policy::None`] when DMARC does not
    /// apply.
    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// Returns the DKIM alignment result: `Pass` when a passing DKIM (or
    /// DKIM2 instance 1) signature is aligned, `Fail` when signatures passed
    /// but none aligned, `TempError` on a DNS error affecting an aligned
    /// identifier, `None` when no signature passed.
    pub fn dkim_result(&self) -> &DmarcResult {
        &self.dkim_result
    }

    /// Returns the SPF alignment result: `Pass` when SPF passed for an
    /// aligned MAIL FROM domain, `Fail` when SPF passed but the domain is not
    /// aligned, `TempError` when SPF returned `temperror` for an aligned
    /// domain or alignment hit a DNS error, `None` otherwise.
    pub fn spf_result(&self) -> &DmarcResult {
        &self.spf_result
    }

    /// Returns the overall DMARC result: the best of the SPF and DKIM
    /// results, ranked `Pass`, `TempError`, `PermError`, `Fail`. When both
    /// are `None`, returns `Fail` with [`Error::NotAligned`] if a record was
    /// applied and `None` otherwise.
    pub fn result(&self) -> DmarcResult {
        match self.mechanism_result() {
            Some(result) => result.clone(),
            None if self.record.is_some() => DmarcResult::Fail(Error::NotAligned),
            None => DmarcResult::None,
        }
    }

    pub(crate) fn mechanism_result(&self) -> Option<&DmarcResult> {
        [&self.spf_result, &self.dkim_result]
            .into_iter()
            .filter_map(|result| {
                let rank = match result {
                    DmarcResult::Pass => 0,
                    DmarcResult::TempError(_) => 1,
                    DmarcResult::PermError(_) => 2,
                    DmarcResult::Fail(_) => 3,
                    DmarcResult::None => return None,
                };
                Some((rank, result))
            })
            .min_by_key(|(rank, _)| *rank)
            .map(|(_, result)| result)
    }

    /// Returns the DMARC Policy Record that was applied, if any.
    pub fn record(&self) -> Option<&Arc<DmarcRecord>> {
        self.record.as_ref()
    }

    /// Returns `true` when the applied record has a `rua=` or `ruf=` tag
    /// with at least one destination.
    pub fn requests_reports(&self) -> bool {
        self.record
            .as_ref()
            .is_some_and(|r| !r.rua.is_empty() || !r.ruf.is_empty())
    }

    /// Returns the `fo=` options of the applied record when a failure report
    /// (RFC 9991) should be sent for this message: the record has `ruf=`
    /// destinations, the result is not a temporary error, and the failed
    /// mechanisms match `fo=`. Returns `None` otherwise.
    pub fn failure_report(&self) -> Option<FailureOptions> {
        match &self.record {
            Some(record)
                if !record.ruf.is_empty()
                    && !matches!(self.mechanism_result(), Some(DmarcResult::TempError(_)))
                    && ((self.dkim_result != DmarcResult::Pass
                        && matches!(
                            record.fo,
                            FailureOptions::Any | FailureOptions::Dkim | FailureOptions::DkimSpf
                        ))
                        || (self.spf_result != DmarcResult::Pass
                            && matches!(
                                record.fo,
                                FailureOptions::Any | FailureOptions::Spf | FailureOptions::DkimSpf
                            ))
                        || (self.dkim_result != DmarcResult::Pass
                            && self.spf_result != DmarcResult::Pass
                            && record.fo == FailureOptions::All)) =>
            {
                Some(record.fo.clone())
            }
            _ => None,
        }
    }
}

impl Display for DmarcResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DmarcResult::Pass => f.write_str("pass"),
            DmarcResult::Fail(err) => write!(f, "fail; {err}"),
            DmarcResult::TempError(err) => write!(f, "temp error; {err}"),
            DmarcResult::PermError(err) => write!(f, "perm error; {err}"),
            DmarcResult::None => f.write_str("none"),
        }
    }
}
