/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{fmt::Display, sync::Arc};

use crate::{DMARCOutput, DMARCResult, Error, Version};

pub mod parse;
pub mod verify;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DMARC {
    pub(crate) v: Version,
    pub(crate) adkim: Alignment,
    pub(crate) aspf: Alignment,
    pub(crate) fo: Report,
    pub(crate) np: Policy,
    pub(crate) p: Policy,
    pub(crate) psd: Psd,
    pub(crate) pct: u8,
    pub(crate) rf: u8,
    pub(crate) ri: u32,
    pub(crate) rua: Vec<URI>,
    pub(crate) ruf: Vec<URI>,
    pub(crate) sp: Policy,
    pub(crate) t: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub struct URI {
    uri: String,
    max_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Alignment {
    Relaxed,
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Psd {
    Yes,
    No,
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Report {
    All,
    Any,
    Dkim,
    Spf,
    DkimSpf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    None,
    Quarantine,
    Reject,
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Format {
    Afrf = 1,
}

impl From<Format> for u64 {
    fn from(f: Format) -> Self {
        f as u64
    }
}

impl URI {
    #[cfg(test)]
    pub fn new(uri: impl Into<String>, max_size: usize) -> Self {
        URI {
            uri: uri.into(),
            max_size,
        }
    }
}

impl From<Error> for DMARCResult {
    fn from(err: Error) -> Self {
        if matches!(&err, Error::DNSError) {
            DMARCResult::TempError(err)
        } else {
            DMARCResult::PermError(err)
        }
    }
}

impl Default for DMARCOutput {
    fn default() -> Self {
        Self {
            domain: String::new(),
            policy: Policy::None,
            record: None,
            spf_result: DMARCResult::None,
            dkim_result: DMARCResult::None,
        }
    }
}

impl DMARCOutput {
    pub(crate) fn with_domain(mut self, domain: &str) -> Self {
        self.domain = domain.to_string();
        self
    }

    pub(crate) fn with_spf_result(mut self, result: DMARCResult) -> Self {
        self.spf_result = result;
        self
    }

    pub(crate) fn with_dkim_result(mut self, result: DMARCResult) -> Self {
        self.dkim_result = result;
        self
    }

    pub(crate) fn with_record(mut self, record: Arc<DMARC>) -> Self {
        self.record = record.into();
        self
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn policy(&self) -> Policy {
        self.policy
    }

    pub fn dkim_result(&self) -> &DMARCResult {
        &self.dkim_result
    }

    pub fn spf_result(&self) -> &DMARCResult {
        &self.spf_result
    }

    pub fn dmarc_record(&self) -> Option<&DMARC> {
        self.record.as_deref()
    }

    /// Returns the failure reporting options
    pub fn failure_report(&self) -> Option<Report> {
        // Send failure reports
        match &self.record {
            Some(record)
                if !record.ruf.is_empty()
                    && (self.dkim_result != DMARCResult::Pass
                        && matches!(record.fo, Report::Any | Report::Dkim | Report::DkimSpf))
                    || (self.spf_result != DMARCResult::Pass
                        && matches!(record.fo, Report::Any | Report::Spf | Report::DkimSpf))
                    || (self.dkim_result != DMARCResult::Pass
                        && self.spf_result != DMARCResult::Pass
                        && record.fo == Report::All) =>
            {
                Some(record.fo.clone())
            }
            _ => None,
        }
    }
}

impl DMARC {
    pub fn ruf(&self) -> &[URI] {
        &self.ruf
    }

    pub fn rua(&self) -> &[URI] {
        &self.rua
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
