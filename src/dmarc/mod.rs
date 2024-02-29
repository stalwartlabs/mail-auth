/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{fmt::Display, sync::Arc};

use serde::{Deserialize, Serialize};

use crate::{DmarcOutput, DmarcResult, Error, Version};

pub mod parse;
pub mod verify;

#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub struct Dmarc {
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

#[derive(Debug, Hash, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct URI {
    pub uri: String,
    pub max_size: usize,
}

#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub(crate) enum Alignment {
    Relaxed,
    Strict,
}

#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub(crate) enum Psd {
    Yes,
    No,
    Default,
}

#[derive(Debug, Hash, Clone, PartialEq, Eq)]
pub enum Report {
    All,
    Any,
    Dkim,
    Spf,
    DkimSpf,
}

#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq)]
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

    pub fn uri(&self) -> &str {
        &self.uri
    }

    pub fn max_size(&self) -> usize {
        self.max_size
    }
}

impl From<Error> for DmarcResult {
    fn from(err: Error) -> Self {
        if matches!(&err, Error::DnsError(_)) {
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

    pub(crate) fn with_record(mut self, record: Arc<Dmarc>) -> Self {
        self.record = record.into();
        self
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn into_domain(self) -> String {
        self.domain
    }

    pub fn policy(&self) -> Policy {
        self.policy
    }

    pub fn dkim_result(&self) -> &DmarcResult {
        &self.dkim_result
    }

    pub fn spf_result(&self) -> &DmarcResult {
        &self.spf_result
    }

    pub fn dmarc_record(&self) -> Option<&Dmarc> {
        self.record.as_deref()
    }

    pub fn dmarc_record_cloned(&self) -> Option<Arc<Dmarc>> {
        self.record.clone()
    }

    pub fn requested_reports(&self) -> bool {
        self.record
            .as_ref()
            .map_or(false, |r| !r.rua.is_empty() || !r.ruf.is_empty())
    }

    /// Returns the failure reporting options
    pub fn failure_report(&self) -> Option<Report> {
        // Send failure reports
        match &self.record {
            Some(record)
                if !record.ruf.is_empty()
                    && ((self.dkim_result != DmarcResult::Pass
                        && matches!(record.fo, Report::Any | Report::Dkim | Report::DkimSpf))
                        || (self.spf_result != DmarcResult::Pass
                            && matches!(
                                record.fo,
                                Report::Any | Report::Spf | Report::DkimSpf
                            ))
                        || (self.dkim_result != DmarcResult::Pass
                            && self.spf_result != DmarcResult::Pass
                            && record.fo == Report::All)) =>
            {
                Some(record.fo.clone())
            }
            _ => None,
        }
    }
}

impl Dmarc {
    pub fn pct(&self) -> u8 {
        self.pct
    }

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
