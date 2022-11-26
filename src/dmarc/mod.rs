use std::{fmt::Display, sync::Arc};

use crate::{DMARCOutput, DMARCResult, Error, Version};

pub mod parse;
pub mod verify;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DMARC {
    v: Version,
    adkim: Alignment,
    aspf: Alignment,
    fo: Report,
    np: Policy,
    p: Policy,
    psd: Psd,
    pct: u8,
    rf: u8,
    ri: u32,
    rua: Vec<URI>,
    ruf: Vec<URI>,
    sp: Policy,
    t: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub(crate) struct URI {
    uri: Vec<u8>,
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
pub(crate) enum Report {
    All,
    Any,
    Dkim,
    Spf,
    DkimSpf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Policy {
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
            uri: uri.into().into_bytes(),
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
            result: DMARCResult::None,
            domain: String::new(),
            policy: Policy::None,
            record: None,
        }
    }
}

impl DMARCOutput {
    pub(crate) fn with_domain(mut self, domain: &str) -> Self {
        self.domain = domain.to_string();
        self
    }

    pub(crate) fn with_result(mut self, result: DMARCResult) -> Self {
        self.result = result;
        self
    }

    pub(crate) fn with_policy(mut self, policy: Policy) -> Self {
        self.policy = policy;
        self
    }

    pub(crate) fn with_record(mut self, record: Arc<DMARC>) -> Self {
        self.record = record.into();
        self
    }
}

impl Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Policy::Quarantine => "quarantine",
                Policy::Reject => "reject",
                Policy::None | Policy::Unspecified => "none",
            }
        )
    }
}
