mod feedback;

use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DateRange {
    begin: u64,
    end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReportMetadata {
    org_name: String,
    email: String,
    extra_contact_info: Option<String>,
    report_id: String,
    date_range: DateRange,
    error: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Alignment {
    Relaxed,
    Strict,
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Disposition {
    None,
    Quarantine,
    Reject,
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionDisposition {
    None,
    Pass,
    Quarantine,
    Reject,
    Unspecified,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct PolicyPublished {
    domain: String,
    version_published: Option<f32>,
    adkim: Alignment,
    aspf: Alignment,
    p: Disposition,
    sp: Disposition,
    testing: bool,
    fo: Option<String>,
}

impl Eq for PolicyPublished {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DMARCResult {
    Pass,
    Fail,
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyOverride {
    Forwarded,
    SampledOut,
    TrustedForwarder,
    MailingList,
    LocalPolicy,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PolicyOverrideReason {
    type_: PolicyOverride,
    comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PolicyEvaluated {
    disposition: ActionDisposition,
    dkim: DMARCResult,
    spf: DMARCResult,
    reason: Vec<PolicyOverrideReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    source_ip: IpAddr,
    count: u32,
    policy_evaluated: PolicyEvaluated,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Extension {
    name: String,
    definition: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Identifier {
    envelope_to: Option<String>,
    envelope_from: String,
    header_from: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DKIMResult {
    None,
    Pass,
    Fail,
    Policy,
    Neutral,
    TempError,
    PermError,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DKIMAuthResult {
    domain: String,
    selector: String,
    result: DKIMResult,
    human_result: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SPFDomainScope {
    Helo,
    MailFrom,
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SPFResult {
    None,
    Neutral,
    Pass,
    Fail,
    SoftFail,
    TempError,
    PermError,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SPFAuthResult {
    domain: String,
    scope: SPFDomainScope,
    result: SPFResult,
    human_result: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AuthResult {
    dkim: Vec<DKIMAuthResult>,
    spf: Vec<SPFAuthResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Record {
    row: Row,
    identifiers: Identifier,
    auth_results: AuthResult,
    extensions: Vec<Extension>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Feedback {
    version: f32,
    report_metadata: ReportMetadata,
    policy_published: PolicyPublished,
    record: Vec<Record>,
    extensions: Vec<Extension>,
}

impl Eq for Feedback {}

impl Default for Row {
    fn default() -> Self {
        Self {
            source_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            count: 0,
            policy_evaluated: PolicyEvaluated::default(),
        }
    }
}

impl Default for Alignment {
    fn default() -> Self {
        Alignment::Unspecified
    }
}

impl Default for Disposition {
    fn default() -> Self {
        Disposition::Unspecified
    }
}

impl Default for ActionDisposition {
    fn default() -> Self {
        ActionDisposition::None
    }
}

impl Default for DMARCResult {
    fn default() -> Self {
        DMARCResult::Unspecified
    }
}

impl Default for PolicyOverride {
    fn default() -> Self {
        PolicyOverride::Other
    }
}

impl Default for DKIMResult {
    fn default() -> Self {
        DKIMResult::None
    }
}

impl Default for SPFResult {
    fn default() -> Self {
        SPFResult::None
    }
}

impl Default for SPFDomainScope {
    fn default() -> Self {
        SPFDomainScope::Unspecified
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    MailParseError,
    ReportParseError(String),
    UncompressError(String),
    NoReportsFound,
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::ReportParseError(err)
    }
}
