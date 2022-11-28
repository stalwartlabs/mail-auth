mod agg_parse;

use std::net::IpAddr;

#[derive(Default)]
pub struct DateRange {
    begin: u32,
    end: u32,
}

pub struct ReportMetadata {
    org_name: String,
    email: String,
    extra_contact_info: Option<String>,
    report_id: String,
    date_range: DateRange,
    error: Vec<String>,
}

pub enum Alignment {
    Relaxed,
    Simple,
    Unspecified,
}

pub enum Disposition {
    None,
    Quarantine,
    Reject,
    Unspecified,
}

pub enum ActionDisposition {
    None,
    Pass,
    Quarantine,
    Reject,
}

pub struct PolicyPublished {
    domain: String,
    version_published: Option<u32>,
    adkim: Alignment,
    aspf: Alignment,
    p: Disposition,
    sp: Disposition,
    testing: bool,
    fo: Option<String>,
}

pub enum DMARCResult {
    Pass,
    Fail,
}

pub enum PolicyOverride {
    Forwarded,
    SampledOut,
    TrustedForwarder,
    MailingList,
    LocalPolicy,
    Other,
}

pub struct PolicyOverrideReason {
    type_: PolicyOverride,
    comment: Option<String>,
}

pub struct PolicyEvaluated {
    disposition: ActionDisposition,
    dkim: DMARCResult,
    spf: DMARCResult,
    reason: Vec<PolicyOverrideReason>,
}

pub struct Row {
    source_ip: IpAddr,
    count: u32,
    policy_evaluated: PolicyEvaluated,
    extensions: Vec<Extension>,
}

pub struct Extension {
    extension: Option<String>,
    name: String,
    definition: String,
}

pub struct Identifier {
    envelope_to: Option<String>,
    envelope_from: String,
    header_from: String,
}

pub enum DKIMResult {
    None,
    Pass,
    Fail,
    Policy,
    Neutral,
    TempError,
    PermError,
}

pub struct DKIMAuthResult {
    domain: String,
    selector: String,
    result: DKIMResult,
    human_result: Option<String>,
}

pub enum SPFDomainScope {
    Helo,
    MailFrom,
    Undefined,
}

pub enum SPFResult {
    None,
    Neutral,
    Pass,
    Fail,
    SoftFail,
    TempError,
    PermError,
}

pub struct SPFAuthResult {
    domain: String,
    scope: SPFDomainScope,
    result: SPFResult,
    human_result: Option<String>,
}

pub struct AuthResult {
    dkim: Vec<DKIMAuthResult>,
    spf: Vec<SPFAuthResult>,
}

pub struct Record {
    row: Row,
    identifiers: Identifier,
    auth_results: AuthResult,
}

pub struct Feedback {
    version: u32,
    report_metadata: ReportMetadata,
    policy_published: PolicyPublished,
    record: Vec<Record>,
    extensions: Vec<Extension>,
}
