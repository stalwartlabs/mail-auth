/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

pub mod generate;
pub mod parse;

use std::fmt::Write;
use std::net::IpAddr;

use crate::{
    dmarc::Dmarc,
    report::{
        ActionDisposition, Alignment, DKIMAuthResult, Disposition, DkimResult, DmarcResult,
        PolicyOverride, PolicyOverrideReason, Record, Report, SPFAuthResult, SPFDomainScope,
        SpfResult,
    },
    ArcOutput, DkimOutput, DmarcOutput, SpfOutput,
};

use super::PolicyPublished;

impl Report {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn version(&self) -> f32 {
        self.version
    }

    pub fn with_version(mut self, version: f32) -> Self {
        self.version = version;
        self
    }

    pub fn org_name(&self) -> &str {
        &self.report_metadata.org_name
    }

    pub fn with_org_name(mut self, org_name: impl Into<String>) -> Self {
        self.report_metadata.org_name = org_name.into();
        self
    }

    pub fn email(&self) -> &str {
        &self.report_metadata.email
    }

    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.report_metadata.email = email.into();
        self
    }

    pub fn extra_contact_info(&self) -> Option<&str> {
        self.report_metadata.extra_contact_info.as_deref()
    }

    pub fn with_extra_contact_info(mut self, extra_contact_info: impl Into<String>) -> Self {
        self.report_metadata.extra_contact_info = Some(extra_contact_info.into());
        self
    }

    pub fn report_id(&self) -> &str {
        &self.report_metadata.report_id
    }

    pub fn with_report_id(mut self, report_id: impl Into<String>) -> Self {
        self.report_metadata.report_id = report_id.into();
        self
    }

    pub fn date_range_begin(&self) -> u64 {
        self.report_metadata.date_range.begin
    }

    pub fn with_date_range_begin(mut self, date_range_begin: u64) -> Self {
        self.report_metadata.date_range.begin = date_range_begin;
        self
    }

    pub fn date_range_end(&self) -> u64 {
        self.report_metadata.date_range.end
    }

    pub fn with_date_range_end(mut self, date_range_end: u64) -> Self {
        self.report_metadata.date_range.end = date_range_end;
        self
    }

    pub fn error(&self) -> &[String] {
        &self.report_metadata.error
    }

    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.report_metadata.error.push(error.into());
        self
    }

    pub fn domain(&self) -> &str {
        &self.policy_published.domain
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.policy_published.domain = domain.into();
        self
    }

    pub fn fo(&self) -> Option<&str> {
        self.policy_published.fo.as_deref()
    }

    pub fn with_fo(mut self, fo: impl Into<String>) -> Self {
        self.policy_published.fo = Some(fo.into());
        self
    }

    pub fn version_published(&self) -> Option<f32> {
        self.policy_published.version_published
    }

    pub fn with_version_published(mut self, version_published: f32) -> Self {
        self.policy_published.version_published = Some(version_published);
        self
    }

    pub fn adkim(&self) -> Alignment {
        self.policy_published.adkim
    }

    pub fn with_adkim(mut self, adkim: Alignment) -> Self {
        self.policy_published.adkim = adkim;
        self
    }

    pub fn aspf(&self) -> Alignment {
        self.policy_published.aspf
    }

    pub fn with_aspf(mut self, aspf: Alignment) -> Self {
        self.policy_published.aspf = aspf;
        self
    }

    pub fn p(&self) -> Disposition {
        self.policy_published.p
    }

    pub fn with_p(mut self, p: Disposition) -> Self {
        self.policy_published.p = p;
        self
    }

    pub fn sp(&self) -> Disposition {
        self.policy_published.sp
    }

    pub fn with_sp(mut self, sp: Disposition) -> Self {
        self.policy_published.sp = sp;
        self
    }

    pub fn testing(&self) -> bool {
        self.policy_published.testing
    }

    pub fn with_testing(mut self, testing: bool) -> Self {
        self.policy_published.testing = testing;
        self
    }

    pub fn records(&self) -> &[Record] {
        &self.record
    }

    pub fn with_record(mut self, record: Record) -> Self {
        self.record.push(record);
        self
    }

    pub fn add_record(&mut self, record: Record) {
        self.record.push(record);
    }

    pub fn with_policy_published(mut self, policy_published: PolicyPublished) -> Self {
        self.policy_published = policy_published;
        self
    }
}

impl Record {
    pub fn new() -> Self {
        Record::default()
    }

    pub fn with_dkim_output(mut self, dkim_output: &[DkimOutput]) -> Self {
        for dkim in dkim_output {
            if let Some(signature) = &dkim.signature {
                let (result, human_result) = match &dkim.result {
                    crate::DkimResult::Pass => (DkimResult::Pass, None),
                    crate::DkimResult::Neutral(err) => {
                        (DkimResult::Neutral, err.to_string().into())
                    }
                    crate::DkimResult::Fail(err) => (DkimResult::Fail, err.to_string().into()),
                    crate::DkimResult::PermError(err) => {
                        (DkimResult::PermError, err.to_string().into())
                    }
                    crate::DkimResult::TempError(err) => {
                        (DkimResult::TempError, err.to_string().into())
                    }
                    crate::DkimResult::None => (DkimResult::None, None),
                };

                self.auth_results.dkim.push(DKIMAuthResult {
                    domain: signature.d.to_string(),
                    selector: signature.s.to_string(),
                    result,
                    human_result,
                });
            }
        }
        self
    }

    pub fn with_spf_output(mut self, spf_output: &SpfOutput, scope: SPFDomainScope) -> Self {
        self.auth_results.spf.push(SPFAuthResult {
            domain: spf_output.domain.to_string(),
            scope,
            result: match spf_output.result {
                crate::SpfResult::Pass => SpfResult::Pass,
                crate::SpfResult::Fail => SpfResult::Fail,
                crate::SpfResult::SoftFail => SpfResult::SoftFail,
                crate::SpfResult::Neutral => SpfResult::Neutral,
                crate::SpfResult::TempError => SpfResult::TempError,
                crate::SpfResult::PermError => SpfResult::PermError,
                crate::SpfResult::None => SpfResult::None,
            },
            human_result: None,
        });
        self
    }

    pub fn with_dmarc_output(mut self, dmarc_output: &DmarcOutput) -> Self {
        self.row.policy_evaluated.disposition = if dmarc_output.dkim_result
            == crate::DmarcResult::Pass
            || dmarc_output.spf_result == crate::DmarcResult::Pass
        {
            ActionDisposition::Pass
        } else {
            match dmarc_output.policy {
                crate::dmarc::Policy::None => ActionDisposition::None,
                crate::dmarc::Policy::Quarantine => ActionDisposition::Quarantine,
                crate::dmarc::Policy::Reject => ActionDisposition::Reject,
                crate::dmarc::Policy::Unspecified => ActionDisposition::None,
            }
        };
        self.row.policy_evaluated.dkim = (&dmarc_output.dkim_result).into();
        self.row.policy_evaluated.spf = (&dmarc_output.spf_result).into();
        self
    }

    pub fn with_arc_output(mut self, arc_output: &ArcOutput) -> Self {
        if arc_output.result == crate::DkimResult::Pass {
            let mut comment = "arc=pass".to_string();
            for set in arc_output.set.iter().rev() {
                let seal = &set.seal.header;
                write!(
                    &mut comment,
                    " as[{}].d={} as[{}].s={}",
                    seal.i, seal.d, seal.i, seal.s
                )
                .ok();
            }
            self.row
                .policy_evaluated
                .reason
                .push(PolicyOverrideReason::new(PolicyOverride::LocalPolicy).with_comment(comment));
        }
        self
    }

    pub fn source_ip(&self) -> Option<IpAddr> {
        self.row.source_ip
    }

    pub fn with_source_ip(mut self, source_ip: IpAddr) -> Self {
        self.row.source_ip = source_ip.into();
        self
    }

    pub fn count(&self) -> u32 {
        self.row.count
    }

    pub fn with_count(mut self, count: u32) -> Self {
        self.row.count = count;
        self
    }

    pub fn action_disposition(&self) -> ActionDisposition {
        self.row.policy_evaluated.disposition
    }

    pub fn with_action_disposition(mut self, disposition: ActionDisposition) -> Self {
        self.row.policy_evaluated.disposition = disposition;
        self
    }

    pub fn dmarc_dkim_result(&self) -> DmarcResult {
        self.row.policy_evaluated.dkim
    }

    pub fn with_dmarc_dkim_result(mut self, dkim: DmarcResult) -> Self {
        self.row.policy_evaluated.dkim = dkim;
        self
    }

    pub fn dmarc_spf_result(&self) -> DmarcResult {
        self.row.policy_evaluated.spf
    }

    pub fn with_dmarc_spf_result(mut self, spf: DmarcResult) -> Self {
        self.row.policy_evaluated.spf = spf;
        self
    }

    pub fn policy_override_reason(&self) -> &[PolicyOverrideReason] {
        &self.row.policy_evaluated.reason
    }

    pub fn with_policy_override_reason(mut self, reason: PolicyOverrideReason) -> Self {
        self.row.policy_evaluated.reason.push(reason);
        self
    }

    pub fn envelope_from(&self) -> &str {
        &self.identifiers.envelope_from
    }

    pub fn with_envelope_from(mut self, envelope_from: impl Into<String>) -> Self {
        self.identifiers.envelope_from = envelope_from.into();
        self
    }

    pub fn header_from(&self) -> &str {
        &self.identifiers.header_from
    }

    pub fn with_header_from(mut self, header_from: impl Into<String>) -> Self {
        self.identifiers.header_from = header_from.into();
        self
    }

    pub fn envelope_to(&self) -> Option<&str> {
        self.identifiers.envelope_to.as_deref()
    }

    pub fn with_envelope_to(mut self, envelope_to: impl Into<String>) -> Self {
        self.identifiers.envelope_to = Some(envelope_to.into());
        self
    }

    pub fn dkim_auth_result(&self) -> &[DKIMAuthResult] {
        &self.auth_results.dkim
    }

    pub fn with_dkim_auth_result(mut self, auth_result: DKIMAuthResult) -> Self {
        self.auth_results.dkim.push(auth_result);
        self
    }

    pub fn spf_auth_result(&self) -> &[SPFAuthResult] {
        &self.auth_results.spf
    }

    pub fn with_spf_auth_result(mut self, auth_result: SPFAuthResult) -> Self {
        self.auth_results.spf.push(auth_result);
        self
    }
}

impl PolicyPublished {
    pub fn from_record(domain: impl Into<String>, dmarc: &Dmarc) -> Self {
        PolicyPublished {
            domain: domain.into(),
            adkim: (&dmarc.adkim).into(),
            aspf: (&dmarc.aspf).into(),
            p: (&dmarc.p).into(),
            sp: (&dmarc.sp).into(),
            testing: dmarc.t,
            fo: match &dmarc.fo {
                crate::dmarc::Report::All => "0",
                crate::dmarc::Report::Any => "1",
                crate::dmarc::Report::Dkim => "d",
                crate::dmarc::Report::Spf => "s",
                crate::dmarc::Report::DkimSpf => "d:s",
            }
            .to_string()
            .into(),
            version_published: None,
        }
    }
}

impl DKIMAuthResult {
    pub fn new() -> Self {
        DKIMAuthResult::default()
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into();
        self
    }

    pub fn selector(&self) -> &str {
        &self.selector
    }

    pub fn with_selector(mut self, selector: impl Into<String>) -> Self {
        self.selector = selector.into();
        self
    }

    pub fn result(&self) -> DkimResult {
        self.result
    }

    pub fn with_result(mut self, result: DkimResult) -> Self {
        self.result = result;
        self
    }

    pub fn human_result(&self) -> Option<&str> {
        self.human_result.as_deref()
    }

    pub fn with_human_result(mut self, human_result: impl Into<String>) -> Self {
        self.human_result = Some(human_result.into());
        self
    }
}

impl SPFAuthResult {
    pub fn new() -> Self {
        SPFAuthResult::default()
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = domain.into();
        self
    }

    pub fn scope(&self) -> SPFDomainScope {
        self.scope
    }

    pub fn with_scope(mut self, scope: SPFDomainScope) -> Self {
        self.scope = scope;
        self
    }

    pub fn result(&self) -> SpfResult {
        self.result
    }

    pub fn with_result(mut self, result: SpfResult) -> Self {
        self.result = result;
        self
    }

    pub fn human_result(&self) -> Option<&str> {
        self.human_result.as_deref()
    }

    pub fn with_human_result(mut self, human_result: impl Into<String>) -> Self {
        self.human_result = Some(human_result.into());
        self
    }
}

impl PolicyOverrideReason {
    pub fn new(type_: PolicyOverride) -> Self {
        PolicyOverrideReason {
            type_,
            comment: None,
        }
    }

    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    pub fn policy_override(&self) -> PolicyOverride {
        self.type_
    }
}

impl From<&crate::DmarcResult> for DmarcResult {
    fn from(result: &crate::DmarcResult) -> Self {
        match result {
            crate::DmarcResult::Pass => DmarcResult::Pass,
            _ => DmarcResult::Fail,
        }
    }
}

impl From<&crate::dmarc::Alignment> for Alignment {
    fn from(aligment: &crate::dmarc::Alignment) -> Self {
        match aligment {
            crate::dmarc::Alignment::Relaxed => Alignment::Relaxed,
            crate::dmarc::Alignment::Strict => Alignment::Strict,
        }
    }
}

impl From<&crate::dmarc::Policy> for Disposition {
    fn from(policy: &crate::dmarc::Policy) -> Self {
        match policy {
            crate::dmarc::Policy::None => Disposition::None,
            crate::dmarc::Policy::Quarantine => Disposition::Quarantine,
            crate::dmarc::Policy::Reject => Disposition::Reject,
            crate::dmarc::Policy::Unspecified => Disposition::None,
        }
    }
}
