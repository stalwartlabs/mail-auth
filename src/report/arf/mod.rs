/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::{borrow::Cow, net::IpAddr};

use super::{AuthFailureType, DeliveryResult, Feedback, FeedbackType, IdentityAlignment};

pub mod generate;
pub mod parse;

impl<'x> Feedback<'x> {
    pub fn new(feedback_type: FeedbackType) -> Self {
        Feedback {
            feedback_type,
            version: 1,
            incidents: 1,
            ..Default::default()
        }
    }

    pub fn original_envelope_id(&self) -> Option<&str> {
        self.original_envelope_id.as_deref()
    }

    pub fn feedback_type(&self) -> FeedbackType {
        self.feedback_type
    }

    pub fn with_original_envelope_id(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.original_envelope_id = Some(value.into());
        self
    }

    pub fn original_mail_from(&self) -> Option<&str> {
        self.original_mail_from.as_deref()
    }

    pub fn with_original_mail_from(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.original_mail_from = Some(value.into());
        self
    }

    pub fn original_rcpt_to(&self) -> Option<&str> {
        self.original_rcpt_to.as_deref()
    }

    pub fn with_original_rcpt_to(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.original_rcpt_to = Some(value.into());
        self
    }

    pub fn reporting_mta(&self) -> Option<&str> {
        self.reporting_mta.as_deref()
    }

    pub fn with_reporting_mta(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.reporting_mta = Some(value.into());
        self
    }

    pub fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }

    pub fn with_user_agent(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.user_agent = Some(value.into());
        self
    }

    pub fn source_ip(&self) -> Option<IpAddr> {
        self.source_ip
    }

    pub fn with_source_ip(mut self, value: IpAddr) -> Self {
        self.source_ip = Some(value);
        self
    }

    pub fn dkim_adsp_dns(&self) -> Option<&str> {
        self.dkim_adsp_dns.as_deref()
    }

    pub fn with_dkim_adsp_dns(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.dkim_adsp_dns = Some(value.into());
        self
    }

    pub fn dkim_canonicalized_body(&self) -> Option<&str> {
        self.dkim_canonicalized_body.as_deref()
    }

    pub fn with_dkim_canonicalized_body(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.dkim_canonicalized_body = Some(value.into());
        self
    }

    pub fn dkim_canonicalized_header(&self) -> Option<&str> {
        self.dkim_canonicalized_header.as_deref()
    }

    pub fn with_dkim_canonicalized_header(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.dkim_canonicalized_header = Some(value.into());
        self
    }

    pub fn dkim_domain(&self) -> Option<&str> {
        self.dkim_domain.as_deref()
    }

    pub fn with_dkim_domain(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.dkim_domain = Some(value.into());
        self
    }

    pub fn dkim_identity(&self) -> Option<&str> {
        self.dkim_identity.as_deref()
    }

    pub fn with_dkim_identity(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.dkim_identity = Some(value.into());
        self
    }

    pub fn dkim_selector(&self) -> Option<&str> {
        self.dkim_selector.as_deref()
    }

    pub fn with_dkim_selector(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.dkim_selector = Some(value.into());
        self
    }

    pub fn dkim_selector_dns(&self) -> Option<&str> {
        self.dkim_selector_dns.as_deref()
    }

    pub fn with_dkim_selector_dns(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.dkim_selector_dns = Some(value.into());
        self
    }

    pub fn spf_dns(&self) -> Option<&str> {
        self.spf_dns.as_deref()
    }

    pub fn with_spf_dns(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.spf_dns = Some(value.into());
        self
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    pub fn with_message(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.message = Some(value.into());
        self
    }

    pub fn headers(&self) -> Option<&str> {
        self.message.as_deref()
    }

    pub fn with_headers(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.headers = Some(value.into());
        self
    }

    pub fn arrival_date(&self) -> Option<i64> {
        self.arrival_date
    }

    pub fn with_arrival_date(mut self, value: i64) -> Self {
        self.arrival_date = Some(value);
        self
    }

    pub fn incidents(&self) -> u32 {
        self.incidents
    }

    pub fn with_incidents(mut self, value: u32) -> Self {
        self.incidents = value;
        self
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn with_version(mut self, value: u32) -> Self {
        self.version = value;
        self
    }

    pub fn source_port(&self) -> u32 {
        self.source_port
    }

    pub fn with_source_port(mut self, value: u32) -> Self {
        self.source_port = value;
        self
    }

    pub fn authentication_results(&self) -> &[Cow<'x, str>] {
        &self.authentication_results
    }

    pub fn with_authentication_results(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.authentication_results.push(value.into());
        self
    }

    pub fn reported_domain(&self) -> &[Cow<'x, str>] {
        &self.reported_domain
    }

    pub fn with_reported_domain(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.reported_domain.push(value.into());
        self
    }

    pub fn reported_uri(&self) -> &[Cow<'x, str>] {
        &self.reported_uri
    }

    pub fn with_reported_uri(mut self, value: impl Into<Cow<'x, str>>) -> Self {
        self.reported_uri.push(value.into());
        self
    }

    pub fn auth_failure(&self) -> AuthFailureType {
        self.auth_failure
    }

    pub fn with_auth_failure(mut self, value: AuthFailureType) -> Self {
        self.auth_failure = value;
        self
    }

    pub fn delivery_result(&self) -> DeliveryResult {
        self.delivery_result
    }

    pub fn with_delivery_result(mut self, value: DeliveryResult) -> Self {
        self.delivery_result = value;
        self
    }

    pub fn identity_alignment(&self) -> IdentityAlignment {
        self.identity_alignment
    }

    pub fn with_identity_alignment(mut self, value: IdentityAlignment) -> Self {
        self.identity_alignment = value;
        self
    }

    pub fn into_owned<'y>(self) -> Feedback<'y> {
        Feedback {
            feedback_type: self.feedback_type,
            arrival_date: self.arrival_date,
            authentication_results: self
                .authentication_results
                .into_iter()
                .map(|ar| ar.into_owned().into())
                .collect(),
            incidents: self.incidents,
            original_envelope_id: self.original_envelope_id.map(|v| v.into_owned().into()),
            original_mail_from: self.original_mail_from.map(|v| v.into_owned().into()),
            original_rcpt_to: self.original_rcpt_to.map(|v| v.into_owned().into()),
            reported_domain: self
                .reported_domain
                .into_iter()
                .map(|ar| ar.into_owned().into())
                .collect(),
            reported_uri: self
                .reported_uri
                .into_iter()
                .map(|ar| ar.into_owned().into())
                .collect(),
            reporting_mta: self.reporting_mta.map(|v| v.into_owned().into()),
            source_ip: self.source_ip,
            user_agent: self.user_agent.map(|v| v.into_owned().into()),
            version: self.version,
            source_port: self.source_port,
            auth_failure: self.auth_failure,
            delivery_result: self.delivery_result,
            dkim_adsp_dns: self.dkim_adsp_dns.map(|v| v.into_owned().into()),
            dkim_canonicalized_body: self.dkim_canonicalized_body.map(|v| v.into_owned().into()),
            dkim_canonicalized_header: self
                .dkim_canonicalized_header
                .map(|v| v.into_owned().into()),
            dkim_domain: self.dkim_domain.map(|v| v.into_owned().into()),
            dkim_identity: self.dkim_identity.map(|v| v.into_owned().into()),
            dkim_selector: self.dkim_selector.map(|v| v.into_owned().into()),
            dkim_selector_dns: self.dkim_selector_dns.map(|v| v.into_owned().into()),
            spf_dns: self.spf_dns.map(|v| v.into_owned().into()),
            identity_alignment: self.identity_alignment,
            message: self.message.map(|v| v.into_owned().into()),
            headers: self.headers.map(|v| v.into_owned().into()),
        }
    }
}
