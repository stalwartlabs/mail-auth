/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Construction and ownership helpers for [`FeedbackReport`].

use super::{FeedbackReport, FeedbackType};

impl<'x> FeedbackReport<'x> {
    /// Returns an empty report of the given type with `version` and
    /// `incidents` set to 1.
    pub fn new(feedback_type: FeedbackType) -> Self {
        FeedbackReport {
            feedback_type,
            version: 1,
            incidents: 1,
            ..Default::default()
        }
    }

    /// Converts every borrowed string into an owned one, detaching the report
    /// from the buffer it was parsed from.
    pub fn into_owned<'y>(self) -> FeedbackReport<'y> {
        FeedbackReport {
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
            reported_domains: self
                .reported_domains
                .into_iter()
                .map(|ar| ar.into_owned().into())
                .collect(),
            reported_uris: self
                .reported_uris
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
