/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_auth::{
    dmarc::{Alignment, Policy},
    report::{
        ReportEnvelope,
        dmarc::{
            AggregateReport, AuthResults, DateRange, Disposition, DkimAuthResult, DkimStatus,
            DmarcStatus, Identifiers, PolicyEvaluated, PolicyOverride, PolicyOverrideReason,
            PolicyPublished, Record, ReportMetadata, ReportVersion, Row, SpfAuthResult, SpfScope,
            SpfStatus,
        },
    },
};

fn main() {
    // Generate a DMARC aggregate report
    let report = AggregateReport {
        version: Some(ReportVersion::V1),
        report_metadata: ReportMetadata {
            org_name: "Initech Industries Incorporated".into(),
            email: "dmarc@initech.net".into(),
            extra_contact_info: Some("XMPP:dmarc@initech.net".into()),
            report_id: "abc-123".into(),
            date_range: DateRange {
                begin: 12345,
                end: 12346,
            },
            errors: vec!["Did not include TPS report cover.".into()],
            generator: None,
        },
        policy_published: PolicyPublished {
            domain: "example.org".into(),
            version_published: Some(ReportVersion::V1),
            adkim: Some(Alignment::Relaxed),
            aspf: Some(Alignment::Strict),
            p: Policy::Quarantine,
            sp: Policy::Reject,
            testing: false,
            ..Default::default()
        },
        records: vec![Record {
            row: Row {
                source_ip: Some("192.168.1.2".parse().unwrap()),
                count: 3,
                policy_evaluated: PolicyEvaluated {
                    disposition: Disposition::Pass,
                    dkim: DmarcStatus::Pass,
                    spf: DmarcStatus::Fail,
                    reason: vec![PolicyOverrideReason {
                        kind: PolicyOverride::TrustedForwarder,
                        comment: Some("it was forwarded".into()),
                    }],
                },
            },
            identifiers: Identifiers {
                envelope_to: Some("other@example.org".into()),
                envelope_from: "hello@example.org".into(),
                header_from: "bye@example.org".into(),
            },
            auth_results: AuthResults {
                dkim: vec![DkimAuthResult {
                    domain: "test.org".into(),
                    selector: "my-selector".into(),
                    result: DkimStatus::PermError,
                    human_result: Some("failed to parse record".into()),
                }],
                spf: vec![SpfAuthResult {
                    domain: "test.org".into(),
                    scope: SpfScope::MailFrom,
                    result: SpfStatus::SoftFail,
                    human_result: Some("dns timed out".into()),
                }],
            },
            extensions: vec![],
        }],
        extensions: vec![],
    }
    .to_rfc5322(&ReportEnvelope {
        from: ("Initech Industries", "noreply-dmarc@initech.net").into(),
        to: vec!["dmarc-reports@example.org"],
        submitter: "initech.net",
        report_domain: "example.org",
        subject: None,
    })
    .unwrap();

    // Print the report to stdout
    println!("{report}");
}
