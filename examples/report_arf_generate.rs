/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_auth::report::{
    ReportEnvelope,
    arf::{AuthFailureType, FeedbackReport, FeedbackType, IdentityAlignment},
};

fn main() {
    // Generate an ARF authentication failure report
    let feedback = FeedbackReport {
        arrival_date: Some(5934759438),
        authentication_results: vec!["dkim=pass".into()],
        incidents: 10,
        original_envelope_id: Some("821-abc-123".into()),
        original_mail_from: Some("hello@world.org".into()),
        original_rcpt_to: Some("ciao@mundo.org".into()),
        reported_domains: vec!["example.org".into(), "example2.org".into()],
        reported_uris: vec!["uri:domain.org".into(), "uri:domain2.org".into()],
        reporting_mta: Some("Manchegator 2.0".into()),
        source_ip: Some("192.168.1.1".parse().unwrap()),
        user_agent: Some("DMARC-Meister".into()),
        source_port: 1234,
        auth_failure: AuthFailureType::Dmarc,
        dkim_domain: Some("dkim-domain.org".into()),
        dkim_identity: Some("my-dkim-identity@domain.org".into()),
        dkim_selector: Some("the-selector".into()),
        identity_alignment: IdentityAlignment::DkimSpf,
        message: Some("From: hello@world.org\r\nTo: ciao@mondo.org\r\n\r\n".into()),
        ..FeedbackReport::new(FeedbackType::AuthFailure)
    }
    .to_rfc5322(&ReportEnvelope {
        from: ("DMARC Reports", "no-reply@example.org").into(),
        to: vec!["ruf@otherdomain.com"],
        submitter: "example.org",
        report_domain: "",
        subject: Some("DMARC Authentication Failure Report"),
    })
    .unwrap();

    // Print the report to stdout
    println!("{feedback}");
}
