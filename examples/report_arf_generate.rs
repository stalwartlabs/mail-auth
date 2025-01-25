/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_auth::report::{AuthFailureType, Feedback, FeedbackType, IdentityAlignment};

fn main() {
    // Generate ARF feedback
    let feedback = Feedback::new(FeedbackType::AuthFailure)
        .with_arrival_date(5934759438)
        .with_authentication_results("dkim=pass")
        .with_incidents(10)
        .with_original_envelope_id("821-abc-123")
        .with_original_mail_from("hello@world.org")
        .with_original_rcpt_to("ciao@mundo.org")
        .with_reported_domain("example.org")
        .with_reported_domain("example2.org")
        .with_reported_uri("uri:domain.org")
        .with_reported_uri("uri:domain2.org")
        .with_reporting_mta("Manchegator 2.0")
        .with_source_ip("192.168.1.1".parse().unwrap())
        .with_user_agent("DMARC-Meister")
        .with_version(2)
        .with_source_port(1234)
        .with_auth_failure(AuthFailureType::Dmarc)
        .with_dkim_adsp_dns("v=dkim1")
        .with_dkim_canonicalized_body("base64 goes here")
        .with_dkim_canonicalized_header("more base64")
        .with_dkim_domain("dkim-domain.org")
        .with_dkim_identity("my-dkim-identity@domain.org")
        .with_dkim_selector("the-selector")
        .with_dkim_selector_dns("v=dkim1;")
        .with_spf_dns("v=spf1")
        .with_identity_alignment(IdentityAlignment::DkimSpf)
        .with_message("From: hello@world.org\r\nTo: ciao@mondo.org\r\n\r\n")
        .to_rfc5322(
            ("DMARC Reports", "no-reply@example.org"),
            "ruf@otherdomain.com",
            "DMARC Authentication Failure Report",
        )
        .unwrap();

    // Print ARF feedback to stdout
    println!("{feedback}");
}
