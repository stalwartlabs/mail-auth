/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_auth::report::{
    ActionDisposition, Alignment, DKIMAuthResult, Disposition, DkimResult, DmarcResult,
    PolicyOverride, PolicyOverrideReason, Record, Report, SPFAuthResult, SPFDomainScope, SpfResult,
};

fn main() {
    // Generate DMARC aggregate report
    let report = Report::new()
        .with_version(1.0)
        .with_org_name("Initech Industries Incorporated")
        .with_email("dmarc@initech.net")
        .with_extra_contact_info("XMPP:dmarc@initech.net")
        .with_report_id("abc-123")
        .with_date_range_begin(12345)
        .with_date_range_end(12346)
        .with_error("Did not include TPS report cover.")
        .with_domain("example.org")
        .with_version_published(1.0)
        .with_adkim(Alignment::Relaxed)
        .with_aspf(Alignment::Strict)
        .with_p(Disposition::Quarantine)
        .with_sp(Disposition::Reject)
        .with_testing(false)
        .with_record(
            Record::new()
                .with_source_ip("192.168.1.2".parse().unwrap())
                .with_count(3)
                .with_action_disposition(ActionDisposition::Pass)
                .with_dmarc_dkim_result(DmarcResult::Pass)
                .with_dmarc_spf_result(DmarcResult::Fail)
                .with_policy_override_reason(
                    PolicyOverrideReason::new(PolicyOverride::Forwarded)
                        .with_comment("it was forwarded"),
                )
                .with_policy_override_reason(
                    PolicyOverrideReason::new(PolicyOverride::MailingList)
                        .with_comment("sent from mailing list"),
                )
                .with_envelope_from("hello@example.org")
                .with_envelope_to("other@example.org")
                .with_header_from("bye@example.org")
                .with_dkim_auth_result(
                    DKIMAuthResult::new()
                        .with_domain("test.org")
                        .with_selector("my-selector")
                        .with_result(DkimResult::PermError)
                        .with_human_result("failed to parse record"),
                )
                .with_spf_auth_result(
                    SPFAuthResult::new()
                        .with_domain("test.org")
                        .with_scope(SPFDomainScope::Helo)
                        .with_result(SpfResult::SoftFail)
                        .with_human_result("dns timed out"),
                ),
        )
        .with_record(
            Record::new()
                .with_source_ip("a:b:c::e:f".parse().unwrap())
                .with_count(99)
                .with_action_disposition(ActionDisposition::Reject)
                .with_dmarc_dkim_result(DmarcResult::Fail)
                .with_dmarc_spf_result(DmarcResult::Pass)
                .with_policy_override_reason(
                    PolicyOverrideReason::new(PolicyOverride::LocalPolicy)
                        .with_comment("on the white list"),
                )
                .with_policy_override_reason(
                    PolicyOverrideReason::new(PolicyOverride::SampledOut)
                        .with_comment("it was sampled out"),
                )
                .with_envelope_from("hello2example.org")
                .with_envelope_to("other2@example.org")
                .with_header_from("bye2@example.org")
                .with_dkim_auth_result(
                    DKIMAuthResult::new()
                        .with_domain("test2.org")
                        .with_selector("my-other-selector")
                        .with_result(DkimResult::Neutral)
                        .with_human_result("something went wrong"),
                )
                .with_spf_auth_result(
                    SPFAuthResult::new()
                        .with_domain("test.org")
                        .with_scope(SPFDomainScope::MailFrom)
                        .with_result(SpfResult::None)
                        .with_human_result("no policy found"),
                ),
        )
        .to_rfc5322(
            "initech.net",
            ("Initech Industries", "noreply-dmarc@initech.net"),
            ["dmarc-reports@example.org"].iter().copied(),
        )
        .unwrap();

    // Print report to stdout
    println!("{report}");
}
