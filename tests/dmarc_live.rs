/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Live DMARC tree-walk tests against real DNS (RFC 9989 Section 4.10).
//!
//! ```sh
//! cargo test --test dmarc_live -- --ignored
//! ```

use mail_auth::{
    AuthenticatedMessage, DkimOutput, DmarcResult, MessageAuthenticator, SpfOutput, SpfResult,
    dkim::Signature, dmarc::verify::DmarcParameters,
};

async fn discover(from: &str) -> mail_auth::DmarcOutput {
    let authenticator = MessageAuthenticator::new_system_conf().unwrap();
    let raw = format!("From: postmaster@{from}\r\n\r\n");
    let message = AuthenticatedMessage::parse(raw.as_bytes()).unwrap();
    let spf = SpfOutput::new(from.to_string()).with_result(SpfResult::None);
    authenticator
        .verify_dmarc(DmarcParameters::new(&message, &[], from, &spf))
        .await
}

#[tokio::test]
#[ignore = "requires live DNS"]
async fn live_policy_at_author_domain() {
    // google.com publishes a DMARC record directly at "_dmarc.google.com".
    let result = discover("google.com").await;
    assert!(
        result.dmarc_record().is_some(),
        "expected a DMARC record for google.com, got {result:?}"
    );
}

#[tokio::test]
#[ignore = "requires live DNS"]
async fn live_dmarc_pass_with_alignment() {
    for domain in ["gmail.com", "stalw.art"] {
        let authenticator = MessageAuthenticator::new_system_conf().unwrap();
        let raw = format!("From: postmaster@{domain}\r\n\r\n");
        let message = AuthenticatedMessage::parse(raw.as_bytes()).unwrap();
        let signature = Signature {
            d: domain.to_string(),
            s: "selector".to_string(),
            ..Default::default()
        };
        let dkim = DkimOutput::pass().with_signature(&signature);
        let spf = SpfOutput::new(domain.to_string()).with_result(SpfResult::Pass);

        let result = authenticator
            .verify_dmarc(DmarcParameters::new(
                &message,
                std::slice::from_ref(&dkim),
                domain,
                &spf,
            ))
            .await;

        println!(
            "{domain}: policy={:?} dkim={:?} spf={:?}",
            result.policy(),
            result.dkim_result(),
            result.spf_result()
        );
        assert!(
            result.dmarc_record().is_some(),
            "{domain}: expected a DMARC record"
        );
        assert_eq!(
            result.dkim_result(),
            &DmarcResult::Pass,
            "{domain}: DKIM should align"
        );
        assert_eq!(
            result.spf_result(),
            &DmarcResult::Pass,
            "{domain}: SPF should align"
        );
    }
}

#[tokio::test]
#[ignore = "requires live DNS"]
async fn live_tree_walk_climbs_to_org_domain() {
    let result = discover("this-subdomain-does-not-exist.google.com").await;
    assert!(
        result.dmarc_record().is_some(),
        "expected the tree walk to discover google.com's policy, got {result:?}"
    );
}
