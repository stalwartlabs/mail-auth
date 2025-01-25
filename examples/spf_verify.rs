/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_auth::{spf::verify::SpfParameters, MessageAuthenticator, SpfResult};

#[tokio::main]
async fn main() {
    // Create an authenticator using Cloudflare DNS
    let authenticator = MessageAuthenticator::new_cloudflare_tls().unwrap();

    // Verify HELO identity
    let result = authenticator
        .verify_spf(SpfParameters::verify_ehlo(
            "127.0.0.1".parse().unwrap(),
            "gmail.com",
            "my-local-domain.org",
        ))
        .await;
    assert_eq!(result.result(), SpfResult::Fail);

    // Verify MAIL-FROM identity
    let result = authenticator
        .verify_spf(SpfParameters::verify_mail_from(
            "::1".parse().unwrap(),
            "gmail.com",
            "my-local-domain.org",
            "sender@gmail.com",
        ))
        .await;
    assert_eq!(result.result(), SpfResult::Fail);
}
