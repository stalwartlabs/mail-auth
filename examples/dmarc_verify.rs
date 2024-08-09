/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use mail_auth::{AuthenticatedMessage, DmarcResult, Resolver};

const TEST_MESSAGE: &str = r#"DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;
d=football.example.com; i=@football.example.com;
q=dns/txt; s=brisbane; t=1528637909; h=from : to :
subject : date : message-id : from : subject : date;
bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus
Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
d=football.example.com; i=@football.example.com;
q=dns/txt; s=test; t=1528637909; h=from : to : subject :
date : message-id : from : subject : date;
bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3
DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz
dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=
From: Joe SixPack <joe@football.example.com>
To: Suzie Q <suzie@shopping.example.net>
Subject: Is dinner ready?
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
Message-ID: <20030712040037.46341.5F8J@football.example.com>

Hi.

We lost the game.  Are you hungry yet?

Joe."#;

#[tokio::main]
async fn main() {
    // Create a resolver using Cloudflare DNS
    let resolver = Resolver::new_cloudflare_tls().unwrap();

    // Verify DKIM signatures
    let authenticated_message = AuthenticatedMessage::parse(TEST_MESSAGE.as_bytes()).unwrap();
    let dkim_result = resolver.verify_dkim(&authenticated_message).await;

    // Verify SPF MAIL-FROM identity
    let spf_result = resolver
        .verify_spf_sender(
            "::1".parse().unwrap(),
            "example.org",
            "my-host-domain.org",
            "sender@example.org",
        )
        .await;

    // Verify DMARC
    let dmarc_result = resolver
        .verify_dmarc(
            &authenticated_message,
            &dkim_result,
            "example.org",
            &spf_result,
            |domain| psl::domain_str(domain).unwrap_or(domain),
        )
        .await;
    assert_eq!(dmarc_result.dkim_result(), &DmarcResult::Pass);
    assert_eq!(dmarc_result.spf_result(), &DmarcResult::Pass);
}
