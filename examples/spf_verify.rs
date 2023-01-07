/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use mail_auth::{Resolver, SpfResult};

#[tokio::main]
async fn main() {
    // Create a resolver using Cloudflare DNS
    let resolver = Resolver::new_cloudflare_tls().unwrap();

    // Verify HELO identity
    let result = resolver
        .verify_spf_helo(
            "127.0.0.1".parse().unwrap(),
            "gmail.com",
            "my-host-domain.org",
        )
        .await;
    assert_eq!(result.result(), SpfResult::Fail);

    // Verify MAIL-FROM identity
    let result = resolver
        .verify_spf_sender(
            "::1".parse().unwrap(),
            "gmail.com",
            "my-host-domain.org",
            "sender@gmail.com",
        )
        .await;
    assert_eq!(result.result(), SpfResult::Fail);
}
