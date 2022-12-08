/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use mail_auth::{
    arc::ArcSet,
    common::{crypto::PrivateKey, headers::HeaderWriter},
    AuthenticatedMessage, AuthenticationResults, Resolver,
};

const TEST_MESSAGE: &str = include_str!("../resources/arc/001.txt");

const RSA_PRIVATE_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIICXwIBAAKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFC
jxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gb
to/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB
AoGBALmn+XwWk7akvkUlqb+dOxyLB9i5VBVfje89Teolwc9YJT36BGN/l4e0l6QX
/1//6DWUTB3KI6wFcm7TWJcxbS0tcKZX7FsJvUz1SbQnkS54DJck1EZO/BLa5ckJ
gAYIaqlA9C0ZwM6i58lLlPadX/rtHb7pWzeNcZHjKrjM461ZAkEA+itss2nRlmyO
n1/5yDyCluST4dQfO8kAB3toSEVc7DeFeDhnC1mZdjASZNvdHS4gbLIA1hUGEF9m
3hKsGUMMPwJBAPW5v/U+AWTADFCS22t72NUurgzeAbzb1HWMqO4y4+9Hpjk5wvL/
eVYizyuce3/fGke7aRYw/ADKygMJdW8H/OcCQQDz5OQb4j2QDpPZc0Nc4QlbvMsj
7p7otWRO5xRa6SzXqqV3+F0VpqvDmshEBkoCydaYwc2o6WQ5EBmExeV8124XAkEA
qZzGsIxVP+sEVRWZmW6KNFSdVUpk3qzK0Tz/WjQMe5z0UunY9Ax9/4PVhp/j61bf
eAYXunajbBSOLlx4D+TunwJBANkPI5S9iylsbLs6NkaMHV6k5ioHBBmgCak95JGX
GMot/L2x0IYyMLAz6oLWh2hm7zwtb0CgOrPo1ke44hFYnfc=
-----END RSA PRIVATE KEY-----"#;

#[tokio::main]
async fn main() {
    // Create a resolver using Cloudflare DNS
    let resolver = Resolver::new_cloudflare_tls().unwrap();

    // Parse message to be sealed
    let authenticated_message = AuthenticatedMessage::parse(TEST_MESSAGE.as_bytes()).unwrap();

    // Verify ARC and DKIM signatures
    let arc_result = resolver.verify_arc(&authenticated_message).await;
    let dkim_result = resolver.verify_dkim(&authenticated_message).await;

    // Build Authenticated-Results header
    let auth_results = AuthenticationResults::new("mx.mydomain.org")
        .with_dkim_result(&dkim_result, "sender@example.org")
        .with_arc_result(&arc_result, "127.0.0.1".parse().unwrap());

    // Seal message
    if arc_result.can_be_sealed() {
        // Seal the e-mail message using RSA-SHA256
        let pk_rsa = PrivateKey::from_rsa_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        let arc_set = ArcSet::new(&auth_results)
            .domain("example.org")
            .selector("default")
            .headers(["From", "To", "Subject", "DKIM-Signature"])
            .seal(&authenticated_message, &arc_result, &pk_rsa)
            .unwrap();

        // Print the sealed message to stdout
        println!("{}{}", arc_set.to_header(), TEST_MESSAGE)
    } else {
        eprintln!("The message could not be sealed, probably an ARC chain with cv=fail was found.")
    }
}
