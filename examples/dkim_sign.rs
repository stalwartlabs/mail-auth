/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_auth::{
    common::{
        crypto::RsaKey,
        crypto::{Ed25519Key, Sha256},
        headers::HeaderWriter,
    },
    dkim::DkimSigner,
};
use mail_parser::decoders::base64::base64_decode;

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

const ED25519_PRIVATE_KEY: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";
const ED25519_PUBLIC_KEY: &str = "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

const TEST_MESSAGE: &str = r#"From: bill@example.com
To: jdoe@example.com
Subject: TPS Report

I'm going to need those TPS reports ASAP. So, if you could do that, that'd be great.
"#;

fn main() {
    // Sign an e-mail message using RSA-SHA256
    #[cfg(feature = "rust-crypto")]
    let pk_rsa = RsaKey::<Sha256>::from_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
    #[cfg(all(
        feature = "ring",
        feature = "rustls-pemfile",
        not(feature = "rust-crypto")
    ))]
    let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(RSA_PRIVATE_KEY).unwrap();

    let signature_rsa = DkimSigner::from_key(pk_rsa)
        .domain("example.com")
        .selector("default")
        .headers(["From", "To", "Subject"])
        .sign(TEST_MESSAGE.as_bytes())
        .unwrap();

    // Sign an e-mail message using ED25519-SHA256
    #[cfg(feature = "rust-crypto")]
    let pk_ed =
        Ed25519Key::from_bytes(&base64_decode(ED25519_PRIVATE_KEY.as_bytes()).unwrap()).unwrap();
    #[cfg(all(feature = "ring", not(feature = "rust-crypto")))]
    let pk_ed = Ed25519Key::from_seed_and_public_key(
        &base64_decode(ED25519_PRIVATE_KEY.as_bytes()).unwrap(),
        &base64_decode(ED25519_PUBLIC_KEY.rsplit_once("p=").unwrap().1.as_bytes()).unwrap(),
    )
    .unwrap();

    let signature_ed = DkimSigner::from_key(pk_ed)
        .domain("example.com")
        .selector("default-ed")
        .headers(["From", "To", "Subject"])
        .sign(TEST_MESSAGE.as_bytes())
        .unwrap();

    // Print the message including both signatures to stdout
    println!(
        "{}{}{}",
        signature_rsa.to_header(),
        signature_ed.to_header(),
        TEST_MESSAGE
    );
}
