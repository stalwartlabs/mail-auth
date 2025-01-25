/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_auth::{AuthenticatedMessage, DkimResult, MessageAuthenticator};

const TEST_MESSAGE: &str = include_str!("../resources/arc/001.txt");

#[tokio::main]
async fn main() {
    // Create an authenticator using Cloudflare DNS
    let authenticator = MessageAuthenticator::new_cloudflare_tls().unwrap();

    // Parse message
    let authenticated_message = AuthenticatedMessage::parse(TEST_MESSAGE.as_bytes()).unwrap();

    // Validate ARC chain
    let result = authenticator.verify_arc(&authenticated_message).await;

    // Make sure ARC passed verification
    assert_eq!(result.result(), &DkimResult::Pass);
}
