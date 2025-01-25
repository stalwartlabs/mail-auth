/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_auth::report::Feedback;

const TEST_MESSAGE: &str = include_str!("../resources/arf/001.eml");

fn main() {
    // Parse Abuse Report Format feedback repot
    let report = Feedback::parse_rfc5322(TEST_MESSAGE.as_bytes()).unwrap();

    // Write ARF to stdout at JSPON
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
