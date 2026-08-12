/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_auth::report::Report;

const TEST_MESSAGE: &str = include_str!("../resources/dmarc-feedback/100.eml");
const MAX_REPORT_SIZE: usize = 25 * 1024 * 1024;

fn main() {
    // Parse DMARC aggregate report
    let report = Report::parse_rfc5322(TEST_MESSAGE.as_bytes(), MAX_REPORT_SIZE).unwrap();

    // Write report to stdout at JSPON
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
