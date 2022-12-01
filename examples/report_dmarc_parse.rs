/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use mail_auth::report::Report;

const TEST_MESSAGE: &str = include_str!("../resources/dmarc-feedback/100.eml");

fn main() {
    // Parse DMARC aggregate report
    let report = Report::parse_rfc5322(TEST_MESSAGE.as_bytes()).unwrap();

    // Write report to stdout at JSPON
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
