/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use mail_auth::report::Feedback;

const TEST_MESSAGE: &str = include_str!("../resources/arf/001.eml");

fn main() {
    // Parse Abuse Report Format feedback repot
    let report = Feedback::parse_rfc5322(TEST_MESSAGE.as_bytes()).unwrap();

    // Write ARF to stdout at JSPON
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
}
