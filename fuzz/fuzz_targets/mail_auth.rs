/*
 * Copyright (c) 2020-2022, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

#![no_main]
use libfuzzer_sys::fuzz_target;

use mail_auth::{
    arc,
    common::parse::TxtRecordParser,
    dkim::{self, Atps, DomainKey, DomainKeyReport},
    dmarc::DMARC,
    report::{Feedback, Report},
    spf::{Macro, SPF},
    AuthenticatedMessage,
};

static RFC822_ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz:=- \r\n";
static XML_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz</>";
static TXT_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz1=;:";

fuzz_target!(|data: &[u8]| {
    let data_rfc822 = into_alphabet(data, RFC822_ALPHABET);
    let data_txt = into_alphabet(data, TXT_ALPHABET);

    dkim::Signature::parse(data).ok();
    dkim::Signature::parse(&data_txt).ok();

    arc::Signature::parse(data).ok();
    arc::Signature::parse(&data_txt).ok();

    arc::Seal::parse(data).ok();
    arc::Seal::parse(&data_txt).ok();

    arc::Results::parse(data).ok();
    arc::Results::parse(&data_txt).ok();

    AuthenticatedMessage::parse(data);
    AuthenticatedMessage::parse(&data_rfc822);

    DomainKey::parse(data).ok();
    DomainKey::parse(&data_txt).ok();

    DomainKeyReport::parse(data).ok();
    DomainKeyReport::parse(&data_txt).ok();

    Atps::parse(data).ok();
    Atps::parse(&data_txt).ok();

    DMARC::parse(data).ok();
    DMARC::parse(&data_txt).ok();

    SPF::parse(data).ok();
    SPF::parse(&data_txt).ok();

    Macro::parse(data).ok();
    Macro::parse(&data_txt).ok();

    Report::parse_xml(data).ok();
    Report::parse_xml(&into_alphabet(data, XML_ALPHABET)).ok();

    Feedback::parse_arf(data);
    Feedback::parse_arf(&data_rfc822);
});

fn into_alphabet(data: &[u8], alphabet: &[u8]) -> Vec<u8> {
    data.iter()
        .map(|&byte| alphabet[byte as usize % alphabet.len()])
        .collect()
}
