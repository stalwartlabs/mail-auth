/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

#![no_main]
use libfuzzer_sys::fuzz_target;

use mail_auth::{
    AuthenticatedMessage, arc,
    dkim::{self, AtpsRecord, DkimReportRecord, DomainKey},
    dkim2::{self, Recipe},
    dmarc::DmarcRecord,
    dns::TxtRecordParser,
    mta_sts::{MtaStsRecord, TlsRptRecord},
    report::{arf::FeedbackReport, dmarc::AggregateReport},
    spf::{Macro, SpfRecord},
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

    arc::ArcAuthResults::parse(data).ok();
    arc::ArcAuthResults::parse(&data_txt).ok();

    AuthenticatedMessage::parse(data);
    AuthenticatedMessage::parse(&data_rfc822);
    AuthenticatedMessage::parse_with_opts(&data_rfc822, Some(data), true);

    dkim2::Signature::parse(data).ok();
    dkim2::Signature::parse(&data_txt).ok();

    dkim2::MessageInstance::parse(data).ok();
    dkim2::MessageInstance::parse(&data_txt).ok();

    Recipe::from_json(data).ok();

    DomainKey::parse(data).ok();
    DomainKey::parse(&data_txt).ok();

    DkimReportRecord::parse(data).ok();
    DkimReportRecord::parse(&data_txt).ok();

    AtpsRecord::parse(data).ok();
    AtpsRecord::parse(&data_txt).ok();

    DmarcRecord::parse(data).ok();
    DmarcRecord::parse(&data_txt).ok();

    SpfRecord::parse(data).ok();
    SpfRecord::parse(&data_txt).ok();

    MtaStsRecord::parse(data).ok();
    MtaStsRecord::parse(&data_txt).ok();

    TlsRptRecord::parse(data).ok();
    TlsRptRecord::parse(&data_txt).ok();

    Macro::parse(data).ok();
    Macro::parse(&data_txt).ok();

    AggregateReport::parse_xml(data).ok();
    AggregateReport::parse_xml(&into_alphabet(data, XML_ALPHABET)).ok();

    FeedbackReport::parse_arf(data).ok();
    FeedbackReport::parse_arf(&data_rfc822).ok();
});

fn into_alphabet(data: &[u8], alphabet: &[u8]) -> Vec<u8> {
    data.iter()
        .map(|&byte| alphabet[byte as usize % alphabet.len()])
        .collect()
}
