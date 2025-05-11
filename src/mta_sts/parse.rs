/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::common::parse::{TagParser, TxtRecordParser, V};

use super::{MtaSts, ReportUri, TlsRpt};

const ID: u64 = (b'i' as u64) | ((b'd' as u64) << 8);
const RUA: u64 = (b'r' as u64) | ((b'u' as u64) << 8) | ((b'a' as u64) << 16);

const MAILTO: u64 = (b'm' as u64)
    | ((b'a' as u64) << 8)
    | ((b'i' as u64) << 16)
    | ((b'l' as u64) << 24)
    | ((b't' as u64) << 32)
    | ((b'o' as u64) << 40);
const HTTPS: u64 = (b'h' as u64)
    | ((b't' as u64) << 8)
    | ((b't' as u64) << 16)
    | ((b'p' as u64) << 24)
    | ((b's' as u64) << 32);

impl TxtRecordParser for MtaSts {
    #[allow(clippy::while_let_on_iterator)]
    fn parse(record: &[u8]) -> crate::Result<Self> {
        let mut record = record.iter();
        let mut id = None;
        let mut has_version = false;

        while let Some(key) = record.key() {
            match key {
                V => {
                    if !record.match_bytes(b"STSv1") || !record.seek_tag_end() {
                        return Err(crate::Error::InvalidRecordType);
                    }
                    has_version = true;
                }
                ID => {
                    id = record.text(false).into();
                }
                _ => {
                    record.ignore();
                }
            }
        }

        if let Some(id) = id {
            if has_version {
                return Ok(MtaSts { id });
            }
        }
        Err(crate::Error::InvalidRecordType)
    }
}

impl TxtRecordParser for TlsRpt {
    #[allow(clippy::while_let_on_iterator)]
    fn parse(record: &[u8]) -> crate::Result<Self> {
        let mut record = record.iter();

        if record.key().unwrap_or(0) != V
            || !record.match_bytes(b"TLSRPTv1")
            || !record.seek_tag_end()
        {
            return Err(crate::Error::InvalidRecordType);
        }

        let mut rua = Vec::new();

        while let Some(key) = record.key() {
            match key {
                RUA => loop {
                    match record.flag_value() {
                        (MAILTO, b':') => {
                            let mail_to = record.text_qp(Vec::with_capacity(20), false, true);
                            if !mail_to.is_empty() {
                                rua.push(ReportUri::Mail(mail_to));
                            }
                        }
                        (HTTPS, b':') => {
                            let mut url = Vec::with_capacity(20);
                            url.extend_from_slice(b"https:");
                            let url = record.text_qp(url, false, true);
                            if !url.is_empty() {
                                rua.push(ReportUri::Http(url));
                            }
                        }
                        _ => {
                            record.ignore();
                            break;
                        }
                    }
                },
                _ => {
                    record.ignore();
                }
            }
        }

        if !rua.is_empty() {
            Ok(TlsRpt { rua })
        } else {
            Err(crate::Error::InvalidRecordType)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        common::parse::TxtRecordParser,
        mta_sts::{MtaSts, ReportUri, TlsRpt},
    };

    #[test]
    fn mta_sts_record_parse() {
        for (mta_sts, expected_mta_sts) in [
            (
                "v=STSv1; id=20160831085700Z;",
                MtaSts {
                    id: "20160831085700Z".to_string(),
                },
            ),
            (
                "v=STSv1; id=20190429T010101",
                MtaSts {
                    id: "20190429T010101".to_string(),
                },
            ),
        ] {
            assert_eq!(MtaSts::parse(mta_sts.as_bytes()).unwrap(), expected_mta_sts);
        }
    }

    #[test]
    fn tlsrpt_parse() {
        for (tls_rpt, expected_tls_rpt) in [
            (
                "v=TLSRPTv1;rua=mailto:reports@example.com",
                TlsRpt {
                    rua: vec![ReportUri::Mail("reports@example.com".to_string())],
                },
            ),
            (
                "v=TLSRPTv1; rua=https://reporting.example.com/v1/tlsrpt",
                TlsRpt {
                    rua: vec![ReportUri::Http(
                        "https://reporting.example.com/v1/tlsrpt".to_string(),
                    )],
                },
            ),
            (
                "v=TLSRPTv1; rua=mailto:tlsrpt@mydomain.com,https://tlsrpt.mydomain.com/v1",
                TlsRpt {
                    rua: vec![
                        ReportUri::Mail("tlsrpt@mydomain.com".to_string()),
                        ReportUri::Http("https://tlsrpt.mydomain.com/v1".to_string()),
                    ],
                },
            ),
        ] {
            assert_eq!(TlsRpt::parse(tls_rpt.as_bytes()).unwrap(), expected_tls_rpt);
        }
    }
}
