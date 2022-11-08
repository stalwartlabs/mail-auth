use std::slice::Iter;

use mail_parser::decoders::quoted_printable::quoted_printable_decode_char;

use crate::common::parse::{ItemParser, TagParser, V};

use super::{Alignment, Error, Format, Policy, Report, DMARC, URI};

impl DMARC {
    pub fn parse(bytes: &[u8]) -> super::Result<Self> {
        let mut record = bytes.iter();
        if record.key().unwrap_or(0) != V {
            return Err(Error::InvalidRecord);
        } else if !record.match_bytes(b"DMARC1") || !record.seek_tag_end() {
            return Err(Error::InvalidVersion);
        }

        let mut dmarc = DMARC {
            adkim: Alignment::Relaxed,
            aspf: Alignment::Relaxed,
            fo: Report::All,
            np: Policy::Unspecified,
            p: Policy::Unspecified,
            pct: 100,
            rf: Format::Afrf as u8,
            ri: 86400,
            rua: vec![],
            ruf: vec![],
            sp: Policy::Unspecified,
        };

        while let Some(key) = record.long_key() {
            match key {
                ADKIM => {
                    dmarc.adkim = record.alignment()?;
                }
                ASPF => {
                    dmarc.aspf = record.alignment()?;
                }
                FO => {
                    dmarc.fo = record.report()?;
                }
                NP => {
                    dmarc.np = record.policy()?;
                }
                P => {
                    dmarc.p = record.policy()?;
                }
                PCT => {
                    dmarc.pct =
                        std::cmp::min(100, record.number().ok_or(Error::ParseFailed)?) as u8;
                }
                RF => {
                    dmarc.rf = record.flags::<Format>() as u8;
                }
                RI => {
                    dmarc.ri = record.number().ok_or(Error::ParseFailed)? as u32;
                }
                RUA => {
                    dmarc.rua = record.uris()?;
                }
                RUF => {
                    dmarc.ruf = record.uris()?;
                }
                SP => {
                    dmarc.sp = record.policy()?;
                }
                _ => {
                    record.ignore();
                }
            }
        }

        if dmarc.sp == Policy::Unspecified {
            dmarc.sp = dmarc.p;
        }
        if dmarc.np == Policy::Unspecified {
            dmarc.np = dmarc.sp;
        }

        Ok(dmarc)
    }
}

pub(crate) trait DMARCParser: Sized {
    fn alignment(&mut self) -> super::Result<Alignment>;
    fn report(&mut self) -> super::Result<Report>;
    fn policy(&mut self) -> super::Result<Policy>;
    fn uris(&mut self) -> super::Result<Vec<URI>>;
}

impl DMARCParser for Iter<'_, u8> {
    fn alignment(&mut self) -> super::Result<Alignment> {
        let a = match self.next_skip_whitespaces().unwrap_or(0) {
            b'r' | b'R' => Alignment::Relaxed,
            b's' | b'S' => Alignment::Strict,
            _ => return Err(Error::ParseFailed),
        };
        if self.seek_tag_end() {
            Ok(a)
        } else {
            Err(Error::ParseFailed)
        }
    }

    fn report(&mut self) -> super::Result<Report> {
        let r = match self.next_skip_whitespaces().unwrap_or(0) {
            b'0' => Report::All,
            b'1' => Report::Any,
            b'd' | b'D' => Report::Dkim,
            b's' | b'S' => Report::Spf,
            _ => return Err(Error::ParseFailed),
        };
        if self.seek_tag_end() {
            Ok(r)
        } else {
            Err(Error::ParseFailed)
        }
    }

    fn policy(&mut self) -> super::Result<Policy> {
        let p = match self.next_skip_whitespaces().unwrap_or(0) {
            b'n' | b'N' if self.match_bytes(b"one") => Policy::None,
            b'q' | b'Q' if self.match_bytes(b"uarantine") => Policy::Quarantine,
            b'r' | b'R' if self.match_bytes(b"eject") => Policy::Reject,
            _ => return Err(Error::ParseFailed),
        };
        if self.seek_tag_end() {
            Ok(p)
        } else {
            Err(Error::ParseFailed)
        }
    }

    #[allow(clippy::while_let_on_iterator)]
    fn uris(&mut self) -> super::Result<Vec<URI>> {
        let mut uris = Vec::new();
        let mut uri = Vec::with_capacity(16);
        let mut size: usize = 0;

        'outer: while let Some(&ch) = self.next() {
            match ch {
                b'%' => {
                    let mut hex1 = 0;

                    while let Some(&ch) = self.next() {
                        if ch.is_ascii_hexdigit() {
                            if hex1 != 0 {
                                if let Some(ch) = quoted_printable_decode_char(hex1, ch) {
                                    uri.push(ch);
                                }
                                break;
                            } else {
                                hex1 = ch;
                            }
                        } else if ch == b';' {
                            break 'outer;
                        } else if !ch.is_ascii_whitespace() {
                            return Err(Error::ParseFailed);
                        }
                    }
                }
                b'!' => {
                    let mut has_digits = false;
                    let mut has_units = false;

                    while let Some(&ch) = self.next() {
                        match ch {
                            b'0'..=b'9' if !has_units => {
                                size =
                                    (size.saturating_mul(10)).saturating_add((ch - b'0') as usize);
                                has_digits = true;
                            }
                            b'k' | b'K' if !has_units && has_digits => {
                                size = size.saturating_mul(1024);
                                has_units = true;
                            }
                            b'm' | b'M' if !has_units && has_digits => {
                                size = size.saturating_mul(1024 * 1024);
                                has_units = true;
                            }
                            b'g' | b'G' if !has_units && has_digits => {
                                size = size.saturating_mul(1024 * 1024 * 1024);
                                has_units = true;
                            }
                            b't' | b'T' if !has_units && has_digits => {
                                size = size.saturating_mul(1024 * 1024 * 1024 * 1024);
                                has_units = true;
                            }
                            b';' => {
                                break 'outer;
                            }
                            b',' => {
                                if !uri.is_empty() {
                                    uris.push(URI {
                                        uri: uri.to_vec(),
                                        max_size: size,
                                    });
                                    uri.clear();
                                }
                                size = 0;
                                break;
                            }
                            _ => {
                                if !ch.is_ascii_whitespace() {
                                    return Err(Error::ParseFailed);
                                }
                            }
                        }
                    }
                }
                b',' => {
                    if !uri.is_empty() {
                        uris.push(URI {
                            uri: uri.to_vec(),
                            max_size: size,
                        });
                        uri.clear();
                    }
                    size = 0;
                }
                b';' => {
                    break;
                }
                _ => {
                    if !ch.is_ascii_whitespace() {
                        uri.push(ch);
                    }
                }
            }
        }

        if !uri.is_empty() {
            uris.push(URI {
                uri,
                max_size: size,
            })
        }

        Ok(uris)
    }
}

impl ItemParser for Format {
    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.eq_ignore_ascii_case(b"afrf") {
            Format::Afrf.into()
        } else {
            None
        }
    }
}

const ADKIM: u64 = (b'a' as u64)
    | (b'd' as u64) << 8
    | (b'k' as u64) << 16
    | (b'i' as u64) << 24
    | (b'm' as u64) << 32;
const ASPF: u64 = (b'a' as u64) | (b's' as u64) << 8 | (b'p' as u64) << 16 | (b'f' as u64) << 24;
const FO: u64 = (b'f' as u64) | (b'o' as u64) << 8;
const NP: u64 = (b'n' as u64) | (b'p' as u64) << 8;
const P: u64 = b'p' as u64;
const PCT: u64 = (b'p' as u64) | (b'c' as u64) << 8 | (b't' as u64) << 16;
const RF: u64 = (b'r' as u64) | (b'f' as u64) << 8;
const RI: u64 = (b'r' as u64) | (b'i' as u64) << 8;
const RUA: u64 = (b'r' as u64) | (b'u' as u64) << 8 | (b'a' as u64) << 16;
const RUF: u64 = (b'r' as u64) | (b'u' as u64) << 8 | (b'f' as u64) << 16;
const SP: u64 = (b's' as u64) | (b'p' as u64) << 8;

#[cfg(test)]
mod test {
    use crate::dmarc::{Alignment, Format, Policy, Report, DMARC, URI};

    #[test]
    fn parse_dmarc() {
        for (record, expected_result) in [
            (
                "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com",
                DMARC {
                    adkim: Alignment::Relaxed,
                    aspf: Alignment::Relaxed,
                    fo: Report::All,
                    np: Policy::None,
                    p: Policy::None,
                    pct: 100,
                    rf: Format::Afrf as u8,
                    ri: 86400,
                    rua: vec![URI::new("mailto:dmarc-feedback@example.com", 0)],
                    ruf: vec![],
                    sp: Policy::None,
                },
            ),
            (
                concat!(
                    "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com;",
                    "ruf=mailto:auth-reports@example.com"
                ),
                DMARC {
                    adkim: Alignment::Relaxed,
                    aspf: Alignment::Relaxed,
                    fo: Report::All,
                    np: Policy::None,
                    p: Policy::None,
                    pct: 100,
                    rf: Format::Afrf as u8,
                    ri: 86400,
                    rua: vec![URI::new("mailto:dmarc-feedback@example.com", 0)],
                    ruf: vec![URI::new("mailto:auth-reports@example.com", 0)],
                    sp: Policy::None,
                },
            ),
            (
                concat!(
                    "v=DMARC1; p=quarantine; rua=mailto:dmarc-feedback@example.com,",
                    "mailto:tld-test@thirdparty.example.net!10m; pct=25"
                ),
                DMARC {
                    adkim: Alignment::Relaxed,
                    aspf: Alignment::Relaxed,
                    fo: Report::All,
                    np: Policy::Quarantine,
                    p: Policy::Quarantine,
                    pct: 25,
                    rf: Format::Afrf as u8,
                    ri: 86400,
                    ruf: vec![],
                    rua: vec![
                        URI::new("mailto:dmarc-feedback@example.com", 0),
                        URI::new("mailto:tld-test@thirdparty.example.net", 10 * 1024 * 1024),
                    ],
                    sp: Policy::Quarantine,
                },
            ),
            (
                concat!(
                    "v=DMARC1; p=reject; sp=quarantine; np=None; aspf=s; adkim=s; fo = 1;",
                    "rua=mailto:dmarc-feedback@example.com"
                ),
                DMARC {
                    adkim: Alignment::Strict,
                    aspf: Alignment::Strict,
                    fo: Report::Any,
                    np: Policy::None,
                    p: Policy::Reject,
                    pct: 100,
                    rf: Format::Afrf as u8,
                    ri: 86400,
                    rua: vec![URI::new("mailto:dmarc-feedback@example.com", 0)],
                    ruf: vec![],
                    sp: Policy::Quarantine,
                },
            ),
            (
                concat!(
                    "v=DMARC1; p=reject; ri = 3600; aspf=r; adkim =r; ",
                    "rua=mailto:dmarc-feedback@example.com!10 K , mailto:user%20@example.com ! 2G;",
                    "ignore_me= true; fo=s; rf = AfrF; ",
                ),
                DMARC {
                    adkim: Alignment::Relaxed,
                    aspf: Alignment::Relaxed,
                    fo: Report::Spf,
                    np: Policy::Reject,
                    p: Policy::Reject,
                    pct: 100,
                    rf: Format::Afrf as u8,
                    ri: 3600,
                    rua: vec![
                        URI::new("mailto:dmarc-feedback@example.com", 10 * 1024),
                        URI::new("mailto:user @example.com", 2 * 1024 * 1024 * 1024),
                    ],
                    ruf: vec![],
                    sp: Policy::Reject,
                },
            ),
        ] {
            assert_eq!(
                DMARC::parse(record.as_bytes())
                    .unwrap_or_else(|err| panic!("{:?} : {:?}", record, err)),
                expected_result,
                "{}",
                record
            );
        }
    }
}
