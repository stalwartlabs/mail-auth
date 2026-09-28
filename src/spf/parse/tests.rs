/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::{
    parse::TxtRecordParser,
    spf::{
        Directive, Macro, Mechanism, Qualifier, RR_FAIL, RR_NEUTRAL_NONE, RR_SOFTFAIL,
        RR_TEMP_PERM_ERROR, SpfRecord, Variable,
    },
};

use super::SPFParser;

#[test]
fn parse_spf() {
    for (record, expected_result) in [
        (
            "v=spf1 +mx a:colo.example.com/28 -all",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Mx {
                            macro_string: Macro::None,
                            ip4_mask: u32::MAX,
                            ip6_mask: u128::MAX,
                        },
                    ),
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::A {
                            macro_string: Macro::Literal(b"colo.example.com".as_slice().into()),
                            ip4_mask: u32::MAX << (32 - 28),
                            ip6_mask: u128::MAX,
                        },
                    ),
                    Directive::new(Qualifier::Fail, Mechanism::All),
                ]),
            },
        ),
        (
            "v=spf1 a:A.EXAMPLE.COM -all",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::A {
                            macro_string: Macro::Literal(b"A.EXAMPLE.COM".as_slice().into()),
                            ip4_mask: u32::MAX,
                            ip6_mask: u128::MAX,
                        },
                    ),
                    Directive::new(Qualifier::Fail, Mechanism::All),
                ]),
            },
        ),
        (
            "v=spf1 +mx -all",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Mx {
                            macro_string: Macro::None,
                            ip4_mask: u32::MAX,
                            ip6_mask: u128::MAX,
                        },
                    ),
                    Directive::new(Qualifier::Fail, Mechanism::All),
                ]),
            },
        ),
        (
            "v=spf1 +mx redirect=_spf.example.com",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                redirect: Macro::Literal(b"_spf.example.com".as_slice().into()).into(),
                exp: None,
                directives: Box::new([Directive::new(
                    Qualifier::Pass,
                    Mechanism::Mx {
                        macro_string: Macro::None,
                        ip4_mask: u32::MAX,
                        ip6_mask: u128::MAX,
                    },
                )]),
            },
        ),
        (
            "v=spf1 a mx -all",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::A {
                            macro_string: Macro::None,
                            ip4_mask: u32::MAX,
                            ip6_mask: u128::MAX,
                        },
                    ),
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Mx {
                            macro_string: Macro::None,
                            ip4_mask: u32::MAX,
                            ip6_mask: u128::MAX,
                        },
                    ),
                    Directive::new(Qualifier::Fail, Mechanism::All),
                ]),
            },
        ),
        (
            "v=spf1 include:example.com include:example.org -all",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Include {
                            macro_string: Macro::Literal(b"example.com".as_slice().into()),
                        },
                    ),
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Include {
                            macro_string: Macro::Literal(b"example.org".as_slice().into()),
                        },
                    ),
                    Directive::new(Qualifier::Fail, Mechanism::All),
                ]),
            },
        ),
        (
            "v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} -all",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Exists {
                            macro_string: Macro::List(Box::new([
                                Macro::Variable {
                                    letter: Variable::Ip,
                                    num_parts: 0,
                                    reverse: true,
                                    escape: false,
                                    delimiters: 1u64 << (b'.' - b'+'),
                                },
                                Macro::Literal(b".".as_slice().into()),
                                Macro::Variable {
                                    letter: Variable::SenderLocalPart,
                                    num_parts: 1,
                                    reverse: true,
                                    escape: false,
                                    delimiters: (1u64 << (b'+' - b'+')) | (1u64 << (b'-' - b'+')),
                                },
                                Macro::Literal(b"._spf.".as_slice().into()),
                                Macro::Variable {
                                    letter: Variable::Domain,
                                    num_parts: 0,
                                    reverse: false,
                                    escape: false,
                                    delimiters: 1u64 << (b'.' - b'+'),
                                },
                            ])),
                        },
                    ),
                    Directive::new(Qualifier::Fail, Mechanism::All),
                ]),
            },
        ),
        (
            "v=spf1 mx -all exp=explain._spf.%{d}",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: Macro::List(Box::new([
                    Macro::Literal(b"explain._spf.".as_slice().into()),
                    Macro::Variable {
                        letter: Variable::Domain,
                        num_parts: 0,
                        reverse: false,
                        escape: false,
                        delimiters: 1u64 << (b'.' - b'+'),
                    },
                ]))
                .into(),
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Mx {
                            macro_string: Macro::None,
                            ip4_mask: u32::MAX,
                            ip6_mask: u128::MAX,
                        },
                    ),
                    Directive::new(Qualifier::Fail, Mechanism::All),
                ]),
            },
        ),
        (
            "v=spf1 ip4:192.0.2.1 ip4:192.0.2.129 -all",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Ip4 {
                            addr: "192.0.2.1".parse().unwrap(),
                            mask: u32::MAX,
                        },
                    ),
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Ip4 {
                            addr: "192.0.2.129".parse().unwrap(),
                            mask: u32::MAX,
                        },
                    ),
                    Directive::new(Qualifier::Fail, Mechanism::All),
                ]),
            },
        ),
        (
            "v=spf1 ip4:192.0.2.0/24 mx -all",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Ip4 {
                            addr: "192.0.2.0".parse().unwrap(),
                            mask: u32::MAX << (32 - 24),
                        },
                    ),
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Mx {
                            macro_string: Macro::None,
                            ip4_mask: u32::MAX,
                            ip6_mask: u128::MAX,
                        },
                    ),
                    Directive::new(Qualifier::Fail, Mechanism::All),
                ]),
            },
        ),
        (
            "v=spf1 mx/30 mx:example.org/30 -all",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Mx {
                            macro_string: Macro::None,
                            ip4_mask: u32::MAX << (32 - 30),
                            ip6_mask: u128::MAX,
                        },
                    ),
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Mx {
                            macro_string: Macro::Literal(b"example.org".as_slice().into()),
                            ip4_mask: u32::MAX << (32 - 30),
                            ip6_mask: u128::MAX,
                        },
                    ),
                    Directive::new(Qualifier::Fail, Mechanism::All),
                ]),
            },
        ),
        (
            "v=spf1 ptr -all",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Ptr {
                            macro_string: Macro::None,
                        },
                    ),
                    Directive::new(Qualifier::Fail, Mechanism::All),
                ]),
            },
        ),
        (
            "v=spf1 exists:%{l1r+}.%{d}",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([Directive::new(
                    Qualifier::Pass,
                    Mechanism::Exists {
                        macro_string: Macro::List(Box::new([
                            Macro::Variable {
                                letter: Variable::SenderLocalPart,
                                num_parts: 1,
                                reverse: true,
                                escape: false,
                                delimiters: 1u64 << (b'+' - b'+'),
                            },
                            Macro::Literal(b".".as_slice().into()),
                            Macro::Variable {
                                letter: Variable::Domain,
                                num_parts: 0,
                                reverse: false,
                                escape: false,
                                delimiters: 1u64 << (b'.' - b'+'),
                            },
                        ])),
                    },
                )]),
            },
        ),
        (
            "v=spf1 exists:%{ir}.%{l1r+}.%{d}",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([Directive::new(
                    Qualifier::Pass,
                    Mechanism::Exists {
                        macro_string: Macro::List(Box::new([
                            Macro::Variable {
                                letter: Variable::Ip,
                                num_parts: 0,
                                reverse: true,
                                escape: false,
                                delimiters: 1u64 << (b'.' - b'+'),
                            },
                            Macro::Literal(b".".as_slice().into()),
                            Macro::Variable {
                                letter: Variable::SenderLocalPart,
                                num_parts: 1,
                                reverse: true,
                                escape: false,
                                delimiters: 1u64 << (b'+' - b'+'),
                            },
                            Macro::Literal(b".".as_slice().into()),
                            Macro::Variable {
                                letter: Variable::Domain,
                                num_parts: 0,
                                reverse: false,
                                escape: false,
                                delimiters: 1u64 << (b'.' - b'+'),
                            },
                        ])),
                    },
                )]),
            },
        ),
        (
            "v=spf1 exists:_h.%{h}._l.%{l}._o.%{o}._i.%{i}._spf.%{d} ?all",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Exists {
                            macro_string: Macro::List(Box::new([
                                Macro::Literal(b"_h.".as_slice().into()),
                                Macro::Variable {
                                    letter: Variable::HeloDomain,
                                    num_parts: 0,
                                    reverse: false,
                                    escape: false,
                                    delimiters: 1u64 << (b'.' - b'+'),
                                },
                                Macro::Literal(b"._l.".as_slice().into()),
                                Macro::Variable {
                                    letter: Variable::SenderLocalPart,
                                    num_parts: 0,
                                    reverse: false,
                                    escape: false,
                                    delimiters: 1u64 << (b'.' - b'+'),
                                },
                                Macro::Literal(b"._o.".as_slice().into()),
                                Macro::Variable {
                                    letter: Variable::SenderDomainPart,
                                    num_parts: 0,
                                    reverse: false,
                                    escape: false,
                                    delimiters: 1u64 << (b'.' - b'+'),
                                },
                                Macro::Literal(b"._i.".as_slice().into()),
                                Macro::Variable {
                                    letter: Variable::Ip,
                                    num_parts: 0,
                                    reverse: false,
                                    escape: false,
                                    delimiters: 1u64 << (b'.' - b'+'),
                                },
                                Macro::Literal(b"._spf.".as_slice().into()),
                                Macro::Variable {
                                    letter: Variable::Domain,
                                    num_parts: 0,
                                    reverse: false,
                                    escape: false,
                                    delimiters: 1u64 << (b'.' - b'+'),
                                },
                            ])),
                        },
                    ),
                    Directive::new(Qualifier::Neutral, Mechanism::All),
                ]),
            },
        ),
        (
            "v=spf1 mx ?exists:%{ir}.whitelist.example.org -all",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Mx {
                            macro_string: Macro::None,
                            ip4_mask: u32::MAX,
                            ip6_mask: u128::MAX,
                        },
                    ),
                    Directive::new(
                        Qualifier::Neutral,
                        Mechanism::Exists {
                            macro_string: Macro::List(Box::new([
                                Macro::Variable {
                                    letter: Variable::Ip,
                                    num_parts: 0,
                                    reverse: true,
                                    escape: false,
                                    delimiters: 1u64 << (b'.' - b'+'),
                                },
                                Macro::Literal(b".whitelist.example.org".as_slice().into()),
                            ])),
                        },
                    ),
                    Directive::new(Qualifier::Fail, Mechanism::All),
                ]),
            },
        ),
        (
            "v=spf1 mx exists:%{l}._%-spf_%_verify%%.%{d} -all",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Mx {
                            macro_string: Macro::None,
                            ip4_mask: u32::MAX,
                            ip6_mask: u128::MAX,
                        },
                    ),
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Exists {
                            macro_string: Macro::List(Box::new([
                                Macro::Variable {
                                    letter: Variable::SenderLocalPart,
                                    num_parts: 0,
                                    reverse: false,
                                    escape: false,
                                    delimiters: 1u64 << (b'.' - b'+'),
                                },
                                Macro::Literal(b"._%20spf_ verify%.".as_slice().into()),
                                Macro::Variable {
                                    letter: Variable::Domain,
                                    num_parts: 0,
                                    reverse: false,
                                    escape: false,
                                    delimiters: 1u64 << (b'.' - b'+'),
                                },
                            ])),
                        },
                    ),
                    Directive::new(Qualifier::Fail, Mechanism::All),
                ]),
            },
        ),
        (
            "v=spf1 mx redirect=%{l1r+}._at_.%{o,=_/}._spf.%{d}",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: Macro::List(Box::new([
                    Macro::Variable {
                        letter: Variable::SenderLocalPart,
                        num_parts: 1,
                        reverse: true,
                        escape: false,
                        delimiters: 1u64 << (b'+' - b'+'),
                    },
                    Macro::Literal(b"._at_.".as_slice().into()),
                    Macro::Variable {
                        letter: Variable::SenderDomainPart,
                        num_parts: 0,
                        reverse: false,
                        escape: false,
                        delimiters: (1u64 << (b',' - b'+'))
                            | (1u64 << (b'=' - b'+'))
                            | (1u64 << (b'_' - b'+'))
                            | (1u64 << (b'/' - b'+')),
                    },
                    Macro::Literal(b"._spf.".as_slice().into()),
                    Macro::Variable {
                        letter: Variable::Domain,
                        num_parts: 0,
                        reverse: false,
                        escape: false,
                        delimiters: 1u64 << (b'.' - b'+'),
                    },
                ]))
                .into(),
                directives: Box::new([Directive::new(
                    Qualifier::Pass,
                    Mechanism::Mx {
                        macro_string: Macro::None,
                        ip4_mask: u32::MAX,
                        ip6_mask: u128::MAX,
                    },
                )]),
            },
        ),
        (
            "v=spf1 -ip4:192.0.2.0/24 a//96 +all",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Fail,
                        Mechanism::Ip4 {
                            addr: "192.0.2.0".parse().unwrap(),
                            mask: u32::MAX << (32 - 24),
                        },
                    ),
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::A {
                            macro_string: Macro::None,
                            ip4_mask: u32::MAX,
                            ip6_mask: u128::MAX << (128 - 96),
                        },
                    ),
                    Directive::new(Qualifier::Pass, Mechanism::All),
                ]),
            },
        ),
        (
            concat!(
                "v=spf1 +mx/11//100 ~a:domain.com/12/123 ?ip6:::1 ",
                "-ip6:a::b/111 ip6:1080::8:800:68.0.3.1/96 "
            ),
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Mx {
                            macro_string: Macro::None,
                            ip4_mask: u32::MAX << (32 - 11),
                            ip6_mask: u128::MAX << (128 - 100),
                        },
                    ),
                    Directive::new(
                        Qualifier::SoftFail,
                        Mechanism::A {
                            macro_string: Macro::Literal(b"domain.com".as_slice().into()),
                            ip4_mask: u32::MAX << (32 - 12),
                            ip6_mask: u128::MAX << (128 - 123),
                        },
                    ),
                    Directive::new(
                        Qualifier::Neutral,
                        Mechanism::Ip6 {
                            addr: "::1".parse().unwrap(),
                            mask: u128::MAX,
                        },
                    ),
                    Directive::new(
                        Qualifier::Fail,
                        Mechanism::Ip6 {
                            addr: "a::b".parse().unwrap(),
                            mask: u128::MAX << (128 - 111),
                        },
                    ),
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Ip6 {
                            addr: "1080::8:800:68.0.3.1".parse().unwrap(),
                            mask: u128::MAX << (128 - 96),
                        },
                    ),
                ]),
            },
        ),
        (
            "v=spf1 mx:example.org -all ra=postmaster rp=15 rr=e:f:s:n",
            SpfRecord {
                ra: Some(b"postmaster".as_slice().into()),
                rp: 15,
                rr: RR_FAIL | RR_NEUTRAL_NONE | RR_SOFTFAIL | RR_TEMP_PERM_ERROR,
                exp: None,
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Mx {
                            macro_string: Macro::Literal(b"example.org".as_slice().into()),
                            ip4_mask: u32::MAX,
                            ip6_mask: u128::MAX,
                        },
                    ),
                    Directive::new(Qualifier::Fail, Mechanism::All),
                ]),
            },
        ),
        (
            "v=spf1 ip6:fe80:0000:0000::0000:0000:0000:1 -all",
            SpfRecord {
                ra: None,
                rp: 100,
                rr: u8::MAX,
                exp: None,
                redirect: None,
                directives: Box::new([
                    Directive::new(
                        Qualifier::Pass,
                        Mechanism::Ip6 {
                            addr: "fe80:0000:0000::0000:0000:0000:1".parse().unwrap(),
                            mask: u128::MAX,
                        },
                    ),
                    Directive::new(Qualifier::Fail, Mechanism::All),
                ]),
            },
        ),
    ] {
        assert_eq!(
            SpfRecord::parse(record.as_bytes())
                .unwrap_or_else(|err| panic!("{record:?} : {err:?}")),
            expected_result,
            "{record}"
        );
    }
}

#[test]
fn parse_ip6() {
    for test in [
        "ABCD:EF01:2345:6789:ABCD:EF01:2345:6789",
        "2001:DB8:0:0:8:800:200C:417A",
        "FF01:0:0:0:0:0:0:101",
        "0:0:0:0:0:0:0:1",
        "0:0:0:0:0:0:0:0",
        "2001:DB8::8:800:200C:417A",
        "2001:DB8:0:0:8:800:200C::",
        "FF01::101",
        "1234::",
        "::1",
        "::",
        "a:b::c:d",
        "a::c:d",
        "a:b:c::d",
        "::c:d",
        "0:0:0:0:0:0:13.1.68.3",
        "0:0:0:0:0:FFFF:129.144.52.38",
        "::13.1.68.3",
        "::FFFF:129.144.52.38",
        "fe80::1",
        "fe80::0000:1",
        "fe80:0000::0000:1",
        "fe80:0000:0000:0000::1",
        "fe80:0000:0000:0000::0000:1",
        "fe80:0000:0000::0000:0000:0000:1",
        "fe80::0000:0000:0000:0000:0000:1",
        "fe80:0000:0000:0000:0000:0000:0000:1",
    ] {
        for test in [test.to_string(), format!("{test} ")] {
            let (ip, stop_char) = test
                .as_bytes()
                .iter()
                .ip6()
                .unwrap_or_else(|err| panic!("{test:?} : {err:?}"));
            assert_eq!(stop_char, b' ', "{test}");
            assert_eq!(ip, test.trim_end().parse::<Ipv6Addr>().unwrap())
        }
    }

    for invalid_test in [
        "0:0:0:0:0:0:0:1:1",
        "0:0:0:0:0:0:13.1.68.3.4",
        "::0:0:0:0:0:0:0:0",
        "0:0:0:0::0:0:0:0",
        " ",
        "",
    ] {
        assert!(
            invalid_test.as_bytes().iter().ip6().is_err(),
            "{}",
            invalid_test
        );
    }
}

#[test]
fn parse_ip4() {
    for test in ["0.0.0.0", "255.255.255.255", "13.1.68.3", "129.144.52.38"] {
        for test in [test.to_string(), format!("{test} ")] {
            let (ip, stop_char) = test
                .as_bytes()
                .iter()
                .ip4()
                .unwrap_or_else(|err| panic!("{test:?} : {err:?}"));
            assert_eq!(stop_char, b' ', "{test}");
            assert_eq!(ip, test.trim_end().parse::<Ipv4Addr>().unwrap());
        }
    }
}
