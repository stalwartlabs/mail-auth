/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use crate::common::headers::{HeaderStream, Writable, Writer};

use super::{Canonicalization, Signature};

pub struct CanonicalBody<'a> {
    canonicalization: Canonicalization,
    body: &'a [u8],
}

impl Writable for CanonicalBody<'_> {
    fn write(self, hasher: &mut impl Writer) {
        let mut crlf_seq = 0;

        match self.canonicalization {
            Canonicalization::Relaxed => {
                let mut last_ch = 0;
                let mut is_empty = true;

                for &ch in self.body {
                    match ch {
                        b' ' | b'\t' => {
                            while crlf_seq > 0 {
                                hasher.write(b"\r\n");
                                crlf_seq -= 1;
                            }
                            is_empty = false;
                        }
                        b'\n' => {
                            crlf_seq += 1;
                        }
                        b'\r' => {}
                        _ => {
                            while crlf_seq > 0 {
                                hasher.write(b"\r\n");
                                crlf_seq -= 1;
                            }

                            if last_ch == b' ' || last_ch == b'\t' {
                                hasher.write(b" ");
                            }

                            hasher.write(&[ch]);
                            is_empty = false;
                        }
                    }

                    last_ch = ch;
                }

                if !is_empty {
                    hasher.write(b"\r\n");
                }
            }
            Canonicalization::Simple => {
                for &ch in self.body {
                    match ch {
                        b'\n' => {
                            crlf_seq += 1;
                        }
                        b'\r' => {}
                        _ => {
                            while crlf_seq > 0 {
                                hasher.write(b"\r\n");
                                crlf_seq -= 1;
                            }
                            hasher.write(&[ch]);
                        }
                    }
                }

                hasher.write(b"\r\n");
            }
        }
    }
}

impl Canonicalization {
    pub fn canonicalize_headers<'a>(
        &self,
        headers: impl Iterator<Item = (&'a [u8], &'a [u8])>,
        hasher: &mut impl Writer,
    ) {
        match self {
            Canonicalization::Relaxed => {
                for (name, value) in headers {
                    for &ch in name {
                        if !ch.is_ascii_whitespace() {
                            hasher.write(&[ch.to_ascii_lowercase()]);
                        }
                    }

                    hasher.write(b":");
                    let mut bw = 0;
                    let mut last_ch = 0;

                    for &ch in value {
                        if !ch.is_ascii_whitespace() {
                            if [b' ', b'\t'].contains(&last_ch) && bw > 0 {
                                hasher.write_len(b" ", &mut bw);
                            }
                            hasher.write_len(&[ch], &mut bw);
                        }
                        last_ch = ch;
                    }

                    if last_ch == b'\n' {
                        hasher.write(b"\r\n");
                    }
                }
            }
            Canonicalization::Simple => {
                for (name, value) in headers {
                    hasher.write(name);
                    hasher.write(b":");
                    hasher.write(value);
                }
            }
        }
    }

    pub fn canonical_headers<'a>(
        &self,
        headers: Vec<(&'a [u8], &'a [u8])>,
    ) -> CanonicalHeaders<'a> {
        CanonicalHeaders {
            canonicalization: *self,
            headers,
        }
    }

    pub fn canonical_body<'a>(&self, body: &'a [u8], l: u64) -> CanonicalBody<'a> {
        CanonicalBody {
            canonicalization: *self,
            body: if l == 0 || body.is_empty() {
                body
            } else {
                &body[..std::cmp::min(l as usize, body.len())]
            },
        }
    }

    pub fn serialize_name(&self, writer: &mut impl Writer) {
        writer.write(match self {
            Canonicalization::Relaxed => b"relaxed",
            Canonicalization::Simple => b"simple",
        });
    }
}

impl Signature {
    pub(crate) fn canonicalize<'x>(
        &self,
        mut message: impl HeaderStream<'x>,
    ) -> (usize, CanonicalHeaders<'x>, Vec<String>, CanonicalBody<'x>) {
        let mut headers = Vec::with_capacity(self.h.len());
        let mut found_headers = vec![false; self.h.len()];
        let mut signed_headers = Vec::with_capacity(self.h.len());

        while let Some((name, value)) = message.next_header() {
            if let Some(pos) = self
                .h
                .iter()
                .position(|header| name.eq_ignore_ascii_case(header.as_bytes()))
            {
                headers.push((name, value));
                found_headers[pos] = true;
                signed_headers.push(std::str::from_utf8(name).unwrap().into());
            }
        }

        let body = message.body();
        let body_len = body.len();
        let canonical_headers = self.ch.canonical_headers(headers);
        let canonical_body = self.ch.canonical_body(body, u64::MAX);

        // Add any missing headers
        signed_headers.reverse();
        for (header, found) in self.h.iter().zip(found_headers) {
            if !found {
                signed_headers.push(header.to_string());
            }
        }

        (body_len, canonical_headers, signed_headers, canonical_body)
    }
}

pub struct CanonicalHeaders<'a> {
    canonicalization: Canonicalization,
    headers: Vec<(&'a [u8], &'a [u8])>,
}

impl<'a> Writable for CanonicalHeaders<'a> {
    fn write(self, writer: &mut impl Writer) {
        self.canonicalization
            .canonicalize_headers(self.headers.into_iter().rev(), writer)
    }
}

#[cfg(test)]
mod test {
    use mail_builder::encoders::base64::base64_encode;

    use super::{CanonicalBody, CanonicalHeaders};
    use crate::{
        common::{
            crypto::{HashImpl, Sha256},
            headers::{HeaderIterator, Writable},
        },
        dkim::Canonicalization,
    };

    #[test]
    #[allow(clippy::needless_collect)]
    fn dkim_canonicalize() {
        for (message, (relaxed_headers, relaxed_body), (simple_headers, simple_body)) in [
            (
                concat!(
                    "A: X\r\n",
                    "B : Y\t\r\n",
                    "\tZ  \r\n",
                    "\r\n",
                    " C \r\n",
                    "D \t E\r\n"
                ),
                (
                    concat!("a:X\r\n", "b:Y Z\r\n",),
                    concat!(" C\r\n", "D E\r\n"),
                ),
                ("A: X\r\nB : Y\t\r\n\tZ  \r\n", " C \r\nD \t E\r\n"),
            ),
            (
                concat!(
                    "  From : John\tdoe <jdoe@domain.com>\t\r\n",
                    "SUB JECT:\ttest  \t  \r\n\r\n",
                    " body \t   \r\n",
                    "\r\n",
                    "\r\n",
                ),
                (
                    concat!("from:John doe <jdoe@domain.com>\r\n", "subject:test\r\n"),
                    concat!(" body\r\n"),
                ),
                (
                    concat!(
                        "  From : John\tdoe <jdoe@domain.com>\t\r\n",
                        "SUB JECT:\ttest  \t  \r\n"
                    ),
                    concat!(" body \t   \r\n"),
                ),
            ),
            (
                concat!("H: value\t\r\n\r\n",),
                (concat!("h:value\r\n"), concat!("")),
                (concat!("H: value\t\r\n"), concat!("\r\n")),
            ),
            (
                concat!("\tx\t: \t\t\tz\r\n\r\nabc",),
                (concat!("x:z\r\n"), concat!("abc\r\n")),
                ("\tx\t: \t\t\tz\r\n", concat!("abc\r\n")),
            ),
            (
                concat!("Subject: hello\r\n\r\n\r\n",),
                (concat!("subject:hello\r\n"), ""),
                ("Subject: hello\r\n", concat!("\r\n")),
            ),
        ] {
            let mut header_iterator = HeaderIterator::new(message.as_bytes());
            let parsed_headers = (&mut header_iterator).collect::<Vec<_>>();
            let raw_body = header_iterator
                .body_offset()
                .map(|pos| &message.as_bytes()[pos..])
                .unwrap_or_default();

            for (canonicalization, expected_headers, expected_body) in [
                (Canonicalization::Relaxed, relaxed_headers, relaxed_body),
                (Canonicalization::Simple, simple_headers, simple_body),
            ] {
                let mut headers = Vec::new();
                CanonicalHeaders {
                    canonicalization,
                    headers: parsed_headers.iter().cloned().rev().collect(),
                }
                .write(&mut headers);
                assert_eq!(expected_headers, String::from_utf8(headers).unwrap());

                let mut body = Vec::new();
                CanonicalBody {
                    canonicalization,
                    body: raw_body,
                }
                .write(&mut body);
                assert_eq!(expected_body, String::from_utf8(body).unwrap());
            }
        }

        // Test empty body hashes
        for (canonicalization, hash) in [
            (
                Canonicalization::Relaxed,
                "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
            ),
            (
                Canonicalization::Simple,
                "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=",
            ),
        ] {
            for body in ["\r\n", ""] {
                let mut hasher = Sha256::hasher();
                CanonicalBody {
                    canonicalization,
                    body: body.as_bytes(),
                }
                .write(&mut hasher);

                assert_eq!(
                    String::from_utf8(base64_encode(hasher.finish().as_ref()).unwrap()).unwrap(),
                    hash,
                );
            }
        }
    }
}
