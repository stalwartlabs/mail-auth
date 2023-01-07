/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::borrow::Cow;

use sha1::Digest;

use crate::common::headers::{HeaderIterator, Writer};

use super::{Canonicalization, Signature};

impl Canonicalization {
    pub fn canonicalize_body(&self, body: &[u8], hasher: &mut impl Writer) {
        let mut crlf_seq = 0;

        match self {
            Canonicalization::Relaxed => {
                let mut last_ch = 0;

                for &ch in body {
                    match ch {
                        b' ' | b'\t' => {
                            while crlf_seq > 0 {
                                hasher.write(b"\r\n");
                                crlf_seq -= 1;
                            }
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
                        }
                    }

                    last_ch = ch;
                }
            }
            Canonicalization::Simple => {
                for &ch in body {
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
            }
        }

        hasher.write(b"\r\n");
    }

    pub fn canonicalize_headers<'x>(
        &self,
        headers: &mut dyn Iterator<Item = (&'x [u8], &'x [u8])>,
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

    pub fn hash_headers<'x, T: Digest + Writer>(
        &self,
        headers: &mut dyn Iterator<Item = (&'x [u8], &'x [u8])>,
    ) -> impl AsRef<[u8]> {
        let mut hasher = T::new();
        self.canonicalize_headers(headers, &mut hasher);
        hasher.finalize()
    }

    pub fn hash_body<T: Digest + Writer>(&self, body: &[u8], l: u64) -> impl AsRef<[u8]> {
        let mut hasher = T::new();
        self.canonicalize_body(
            if l == 0 || body.is_empty() {
                body
            } else {
                &body[..std::cmp::min(l as usize, body.len())]
            },
            &mut hasher,
        );
        hasher.finalize()
    }

    pub fn serialize_name(&self, writer: &mut impl Writer) {
        writer.write(match self {
            Canonicalization::Relaxed => b"relaxed",
            Canonicalization::Simple => b"simple",
        });
    }
}

impl<'x> Signature<'x> {
    #[allow(clippy::while_let_on_iterator)]
    pub(crate) fn canonicalize(
        &self,
        message: &'x [u8],
        header_hasher: &mut impl Writer,
        body_hasher: &mut impl Writer,
    ) -> (usize, Vec<Cow<'x, str>>) {
        let mut headers_it = HeaderIterator::new(message);
        let mut headers = Vec::with_capacity(self.h.len());
        let mut found_headers = vec![false; self.h.len()];
        let mut signed_headers = Vec::with_capacity(self.h.len());

        for (name, value) in &mut headers_it {
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

        let body = headers_it
            .body_offset()
            .and_then(|pos| message.get(pos..))
            .unwrap_or_default();
        let body_len = body.len();
        self.ch
            .canonicalize_headers(&mut headers.into_iter().rev(), header_hasher);
        self.cb.canonicalize_body(body, body_hasher);

        // Add any missing headers
        signed_headers.reverse();
        for (header, found) in self.h.iter().zip(found_headers) {
            if !found {
                signed_headers.push(header.to_string().into());
            }
        }

        (body_len, signed_headers)
    }
}

#[cfg(test)]
mod test {
    use crate::{common::headers::HeaderIterator, dkim::Canonicalization};

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
                (concat!("h:value\r\n"), concat!("\r\n")),
                (concat!("H: value\t\r\n"), concat!("\r\n")),
            ),
            (
                concat!("\tx\t: \t\t\tz\r\n\r\nabc",),
                (concat!("x:z\r\n"), concat!("abc\r\n")),
                ("\tx\t: \t\t\tz\r\n", concat!("abc\r\n")),
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
                let mut body = Vec::new();

                canonicalization
                    .canonicalize_headers(&mut parsed_headers.clone().into_iter(), &mut headers);
                canonicalization.canonicalize_body(raw_body, &mut body);

                assert_eq!(expected_headers, String::from_utf8(headers).unwrap());
                assert_eq!(expected_body, String::from_utf8(body).unwrap());
            }
        }
    }
}
