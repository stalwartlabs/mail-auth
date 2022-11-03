/*
 * Copyright Stalwart Labs Ltd. See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::io::Write;

use crate::common::headers::HeaderIterator;

use super::{Canonicalization, DKIMSigner};

impl Canonicalization {
    pub fn canonicalize_body(&self, message: &[u8], mut hasher: impl Write) -> std::io::Result<()> {
        let mut crlf_seq = 0;

        match self {
            Canonicalization::Relaxed => {
                let mut last_ch = 0;

                for &ch in message {
                    match ch {
                        b' ' | b'\t' => {
                            while crlf_seq > 0 {
                                let _ = hasher.write(b"\r\n")?;
                                crlf_seq -= 1;
                            }
                        }
                        b'\n' => {
                            crlf_seq += 1;
                        }
                        b'\r' => {}
                        _ => {
                            while crlf_seq > 0 {
                                let _ = hasher.write(b"\r\n")?;
                                crlf_seq -= 1;
                            }

                            if last_ch == b' ' || last_ch == b'\t' {
                                let _ = hasher.write(b" ")?;
                            }

                            let _ = hasher.write(&[ch])?;
                        }
                    }

                    last_ch = ch;
                }
            }
            Canonicalization::Simple => {
                for &ch in message {
                    match ch {
                        b'\n' => {
                            crlf_seq += 1;
                        }
                        b'\r' => {}
                        _ => {
                            while crlf_seq > 0 {
                                let _ = hasher.write(b"\r\n")?;
                                crlf_seq -= 1;
                            }
                            let _ = hasher.write(&[ch])?;
                        }
                    }
                }
            }
        }

        hasher.write_all(b"\r\n")
    }

    pub fn canonicalize_headers<'x>(
        &self,
        headers: impl Iterator<Item = (&'x [u8], &'x [u8])>,
        mut hasher: impl Write,
    ) -> std::io::Result<()> {
        match self {
            Canonicalization::Relaxed => {
                for (name, value) in headers {
                    for &ch in name {
                        if !ch.is_ascii_whitespace() {
                            let _ = hasher.write(&[ch.to_ascii_lowercase()])?;
                        }
                    }
                    let _ = hasher.write(b":")?;
                    let mut bytes_written = 0;
                    let mut last_ch = 0;

                    for &ch in value {
                        if !ch.is_ascii_whitespace() {
                            if [b' ', b'\t'].contains(&last_ch) && bytes_written > 0 {
                                bytes_written += hasher.write(b" ")?;
                            }
                            bytes_written += hasher.write(&[ch])?;
                        }
                        last_ch = ch;
                    }
                    let _ = hasher.write(b"\r\n");
                }
            }
            Canonicalization::Simple => {
                for (name, value) in headers {
                    let _ = hasher.write(name)?;
                    let _ = hasher.write(b":")?;
                    let _ = hasher.write(value)?;
                }
            }
        }

        Ok(())
    }

    pub fn serialize_name(&self, mut writer: impl Write) -> std::io::Result<()> {
        writer.write_all(match self {
            Canonicalization::Relaxed => b"relaxed",
            Canonicalization::Simple => b"simple",
        })
    }
}

impl<'x> DKIMSigner<'x> {
    #[allow(clippy::while_let_on_iterator)]
    pub(crate) fn canonicalize(
        &self,
        message: &[u8],
        header_hasher: impl Write,
        body_hasher: impl Write,
    ) -> super::Result<(usize, Vec<Vec<u8>>)> {
        let mut headers_it = HeaderIterator::new(message);
        let mut headers = Vec::with_capacity(self.sign_headers.len());
        let mut found_headers = vec![false; self.sign_headers.len()];
        let mut signed_headers = Vec::with_capacity(self.sign_headers.len());

        for (name, value) in &mut headers_it {
            if let Some(pos) = self
                .sign_headers
                .iter()
                .position(|header| header.eq_ignore_ascii_case(name))
            {
                headers.push((name, value));
                found_headers[pos] = true;
                signed_headers.push(name.to_vec());
            }
        }

        let body = headers_it
            .body_offset()
            .and_then(|pos| message.get(pos..))
            .unwrap_or_default();
        let body_len = body.len();
        self.ch
            .canonicalize_headers(headers.into_iter().rev(), header_hasher)?;
        self.cb.canonicalize_body(body, body_hasher)?;

        // Add any missing headers
        signed_headers.reverse();
        for (header, found) in self.sign_headers.iter().zip(found_headers) {
            if !found {
                signed_headers.push(header.to_vec());
            }
        }

        Ok((body_len, signed_headers))
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
                    .canonicalize_headers(parsed_headers.clone().into_iter(), &mut headers)
                    .unwrap();
                canonicalization
                    .canonicalize_body(raw_body, &mut body)
                    .unwrap();

                assert_eq!(expected_headers, String::from_utf8(headers).unwrap());
                assert_eq!(expected_body, String::from_utf8(body).unwrap());
            }
        }
    }
}
