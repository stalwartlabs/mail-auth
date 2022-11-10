use crate::common::AuthenticatedMessage;

use super::{DomainKey, Flag, Signature};

impl<'x> AuthenticatedMessage<'x> {
    pub fn signed_headers<'z: 'x>(
        &'z self,
        headers: &'x [Vec<u8>],
        dkim_hdr_name: &'x [u8],
        dkim_hdr_value: &'x [u8],
    ) -> impl Iterator<Item = (&'x [u8], &'x [u8])> {
        let mut last_header_pos: Vec<(&[u8], usize)> = Vec::new();
        headers
            .iter()
            .filter_map(move |h| {
                let header_pos = if let Some((_, header_pos)) = last_header_pos
                    .iter_mut()
                    .find(|(lh, _)| lh.eq_ignore_ascii_case(h))
                {
                    header_pos
                } else {
                    last_header_pos.push((h, 0));
                    &mut last_header_pos.last_mut().unwrap().1
                };
                if let Some((last_pos, result)) = self
                    .headers
                    .iter()
                    .rev()
                    .enumerate()
                    .skip(*header_pos)
                    .find(|(_, (mh, _))| h.eq_ignore_ascii_case(mh))
                {
                    *header_pos = last_pos + 1;
                    Some(*result)
                } else {
                    *header_pos = self.headers.len();
                    None
                }
            })
            .chain([(dkim_hdr_name, dkim_hdr_value)])
    }
}

impl<'x> Signature<'x> {
    #[allow(clippy::while_let_on_iterator)]
    pub fn validate_auid(&self, record: &DomainKey) -> bool {
        // Enforce t=s flag
        if !self.i.is_empty() && record.has_flag(Flag::MatchDomain) {
            let mut auid = self.i.as_ref().iter();
            let mut domain = self.d.as_ref().iter();
            while let Some(&ch) = auid.next() {
                if ch == b'@' {
                    break;
                }
            }
            while let Some(ch) = auid.next() {
                if let Some(dch) = domain.next() {
                    if !ch.eq_ignore_ascii_case(dch) {
                        return false;
                    }
                } else {
                    break;
                }
            }
            if domain.next().is_some() {
                return false;
            }
        }

        true
    }
}

pub(crate) trait Verifier: Sized {
    fn strip_signature(&self) -> Vec<u8>;
}

impl Verifier for &[u8] {
    fn strip_signature(&self) -> Vec<u8> {
        let mut unsigned_dkim = Vec::with_capacity(self.len());
        let mut iter = self.iter().enumerate();
        let mut last_ch = b';';
        while let Some((pos, &ch)) = iter.next() {
            match ch {
                b'=' if last_ch == b'b' => {
                    unsigned_dkim.push(ch);
                    #[allow(clippy::while_let_on_iterator)]
                    while let Some((_, &ch)) = iter.next() {
                        if ch == b';' {
                            unsigned_dkim.push(b';');
                            break;
                        }
                    }
                    last_ch = 0;
                }
                b'b' | b'B' if last_ch == b';' => {
                    last_ch = b'b';
                    unsigned_dkim.push(ch);
                }
                b';' => {
                    last_ch = b';';
                    unsigned_dkim.push(ch);
                }
                b'\r' if pos == self.len() - 2 => (),
                b'\n' if pos == self.len() - 1 => (),
                _ => {
                    unsigned_dkim.push(ch);
                    if !ch.is_ascii_whitespace() {
                        last_ch = 0;
                    }
                }
            }
        }
        unsigned_dkim
    }
}

#[cfg(test)]
mod test {

    use crate::dkim::verify::Verifier;

    #[test]
    fn dkim_strip_signature() {
        for (value, stripped_value) in [
            ("b=abc;h=From\r\n", "b=;h=From"),
            ("bh=B64b=;h=From;b=abc\r\n", "bh=B64b=;h=From;b="),
            ("h=From; b = abc\r\ndef\r\n; v=1\r\n", "h=From; b =; v=1"),
            ("B\r\n=abc;v=1\r\n", "B\r\n=;v=1"),
        ] {
            assert_eq!(
                String::from_utf8(value.as_bytes().strip_signature()).unwrap(),
                stripped_value
            );
        }
    }
}
