use std::slice::Iter;

use mail_parser::decoders::quoted_printable::quoted_printable_decode_char;

pub(crate) const V: u64 = b'v' as u64;
pub(crate) const A: u64 = b'a' as u64;
pub(crate) const B: u64 = b'b' as u64;
pub(crate) const BH: u64 = (b'b' as u64) | ((b'h' as u64) << 8);
pub(crate) const C: u64 = b'c' as u64;
pub(crate) const D: u64 = b'd' as u64;
pub(crate) const H: u64 = b'h' as u64;
pub(crate) const I: u64 = b'i' as u64;
pub(crate) const K: u64 = b'k' as u64;
pub(crate) const L: u64 = b'l' as u64;
pub(crate) const P: u64 = b'p' as u64;
pub(crate) const R: u64 = b'r' as u64;
pub(crate) const S: u64 = b's' as u64;
pub(crate) const T: u64 = b't' as u64;
pub(crate) const X: u64 = b'x' as u64;
pub(crate) const Y: u64 = b'y' as u64;
pub(crate) const Z: u64 = b'z' as u64;

pub(crate) trait TxtRecordParser: Sized {
    fn parse(record: &[u8]) -> crate::Result<Self>;
}

pub(crate) trait TagParser: Sized {
    fn match_bytes(&mut self, bytes: &[u8]) -> bool;
    fn key(&mut self) -> Option<u64>;
    fn value(&mut self) -> u64;
    fn tag(&mut self) -> Vec<u8>;
    fn tag_qp(&mut self) -> Vec<u8>;
    fn headers_qp(&mut self) -> Vec<Vec<u8>>;
    fn number(&mut self) -> Option<u64>;
    fn items<T: ItemParser>(&mut self) -> Vec<T>;
    fn flags<T: ItemParser + Into<u64>>(&mut self) -> u64;
    fn ignore(&mut self);
    fn seek_tag_end(&mut self) -> bool;
    fn next_skip_whitespaces(&mut self) -> Option<u8>;
}

pub(crate) trait ItemParser: Sized {
    fn parse(bytes: &[u8]) -> Option<Self>;
}

impl TagParser for Iter<'_, u8> {
    #[allow(clippy::while_let_on_iterator)]
    fn key(&mut self) -> Option<u64> {
        let mut key: u64 = 0;
        let mut shift = 0;

        while let Some(&ch) = self.next() {
            match ch {
                b'a'..=b'z' if shift < 64 => {
                    key |= (ch as u64) << shift;
                    shift += 8;
                }
                b' ' | b'\t' | b'\r' | b'\n' => (),
                b'=' => {
                    return key.into();
                }
                b'A'..=b'Z' if shift < 64 => {
                    key |= ((ch - b'A' + b'a') as u64) << shift;
                    shift += 8;
                }
                b';' => {
                    key = 0;
                }
                _ => {
                    key = u64::MAX;
                    shift = 64;
                }
            }
        }

        None
    }

    #[allow(clippy::while_let_on_iterator)]
    fn value(&mut self) -> u64 {
        let mut value: u64 = 0;
        let mut shift = 0;

        while let Some(&ch) = self.next() {
            match ch {
                b'a'..=b'z' if shift < 64 => {
                    value |= (ch as u64) << shift;
                    shift += 8;
                }
                b' ' | b'\t' | b'\r' | b'\n' => (),
                b'A'..=b'Z' if shift < 64 => {
                    value |= ((ch - b'A' + b'a') as u64) << shift;
                    shift += 8;
                }
                b';' => {
                    break;
                }
                _ => {
                    value = u64::MAX;
                    shift = 64;
                }
            }
        }

        value
    }

    #[inline(always)]
    #[allow(clippy::while_let_on_iterator)]
    fn match_bytes(&mut self, bytes: &[u8]) -> bool {
        'outer: for byte in bytes {
            while let Some(&ch) = self.next() {
                if !ch.is_ascii_whitespace() {
                    if ch.eq_ignore_ascii_case(byte) {
                        continue 'outer;
                    } else {
                        return false;
                    }
                }
            }
            return false;
        }

        true
    }

    #[inline(always)]
    fn tag(&mut self) -> Vec<u8> {
        let mut tag = Vec::with_capacity(20);
        for &ch in self {
            if ch == b';' {
                break;
            } else if !ch.is_ascii_whitespace() {
                tag.push(ch);
            }
        }
        tag
    }

    #[inline(always)]
    #[allow(clippy::while_let_on_iterator)]
    fn tag_qp(&mut self) -> Vec<u8> {
        let mut tag = Vec::with_capacity(20);
        'outer: while let Some(&ch) = self.next() {
            if ch == b';' {
                break;
            } else if ch == b'=' {
                let mut hex1 = 0;

                while let Some(&ch) = self.next() {
                    if ch.is_ascii_hexdigit() {
                        if hex1 != 0 {
                            if let Some(ch) = quoted_printable_decode_char(hex1, ch) {
                                tag.push(ch);
                            }
                            break;
                        } else {
                            hex1 = ch;
                        }
                    } else if ch == b';' {
                        break 'outer;
                    } else if !ch.is_ascii_whitespace() {
                        break;
                    }
                }
            } else if !ch.is_ascii_whitespace() {
                tag.push(ch);
            }
        }
        tag
    }

    #[inline(always)]
    #[allow(clippy::while_let_on_iterator)]
    fn headers_qp(&mut self) -> Vec<Vec<u8>> {
        let mut tags = Vec::new();
        let mut tag = Vec::with_capacity(20);

        'outer: while let Some(&ch) = self.next() {
            if ch == b';' {
                break;
            } else if ch == b'|' {
                if !tag.is_empty() {
                    tags.push(tag.to_vec());
                    tag.clear();
                }
            } else if ch == b'=' {
                let mut hex1 = 0;

                while let Some(&ch) = self.next() {
                    if ch.is_ascii_hexdigit() {
                        if hex1 != 0 {
                            if let Some(ch) = quoted_printable_decode_char(hex1, ch) {
                                tag.push(ch);
                            }
                            break;
                        } else {
                            hex1 = ch;
                        }
                    } else if ch == b'|' {
                        if !tag.is_empty() {
                            tags.push(tag.to_vec());
                            tag.clear();
                        }
                        break;
                    } else if ch == b';' {
                        break 'outer;
                    } else if !ch.is_ascii_whitespace() {
                        break;
                    }
                }
            } else if !ch.is_ascii_whitespace() {
                tag.push(ch);
            }
        }

        if !tag.is_empty() {
            tags.push(tag);
        }

        tags
    }

    #[inline(always)]
    fn number(&mut self) -> Option<u64> {
        let mut num: u64 = 0;
        let mut has_digits = false;

        for &ch in self {
            if ch == b';' {
                break;
            } else if ch.is_ascii_digit() {
                num = (num.saturating_mul(10)).saturating_add((ch - b'0') as u64);
                has_digits = true;
            } else if !ch.is_ascii_whitespace() {
                return None;
            }
        }

        if has_digits {
            num.into()
        } else {
            None
        }
    }

    #[inline(always)]
    fn ignore(&mut self) {
        for &ch in self {
            if ch == b';' {
                break;
            }
        }
    }

    #[inline(always)]
    fn seek_tag_end(&mut self) -> bool {
        for &ch in self {
            if ch == b';' {
                return true;
            } else if !ch.is_ascii_whitespace() {
                return false;
            }
        }
        true
    }

    #[inline(always)]
    fn next_skip_whitespaces(&mut self) -> Option<u8> {
        for &ch in self {
            if !ch.is_ascii_whitespace() {
                return ch.into();
            }
        }
        None
    }

    fn items<T: ItemParser>(&mut self) -> Vec<T> {
        let mut buf = Vec::with_capacity(10);
        let mut items = Vec::new();
        for &ch in self {
            if ch == b':' {
                if !buf.is_empty() {
                    if let Some(item) = T::parse(&buf) {
                        items.push(item);
                    }
                    buf.clear();
                }
            } else if ch == b';' {
                break;
            } else if !ch.is_ascii_whitespace() {
                buf.push(ch);
            }
        }
        if !buf.is_empty() {
            if let Some(item) = T::parse(&buf) {
                items.push(item);
            }
        }
        items
    }

    fn flags<T: ItemParser + Into<u64>>(&mut self) -> u64 {
        let mut buf = Vec::with_capacity(10);
        let mut flags = 0;
        for &ch in self {
            if ch == b':' {
                if !buf.is_empty() {
                    if let Some(item) = T::parse(&buf) {
                        flags |= item.into();
                    }
                    buf.clear();
                }
            } else if ch == b';' {
                break;
            } else if !ch.is_ascii_whitespace() {
                buf.push(ch);
            }
        }
        if !buf.is_empty() {
            if let Some(item) = T::parse(&buf) {
                flags |= item.into();
            }
        }
        flags
    }
}

impl ItemParser for Vec<u8> {
    fn parse(bytes: &[u8]) -> Option<Self> {
        Some(bytes.to_vec())
    }
}
