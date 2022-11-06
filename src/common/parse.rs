use std::slice::Iter;

use mail_parser::decoders::quoted_printable::quoted_printable_decode_char;

pub(crate) const V: u16 = b'v' as u16;
pub(crate) const A: u16 = b'a' as u16;
pub(crate) const B: u16 = b'b' as u16;
pub(crate) const BH: u16 = (b'b' as u16) | ((b'h' as u16) << 8);
pub(crate) const C: u16 = b'c' as u16;
pub(crate) const D: u16 = b'd' as u16;
pub(crate) const H: u16 = b'h' as u16;
pub(crate) const I: u16 = b'i' as u16;
pub(crate) const K: u16 = b'k' as u16;
pub(crate) const L: u16 = b'l' as u16;
pub(crate) const P: u16 = b'p' as u16;
pub(crate) const S: u16 = b's' as u16;
pub(crate) const T: u16 = b't' as u16;
pub(crate) const X: u16 = b'x' as u16;
pub(crate) const Z: u16 = b'z' as u16;

pub(crate) trait TagParser: Sized {
    fn match_bytes(&mut self, bytes: &[u8]) -> bool;
    fn get_key(&mut self) -> Option<u16>;
    fn get_tag(&mut self) -> Vec<u8>;
    fn get_tag_qp(&mut self) -> Vec<u8>;
    fn get_headers_qp(&mut self) -> Vec<Vec<u8>>;
    fn get_number(&mut self) -> u64;
    fn get_items<T: ItemParser>(&mut self, separator: u8) -> Vec<T>;
    fn get_flags<T: ItemParser + Into<u64>>(&mut self, separator: u8) -> u64;
    fn ignore(&mut self);
    fn seek_tag_end(&mut self) -> bool;
    fn next_skip_whitespaces(&mut self) -> Option<u8>;
}

pub(crate) trait ItemParser: Sized {
    fn parse(bytes: &[u8]) -> Option<Self>;
}

impl TagParser for Iter<'_, u8> {
    #[allow(clippy::while_let_on_iterator)]
    fn get_key(&mut self) -> Option<u16> {
        let mut key1: u8 = 0;
        let mut key2: u8 = 0;

        while let Some(&ch) = self.next() {
            match ch {
                b'a'..=b'z' => {
                    if key1 == 0 {
                        key1 = ch;
                    } else if key2 == 0 {
                        key2 = ch;
                    } else {
                        key1 = 0x7f;
                        key2 = 0x7f;
                    }
                }
                b' ' | b'\t' | b'\r' | b'\n' => (),
                b'=' => {
                    return (key1 as u16 | ((key2 as u16) << 8)).into();
                }
                b'A'..=b'Z' => {
                    if key1 == 0 {
                        key1 = ch - b'A' + b'a';
                    } else if key2 == 0 {
                        key2 = ch - b'A' + b'a';
                    } else {
                        key1 = 0x7f;
                        key2 = 0x7f;
                    }
                }
                b';' => {
                    key1 = 0;
                    key2 = 0;
                }
                _ => {
                    key1 = 0x7f;
                    key2 = 0x7f;
                }
            }
        }

        None
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
    fn get_tag(&mut self) -> Vec<u8> {
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
    fn get_tag_qp(&mut self) -> Vec<u8> {
        let mut tag = Vec::with_capacity(20);
        'outer: while let Some(&ch) = self.next() {
            if ch == b';' {
                break;
            } else if ch == b'=' {
                let mut hex1 = 0;

                while let Some(&ch) = self.next() {
                    if ch.is_ascii_digit() {
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
    fn get_headers_qp(&mut self) -> Vec<Vec<u8>> {
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
                    if ch.is_ascii_digit() {
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
    fn get_number(&mut self) -> u64 {
        let mut num: u64 = 0;

        for &ch in self {
            if ch == b';' {
                break;
            } else if ch.is_ascii_digit() {
                num = (num.saturating_mul(10)) + (ch - b'0') as u64;
            } else if !ch.is_ascii_whitespace() {
                return 0;
            }
        }

        num
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

    fn get_items<T: ItemParser>(&mut self, separator: u8) -> Vec<T> {
        let mut buf = Vec::with_capacity(10);
        let mut items = Vec::new();
        for &ch in self {
            if ch == separator {
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

    fn get_flags<T: ItemParser + Into<u64>>(&mut self, separator: u8) -> u64 {
        let mut buf = Vec::with_capacity(10);
        let mut flags = 0;
        for &ch in self {
            if ch == separator {
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
