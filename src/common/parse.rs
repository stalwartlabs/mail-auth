use std::slice::Iter;

use mail_parser::decoders::quoted_printable::quoted_printable_decode_char;

pub(crate) trait TagParser: Sized {
    fn match_bytes(&mut self, bytes: &[u8]) -> bool;
    fn get_tag(&mut self) -> Vec<u8>;
    fn get_tag_qp(&mut self) -> Vec<u8>;
    fn get_headers_qp(&mut self) -> Vec<Vec<u8>>;
    fn get_number(&mut self) -> u64;
    fn get_items<T: ItemParser>(&mut self, separator: u8) -> Vec<T>;
    fn ignore(&mut self);
    fn skip_whitespaces(&mut self) -> bool;
    fn next_skip_whitespaces(&mut self) -> Option<u8>;
}

pub(crate) trait ItemParser: Sized {
    fn parse(bytes: &[u8]) -> Option<Self>;
}

impl TagParser for Iter<'_, u8> {
    #[inline(always)]
    fn match_bytes(&mut self, bytes: &[u8]) -> bool {
        let mut pos = 0;

        for ch in self {
            if !ch.is_ascii_whitespace() {
                if bytes[pos].eq_ignore_ascii_case(ch) {
                    if pos < bytes.len() - 1 {
                        pos += 1;
                    } else {
                        break;
                    }
                } else {
                    return false;
                }
            }
        }

        pos == bytes.len() - 1
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
    fn skip_whitespaces(&mut self) -> bool {
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
}

impl ItemParser for Vec<u8> {
    fn parse(bytes: &[u8]) -> Option<Self> {
        Some(bytes.to_vec())
    }
}
