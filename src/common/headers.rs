use std::{
    iter::{Enumerate, Peekable},
    slice::Iter,
};

#[derive(Clone, Copy)]
enum State {
    Name { start: usize },
    Value { start: usize, colon: usize },
}

pub(crate) struct HeaderIterator<'x> {
    message: &'x [u8],
    iter: Peekable<Enumerate<Iter<'x, u8>>>,
    state: State,
}

impl<'x> HeaderIterator<'x> {
    pub fn new(message: &'x [u8]) -> Self {
        HeaderIterator {
            message,
            iter: message.iter().enumerate().peekable(),
            state: State::Name { start: 0 },
        }
    }

    pub fn body_offset(&mut self) -> Option<usize> {
        self.iter.peek().map(|(pos, _)| *pos)
    }
}

impl<'x> Iterator for HeaderIterator<'x> {
    type Item = (&'x [u8], &'x [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let mut last_ch = 0;
        while let Some((pos, &ch)) = self.iter.next() {
            if ch == b':' {
                if let State::Name { start } = &self.state {
                    self.state = State::Value {
                        start: *start,
                        colon: pos,
                    };
                }
            } else if ch == b'\n' {
                match self.state {
                    State::Value { start, colon } => {
                        if self
                            .iter
                            .peek()
                            .map_or(true, |(_, next_byte)| ![b' ', b'\t'].contains(next_byte))
                        {
                            let header_name = self.message.get(start..colon).unwrap_or_default();
                            let header_value =
                                self.message.get(colon + 1..pos + 1).unwrap_or_default();
                            self.state = State::Name { start: pos + 1 };
                            return Some((header_name, header_value));
                        }
                    }
                    State::Name { start } => {
                        if last_ch == b'\r' || start == pos {
                            // End of headers
                            return None;
                        } else if self
                            .iter
                            .peek()
                            .map_or(true, |(_, next_byte)| ![b' ', b'\t'].contains(next_byte))
                        {
                            // Invalid header, return anyway.
                            let header_name = self.message.get(start..pos + 1).unwrap_or_default();
                            self.state = State::Name { start: pos + 1 };
                            return Some((header_name, b""));
                        }
                    }
                }
            }

            last_ch = ch;
        }

        None
    }
}

#[cfg(test)]
mod test {
    use super::HeaderIterator;

    #[test]
    fn header_iterator() {
        for (message, headers) in [
            (
                "From: a\nTo: b\nEmpty:\nMulti: 1\n 2\nSubject: c\n\nNot-header: ignore\n",
                vec![
                    ("From", " a\n"),
                    ("To", " b\n"),
                    ("Empty", "\n"),
                    ("Multi", " 1\n 2\n"),
                    ("Subject", " c\n"),
                ],
            ),
            (
                ": a\nTo: b\n \n \nc\n:\nFrom : d\nSubject: e\n\nNot-header: ignore\n",
                vec![
                    ("", " a\n"),
                    ("To", " b\n \n \n"),
                    ("c\n", ""),
                    ("", "\n"),
                    ("From ", " d\n"),
                    ("Subject", " e\n"),
                ],
            ),
            (
                concat!(
                    "A: X\r\n",
                    "B : Y\t\r\n",
                    "\tZ  \r\n",
                    "\r\n",
                    " C \r\n",
                    "D \t E\r\n"
                ),
                vec![("A", " X\r\n"), ("B ", " Y\t\r\n\tZ  \r\n")],
            ),
        ] {
            assert_eq!(
                HeaderIterator::new(message.as_bytes())
                    .map(|(h, v)| {
                        (
                            std::str::from_utf8(h).unwrap(),
                            std::str::from_utf8(v).unwrap(),
                        )
                    })
                    .collect::<Vec<_>>(),
                headers
            );
        }
    }
}
