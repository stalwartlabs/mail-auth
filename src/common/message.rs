/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use mail_parser::{parsers::MessageStream, Address, HeaderName, HeaderValue, Message};

use crate::{arc, common::crypto::HashAlgorithm, dkim, AuthenticatedMessage};

use super::headers::{AuthenticatedHeader, Header, HeaderParser};

impl<'x> AuthenticatedMessage<'x> {
    pub fn parse(raw_message: &'x [u8]) -> Option<Self> {
        Self::parse_with_opts(raw_message, true)
    }

    pub fn from_parsed(parsed: &'x Message<'x>, strict: bool) -> Self {
        let root = parsed.root_part();
        let mut message = AuthenticatedMessage {
            raw_message: parsed.raw_message(),
            body_offset: root.raw_body_offset(),
            headers: Vec::with_capacity(root.headers.len()),
            ..Default::default()
        };

        for header in root.headers() {
            let name =
                &parsed.raw_message[header.offset_field as usize..header.offset_start as usize - 1];
            let value =
                &parsed.raw_message[header.offset_start as usize..header.offset_end as usize];

            match &header.name {
                HeaderName::From => {
                    message.parse_from(&header.value);
                }
                HeaderName::Date => {
                    message.date_header_present = true;
                }
                HeaderName::Received => {
                    message.received_headers_count += 1;
                }
                HeaderName::MessageId => {
                    message.message_id_header_present = true;
                }
                HeaderName::DkimSignature => {
                    message.parse_dkim(name, value, strict);
                }
                HeaderName::ArcAuthenticationResults => {
                    message.parse_aar(name, value);
                }
                HeaderName::ArcSeal => {
                    message.parse_as(name, value);
                }
                HeaderName::ArcMessageSignature => {
                    message.parse_ams(name, value, strict);
                }
                _ => (),
            }

            message.headers.push((name, value))
        }

        message.finalize()
    }

    pub fn parse_with_opts(raw_message: &'x [u8], strict: bool) -> Option<Self> {
        let mut message = AuthenticatedMessage {
            raw_message,
            ..Default::default()
        };

        let mut headers = HeaderParser::new(raw_message);

        for (header, value) in &mut headers {
            let name = match header {
                AuthenticatedHeader::Ds(name) => {
                    message.parse_dkim(name, value, strict);
                    name
                }
                AuthenticatedHeader::Aar(name) => {
                    message.parse_aar(name, value);
                    name
                }
                AuthenticatedHeader::Ams(name) => {
                    message.parse_ams(name, value, strict);
                    name
                }
                AuthenticatedHeader::As(name) => {
                    message.parse_as(name, value);
                    name
                }
                AuthenticatedHeader::From(name) => {
                    message.parse_from(&MessageStream::new(value).parse_address());
                    name
                }
                AuthenticatedHeader::Other(name) => name,
            };

            message.headers.push((name, value));
        }

        if !message.headers.is_empty() {
            // Update header counts
            message.received_headers_count = headers.num_received;
            message.message_id_header_present = headers.has_message_id;
            message.date_header_present = headers.has_date;

            // Obtain message body
            if let Some(offset) = headers.body_offset() {
                message.body_offset = offset as u32;
            } else {
                message.body_offset = raw_message.len() as u32;
            }
            Some(message.finalize())
        } else {
            None
        }
    }

    fn parse_dkim(&mut self, name: &'x [u8], value: &'x [u8], strict: bool) {
        let signature = match dkim::Signature::parse(value) {
            Ok(signature) if signature.l == 0 || !strict => {
                let ha = HashAlgorithm::from(signature.a);
                if !self
                    .body_hashes
                    .iter()
                    .any(|(c, h, l, _)| c == &signature.cb && h == &ha && l == &signature.l)
                {
                    self.body_hashes
                        .push((signature.cb, ha, signature.l, Vec::new()));
                }
                Ok(signature)
            }
            Ok(_) => Err(crate::Error::SignatureLength),
            Err(err) => Err(err),
        };

        self.dkim_headers.push(Header::new(name, value, signature));
    }

    fn parse_aar(&mut self, name: &'x [u8], value: &'x [u8]) {
        let results = arc::Results::parse(value);
        if !self.has_arc_errors {
            self.has_arc_errors = results.is_err();
        }
        self.aar_headers.push(Header::new(name, value, results));
    }

    fn parse_ams(&mut self, name: &'x [u8], value: &'x [u8], strict: bool) {
        let signature = match arc::Signature::parse(value) {
            Ok(signature) if signature.l == 0 || !strict => {
                let ha = HashAlgorithm::from(signature.a);
                if !self
                    .body_hashes
                    .iter()
                    .any(|(c, h, l, _)| c == &signature.cb && h == &ha && l == &signature.l)
                {
                    self.body_hashes
                        .push((signature.cb, ha, signature.l, Vec::new()));
                }
                Ok(signature)
            }
            Ok(_) => {
                self.has_arc_errors = true;
                Err(crate::Error::SignatureLength)
            }
            Err(err) => {
                self.has_arc_errors = true;
                Err(err)
            }
        };

        self.ams_headers.push(Header::new(name, value, signature));
    }

    fn parse_as(&mut self, name: &'x [u8], value: &'x [u8]) {
        let seal = arc::Seal::parse(value);
        if !self.has_arc_errors {
            self.has_arc_errors = seal.is_err();
        }
        self.as_headers.push(Header::new(name, value, seal));
    }

    fn parse_from(&mut self, value: &HeaderValue<'x>) {
        match value {
            HeaderValue::Address(Address::List(list)) => {
                self.from.extend(
                    list.iter()
                        .filter_map(|a| a.address.as_ref().map(|a| a.to_lowercase())),
                );
            }
            HeaderValue::Address(Address::Group(group_list)) => {
                self.from.extend(group_list.iter().flat_map(|group| {
                    group
                        .addresses
                        .iter()
                        .filter_map(|a| a.address.as_ref().map(|a| a.to_lowercase()))
                }))
            }
            _ => (),
        }
    }

    fn finalize(mut self) -> Self {
        let body = self
            .raw_message
            .get(self.body_offset as usize..)
            .unwrap_or_default();

        // Calculate body hashes
        for (cb, ha, l, bh) in &mut self.body_hashes {
            *bh = ha.hash(cb.canonical_body(body, *l)).as_ref().to_vec();
        }

        // Sort ARC headers
        if !self.as_headers.is_empty() && !self.has_arc_errors {
            self.as_headers.sort_unstable_by(|a, b| {
                a.header
                    .as_ref()
                    .unwrap()
                    .i
                    .cmp(&b.header.as_ref().unwrap().i)
            });
            self.ams_headers.sort_unstable_by(|a, b| {
                a.header
                    .as_ref()
                    .unwrap()
                    .i
                    .cmp(&b.header.as_ref().unwrap().i)
            });
            self.aar_headers.sort_unstable_by(|a, b| {
                a.header
                    .as_ref()
                    .unwrap()
                    .i
                    .cmp(&b.header.as_ref().unwrap().i)
            });
        }

        self
    }

    pub fn received_headers_count(&self) -> usize {
        self.received_headers_count
    }

    pub fn has_message_id_header(&self) -> bool {
        self.message_id_header_present
    }

    pub fn has_date_header(&self) -> bool {
        self.date_header_present
    }

    pub fn raw_message(&self) -> &[u8] {
        self.raw_message
    }

    pub fn raw_headers(&self) -> &[u8] {
        self.raw_message
            .get(..self.body_offset as usize)
            .unwrap_or_default()
    }

    pub fn raw_parsed_headers(&self) -> &[(&[u8], &[u8])] {
        &self.headers
    }

    pub fn raw_body(&self) -> &[u8] {
        self.raw_message
            .get(self.body_offset as usize..)
            .unwrap_or_default()
    }

    pub fn body_offset(&self) -> usize {
        self.body_offset as usize
    }

    pub fn froms(&self) -> &[String] {
        &self.from
    }

    pub fn from(&self) -> &str {
        self.from.first().map_or("", |f| f.as_str())
    }
}
