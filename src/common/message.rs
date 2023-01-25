/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use mail_parser::{parsers::MessageStream, HeaderValue};

use crate::{arc, common::crypto::HashAlgorithm, dkim, AuthenticatedMessage};

use super::headers::{AuthenticatedHeader, Header, HeaderParser};

impl<'x> AuthenticatedMessage<'x> {
    pub fn parse(raw_message: &'x [u8]) -> Option<Self> {
        let mut message = AuthenticatedMessage {
            headers: Vec::new(),
            from: Vec::new(),
            raw_message,
            body_offset: 0,
            body_hashes: Vec::new(),
            dkim_headers: Vec::new(),
            ams_headers: Vec::new(),
            as_headers: Vec::new(),
            aar_headers: Vec::new(),
            received_headers_count: 0,
            date_header_present: false,
            message_id_header_present: false,
        };

        let mut headers = HeaderParser::new(raw_message);
        let mut has_arc_errors = false;

        for (header, value) in &mut headers {
            let name = match header {
                AuthenticatedHeader::Ds(name) => {
                    let signature = dkim::Signature::parse(value);
                    if let Ok(signature) = &signature {
                        let ha = HashAlgorithm::from(signature.a);
                        if !message
                            .body_hashes
                            .iter()
                            .any(|(c, h, l, _)| c == &signature.cb && h == &ha && l == &signature.l)
                        {
                            message
                                .body_hashes
                                .push((signature.cb, ha, signature.l, Vec::new()));
                        }
                    }
                    message
                        .dkim_headers
                        .push(Header::new(name, value, signature));
                    name
                }
                AuthenticatedHeader::Aar(name) => {
                    let results = arc::Results::parse(value);
                    if !has_arc_errors {
                        has_arc_errors = results.is_err();
                    }
                    message.aar_headers.push(Header::new(name, value, results));
                    name
                }
                AuthenticatedHeader::Ams(name) => {
                    let signature = arc::Signature::parse(value);

                    if let Ok(signature) = &signature {
                        let ha = HashAlgorithm::from(signature.a);
                        if !message
                            .body_hashes
                            .iter()
                            .any(|(c, h, l, _)| c == &signature.cb && h == &ha && l == &signature.l)
                        {
                            message
                                .body_hashes
                                .push((signature.cb, ha, signature.l, Vec::new()));
                        }
                    } else {
                        has_arc_errors = true;
                    }

                    message
                        .ams_headers
                        .push(Header::new(name, value, signature));
                    name
                }
                AuthenticatedHeader::As(name) => {
                    let seal = arc::Seal::parse(value);
                    if !has_arc_errors {
                        has_arc_errors = seal.is_err();
                    }
                    message.as_headers.push(Header::new(name, value, seal));
                    name
                }
                AuthenticatedHeader::From(name) => {
                    match MessageStream::new(value).parse_address() {
                        HeaderValue::Address(addr) => {
                            if let Some(addr) = addr.address {
                                message.from.push(addr.to_lowercase());
                            }
                        }
                        HeaderValue::AddressList(list) => {
                            message.from.extend(
                                list.into_iter()
                                    .filter_map(|a| a.address.map(|a| a.to_lowercase())),
                            );
                        }
                        HeaderValue::Group(group) => {
                            message.from.extend(
                                group
                                    .addresses
                                    .into_iter()
                                    .filter_map(|a| a.address.map(|a| a.to_lowercase())),
                            );
                        }
                        HeaderValue::GroupList(group_list) => {
                            message
                                .from
                                .extend(group_list.into_iter().flat_map(|group| {
                                    group
                                        .addresses
                                        .into_iter()
                                        .filter_map(|a| a.address.map(|a| a.to_lowercase()))
                                }))
                        }
                        _ => (),
                    }

                    name
                }
                AuthenticatedHeader::Other(name) => name,
            };

            message.headers.push((name, value));
        }

        if message.headers.is_empty() {
            return None;
        }

        // Update header counts
        message.received_headers_count = headers.num_received;
        message.message_id_header_present = headers.has_message_id;
        message.date_header_present = headers.has_date;

        // Obtain message body
        if let Some(offset) = headers.body_offset() {
            message.body_offset = offset;
        } else {
            message.body_offset = raw_message.len();
        }
        let body = raw_message.get(message.body_offset..).unwrap_or_default();

        // Calculate body hashes
        for (cb, ha, l, bh) in &mut message.body_hashes {
            *bh = ha.hash(cb.canonical_body(body, *l)).as_ref().to_vec();
        }

        // Sort ARC headers
        if !message.as_headers.is_empty() && !has_arc_errors {
            message.as_headers.sort_unstable_by(|a, b| {
                a.header
                    .as_ref()
                    .unwrap()
                    .i
                    .cmp(&b.header.as_ref().unwrap().i)
            });
            message.ams_headers.sort_unstable_by(|a, b| {
                a.header
                    .as_ref()
                    .unwrap()
                    .i
                    .cmp(&b.header.as_ref().unwrap().i)
            });
            message.aar_headers.sort_unstable_by(|a, b| {
                a.header
                    .as_ref()
                    .unwrap()
                    .i
                    .cmp(&b.header.as_ref().unwrap().i)
            });
        }

        message.into()
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

    pub fn raw_headers(&self) -> &[u8] {
        self.raw_message.get(..self.body_offset).unwrap_or_default()
    }

    pub fn body_offset(&self) -> usize {
        self.body_offset
    }

    pub fn froms(&self) -> &[String] {
        &self.from
    }

    pub fn from(&self) -> &str {
        self.from.first().map_or("", |f| f.as_str())
    }
}
