/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::headers::{AuthenticatedHeader, Header, HeaderParser};
#[cfg(feature = "arc")]
use crate::arc;
use crate::{AuthenticatedMessage, Error, common::crypto::HashAlgorithm, dkim, dkim2};
use mail_parser::{Address, HeaderName, HeaderValue, Message, parsers::MessageStream};

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
                #[cfg(feature = "arc")]
                HeaderName::ArcAuthenticationResults => {
                    message.parse_aar(name, value);
                }
                #[cfg(feature = "arc")]
                HeaderName::ArcSeal => {
                    message.parse_as(name, value);
                }
                #[cfg(feature = "arc")]
                HeaderName::ArcMessageSignature => {
                    message.parse_ams(name, value, strict);
                }
                HeaderName::Other(other) if other.eq_ignore_ascii_case("DKIM2-Signature") => {
                    message.parse_dkim2_signature(name, value);
                }
                HeaderName::Other(other) if other.eq_ignore_ascii_case("Message-Instance") => {
                    message.parse_dkim2_instance(name, value);
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
                AuthenticatedHeader::D2s(name) => {
                    message.parse_dkim2_signature(name, value);
                    name
                }
                AuthenticatedHeader::D2i(name) => {
                    message.parse_dkim2_instance(name, value);
                    name
                }
                #[cfg(feature = "arc")]
                AuthenticatedHeader::Aar(name) => {
                    message.parse_aar(name, value);
                    name
                }
                #[cfg(feature = "arc")]
                AuthenticatedHeader::Ams(name) => {
                    message.parse_ams(name, value, strict);
                    name
                }
                #[cfg(feature = "arc")]
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
        match dkim::Signature::parse(value) {
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
                self.dkim_headers.push(Header::new(name, value, signature));
            }
            Ok(_) => {
                self.push_dkim_error(name, value, Error::Dkim(dkim::DkimError::SignatureLength));
            }
            Err(err) => self.push_dkim_error(name, value, err),
        }
    }

    fn parse_dkim2_signature(&mut self, name: &'x [u8], value: &'x [u8]) {
        match dkim2::Signature::parse(value) {
            Ok(signature) => self
                .dkim2_signatures
                .push(Header::new(name, value, signature)),
            Err(err) => self.push_dkim2_error(name, value, err),
        }
    }

    fn parse_dkim2_instance(&mut self, name: &'x [u8], value: &'x [u8]) {
        match dkim2::MessageInstance::parse(value) {
            Ok(instance) => self
                .dkim2_instances
                .push(Header::new(name, value, instance)),
            Err(err) => self.push_dkim2_error(name, value, err),
        }
    }

    #[cfg(feature = "arc")]
    fn parse_aar(&mut self, name: &'x [u8], value: &'x [u8]) {
        match arc::Results::parse(value) {
            Ok(results) => self.aar_headers.push(Header::new(name, value, results)),
            Err(err) => self.push_arc_error(name, value, err),
        }
    }

    #[cfg(feature = "arc")]
    fn parse_ams(&mut self, name: &'x [u8], value: &'x [u8], strict: bool) {
        match arc::Signature::parse(value) {
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
                self.ams_headers.push(Header::new(name, value, signature));
            }
            Ok(_) => {
                self.push_arc_error(name, value, Error::Arc(arc::ArcError::SignatureLength));
            }
            Err(err) => self.push_arc_error(name, value, err),
        }
    }

    #[cfg(feature = "arc")]
    fn parse_as(&mut self, name: &'x [u8], value: &'x [u8]) {
        match arc::Seal::parse(value) {
            Ok(seal) => self.as_headers.push(Header::new(name, value, seal)),
            Err(err) => self.push_arc_error(name, value, err),
        }
    }

    fn push_dkim_error(&mut self, name: &'x [u8], value: &'x [u8], err: Error) {
        self.has_dkim_errors = true;
        self.errors.push(Header::new(name, value, err));
    }

    fn push_dkim2_error(&mut self, name: &'x [u8], value: &'x [u8], err: Error) {
        self.has_dkim2_errors = true;
        self.errors.push(Header::new(name, value, err));
    }

    #[cfg(feature = "arc")]
    fn push_arc_error(&mut self, name: &'x [u8], value: &'x [u8], err: Error) {
        self.has_arc_errors = true;
        self.errors.push(Header::new(name, value, err));
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
        #[cfg(feature = "arc")]
        if !self.as_headers.is_empty() && !self.has_arc_errors {
            self.as_headers.sort_unstable_by_key(|h| h.header.i);
            self.ams_headers.sort_unstable_by_key(|h| h.header.i);
            self.aar_headers.sort_unstable_by_key(|h| h.header.i);
        }

        // Sort DKIM2 signatures and instances
        if !self.has_dkim2_errors {
            self.dkim2_signatures.sort_unstable_by_key(|h| h.header.i);
            self.dkim2_instances.sort_unstable_by_key(|h| h.header.m);
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
