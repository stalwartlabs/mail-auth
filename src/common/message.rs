use std::borrow::Cow;

use mail_parser::{parsers::MessageStream, HeaderValue};

use crate::{
    arc::{self, ChainValidation, Seal, Set},
    dkim::{self, Canonicalization, HashAlgorithm},
};

use super::headers::{AuthenticatedHeader, Header, HeaderParser};

pub struct AuthenticatedMessage<'x> {
    pub(crate) headers: Vec<(&'x [u8], &'x [u8])>,
    pub(crate) from: Vec<Cow<'x, str>>,
    pub(crate) body: &'x [u8],
    pub(crate) body_hashes: Vec<(Canonicalization, HashAlgorithm, u64, Vec<u8>)>,
    pub(crate) failed: Vec<Header<'x, arc::Error>>,
    pub(crate) dkim_headers: Vec<Header<'x, dkim::Signature<'x>>>,
    pub(crate) arc_sets: Vec<Set<'x>>,
    pub(crate) cv: ChainValidation,
}

impl<'x> AuthenticatedMessage<'x> {
    pub fn new(raw_message: &'x [u8]) -> Option<Self> {
        let mut message = AuthenticatedMessage {
            headers: Vec::new(),
            from: Vec::new(),
            body: raw_message,
            body_hashes: Vec::new(),
            failed: Vec::new(),
            dkim_headers: Vec::new(),
            arc_sets: Vec::new(),
            cv: ChainValidation::None,
        };

        let mut ams_headers = Vec::new();
        let mut as_headers = Vec::new();
        let mut aar_headers = Vec::new();

        let mut headers = HeaderParser::new(raw_message);

        for (header, value) in &mut headers {
            let name = match header {
                AuthenticatedHeader::Ds(name) => {
                    match dkim::Signature::parse(value) {
                        Ok(s) => {
                            message.dkim_headers.push(Header::new(name, value, s));
                        }
                        Err(err) => {
                            message.failed.push(Header::new(name, value, err.into()));
                        }
                    }

                    name
                }
                AuthenticatedHeader::Aar(name) => {
                    match arc::Results::parse(value) {
                        Ok(r) => {
                            aar_headers.push(Header::new(name, value, r));
                        }
                        Err(err) => {
                            message.failed.push(Header::new(name, value, err));
                        }
                    }

                    name
                }
                AuthenticatedHeader::Ams(name) => {
                    match arc::Signature::parse(value) {
                        Ok(s) => {
                            ams_headers.push(Header::new(name, value, s));
                        }
                        Err(err) => {
                            message.failed.push(Header::new(name, value, err));
                        }
                    }

                    name
                }
                AuthenticatedHeader::As(name) => {
                    match arc::Seal::parse(value) {
                        Ok(s) => {
                            as_headers.push(Header::new(name, value, s));
                        }
                        Err(err) => {
                            message.failed.push(Header::new(name, value, err));
                        }
                    }
                    name
                }
                AuthenticatedHeader::From(name) => {
                    match MessageStream::new(value).parse_address() {
                        HeaderValue::Address(addr) => {
                            if let Some(addr) = addr.address {
                                message.from.push(addr);
                            }
                        }
                        HeaderValue::AddressList(list) => {
                            message
                                .from
                                .extend(list.into_iter().filter_map(|a| a.address));
                        }
                        HeaderValue::Group(group) => {
                            message
                                .from
                                .extend(group.addresses.into_iter().filter_map(|a| a.address));
                        }
                        HeaderValue::GroupList(group_list) => {
                            message
                                .from
                                .extend(group_list.into_iter().flat_map(|group| {
                                    group.addresses.into_iter().filter_map(|a| a.address)
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

        // Group ARC headers in sets
        let arc_headers = ams_headers.len();
        if (1..=50).contains(&arc_headers)
            && (arc_headers == as_headers.len())
            && (arc_headers == aar_headers.len())
        {
            as_headers.sort_unstable_by(|a, b| a.header.i.cmp(&b.header.i));
            ams_headers.sort_unstable_by(|a, b| a.header.i.cmp(&b.header.i));
            aar_headers.sort_unstable_by(|a, b| a.header.i.cmp(&b.header.i));
            let mut success = true;

            for (pos, ((seal, signature), results)) in as_headers
                .into_iter()
                .zip(ams_headers)
                .zip(aar_headers)
                .enumerate()
            {
                if success {
                    success = (seal.header.i as usize == (pos + 1))
                        && (signature.header.i as usize == (pos + 1))
                        && (results.header.i as usize == (pos + 1))
                        && ((pos == 0 && seal.header.cv == ChainValidation::None)
                            || (pos > 0 && seal.header.cv == ChainValidation::Pass));
                }
                message.arc_sets.push(Set {
                    signature,
                    seal,
                    results,
                });
            }

            if !success {
                for set in message.arc_sets.drain(..) {
                    for (name, value) in [
                        (set.signature.name, set.signature.value),
                        (set.seal.name, set.seal.value),
                        (set.results.name, set.results.value),
                    ] {
                        message
                            .failed
                            .push(Header::new(name, value, arc::Error::BrokenArcChain));
                    }
                }
                message.cv = ChainValidation::Fail;
            }
        } else if arc_headers > 0 {
            // Missing ARC headers, fail all.
            message.failed.extend(
                ams_headers
                    .into_iter()
                    .map(|h| Header::new(h.name, h.value, arc::Error::BrokenArcChain))
                    .chain(
                        as_headers
                            .into_iter()
                            .map(|h| Header::new(h.name, h.value, arc::Error::BrokenArcChain)),
                    )
                    .chain(
                        aar_headers
                            .into_iter()
                            .map(|h| Header::new(h.name, h.value, arc::Error::BrokenArcChain)),
                    ),
            );
            message.cv = ChainValidation::Fail;
        }

        message.body = headers
            .body_offset()
            .and_then(|pos| raw_message.get(pos..))
            .unwrap_or_default();

        if !message.headers.is_empty() {
            message.into()
        } else {
            None
        }
    }
}

impl<'x, T> Header<'x, T> {
    pub fn new(name: &'x [u8], value: &'x [u8], header: T) -> Self {
        Header {
            name,
            value,
            header,
        }
    }
}
