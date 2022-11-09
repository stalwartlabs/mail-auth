use std::time::SystemTime;

use mail_parser::{parsers::MessageStream, HeaderValue};
use sha1::Sha1;
use sha2::Sha256;

use crate::{
    arc::{self, ChainValidation, Set},
    dkim::{self, Algorithm, HashAlgorithm},
    Error,
};

use super::{
    headers::{AuthenticatedHeader, Header, HeaderParser},
    AuthPhase, AuthResult, AuthenticatedMessage,
};

impl<'x> AuthenticatedMessage<'x> {
    #[inline(always)]
    pub fn new(raw_message: &'x [u8]) -> Option<Self> {
        Self::new_(
            raw_message,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        )
    }

    pub(crate) fn new_(raw_message: &'x [u8], now: u64) -> Option<Self> {
        let mut message = AuthenticatedMessage {
            headers: Vec::new(),
            from: Vec::new(),
            dkim_headers: Vec::new(),
            arc_sets: Vec::new(),
            arc_result: AuthResult::None,
            dkim_result: AuthResult::None,
            phase: AuthPhase::Done,
        };

        let mut ams_headers = Vec::new();
        let mut as_headers = Vec::new();
        let mut aar_headers = Vec::new();

        let mut headers = HeaderParser::new(raw_message);
        let mut dkim_headers = Vec::new();

        for (header, value) in &mut headers {
            let name = match header {
                AuthenticatedHeader::Ds(name) => {
                    match dkim::Signature::parse(value) {
                        Ok(signature) => {
                            if signature.x == 0 || (signature.x > signature.t && signature.x > now)
                            {
                                dkim_headers.push(Header::new(name, value, signature));
                            } else {
                                message.dkim_result = AuthResult::PermFail(Header::new(
                                    name,
                                    value,
                                    crate::Error::SignatureExpired,
                                ));
                            }
                        }
                        Err(err) => {
                            message.dkim_result =
                                AuthResult::PermFail(Header::new(name, value, err));
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
                            message.arc_result =
                                AuthResult::PermFail(Header::new(name, value, err));
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
                            message.arc_result =
                                AuthResult::PermFail(Header::new(name, value, err));
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
                            message.arc_result =
                                AuthResult::PermFail(Header::new(name, value, err));
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

        if message.headers.is_empty() {
            return None;
        }

        // Obtain message body
        let body = headers
            .body_offset()
            .and_then(|pos| raw_message.get(pos..))
            .unwrap_or_default();
        let mut body_hashes = Vec::new();

        // Group ARC headers in sets
        let arc_headers = ams_headers.len();
        if (1..=50).contains(&arc_headers)
            && (arc_headers == as_headers.len())
            && (arc_headers == aar_headers.len())
        {
            as_headers.sort_unstable_by(|a, b| a.header.i.cmp(&b.header.i));
            ams_headers.sort_unstable_by(|a, b| a.header.i.cmp(&b.header.i));
            aar_headers.sort_unstable_by(|a, b| a.header.i.cmp(&b.header.i));

            for (pos, ((seal, signature), results)) in as_headers
                .into_iter()
                .zip(ams_headers)
                .zip(aar_headers)
                .enumerate()
            {
                if (seal.header.i as usize == (pos + 1))
                    && (signature.header.i as usize == (pos + 1))
                    && (results.header.i as usize == (pos + 1))
                    && ((pos == 0 && seal.header.cv == ChainValidation::None)
                        || (pos > 0 && seal.header.cv == ChainValidation::Pass))
                {
                    // Validate last signature in the chain
                    if pos == arc_headers - 1 {
                        // Validate expiration
                        let signature_ = &signature.header;
                        if signature_.x > 0 && (signature_.x < signature_.t || signature_.x < now) {
                            message.arc_result = AuthResult::PermFail(Header::new(
                                signature.name,
                                signature.value,
                                Error::SignatureExpired,
                            ));
                            break;
                        }

                        // Validate body hash
                        let bh = match signature_.a {
                            Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
                                signature_.cb.hash_body::<Sha256>(body, signature_.l)
                            }
                            Algorithm::RsaSha1 => {
                                signature_.cb.hash_body::<Sha1>(body, signature_.l)
                            }
                        }
                        .unwrap_or_default();

                        let success = bh == signature_.bh;
                        body_hashes.push((
                            signature_.cb,
                            HashAlgorithm::from(signature_.a),
                            signature_.l,
                            bh,
                        ));

                        if !success {
                            message.arc_result = AuthResult::PermFail(Header::new(
                                signature.name,
                                signature.value,
                                Error::FailedBodyHashMatch,
                            ));
                            break;
                        }
                    }

                    message.arc_sets.push(Set {
                        signature,
                        seal,
                        results,
                    });
                } else {
                    message.arc_result = AuthResult::PermFail(Header::new(
                        signature.name,
                        signature.value,
                        Error::ARCBrokenChain,
                    ));
                    break;
                }
            }
        } else if arc_headers > 0 && message.arc_result == AuthResult::None {
            // Missing ARC headers, fail all.
            let header = ams_headers
                .into_iter()
                .map(|h| Header::new(h.name, h.value, Error::ARCBrokenChain))
                .chain(
                    as_headers
                        .into_iter()
                        .map(|h| Header::new(h.name, h.value, Error::ARCBrokenChain)),
                )
                .chain(
                    aar_headers
                        .into_iter()
                        .map(|h| Header::new(h.name, h.value, Error::ARCBrokenChain)),
                )
                .next()
                .unwrap();
            message.arc_result = AuthResult::PermFail(header);
        }

        // Validate body hash of DKIM signatures
        if !dkim_headers.is_empty() {
            message.dkim_headers = Vec::with_capacity(dkim_headers.len());
            for header in dkim_headers {
                let signature = &header.header;
                let ha = HashAlgorithm::from(signature.a);

                let bh = if let Some((_, _, _, bh)) = body_hashes
                    .iter()
                    .find(|(c, h, l, _)| c == &signature.cb && h == &ha && l == &signature.l)
                {
                    bh
                } else {
                    let bh = match signature.a {
                        Algorithm::RsaSha256 | Algorithm::Ed25519Sha256 => {
                            signature.cb.hash_body::<Sha256>(body, signature.l)
                        }
                        Algorithm::RsaSha1 => signature.cb.hash_body::<Sha1>(body, signature.l),
                    }
                    .unwrap_or_default();

                    body_hashes.push((signature.cb, ha, signature.l, bh));
                    &body_hashes.last().unwrap().3
                };

                if bh == &signature.bh {
                    message.dkim_headers.push(header);
                } else {
                    message.dkim_result = AuthResult::PermFail(Header::new(
                        header.name,
                        header.value,
                        crate::Error::FailedBodyHashMatch,
                    ));
                }
            }
        }

        if !message.dkim_headers.is_empty() {
            message.dkim_headers.reverse();
            message.phase = AuthPhase::Dkim;
        } else if !message.arc_sets.is_empty() && message.arc_result == AuthResult::None {
            message.phase = AuthPhase::Ams;
        }

        message.into()
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
