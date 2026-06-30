/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::{
    Dkim2Result,
    common::crypto::{Algorithm, DkimKey, HashAlgorithm},
};

pub mod builder;
pub mod canonicalize;
pub mod dsn;
pub mod headers;
pub mod parse;
pub mod recipe;
mod recipe_serializer;
pub mod sign;
pub mod verify;

#[cfg(test)]
mod interop_test;

pub use dsn::{Dkim2Dsn, Dkim2DsnFailure, Dkim2DsnOutput};
pub use recipe::{BodyRecipe, HeaderRecipe, Recipe, Step};
pub use sign::{Dkim2Signed, Envelope, Hop};

pub struct NeedDomain;
pub struct NeedSelector;
pub struct Done;

pub struct Dkim2Signer<State = NeedDomain> {
    _state: std::marker::PhantomData<State>,
    pub keys: Vec<KeyEntry>,
    pub domain: String,
    pub flags: Vec<Flag>,
    pub nonce: Option<String>,
}

pub struct KeyEntry {
    pub key: DkimKey,
    pub selector: String,
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Signature {
    pub i: u32,
    pub m: u32,
    pub t: u64,
    pub d: String,
    pub s: Vec<SignatureValue>,
    pub chain: ChainBinding,
    pub n: Option<String>,
    pub flags: Vec<Flag>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignatureValue {
    pub selector: String,
    pub a: Algorithm,
    pub b: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ChainBinding {
    Envelope {
        mail_from: String,
        rcpt_to: Vec<String>,
    },
    NextDomain(String),
}

impl Default for ChainBinding {
    fn default() -> Self {
        ChainBinding::Envelope {
            mail_from: String::new(),
            rcpt_to: Vec::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Flag {
    DoNotModify,
    DoNotExplode,
    Feedback,
    FeedHere,
    Exploded,
    Unknown(String),
}

impl Flag {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Flag::DoNotModify => b"donotmodify",
            Flag::DoNotExplode => b"donotexplode",
            Flag::Feedback => b"feedback",
            Flag::FeedHere => b"feedhere",
            Flag::Exploded => b"exploded",
            Flag::Unknown(value) => value.as_bytes(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct MessageInstance {
    pub m: u32,
    pub hashes: Vec<MessageHash>,
    pub recipe: Option<Recipe>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MessageHash {
    pub name: Option<HashAlgorithm>,
    pub header_hash: Vec<u8>,
    pub body_hash: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Dkim2Output<'x> {
    pub(crate) result: Dkim2Result,
    pub(crate) chain: Vec<ChainLink<'x>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ChainLink<'x> {
    pub signature: &'x Signature,
    pub instance: Option<&'x MessageInstance>,
    pub result: Dkim2Result,
    pub custody_ok: bool,
}

impl<'x> Dkim2Output<'x> {
    pub fn result(&self) -> &Dkim2Result {
        &self.result
    }

    pub fn chain(&self) -> &[ChainLink<'x>] {
        &self.chain
    }

    pub fn error(&self) -> Option<&crate::Error> {
        match &self.result {
            Dkim2Result::Fail(err) | Dkim2Result::PermError(err) | Dkim2Result::TempError(err) => {
                Some(err)
            }
            Dkim2Result::Pass | Dkim2Result::None => None,
        }
    }

    pub fn failure_reason(&self) -> Option<String> {
        self.error().map(|err| err.to_string())
    }

    /// Returns true if any signer in the verified chain requested feedback
    /// (the `feedback` flag, draft-ietf-dkim-dkim2-spec-03 §8.10).
    pub fn feedback_requested(&self) -> bool {
        self.chain
            .iter()
            .any(|link| link.signature.flags.contains(&Flag::Feedback))
    }

    /// Domains (`d=`) of the signatures that requested feedback.
    pub fn feedback_domains(&self) -> Vec<&str> {
        self.chain
            .iter()
            .filter(|link| link.signature.flags.contains(&Flag::Feedback))
            .map(|link| link.signature.d.as_str())
            .collect()
    }

    /// If a privacy-conscious Forwarder set the `feedhere` flag, returns the
    /// domain of the most recent such hop, via which feedback should be relayed
    /// instead of being sent directly to the requestor (§8.10). Otherwise `None`.
    pub fn feedback_relay(&self) -> Option<&str> {
        self.chain
            .iter()
            .filter(|link| link.signature.flags.contains(&Flag::FeedHere))
            .max_by_key(|link| link.signature.i)
            .map(|link| link.signature.d.as_str())
    }
}

impl From<Dkim2Result> for Dkim2Output<'_> {
    fn from(result: Dkim2Result) -> Self {
        Dkim2Output {
            result,
            chain: Vec::new(),
        }
    }
}

impl Signature {
    pub fn domain(&self) -> &str {
        &self.d
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Dkim2Error {
    InstanceMissing(u32),
    InstanceSyntax(u32),
    InstanceTagMissing { m: u32, tag: &'static str },
    InstanceNotSigned(u32),
    InstanceAboveSignature(u32),
    SignatureMissing(u32),
    SignatureSyntax(u32),
    SignatureTagMissing { i: u32, tag: &'static str },
    SignatureTagUnexpected { i: u32, tag: &'static str },
    SequenceGap,
    SequenceOverflow,
    SignatureExpired(u32),
    MailFromMismatch(u32),
    RcptToMismatch(u32),
    MailFromDomainMismatch(u32),
    NextDomainMismatch(u32),
    PublicKeyFetch(u32),
    PublicKeyMissing(u32),
    PublicKeyMultiple(u32),
    PublicKeySyntax(u32),
    PublicKeyAlgorithmMismatch(u32),
    PublicKeyRevoked(u32),
    IncorrectSignature(u32),
    NoValidAlgorithm(u32),
    HeaderHashMismatch(u32),
    BodyHashMismatch(u32),
    Modified,
    Exploded,
}

impl std::fmt::Display for Dkim2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Dkim2Error::InstanceMissing(m) => write!(f, "Message-Instance m={m} missing"),
            Dkim2Error::InstanceSyntax(m) => write!(f, "Message-Instance m={m} syntax error"),
            Dkim2Error::InstanceTagMissing { m, tag } => {
                write!(f, "Message-Instance m={m} tag={tag} missing")
            }
            Dkim2Error::InstanceNotSigned(m) => write!(f, "Message-Instance m={m} is not signed"),
            Dkim2Error::InstanceAboveSignature(m) => {
                write!(
                    f,
                    "Message-Instance m={m} is higher than any DKIM2-Signature"
                )
            }
            Dkim2Error::SignatureMissing(i) => write!(f, "DKIM2-Signature i={i} missing"),
            Dkim2Error::SignatureSyntax(i) => write!(f, "DKIM2-Signature i={i} syntax error"),
            Dkim2Error::SignatureTagMissing { i, tag } => {
                write!(f, "DKIM2-Signature i={i} tag={tag} missing")
            }
            Dkim2Error::SignatureTagUnexpected { i, tag } => {
                write!(f, "DKIM2-Signature i={i} tag={tag} was unexpected")
            }
            Dkim2Error::SequenceGap => write!(f, "DKIM2 sequence numbering has a gap"),
            Dkim2Error::SequenceOverflow => {
                write!(f, "DKIM2 sequence numbering would overflow")
            }
            Dkim2Error::SignatureExpired(i) => write!(f, "DKIM2-Signature i={i} signature expired"),
            Dkim2Error::MailFromMismatch(i) => {
                write!(f, "DKIM2-Signature i={i} MAIL FROM did not match")
            }
            Dkim2Error::RcptToMismatch(i) => {
                write!(f, "DKIM2-Signature i={i} RCPT TO did not match")
            }
            Dkim2Error::MailFromDomainMismatch(i) => {
                write!(f, "DKIM2-Signature i={i} MAIL FROM and d= do not match")
            }
            Dkim2Error::NextDomainMismatch(i) => {
                write!(f, "DKIM2-Signature i={i} nd= does not match")
            }
            Dkim2Error::PublicKeyFetch(i) => {
                write!(f, "DKIM2-Signature i={i} public key could not be fetched")
            }
            Dkim2Error::PublicKeyMissing(i) => {
                write!(f, "DKIM2-Signature i={i} public key does not exist")
            }
            Dkim2Error::PublicKeyMultiple(i) => {
                write!(f, "DKIM2-Signature i={i} public key has multiple records")
            }
            Dkim2Error::PublicKeySyntax(i) => {
                write!(f, "DKIM2-Signature i={i} public key has a syntax error")
            }
            Dkim2Error::PublicKeyAlgorithmMismatch(i) => {
                write!(f, "DKIM2-Signature i={i} public key algorithm mismatch")
            }
            Dkim2Error::PublicKeyRevoked(i) => {
                write!(f, "DKIM2-Signature i={i} public key has been revoked")
            }
            Dkim2Error::IncorrectSignature(i) => {
                write!(f, "DKIM2-Signature i={i} incorrect signature")
            }
            Dkim2Error::NoValidAlgorithm(i) => {
                write!(f, "DKIM2-Signature i={i} has no valid signature algorithms")
            }
            Dkim2Error::HeaderHashMismatch(m) => {
                write!(f, "Message-Instance m={m} header hash mismatch")
            }
            Dkim2Error::BodyHashMismatch(m) => {
                write!(f, "Message-Instance m={m} body hash mismatch")
            }
            Dkim2Error::Modified => {
                write!(f, "Message has been modified despite a donotmodify request")
            }
            Dkim2Error::Exploded => {
                write!(
                    f,
                    "Message has been exploded despite a donotexplode request"
                )
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn signed(i: u32, domain: &str, flags: Vec<Flag>) -> Signature {
        Signature {
            i,
            d: domain.to_string(),
            flags,
            ..Default::default()
        }
    }

    #[test]
    fn feedback_accessors() {
        let sig1 = signed(1, "a.example", vec![Flag::Feedback]);
        let sig2 = signed(2, "b.example", vec![Flag::Feedback, Flag::FeedHere]);
        let link = |signature| ChainLink {
            signature,
            instance: None,
            result: Dkim2Result::Pass,
            custody_ok: true,
        };
        let output = Dkim2Output {
            result: Dkim2Result::Pass,
            chain: vec![link(&sig1), link(&sig2)],
        };

        assert!(output.feedback_requested());
        assert_eq!(output.feedback_domains(), vec!["a.example", "b.example"]);
        assert_eq!(output.feedback_relay(), Some("b.example"));

        let none = Dkim2Output::from(Dkim2Result::Pass);
        assert!(!none.feedback_requested());
        assert!(none.feedback_domains().is_empty());
        assert_eq!(none.feedback_relay(), None);
    }
}
