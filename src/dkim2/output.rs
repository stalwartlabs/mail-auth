/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Verification results: [`Dkim2Result`], [`Dkim2Output`] and [`ChainLink`].

use super::{Flag, MessageInstance, Signature};
use crate::{DnsError, Error};

/// Outcome of a DKIM2 verification (§11.1).
///
/// The error carried by the failure variants is usually an [`Error::Dkim2`]
/// naming the check that failed.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Dkim2Result {
    /// Every signature verified, every hash matched, the most recent
    /// signature matches the SMTP envelope and the chain of custody is
    /// unbroken.
    Pass,
    /// The chain could be evaluated but a signature, a hash or a
    /// `donotmodify`/`donotexplode` request check did not pass.
    Fail(crate::Error),
    /// The chain cannot be verified because of an unrecoverable problem, such
    /// as a malformed or missing header field or tag, an envelope or chain
    /// of custody mismatch, an expired signature, or a missing, invalid or
    /// revoked public key.
    PermError(crate::Error),
    /// A public key could not be fetched because of a temporary DNS error; a
    /// later attempt may succeed.
    TempError(crate::Error),
    /// The message has no `DKIM2-Signature` header field, or the signature
    /// numbering does not start at 1 without gaps, which makes the message
    /// unsigned (§8.1).
    None,
}

impl From<Error> for Dkim2Result {
    fn from(err: Error) -> Self {
        if matches!(&err, Error::Dns(DnsError::Resolver(_))) {
            Dkim2Result::TempError(err)
        } else {
            Dkim2Result::PermError(err)
        }
    }
}

/// Result of [`MessageAuthenticator::verify_dkim2`](crate::MessageAuthenticator::verify_dkim2).
///
/// Holds the overall [`Dkim2Result`] and, when the chain passes, one
/// [`ChainLink`] per signature. The links borrow from the verified
/// [`AuthenticatedMessage`](crate::AuthenticatedMessage).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Dkim2Output<'x> {
    pub(crate) result: Dkim2Result,
    pub(crate) chain: Vec<ChainLink<'x>>,
}

/// One verified hop of a DKIM2 chain, in ascending `i=` order.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ChainLink<'x> {
    /// The `DKIM2-Signature` of this hop.
    pub signature: &'x Signature,
    /// The `Message-Instance` whose `m=` equals the signature's `m=`, if
    /// present.
    pub instance: Option<&'x MessageInstance>,
    /// Verification result of this hop.
    pub result: Dkim2Result,
    /// Whether this hop continues the chain of custody of the previous one.
    pub custody_ok: bool,
}

impl<'x> Dkim2Output<'x> {
    /// Returns the overall verification result.
    pub fn result(&self) -> &Dkim2Result {
        &self.result
    }

    /// Returns the verified hops in ascending `i=` order. Empty unless
    /// [`result`](Self::result) is [`Dkim2Result::Pass`].
    pub fn chain(&self) -> &[ChainLink<'x>] {
        &self.chain
    }

    /// Returns the error carried by a `Fail`, `PermError` or `TempError`
    /// result, or `None` for `Pass` and `None`.
    pub fn error(&self) -> Option<&crate::Error> {
        match &self.result {
            Dkim2Result::Fail(err) | Dkim2Result::PermError(err) | Dkim2Result::TempError(err) => {
                Some(err)
            }
            Dkim2Result::Pass | Dkim2Result::None => None,
        }
    }

    /// Returns true if any signer in the verified chain requested feedback
    /// with the `feedback` flag (§8.10).
    pub fn feedback_requested(&self) -> bool {
        self.chain
            .iter()
            .any(|link| link.signature.flags.contains(&Flag::Feedback))
    }

    /// Returns the signing domains (`d=`) of the signatures that set the
    /// `feedback` flag, in ascending `i=` order.
    pub fn feedback_domains(&self) -> impl Iterator<Item = &str> {
        self.chain
            .iter()
            .filter(|link| link.signature.flags.contains(&Flag::Feedback))
            .map(|link| link.signature.d.as_str())
    }

    /// Returns the signing domain of the most recent hop that set the
    /// `feedhere` flag, or `None` if no hop did.
    ///
    /// A privacy-conscious Forwarder sets `feedhere` so that feedback is
    /// relayed through it instead of being sent directly to the requestor
    /// (§8.10).
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::dkim2::{Flag, Signature};

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
        assert_eq!(
            output.feedback_domains().collect::<Vec<_>>(),
            vec!["a.example", "b.example"]
        );
        assert_eq!(output.feedback_relay(), Some("b.example"));

        let none = Dkim2Output::from(Dkim2Result::Pass);
        assert!(!none.feedback_requested());
        assert!(none.feedback_domains().next().is_none());
        assert_eq!(none.feedback_relay(), None);
    }
}
