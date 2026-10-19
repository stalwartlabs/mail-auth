/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! Verification results: [`Dkim2Result`], [`Dkim2Output`] and [`ChainLink`].

use super::{Flag, MessageInstance, Signature};
use crate::{AuthenticatedMessage, DnsError, Error, headers::Header};

/// Outcome of a DKIM2 verification (§14.1).
///
/// The error carried by the failure variants is usually an [`Error::Dkim2`]
/// naming the check that failed.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Dkim2Result {
    /// The message is a Validly Signed DKIM2 Message: every signature
    /// verified, every hash matched, the most recent signature matches the
    /// SMTP envelope, the chain of custody is unbroken and every `From`
    /// header field is Authentic. For a provisional verification, the message
    /// is Provisionally Verified (§13.1).
    Pass,
    /// The chain could be evaluated but a signature or a hash was not
    /// correct.
    Fail(crate::Error),
    /// The chain cannot be verified because of an unrecoverable problem, such
    /// as a malformed or missing header field or tag, a gap in the
    /// numbering, an envelope or chain of custody mismatch, a timestamp out
    /// of range, a missing, invalid or revoked public key, or a `From` header
    /// field that is not Authentic.
    PermError(crate::Error),
    /// A public key could not be fetched because of a temporary DNS error; a
    /// later attempt may succeed.
    TempError(crate::Error),
    /// The message has no `DKIM2-Signature` and no `Message-Instance` header
    /// field, so there was nothing to verify. This follows the `none` result
    /// of DKIM and ARC; §14.2 itself has no such state.
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

/// Which checks a DKIM2 verification performed.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
pub enum Verification {
    /// Every check of §14: the message is a Validly Signed DKIM2 Message
    /// when the result is [`Dkim2Result::Pass`].
    #[default]
    Full,
    /// Only the checks for a Provisionally Verified message (§13.1): header
    /// field validity, timestamps, the envelope against the most recent
    /// signature, that signature and the hashes of the most recent
    /// `Message-Instance`.
    Provisional,
}

/// Result of [`MessageAuthenticator::verify_dkim2`](crate::MessageAuthenticator::verify_dkim2)
/// and [`MessageAuthenticator::verify_dkim2_provisionally`](crate::MessageAuthenticator::verify_dkim2_provisionally).
///
/// Holds the overall [`Dkim2Result`] and, when the chain passes, one
/// [`ChainLink`] per signature. The links borrow from the verified
/// [`AuthenticatedMessage`](crate::AuthenticatedMessage). A passing full
/// verification is the proof of validity that
/// [`Dkim2Signer`](super::Dkim2Signer) requires to sign a message that
/// already carries DKIM2 header fields (§12).
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Dkim2Output<'x> {
    pub(crate) result: Dkim2Result,
    pub(crate) chain: Vec<ChainLink<'x>>,
    pub(crate) verification: Verification,
    pub(crate) raw_message: &'x [u8],
    pub(crate) signature_fields: &'x [Header<'x, Signature>],
    pub(crate) instance_fields: &'x [Header<'x, MessageInstance>],
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

    /// Returns which checks were performed.
    pub fn verification(&self) -> Verification {
        self.verification
    }

    /// Returns the verified hops in ascending `i=` order. Empty unless
    /// [`result`](Self::result) is [`Dkim2Result::Pass`]; after a
    /// provisional verification it holds only the most recent signature.
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
    /// with the `feedback` flag (§10.10).
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
    /// (§10.10).
    pub fn feedback_relay(&self) -> Option<&str> {
        self.chain
            .iter()
            .filter(|link| link.signature.flags.contains(&Flag::FeedHere))
            .max_by_key(|link| link.signature.i)
            .map(|link| link.signature.d.as_str())
    }

    pub(crate) fn is_full_pass(&self) -> bool {
        matches!(self.result, Dkim2Result::Pass) && self.verification == Verification::Full
    }

    pub(crate) fn is_proof_for(&self, message: &AuthenticatedMessage<'_>) -> bool {
        self.is_full_pass()
            && !message.has_dkim2_errors
            && same_values(self.signature_fields, &message.dkim2_signatures)
            && same_values(self.instance_fields, &message.dkim2_instances)
    }

    pub(crate) fn covers(&self, raw_message: &[u8]) -> bool {
        !self.raw_message.is_empty() && std::ptr::eq(self.raw_message, raw_message)
    }
}

fn same_values<T>(proof: &[Header<'_, T>], message: &[Header<'_, T>]) -> bool {
    proof.len() == message.len()
        && proof
            .iter()
            .zip(message)
            .all(|(proof, message)| proof.value == message.value)
}

impl From<Dkim2Result> for Dkim2Output<'_> {
    fn from(result: Dkim2Result) -> Self {
        Dkim2Output {
            result,
            chain: Vec::new(),
            verification: Verification::Full,
            raw_message: &[],
            signature_fields: &[],
            instance_fields: &[],
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
            chain: vec![link(&sig1), link(&sig2)],
            ..Dkim2Output::from(Dkim2Result::Pass)
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
