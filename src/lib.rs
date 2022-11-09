/*
 * Copyright Stalwart Labs Ltd. See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::fmt::Display;

pub mod arc;
pub mod common;
pub mod dkim;
pub mod dmarc;
pub mod spf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    ParseError,
    MissingParameters,
    NoHeadersFound,
    CryptoError(String),
    Io(String),
    Base64,
    UnsupportedVersion,
    UnsupportedAlgorithm,
    UnsupportedCanonicalization,
    UnsupportedRecordVersion,
    UnsupportedKeyType,
    FailedBodyHashMatch,
    RevokedPublicKey,
    IncompatibleAlgorithms,
    FailedVerification,
    SignatureExpired,
    FailedAUIDMatch,
    DNSFailure,

    ARCInvalidInstance,
    ARCInvalidCV,
    ARCHasHeaderTag,
    ARCBrokenChain,

    InvalidVersion,
    InvalidRecord,

    InvalidIp4,
    InvalidIp6,
    InvalidMacro,
}

pub type Result<T> = std::result::Result<T, Error>;

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ParseError => write!(f, "Parse error"),
            Error::MissingParameters => write!(f, "Missing parameters"),
            Error::NoHeadersFound => write!(f, "No headers found"),
            Error::CryptoError(err) => write!(f, "Cryptography layer error: {}", err),
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::Base64 => write!(f, "Base64 encode or decode error."),
            Error::UnsupportedVersion => write!(f, "Unsupported version in DKIM Signature."),
            Error::UnsupportedAlgorithm => write!(f, "Unsupported algorithm in DKIM Signature."),
            Error::UnsupportedCanonicalization => {
                write!(f, "Unsupported canonicalization method in DKIM Signature.")
            }
            Error::UnsupportedRecordVersion => {
                write!(f, "Unsupported version in DKIM DNS record.")
            }
            Error::UnsupportedKeyType => {
                write!(f, "Unsupported key type in DKIM DNS record.")
            }
            Error::FailedBodyHashMatch => {
                write!(f, "Calculated body hash does not match signature hash.")
            }
            Error::RevokedPublicKey => write!(f, "Public key for this signature has been revoked."),
            Error::IncompatibleAlgorithms => write!(
                f,
                "Incompatible algorithms used in signature and DKIM DNS record."
            ),
            Error::FailedVerification => write!(f, "Signature verification failed."),
            Error::SignatureExpired => write!(f, "Signature expired."),
            Error::FailedAUIDMatch => write!(f, "AUID does not match domain name."),
            Error::ARCInvalidInstance => write!(f, "Invalid 'i=' value found in ARC header."),
            Error::ARCInvalidCV => write!(f, "Invalid 'cv=' value found in ARC header."),
            Error::ARCHasHeaderTag => write!(f, "Invalid 'h=' tag present in ARC-Seal."),
            Error::ARCBrokenChain => write!(f, "Broken or missing ARC chain."),
            Error::InvalidVersion => write!(f, "Invalid version."),
            Error::InvalidRecord => write!(f, "Invalid record."),
            Error::InvalidIp4 => write!(f, "Invalid IPv4."),
            Error::InvalidIp6 => write!(f, "Invalid IPv6."),
            Error::InvalidMacro => write!(f, "Invalid SPF macro."),
            Error::DNSFailure => write!(f, "DNS failure."),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err.to_string())
    }
}

impl From<rsa::errors::Error> for Error {
    fn from(err: rsa::errors::Error) -> Self {
        Error::CryptoError(err.to_string())
    }
}

impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(err: ed25519_dalek::ed25519::Error) -> Self {
        Error::CryptoError(err.to_string())
    }
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
