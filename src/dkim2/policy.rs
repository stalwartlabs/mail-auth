/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

//! The DKIM2 Domain Policy Record (§3.8, draft-ietf-dkim-dkim2-dns
//! Section 5).

use crate::{
    DnsError, Error,
    parse::{TxtRecordParser, starts_with_dkim1_version},
};

/// A DKIM2 Domain Policy Record (§3.8).
///
/// Published as a TXT record at `_domainkey.<domain>` (for `example.com`,
/// `_domainkey.example.com`). It tells verifiers whether subdomains of the
/// domain may make `From` header fields that use the domain Authentic: a
/// signature whose `d=` is a subdomain of the `From` domain is accepted
/// unless the record has the `strict` flag (§11.1). The record applies only
/// to the domain that holds it, it is not inherited by subdomains or
/// parents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DomainPolicy {
    pub(crate) strict: bool,
}

impl DomainPolicy {
    /// Creates a record with the `strict` flag. [`DomainPolicy::default`]
    /// creates one without it, which is equivalent to having no record.
    pub fn strict() -> Self {
        DomainPolicy { strict: true }
    }

    /// Returns `true` when the record has `f=strict`: subdomains are not
    /// authorized to make `From` header fields that use the domain
    /// Authentic.
    pub fn is_strict(&self) -> bool {
        self.strict
    }
}

impl TxtRecordParser for DomainPolicy {
    fn parse(record: &[u8]) -> crate::Result<Self> {
        if !starts_with_dkim1_version(record) {
            return Err(Error::Dns(DnsError::InvalidRecordType));
        }
        let strict = record
            .split(|&ch| ch == b';')
            .filter_map(|tag| {
                let mut parts = tag.splitn(2, |&ch| ch == b'=');
                let name = parts.next()?;
                let value = parts.next()?;
                (name.trim_ascii() == b"f").then_some(value)
            })
            .any(|value| {
                value
                    .split(|&ch| ch == b':')
                    .any(|flag| flag.trim_ascii() == b"strict")
            });
        Ok(DomainPolicy { strict })
    }

    fn parse_records(records: &[Vec<u8>]) -> crate::Result<Self> {
        let mut policies = records
            .iter()
            .filter(|record| starts_with_dkim1_version(record));
        match (policies.next(), policies.next()) {
            (Some(record), None) => Self::parse(record),
            (Some(_), Some(_)) => Err(Error::Dns(DnsError::MultipleRecords)),
            (None, _) => Ok(DomainPolicy::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DomainPolicy;
    use crate::{DnsError, Error, parse::TxtRecordParser};

    #[test]
    fn parse_domain_policy() {
        for (record, strict) in [
            ("v=DKIM1", false),
            ("v=DKIM1;", false),
            ("v=DKIM1; f=", false),
            ("v=DKIM1; f=strict", true),
            ("v = DKIM1 ; f = other : strict ;", true),
            ("v=DKIM1; f=other:future", false),
            ("v=DKIM1; f=Strict", false),
            ("v=DKIM1; x=strict", false),
            ("v=DKIM1; p=abc; f=strict", true),
        ] {
            assert_eq!(
                DomainPolicy::parse(record.as_bytes()).map(|policy| policy.is_strict()),
                Ok(strict),
                "{record}"
            );
        }
        for record in ["", "f=strict", "f=strict; v=DKIM1", "v=DKIM2; f=strict"] {
            assert_eq!(
                DomainPolicy::parse(record.as_bytes()),
                Err(Error::Dns(DnsError::InvalidRecordType)),
                "{record}"
            );
        }
    }

    // Records that do not begin with v=DKIM1 are ignored; more than one remaining is an error.
    #[test]
    fn domain_policy_record_selection() {
        let records = |list: &[&str]| -> Vec<Vec<u8>> {
            list.iter().map(|r| r.as_bytes().to_vec()).collect()
        };
        assert_eq!(
            DomainPolicy::parse_records(&records(&["v=spf1 -all", "v=DKIM1; f=strict", "f=x"])),
            Ok(DomainPolicy::strict())
        );
        assert_eq!(
            DomainPolicy::parse_records(&records(&["v=DKIM1", "v=DKIM1; f=strict"])),
            Err(Error::Dns(DnsError::MultipleRecords))
        );
        assert_eq!(
            DomainPolicy::parse_records(&records(&["v=spf1 -all", "hello"])),
            Ok(DomainPolicy::default())
        );
        assert_eq!(
            DomainPolicy::parse_records(&[]),
            Ok(DomainPolicy::default())
        );
    }
}
