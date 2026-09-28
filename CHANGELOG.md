# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](https://semver.org/).

## [0.14.0] - 2026-XX-XX

This release reorganizes the public API. Most changes are renames and moves; the [migration guide](#migrating-from-013) below lists every one of them with its replacement.

### Added
- `DnsCache` trait: one implementation supplies all five record caches (TXT, MX, A, AAAA, PTR) to every verifier through `Parameters::with_cache`.
- `report::ReportEnvelope`: the sender, recipients, submitter, report domain and optional subject used by every `write_rfc5322`/`to_rfc5322` method.
- `report::dmarc::ReportVersion` for the aggregate report format version (`1.0`), with `Display`, `FromStr` and `as_str()`.
- `AuthenticatedMessage` accessors `dkim_signatures()`, `dkim2_signatures()`, `dkim2_instances()`, `arc_message_signatures()`, `arc_seals()`, `arc_authentication_results()`, `errors()`, `has_dkim_errors()`, `has_dkim2_errors()`, `has_arc_errors()`, and `retain_dkim_signatures()` to discard signatures before verification.
- `AuthenticationResults::set_*` for every result type, and `set_dkim_results`.
- `AuthenticatedMessage::dkim2_return_path()`.
- `DkimOutput::is_atps()`, `impl From<DkimResult> for DkimOutput`, `arc::ArcResult` and `impl From<ArcResult> for ArcOutput`.
- `DomainKey::is_testing()` (`t=y`) and `DomainKey::requires_strict_identity()` (`t=s`).
- `DkimSigner::template()`.
- `dns::has_valid_labels()`.
- `SpfParameters` is `Copy`, so the same value can be passed to `verify_spf` and to `with_spf_result`/`ReceivedSpf::new`.
- `impl From<&Dkim2Dsn> for Parameters`, so `verify_dkim2_dsn(&dsn, envelope)` works without a cache like the other verifiers.
- `Dkim2Error::RecipeSyntax`, returned by `Recipe::to_json`, `Recipe::from_json` and `MessageInstance::parse` for an invalid recipe. `Dkim2Error` is exhaustive, so a `match` over it needs a new arm.
- `TlsReport::write_rfc5322_json()`.
- `Display` for `dmarc::Alignment` (`r`, `s`); serde derives for `dmarc::Alignment` and `dmarc::Policy`; `Default` for `dmarc::Policy` (`Unspecified`).
- `Display` and `std::error::Error` for `report::ReportError`.
- Documentation on every public item; the crate now builds with `#![warn(missing_docs)]`.

### Changed
- Bump `mail-parser` to 1.0. `AuthenticatedMessage::from_parsed` takes a 1.0 `Message`, and `tlsrpt::DateRange` holds the 1.0 `DateTime`.
- Replaced `base64` with `encodify` for better performance and reduced memory usage.
- UTF-8 validation uses `simdutf8` for DKIM and DKIM2 `Display` output, ARF report parsing and generation, and DKIM2, DMARC and MTA-STS tag values. Lossy conversions validate with SIMD first and fall back to `String::from_utf8_lossy` only for invalid input.
- The `common` module is gone. Its contents moved to `dns`, `crypto`, `headers`, `message`, `auth_results`, `iprev` and `dkim`. DMARC aggregate report types moved to `report::dmarc` and ARF types to `report::arf`.
- Every verifier takes `Parameters<'x, P, C: DnsCache>` with a single cache type parameter. `Parameters::params` is now `input`, and the five `cache_*` fields are replaced by `cache: Option<&C>`.
- Parsed DNS TXT record types carry a `Record` suffix (`SpfRecord`, `DmarcRecord`, `DkimReportRecord`, `AtpsRecord`, `MtaStsRecord`, `TlsRptRecord`).
- `SpfResult` displays lowercase RFC 7208 tokens (`softfail`, `temperror`) and implements `FromStr`. Text built with `{result}`, such as an SMTP reply, changes accordingly.
- `AuthenticationResults::with_spf_result` and `ReceivedSpf::new` take `SpfParameters` for the values they report. The identity written to the header follows the identity that `check_host` evaluated, so a `helo_and_mail_from` check that stopped at HELO is reported as `smtp.helo`. Pass the MAIL FROM address as received, empty for the null reverse-path: `check_host` substitutes `postmaster@<domain>` itself, and a substituted address would be reported instead of `<>`.
- `verify_dkim2` reports a `Message-Instance` with an invalid recipe as `PermError(Dkim2(RecipeSyntax))` instead of `PermError(Dkim2(Modified))`.
- `authorized_report_addresses` (formerly `verify_dmarc_report_address`) returns `Result<Vec<&T>>`: `Err` on a DNS resolver error, otherwise the authorized addresses (possibly empty).
- `AggregateReport::parse_xml` and `FeedbackReport::parse_arf` return `Result<Self, ReportError>`. `FeedbackReport::parse_rfc5322` takes a `max_size` limit on the raw message length (the DMARC and TLS parsers limit the decompressed report size).
- Report version fields hold `Option<ReportVersion>`. Versions other than `1.0` parse as `None`, from XML and with serde. The published alignment fields are `Option<dmarc::Alignment>` and the published policy fields are `dmarc::Policy`. These, and the renamed fields (`records`, `errors`, `kind`, `reported_domains`, `reported_uris`), which have no serde aliases, change the serde representation of `AggregateReport` and `FeedbackReport`; data stored with 0.13 must be migrated.
- ARF reports generated without a subject use "Authentication Failure Report" or "Abuse Report". Their Message-ID uses `ReportEnvelope::submitter` when `reporting_mta` is not set or empty (previously `localhost`). The `To` header is written as an address list (`To: <ruf@example.com>`) built from `ReportEnvelope::to`, as for the other report types, so pass several recipients as separate entries rather than one comma-separated string.
- `Dkim2Signer::sign_with_message_instance` returns `Dkim2Signed` with `message_instance: None`, since the caller supplies and writes the instance.
- `DkimSigner::expiration` and `ArcSealer::expiration` take a `Duration`, rounded up to whole seconds; the resulting `x=` saturates at `u64::MAX` instead of overflowing.
- Typestate markers for `DkimSigner`, `ArcSealer` and `Dkim2Signer` live in the new `signer` module; `Done` is now `Ready`. `DkimSigner` and `ArcSealer` no longer implement `Default`, which allowed skipping the builder.
- The `builder`, `generate` and `parse` submodules of `report::dmarc`, `report::arf` and `report::tlsrpt` are private; they only held inherent methods, which remain available on the report types.

### Removed
- The `rkyv` feature. mail-parser 1.0 no longer supports rkyv, and `tlsrpt::DateRange` holds its `DateTime`.
- The `Version` enum and the `version`/`v` fields of `SpfRecord`, `DmarcRecord` and `AtpsRecord`. The parsers already rejected every other version.
- The getter and `with_` setter pairs on report types (`AggregateReport`, `Record`, `DkimAuthResult`, `SpfAuthResult`, `PolicyOverrideReason`, `FeedbackReport`, `FailureDetails`). Report fields are public; build reports with struct literals and `..Default::default()`.
- `report::Alignment` and the published-policy `report::Disposition` (replaced by `dmarc::Alignment` and `dmarc::Policy`), with their `FromStr` implementations and the `From<&dmarc::Alignment>` and `From<&dmarc::Policy>` conversions into them.
- `Report::add_record` and `Report::with_policy_published`; push to `AggregateReport::records` and assign `policy_published`.
- `Dkim2Output::failure_reason()` and `DmarcOutput::dmarc_record_cloned()`.
- `spf::verify::HasValidLabels` (use `dns::has_valid_labels`).
- Public constructors of `DkimOutput` (`pass`, `neutral`, `fail`, `perm_err`, `temp_err`, `dns_error`, `with_report`, `with_atps`), `ArcOutput` (`with_result`, `with_set`) and `DmarcOutput` (`new`, `with_domain`, `with_spf_result`, `with_dkim_result`, `with_record`). Build a `DkimOutput` with `From<DkimResult>` and `with_signature`, and an `ArcOutput` with `From<ArcResult>`. A `DmarcOutput` comes from `verify_dmarc`; `DmarcOutput::default()` gives an empty one.
- Public access to internals: the fields of `AuthenticatedMessage`, `MessageAuthenticator`, `DkimSigner`, `Dkim2Signer` and `DomainKey`; `dkim2::KeyEntry`; `HeaderStream`; `dkim::Signature::canonicalize`; `dkim::canonicalize::{BodyHasher, CanonicalBody, CanonicalHeaders}`; `Canonicalization::{canonicalize_headers, canonical_headers, canonical_body, serialize_name}`; `HashAlgorithm::{headers_hash, body_hash}`; `AuthenticatedMessage::signed_headers`; `DomainKey::has_flag`; `common::to_a_label`; `auth_results::AsAuthResult`.

### Fixed
- DMARC aggregate report parsing skips unknown elements under `<feedback>`. Previously such an element ended parsing early, dropping the records after it or failing with a missing element error.

### Migrating from 0.13

#### Module paths

| 0.13 | 0.14 |
|---|---|
| `common::resolver::{ToFqdn, ToReverseName, DnsEntry}` | `dns::{ToFqdn, ToReverseName, DnsEntry}` |
| `common::resolver::mock_resolve` (feature `test`) | `dns::mock_resolve` |
| `common::parse::TxtRecordParser` | `dns::TxtRecordParser` |
| `common::cache::NoCache` | `dns::NoCache` (also `mail_auth::NoCache`) |
| `common::doh::DohResolver` | `dns::DohResolver` |
| `common::verify::{DomainKey, VerifySignature}` | `dkim::{DomainKey, VerifySignature}` |
| `common::crypto::*` | `crypto::*` |
| `common::headers::*` | `headers::*` |
| `common::auth_results::*` | `auth_results::*` |
| `common::message::*` | `message::*` |
| `mta_sts::parse` | merged into `mta_sts` |
| `report::{Report, Record, ReportMetadata, PolicyPublished, ...}` | `report::dmarc::*` |
| `report::{Feedback, FeedbackType, AuthFailureType, ...}` | `report::arf::*` |
| `dkim::{NeedDomain, NeedSelector, NeedHeaders, Done}`, `dkim2::{NeedDomain, NeedSelector, Done}` | `signer::{NeedDomain, NeedSelector, NeedHeaders, Ready}` |

The crate root still re-exports `MessageAuthenticator`, `AuthenticatedMessage`,
`AuthenticationResults`, `ReceivedSpf`, `Error`, `DnsError`, `Result`,
`Parameters`, `ResolverCache` and every `*Result`/`*Output` type. It now also
re-exports `DnsCache`, `NoCache` and `ArcResult`.

#### Types

| 0.13 | 0.14 |
|---|---|
| `MX` | `Mx` |
| `Txt` | `TxtRecord` |
| `Txt::SpfMacro`, `Txt::DomainKeyReport` | `TxtRecord::SpfExplanation`, `TxtRecord::DkimReport` |
| `spf::Spf` | `spf::SpfRecord` |
| `dmarc::Dmarc` | `dmarc::DmarcRecord` |
| `dmarc::Report` (the `fo=` tag) | `dmarc::FailureOptions` |
| `dmarc::URI` | `dmarc::Uri` |
| `dkim::DomainKeyReport` | `dkim::DkimReportRecord` |
| `dkim::Atps` | `dkim::AtpsRecord` |
| `mta_sts::MtaSts`, `mta_sts::TlsRpt` | `mta_sts::MtaStsRecord`, `mta_sts::TlsRptRecord` |
| `arc::Set` | `arc::ChainLink` |
| `arc::ArcSet` | `arc::SealedSet` |
| `arc::Results` | `arc::ArcAuthResults` |
| `report::Error` | `report::ReportError` |
| `report::Report` | `report::dmarc::AggregateReport` |
| `report::DKIMAuthResult`, `report::SPFAuthResult` | `report::dmarc::DkimAuthResult`, `report::dmarc::SpfAuthResult` |
| `report::SPFDomainScope` | `report::dmarc::SpfScope` |
| `report::AuthResult` | `report::dmarc::AuthResults` |
| `report::Identifier` | `report::dmarc::Identifiers` |
| `report::DkimResult`, `report::SpfResult`, `report::DmarcResult` | `report::dmarc::DkimStatus`, `SpfStatus`, `DmarcStatus` |
| `report::ActionDisposition` | `report::dmarc::Disposition` |
| `report::Disposition` (published `p=`, `sp=`, `np=`) | `dmarc::Policy` |
| `report::Alignment` | `Option<dmarc::Alignment>` (`Unspecified` is `None`) |
| `report::Feedback` | `report::arf::FeedbackReport` |
| `report::tlsrpt::Policy` | `report::tlsrpt::PolicyResult` |
| `report::tlsrpt::ResultType` | `report::tlsrpt::FailureType` |

#### Enum variants

| 0.13 | 0.14 |
|---|---|
| `Error::ParseError` | `Error::Parse` |
| `DkimError::FailedBodyHashMatch`, `ArcError::FailedBodyHashMatch` | `BodyHashMismatch` |
| `DkimError::FailedAuidMatch` | `DkimError::AuidMismatch` |
| `DkimError::RevokedPublicKey` | `DkimError::PublicKeyRevoked` |
| `DkimError::SignatureLength`, `ArcError::SignatureLength` | `BodyLengthTag` |
| `ArcError::InvalidCV` | `ArcError::InvalidChainValidation` |
| `report::Error::MailParseError` | `ReportError::MailParse` |
| `report::Error::ReportParseError(_)` | `ReportError::Parse(_)` |
| `report::Error::UncompressError(_)` | `ReportError::Decompress(_)` |
| `report::Error::ReportTooLarge` | `ReportError::TooLarge` |
| `report::Error::NoReportsFound` | `ReportError::NotFound` |

#### Fields

| 0.13 | 0.14 |
|---|---|
| `RecordSet::rrset` | `RecordSet::records` |
| `Parameters::params` | `Parameters::input` |
| `Parameters::{cache_txt, cache_mx, cache_ptr, cache_ipv4, cache_ipv6}` | `Parameters::cache` |
| `MessageAuthenticator.0` | `MessageAuthenticator::resolver()` (both backends) |
| `DkimSigner::template` | `DkimSigner::template()` |
| `Dkim2Dsn::raw` | `Dkim2Dsn::dsn` |
| `DmarcParameters::rfc5321_mail_from_domain` | `DmarcParameters::mail_from_domain` |
| `ReportMetadata::error` | `ReportMetadata::errors` |
| `Report::record` | `AggregateReport::records` |
| `Report::version: f32`, `PolicyPublished::version_published: Option<f32>` | `Option<ReportVersion>` |
| `PolicyOverrideReason::type_` | `PolicyOverrideReason::kind` |
| `Feedback::reported_domain`, `Feedback::reported_uri` | `FeedbackReport::reported_domains`, `FeedbackReport::reported_uris` |
| `Feedback::source_port: u32` | `FeedbackReport::source_port: u16` |
| `Summary::total_success`, `Summary::total_failure` | `Summary::successful_sessions`, `Summary::failed_sessions` |
| `AuthenticatedMessage::{from, headers, raw_message, body_offset}` | `from_addresses()`, `headers()`, `raw_message()`, `body_offset()` |
| `AuthenticatedMessage::{received_headers_count, date_header_present, message_id_header_present}` | `received_headers_count()`, `has_date_header()`, `has_message_id_header()` |
| `AuthenticatedMessage::{dkim_headers, dkim2_signatures, dkim2_instances, errors}` (read) | `dkim_signatures()`, `dkim2_signatures()`, `dkim2_instances()`, `errors()` |
| `AuthenticatedMessage::{ams_headers, as_headers, aar_headers}` (feature `arc`) | `arc_message_signatures()`, `arc_seals()`, `arc_authentication_results()` |
| `AuthenticatedMessage::{has_dkim_errors, has_dkim2_errors, has_arc_errors}` | the methods of the same name |
| `AuthenticatedMessage::{dkim_headers, errors}` (write) | `retain_dkim_signatures()`, see below |

The serde names of renamed report fields follow the new Rust names, except for
TLS-RPT fields, which keep their RFC 8460 JSON names.

`ReportVersion` replaces the `f32` version: convert a stored number with
`(v == 1.0).then_some(ReportVersion::V1)` and write one with `v.as_str()` or
`v.to_string()` (both give `"1.0"`, where `1.0f32.to_string()` gave `"1"`).

The getters and `with_*` setters of the DMARC report types reached into nested
structs. Their field paths:

| 0.13 | 0.14 |
|---|---|
| `record.count()` | `record.row.count` |
| `record.source_ip()`, `with_source_ip(ip)` | `record.row.source_ip` |
| `record.action_disposition()` | `record.row.policy_evaluated.disposition` |
| `record.dmarc_dkim_result()`, `dmarc_spf_result()` | `record.row.policy_evaluated.dkim`, `.spf` |
| `record.envelope_to()`, `envelope_from()`, `header_from()` and their `with_*` | `record.identifiers.envelope_to`, `.envelope_from`, `.header_from` |
| `record.dkim_auth_result()`, `spf_auth_result()` | `record.auth_results.dkim`, `.spf` |
| `report.domain()`, `p()`, `sp()`, `np()`, `adkim()`, `aspf()`, `fo()`, `testing()` | `report.policy_published.domain`, `.p`, `.sp`, `.np`, `.adkim`, `.aspf`, `.fo`, `.testing` |
| `report.org_name()`, `email()`, `report_id()`, `extra_contact_info()` | `report.report_metadata.org_name`, `.email`, `.report_id`, `.extra_contact_info` |
| `report.date_range_begin()`, `date_range_end()` | `report.report_metadata.date_range.begin`, `.end` |
| `feedback.reported_domain()`, `reported_uri()` | `feedback.reported_domains`, `.reported_uris` |

Code that imported `report::*` to reach the old published-policy
`Disposition` gets the action enum `report::dmarc::Disposition` after
switching to `report::dmarc::*`; the published policy is `dmarc::Policy`.

#### Functions and methods

| 0.13 | 0.14 |
|---|---|
| `AuthenticatedMessage::raw_parsed_headers()` | `headers()` |
| `AuthenticatedMessage::froms()` | `from_addresses()` |
| `AuthenticatedMessage::from()` | `first_from_address()` |
| `AuthenticatedMessage::get_canonicalized_header().await` returning `Result` | `canonicalized_dkim_headers()` returning `Option` |
| `dkim2::Signature::dsn_return_path(&signatures)` | `message.dkim2_return_path()` |
| `SpfParameters::verify_ehlo(ip, helo, host)` | `SpfParameters::helo(ip, helo, host)` |
| `SpfParameters::verify_mail_from(ip, helo, host, sender)` | `SpfParameters::mail_from(ip, helo, host, sender)` |
| `SpfParameters::verify(ip, helo, host, sender)` | `SpfParameters::helo_and_mail_from(ip, helo, host, sender)` |
| `auth_results.with_spf_ehlo_result(&spf, ip, helo)` | `auth_results.with_spf_result(&spf, &SpfParameters::helo(ip, helo, host))`; `host` (the local host name) is not written to Authentication-Results |
| `auth_results.with_spf_mailfrom_result(&spf, ip, from, helo)` | `auth_results.with_spf_result(&spf, &SpfParameters::mail_from(ip, helo, host, from))` |
| `ReceivedSpf::new(&spf, ip, helo, mail_from, hostname)` | `ReceivedSpf::new(&spf, &SpfParameters::mail_from(ip, helo, hostname, mail_from))` |
| `SpfResult::try_from(value)` | `value.parse::<SpfResult>()` |
| `domain.has_valid_labels()` (`HasValidLabels`) | `dns::has_valid_labels(domain)` |
| `verify_dmarc_report_address(domain, &addresses, cache)` | `authorized_report_addresses(Parameters::new((domain, addresses.as_slice())).with_cache(&caches))`; the tuple needs a slice (`&Vec<T>` does not coerce inside it); `None` becomes `Err(_)`, `Some(v)` becomes `Ok(v)` |
| `DkimOutput::pass()`, `neutral(e)`, `fail(e)`, `perm_err(e)`, `temp_err(e)` | `DkimOutput::from(DkimResult::Pass)` and so on |
| `DkimOutput::pass().with_signature(&signature)` | `DkimOutput::from(DkimResult::Pass).with_signature(&signature)` |
| `DmarcOutput::default().with_*(..)` | not available; use the output of `verify_dmarc` |
| `DkimOutput::failure_report_addr()` | `DkimOutput::report_address()` |
| `ArcOutput::default().with_result(result)` | `ArcOutput::from(result)` |
| `ArcOutput::sets()` | `ArcOutput::chain()` |
| `DmarcOutput::dmarc_record()` | `DmarcOutput::record()` (returns `Option<&Arc<DmarcRecord>>`) |
| `DmarcOutput::dmarc_record_cloned()` | `DmarcOutput::record().cloned()` |
| `DmarcOutput::requested_reports()` | `DmarcOutput::requests_reports()` |
| `Dkim2Output::failure_reason()` | `Dkim2Output::error().map(ToString::to_string)` |
| `Dkim2Output::feedback_domains()` returning `Vec` | returns an iterator; add `.collect::<Vec<_>>()` if needed |
| `DkimSigner::agent_user_identifier(auid)` | `DkimSigner::identity(auid)` |
| `DkimSigner::atpsh(hash)` | `DkimSigner::atps_hash(hash)` |
| `DkimSigner::expiration(secs)`, `ArcSealer::expiration(secs)` | `expiration(Duration::from_secs(secs))` |
| `Dkim2Signer::sign_with_message_instance(..)` returning `Signature` | returns `Dkim2Signed`; use `.signature` |
| `Report::new()`, `Record::new()`, `DKIMAuthResult::new()`, `SPFAuthResult::new()` | `Default::default()` |
| `PolicyOverrideReason::new(kind).with_comment(c)` | `PolicyOverrideReason { kind, comment: Some(c) }` |
| `record.with_action_disposition(d)`, `report.with_domain(d)`, other `with_*`/getter pairs | assign or read the public field |
| `FailureDetails::with_failure_reason_code(c)` and the other `with_*` setters | assign the public field |
| `Feedback::parse_rfc5322(bytes)` | `FeedbackReport::parse_rfc5322(bytes, max_size)` |
| `Feedback::parse_arf(bytes)` returning `Option` | returns `Result<_, ReportError>` |
| `Report::parse_xml(bytes)` returning `Result<_, String>` | returns `Result<_, ReportError>` |
| `report.write_rfc5322(submitter, from, to, writer)` | `report.write_rfc5322(&envelope, writer)` |
| `feedback.write_rfc5322(from, to, subject, writer)` | `feedback.write_rfc5322(&envelope, writer)` |
| `tls_report.write_rfc5322(report_domain, submitter, from, to, writer)` | `tls_report.write_rfc5322(&envelope, writer)` |
| `tls_report.write_rfc5322_from_bytes(report_domain, submitter, from, to, &gzip_json, writer)` | `TlsReport::write_rfc5322_json(&json, &envelope, writer)` (uncompressed JSON) |
| `report.to_rfc5322(submitter, from, to)` | `report.to_rfc5322(&envelope)` |
| `feedback.to_rfc5322(from, to, subject)` | `feedback.to_rfc5322(&envelope)` |
| `tls_report.to_rfc5322(report_domain, submitter, from, to)` | `tls_report.to_rfc5322(&envelope)` |
| `mx_lookup(domain, None::<&NoCache<_, _>>)` | `mx_lookup(domain, None::<&NoCache>)` |

#### DNS caches

Implement `DnsCache` once on the type that owns the caches and pass it with
`Parameters::with_cache`:

```rust
impl DnsCache for MyCaches {
    type Txt = MyCache<Box<str>, TxtRecord>;
    type Mx = MyCache<Box<str>, RecordSet<Mx>>;
    type Ipv4 = MyCache<Box<str>, RecordSet<Ipv4Addr>>;
    type Ipv6 = MyCache<Box<str>, RecordSet<Ipv6Addr>>;
    type Ptr = MyCache<IpAddr, RecordSet<Box<str>>>;

    fn txt(&self) -> Option<&Self::Txt> { Some(&self.txt) }
    fn mx(&self) -> Option<&Self::Mx> { Some(&self.mx) }
    fn ipv4(&self) -> Option<&Self::Ipv4> { Some(&self.ipv4) }
    fn ipv6(&self) -> Option<&Self::Ipv6> { Some(&self.ipv6) }
    fn ptr(&self) -> Option<&Self::Ptr> { Some(&self.ptr) }
}

// 0.13: Parameters::new(input).with_txt_cache(&c.txt).with_mx_cache(&c.mx)...
let params = Parameters::new(input).with_cache(&caches);
```

A function that names the parameter type shrinks from seven generics to
`Parameters<'_, T, MyCaches>`.

#### Filtering DKIM signatures before verification

`AuthenticatedMessage` fields are private. Code that edited `dkim_headers` and
`errors` directly uses `retain_dkim_signatures`. The closure returns a
`DkimError`; a rejected signature is dropped and its error recorded as
`Error::Dkim`, which `verify_dkim` reports as `neutral`:

```rust
message.retain_dkim_signatures(|signature| {
    if signature.a == Algorithm::RsaSha1 {
        Err(DkimError::UnsupportedAlgorithm)
    } else {
        Ok(())
    }
});
```

#### Building reports

Report types have public fields and no setters:

```rust
let report = AggregateReport {
    version: Some(ReportVersion::V1),
    report_metadata: ReportMetadata {
        org_name: "Example".into(),
        report_id: "abc-123".into(),
        ..Default::default()
    },
    policy_published: PolicyPublished::from_record("example.org", &dmarc_record),
    records: vec![
        Record::default()
            .with_dkim_output(&dkim_output)
            .with_spf_output(&spf_output, SpfScope::MailFrom)
            .with_dmarc_output(&dmarc_output),
    ],
    ..Default::default()
};

report.write_rfc5322(
    &ReportEnvelope {
        from: ("DMARC Reports", "noreply@example.org").into(),
        to: vec!["rua@example.com"],
        submitter: "example.org",
        report_domain: "",
        subject: None,
    },
    &mut writer,
)?;
```


## [0.13.3] - 2026-09-18

### Fixed
- DMARC: Aggregate reports serialise at most one `spf` element per record, dropping `helo` scoped results, as RFC 9990 Appendix A caps `AuthResultType/spf` at `maxOccurs="1"` and Section 3.1.1.13 restricts it to the `MAIL FROM` identity with `mfrom` as the only valid scope.
- DMARC: The aggregate report `version` element is written as `1.0` rather than `1`, per RFC 9990 Section 3.1.1.2.

## [0.13.2] - 2026-09-13

### Added
- DMARC: New `DmarcOutput::result` returns the overall DMARC result: `fail` when a policy record exists but no Authenticated Identifier aligns (RFC 9989 Section 5.3.5).

### Fixed
- SPF: `SpfParameters::verify` now checks the `MAIL FROM` identity whenever the `HELO` check does not return `fail`, instead of only when it returns `pass` (#61).
- DMARC: A `temperror` SPF result or DKIM signature whose identifier aligns with the Author Domain, or a DNS error while resolving an Organizational Domain for relaxed alignment, yields `temperror` instead of `fail` (RFC 9989 Section 5.3.6).
- DMARC: A policy record without a `p` tag is treated as `p=none` when it has a `rua` tag and ignored otherwise, regardless of its `sp` and `np` tags (RFC 9989 Section 4.10.1).
- DNS: A name that cannot be encoded as a DNS name, such as one with a label longer than 63 bytes, is reported as `Error::ParseError` instead of a resolver error.

## [0.13.1] - 2026-09-12

### Changed
- Bump `mail-builder` to 1.0.0.

## [0.13.0] - 2026-09-09

### Changed
- Performance enhancements.

## [0.12.2] - 2026-08-18

### Changed
- Bump `mail-builder` dependency to 0.5.

## [0.12.1] - 2026-08-16

### Changed
- MX and PTR records are now returned as A-labels.

### Fixed
- DMARC: Identifiers are converted to their A-label form before alignment, and alignment is no longer case sensitive.
- DMARC: External reporting addresses are compared to the policy domain in their A-label form.

## [0.12.0] - 2026-08-12

### Added
- DKIM2: Cap the signature chain at 50 `DKIM2-Signature` / `Message-Instance` header fields, reported as `Dkim2Error::ChainTooLong`.
- DKIM2: Accept an imaginary hop (`nd=`) that follows a real hop, provided its `d=` matches a recipient of the previous hop ([draft-ietf-dkim-dkim2-spec-04](https://datatracker.ietf.org/doc/html/draft-ietf-dkim-dkim2-spec-04) §9.3).

### Changed
- `Report::parse_rfc5322` and `TlsReport::parse_rfc5322` now take a `max_size` argument, which bounds the size of a decompressed report.

### Fixed
- Report parsing: Reject `.gz` and `.zip` attachments that decompress beyond `max_size`, and stop sizing the output buffer from the attacker-controlled ZIP size fields.

## [0.11.2] - 2026-07-12

### Changed
- Bump `mail-parser` to 0.11.5.

## [0.11.1] - 2026-07-05

### Added
- [RFC 9989 - Domain-based Message Authentication, Reporting, and Conformance (DMARC)](https://datatracker.ietf.org/doc/html/rfc9989) support.
- [RFC 9990 - DMARC Aggregate Reporting](https://datatracker.ietf.org/doc/html/rfc9990) support.
- [RFC 9991 - DMARC Failure Reporting](https://datatracker.ietf.org/doc/html/rfc9991) support.

## [0.11.0] - 2026-07-03

### Added
- DKIM2 support ([draft-ietf-dkim-dkim2-spec-03](https://datatracker.ietf.org/doc/html/draft-ietf-dkim-dkim2-spec-03)).
- WASM support (#18).

### Changed
- ARC is now gated under the `arc` feature. The ARC implementation is now considered historic, see [Reclassifying ARC as Historic](https://datatracker.ietf.org/doc/draft-ietf-dmarc-arc-to-historic/).

## [0.10.0] - 2026-06-25

### Added
- Include DNSSEC status in cache entries.

## [0.9.2] - 2026-06-24

### Changed
- Use `rustls-platform-verifier` in `hickory-resolver`.

### Fixed
- Body canonicalization uses header canonicalization settings.

## [0.9.1] - 2026-06-19

### Fixed
- Security: Header injection in `Authentication-Results`.

## [0.9.0] - 2026-05-05

### Changed
- Bump `hickory-resolver` to 0.26.

## [0.8.0] - 2026-04-13

### Added
- `aws-lc-rs` backend.

### Changed
- Use boxed slices in caches to slightly reduce memory usage.

### Removed
- `rust-crypto` backend.

## [0.7.5] - 2025-12-21

### Added
- Streaming DKIM signing API to reduce memory usage for large emails (#47).

### Fixed
- PKCS#8 key DER decoding regression (#51).

## [0.7.4] - 2025-12-19

### Changed
- Parse PEM with `rustls-pki-types` (#49).

## [0.7.3] - 2025-12-02

### Changed
- Bump `zip` to 6.0.

### Fixed
- SPF verification with mixed `redirect` and `include` mechanisms.

## [0.7.2] - 2025-09-14

### Changed
- Bump `quick-xml` to 0.38.
- Bump `zip` to 5.1.

## [0.7.1] - 2025-06-03

### Changed
- Bump `hickory-resolver` to 0.26.0-alpha.1.
- Bump `zip` to 4.0.

## [0.7.0] - 2025-05-11

### Added
- `rkyv` support.

### Changed
- Bump `mail-parser` to 0.11.
- Bump `hickory-resolver` to 0.25.
- Make `zip` dependency optional.

## [0.6.1] - 2025-01-26

### Changed
- Bump `mail-parser` to 0.10.0.

## [0.6.0] - 2024-12-29

### Changed
- `Resolver` is now `MessageAuthenticator`.
- Bring your own cache (or none at all): All validation functions can now take a `Parameters` struct that allows you to provide custom caches implementing the `ResolverCache` trait. By default no cache is used.

## [0.5.1] - 2024-12-18

### Added
- Build `AuthenticatedMessage` from `mail-parser::Message`.

## [0.5.0] - 2024-08-11

### Fixed
- Use public suffix list for DMARC relaxed alignment verification (#37).
- Increase DNS lookup limit to 10 during SPF verification (#35).

## [0.4.3] - 2024-06-19

### Added
- `TlsReport` is now clonable.

### Changed
- Bump `quick-xml` dependency to 0.3.2.

### Fixed
- Domain name length check in SPF verification (#34).
- DNS lookup limit being hit too early during SPF verification (#35).

## [0.4.2] - 2024-05-29

### Fixed
- IPv6 parsing bug in SPF parser (#32).

## [0.4.1] - 2024-05-28

### Changed
- Bump `zip` dependency to 2.1.1.

## [0.4.0] - 2024-05-18

### Changed
- DKIM verification defaults to `strict` mode and ignores signatures with a `l=` tag to avoid exploits (see https://stalw.art/blog/dkim-exploit). Use `AuthenticatedMessage::parse_with_opts(&message, false)` to enable `relaxed` mode.
- Parsed fields are now public.

## [0.3.11] - 2024-04-03

### Added
- DKIM keypair generation for both RSA and Ed25519.

### Fixed
- Check PTR against FQDN, including the dot at the end (#28).

## [0.3.10] - 2024-03-28

### Added
- `Resolver` is now cloneable.

## [0.3.9] - 2024-03-14

### Changed
- Use relaxed parsing for DNS names (#25).

## [0.3.8] - 2024-03-01

### Changed
- Made `pct` field accessible.
- ARF Feedback storage of messages of headers as strings.

## [0.3.7] - 2023-12-28

### Changed
- Bump `rustls-pemfile` dependency to 2.

### Fixed
- Incorrect body hash when content is empty (#22).

## [0.3.6] - 2023-10-21

### Changed
- Bump `hickory-resolver` dependency to 0.24.

## [0.3.5] - 2023-10-04

### Changed
- Bump `ring` dependency to 0.17.

## [0.3.4] - 2023-10-04

### Added
- `to_reverse_name` method on `IpAddr` to convert an IP address to a reverse DNS domain name.
- `txt_raw_lookup` method on `Resolver` to perform a raw TXT lookup.

## [0.3.3] - 2023-09-05

### Changed
- Bump `mail-parser` dependency to 0.9.
- Bump `trust-dns-resolver` dependency to 0.23.

## [0.3.2] - 2023-06-02

### Changed
- Bump `mail-builder` dependency to 0.3.
- Bump `quick-xml` dependency to 0.28.

## [0.3.1] - 2023-04-14

### Fixed
- Avoid panicking on invalid RSA key input (#17).

## [0.3.0] - 2023-01-27

### Added
- `ring` backend support.
- Reverse IP authentication (iprev).
- MTA-STS lookup.
- SMTP TLS Report generation and parsing.

### Changed
- API improvements: `DkimSigner` and `ArcSealer` builders.

### Fixed
- Bug fixes.

## [0.2.0] - 2022-12-05

### Fixed
- Acronyms in type names do not match the recommended spelling from RFC 430 (#31).
- Inconsistent use of '.' at the end of strings on fmt::Display impl for Error (#31).

## [0.1.0] - 2022-12-01

### Added
- Initial release.
