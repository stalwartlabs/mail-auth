# Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](https://semver.org/).

## [0.15.0] - 2026-10-30

### Added
- DKIM2: updated to [draft-ietf-dkim-dkim2-spec-08](https://datatracker.ietf.org/doc/html/draft-ietf-dkim-dkim2-spec-08) (from -07).
- DKIM2: pure ML-DSA-44 (`mldsa44`) signatures, published as `k=mldsa44` with the raw public key (`crypto::MlDsa44Key`, `DkimKeyPair::generate_mldsa44`).
- DKIM2: AND (`,`) and OR (`|`) groups in `s=` and `h=`; `Dkim2Signer::additional_key` adds an alternative key and the new `hybrid_key` a key that must also verify.

### Changed
- DKIM2: timestamp, envelope, chain of custody and `From` errors are now `Fail` instead of `PermError`, and a null body recipe fails full verification.
- DKIM2: `Dkim2Error::NotValidlySigned` is renamed `NotFullyVerified`, and several errors were added or replaced to match the -08 result texts.

### Removed
- DKIM2: the `mldsa44-ed25519-sha512` composite algorithm.

### Fixed
- DKIM: relaxed body canonicalization now ignores whitespace-only lines at the end of the body (RFC 6376, Section 3.4.4), which produced a `bh=` that other implementations rejected (#62).

## [0.14.1] - 2026-10-26

### Fixed
- Disable the default features of `aws-lc-sys`, which enabled `all-bindings` and required CMake and bindgen on targets without pregenerated bindings (such as FreeBSD).

## [0.14.0] - 2026-10-24

This release reorganizes the public API and updates DKIM2 to draft-ietf-dkim-dkim2-spec-07. Most API changes are renames and moves; see the [crate documentation](https://docs.rs/mail-auth) for the new names and the README (sections "Backends", "DKIM2 Signing", "DKIM2 Chain Verification" and "DNS Caching") for usage.

### Added
- DKIM2: updated to [draft-ietf-dkim-dkim2-spec-07](https://datatracker.ietf.org/doc/html/draft-ietf-dkim-dkim2-spec-07) (from -04), with stricter parsing, chain of custody and `From` checks, and more detailed errors.
- DKIM2: `mldsa44-ed25519-sha512` post-quantum composite algorithm (`crypto::MlDsa44Ed25519Key`, `DkimKeyPair::generate_mldsa44_ed25519`).
- DKIM2: SHA-512 `Message-Instance` hashes (`Dkim2Signer::hashes`), `MessageAuthenticator::verify_dkim2_provisionally`, `Dkim2Signer::out_of_band_arrangement` and `Hop::exploded` (new `Hop::Exploded` variant) to flag single-recipient copies of an exploded message.
- `DnsCache` trait: one implementation supplies all record caches to every verifier through `Parameters::with_cache`.
- Negative DNS caching (RFC 2308), capped by `MessageAuthenticator::with_max_negative_ttl`.
- `AuthenticatedMessage` accessor methods.
- Documentation on every public item.

### Changed
- Bump `mail-parser` to 1.0.
- The `common` module is gone; its contents moved to `dns`, `crypto`, `headers`, `message`, `auth_results`, `iprev` and `dkim`.
- Verifiers take `Parameters<'x, P, C: DnsCache>`; `Parameters::params` is now `input` and the `cache_*` fields are replaced by `cache`. MX, A, AAAA and PTR caches hold `Result<RecordSet<T>, Negative>`.
- Renamed types and variants, including the `Record` suffix on parsed DNS record types (`SpfRecord`, `DmarcRecord`, ...), `Txt` to `TxtRecord`, `MX` to `Mx`, `Error::ParseError` to `Error::Parse`.
- SPF: `SpfParameters::{verify_ehlo, verify_mail_from, verify}` are now `{helo, mail_from, helo_and_mail_from}`, `with_spf_result` and `ReceivedSpf::new` take `SpfParameters`, and `SpfResult` displays lowercase tokens.
- `verify_dmarc_report_address` is now `authorized_report_addresses` and returns a `Result`.
- `DkimSigner` and `ArcSealer` no longer implement `Default`, `expiration` takes a `Duration`, and the signer typestate markers moved to the `signer` module (`Done` is now `Ready`).
- DKIM2 signing methods take a new `verified: Option<&Dkim2Output>` argument, `sign_with_message_instance` returns `Dkim2Signed`, and `MessageInstance::from_message`, `from_recipe` and `Recipe::diff` changed signature.
- DKIM2: the exhaustive enums `Dkim2Error`, `crypto::Algorithm`, `crypto::HashAlgorithm`, `crypto::DkimKey` and `crypto::HashOutput` gained variants (and `Dkim2Error` lost some), so `match` expressions need updating.

### Removed
- The `ring` feature and backend; the backends are `aws-lc-rs` (default) and `rust-crypto`.
- The `rkyv` feature.
- The `donotmodify` and `donotexplode` DKIM2 flags.
- The `Version` enum and `version` fields of `SpfRecord`, `DmarcRecord` and `AtpsRecord`.
- The `report` module and feature (DMARC aggregate, ARF and TLS-RPT report parsing and generation), together with the `flate2` and `zip` re-exports.
- Public constructors of `DkimOutput`, `ArcOutput` and `DmarcOutput` (use `From<DkimResult>` and `From<ArcResult>`).
- Public fields of `AuthenticatedMessage`, `MessageAuthenticator`, `DkimSigner`, `Dkim2Signer` and `DomainKey`; use the accessors, and `retain_dkim_signatures` to filter signatures before verification.

### Fixed

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
