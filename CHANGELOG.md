mail-auth 0.7.1
================================
- Bump `hickory-resolver`to 0.26.0-alpha.1
- Bump `zip` to 4.0

mail-auth 0.7.0
================================
- Bump `mail-parser` to 0.11.
- Bump `hickory-resolver` to 0.25.
- Added `rkyv` support.
- Make `zip` dependency optional.

mail-auth 0.6.1
================================
- Bump `mail-parser` to 0.10.0.

mail-auth 0.6.0
================================
- `Resolver` is now `MessageAuthenticator`.
- Bring your own cache (or none at all): All validation functions can now take a `Parameters` struct that allows you to provide custom caches implementing the `ResolverCache` trait. By default no cache is used.

mail-auth 0.5.1
================================
- Build `AuthenticatedMessage` from `mail-parser::Message`.

mail-auth 0.5.0
================================
- Fix: Use public suffix list for DMARC relaxed alignment verification (#37)
- Fix: Increase DNS lookup limit to 10 during SPF verification (#35)

mail-auth 0.4.3
================================
- Fix: Domain name length check in SPF verification (#34)
- Fix: DNS lookup limit being hit too early during SPF verification (#35)
- Make `TlsReport` clonable.
- Bump `quick-xml` dependency to 0.3.2.

mail-auth 0.4.2
================================
- Fix: IPv6 parsing bug in SPF parser (#32)

mail-auth 0.4.1
================================
- Bump `zip` dependency to 2.1.1.

mail-auth 0.4.0
================================
- DKIM verification defaults to `strict` mode and ignores signatures with a `l=` tag to avoid exploits (see https://stalw.art/blog/dkim-exploit). Use `AuthenticatedMessage::parse_with_opts(&message, false)` to enable `relaxed` mode.
- Parsed fields are now public.

mail-auth 0.3.11
================================
- Added: DKIM keypair generation for both RSA and Ed25519.
- Fix:  Check PTR against FQDN (including dot at the end) #28 

mail-auth 0.3.10
================================
- Make `Resolver` cloneable.

mail-auth 0.3.9
================================
- Use relaxed parsing for DNS names (#25)

mail-auth 0.3.8
================================
- Made `pct` field accessible.
- ARF Feedback storage of messages of headers as strings.

mail-auth 0.3.7
================================
- Fix: Incorrect body hash when content is empty (#22)
- Bump to `rustls-pemfile` dependency to 2.

mail-auth 0.3.6
================================
- Bump `hickory-resolver` dependency to 0.24.

mail-auth 0.3.5
================================
- Bump `ring` dependency to 0.17.

mail-auth 0.3.4
================================
- Added `to_reverse_name` method to `IpAddr` to convert an IP address to a reverse DNS domain name.
- Added `txt_raw_lookup` method to `Resolver` to perform a raw TXT lookup.

mail-auth 0.3.3
================================
- Bump `mail-parser` dependency to 0.9
- Bump `trust-dns-resolver` dependency to 0.23

mail-auth 0.3.2
================================
- Bump `mail-builder` dependency to 0.3
- Bump `quick-xml` dependency to 0.28

mail-auth 0.3.1
================================
- Fix: Avoid panicking on invalid RSA key input (#17)

mail-auth 0.3.0
================================
- ``ring`` backend support.
- API improvements: ``DkimSigner`` and ``ArcSealer`` builders.
- Reverse IP authentication (iprev).
- MTA-STS lookup.
- SMTP TLS Report generation and parsing.
- Bug fixes.

mail-auth 0.2.0
================================
- Fixed: Acronyms in type names do not match the recommended spelling from RFC 430 (#31)
- Fixed: Inconsistent use of '.' at the end of strings on fmt::Display impl for Error (#31)

mail-auth 0.1.0
================================
- Initial release.
