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
