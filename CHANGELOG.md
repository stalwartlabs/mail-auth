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
