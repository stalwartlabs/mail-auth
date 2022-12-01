# mail-auth

[![crates.io](https://img.shields.io/crates/v/mail-auth)](https://crates.io/crates/mail-auth)
[![build](https://github.com/stalwartlabs/mail-auth/actions/workflows/rust.yml/badge.svg)](https://github.com/stalwartlabs/mail-auth/actions/workflows/rust.yml)
[![docs.rs](https://img.shields.io/docsrs/mail-auth)](https://docs.rs/mail-auth)
[![crates.io](https://img.shields.io/crates/l/mail-auth)](http://www.apache.org/licenses/LICENSE-2.0)

_mail-auth_ is an e-mail authentication and reporting library written in Rust that supports the **DKIM**, **ARC**, **SPF** and **DMARC**
protocols. The library aims to be fast, safe and correct while supporting all major [message authentication and reporting RFCs](#conformed-rfcs). 

Features:

- **DomainKeys Identified Mail (DKIM)**:
  - ED25519-SHA256 (Edwards-Curve Digital Signature Algorithm), RSA-SHA256 and RSA-SHA1 signing and verification.
  - DKIM Authorized Third-Party Signatures.
  - DKIM failure reporting using the Abuse Reporting Format.
- **Authenticated Received Chain (ARC)**:
  - ED25519-SHA256 (Edwards-Curve Digital Signature Algorithm), RSA-SHA256 and RSA-SHA1 chain verification.
  - ARC sealing.
- **Sender Policy Framework (SPF)**:
  - Policy evaluation.
  - SPF failure reporting using the Abuse Reporting Format.
- **Domain-based Message Authentication, Reporting, and Conformance (DMARC)**:
  - Policy evaluation.
  - DMARC aggregate report parsing and generation.
- **Abuse Reporting Format (ARF)**:
  - Abuse and Authentication failure reporting.
  - Feedback report parsing and generation.


## Usage examples

### DKIM Signature Verification

```rust
    // Create a resolver using Cloudflare DNS
    let resolver = Resolver::new_cloudflare_tls().unwrap();

    // Parse message
    let authenticated_message = AuthenticatedMessage::parse(RFC5322_MESSAGE.as_bytes()).unwrap();

    // Validate signature
    let result = resolver.verify_dkim(&authenticated_message).await;

    // Make sure all signatures passed verification
    assert!(result.iter().all(|s| s.result() == &DKIMResult::Pass));
```

### DKIM Signing

```rust
    // Sign an e-mail message using RSA-SHA256
    let pk_rsa = PrivateKey::from_rsa_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
    let signature_rsa = Signature::new()
        .headers(["From", "To", "Subject"])
        .domain("example.com")
        .selector("default")
        .sign(RFC5322_MESSAGE.as_bytes(), &pk_rsa)
        .unwrap();

    // Sign an e-mail message using ED25519-SHA256
    let pk_ed = PrivateKey::from_ed25519(
        &base64_decode(ED25519_PUBLIC_KEY.as_bytes()).unwrap(),
        &base64_decode(ED25519_PRIVATE_KEY.as_bytes()).unwrap(),
    )
    .unwrap();
    let signature_ed = Signature::new()
        .headers(["From", "To", "Subject"])
        .domain("example.com")
        .selector("default-ed")
        .sign(RFC5322_MESSAGE.as_bytes(), &pk_ed)
        .unwrap();

    // Print the message including both signatures to stdout
    println!(
        "{}{}{}",
        signature_rsa.to_header(),
        signature_ed.to_header(),
        RFC5322_MESSAGE
    );
```

### ARC Chain Verification

```rust
    // Create a resolver using Cloudflare DNS
    let resolver = Resolver::new_cloudflare_tls().unwrap();

    // Parse message
    let authenticated_message = AuthenticatedMessage::parse(RFC5322_MESSAGE.as_bytes()).unwrap();

    // Validate ARC chain
    let result = resolver.verify_arc(&authenticated_message).await;

    // Make sure ARC passed verification
    assert_eq!(result.result(), &DKIMResult::Pass);
```

### ARC Chain Sealing

```rust
    // Create a resolver using Cloudflare DNS
    let resolver = Resolver::new_cloudflare_tls().unwrap();

    // Parse message to be sealed
    let authenticated_message = AuthenticatedMessage::parse(RFC5322_MESSAGE.as_bytes()).unwrap();

    // Verify ARC and DKIM signatures
    let arc_result = resolver.verify_arc(&authenticated_message).await;
    let dkim_result = resolver.verify_dkim(&authenticated_message).await;

    // Build Authenticated-Results header
    let auth_results = AuthenticationResults::new("mx.mydomain.org")
        .with_dkim_result(&dkim_result, "sender@example.org")
        .with_arc_result(&arc_result, "127.0.0.1".parse().unwrap());

    // Seal message
    if arc_result.can_be_sealed() {
        // Seal the e-mail message using RSA-SHA256
        let pk_rsa = PrivateKey::from_rsa_pkcs1_pem(RSA_PRIVATE_KEY).unwrap();
        let arc_set = ARC::new(&auth_results)
            .domain("example.org")
            .selector("default")
            .headers(["From", "To", "Subject", "DKIM-Signature"])
            .seal(&authenticated_message, &arc_result, &pk_rsa)
            .unwrap();

        // Print the sealed message to stdout
        println!("{}{}", arc_set.to_header(), RFC5322_MESSAGE)
    } else {
        eprintln!("The message could not be sealed, probably an ARC chain with cv=fail was found.")
    }
```

### SPF Policy Evaluation

```rust
    // Create a resolver using Cloudflare DNS
    let resolver = Resolver::new_cloudflare_tls().unwrap();

    // Verify HELO identity
    let result = resolver
        .verify_spf_helo("127.0.0.1".parse().unwrap(), "gmail.com")
        .await;
    assert_eq!(result.result(), SPFResult::Fail);

    // Verify MAIL-FROM identity
    let result = resolver
        .verify_spf_sender("::1".parse().unwrap(), "gmail.com", "sender@gmail.com")
        .await;
    assert_eq!(result.result(), SPFResult::Fail);
```

### DMARC Policy Evaluation

```rust
    // Create a resolver using Cloudflare DNS
    let resolver = Resolver::new_cloudflare_tls().unwrap();

    // Verify DKIM signatures
    let authenticated_message = AuthenticatedMessage::parse(RFC5322_MESSAGE.as_bytes()).unwrap();
    let dkim_result = resolver.verify_dkim(&authenticated_message).await;

    // Verify SPF MAIL-FROM identity
    let spf_result = resolver
        .verify_spf_sender("::1".parse().unwrap(), "example.org", "sender@example.org")
        .await;

    // Verify DMARC
    let dmarc_result = resolver
        .verify_dmarc(
            &authenticated_message,
            &dkim_result,
            "example.org",
            &spf_result,
        )
        .await;
    assert_eq!(dmarc_result.dkim_result(), &DMARCResult::Pass);
    assert_eq!(dmarc_result.spf_result(), &DMARCResult::Pass);
```

More examples available under the [examples](examples) directory.

## Testing & Fuzzing

To run the testsuite:

```bash
 $ cargo test --all-features
```

To fuzz the library with `cargo-fuzz`:

```bash
 $ cargo +nightly fuzz run mail_parser
```

## Conformed RFCs

### DKIM

- [RFC 6376 - DomainKeys Identified Mail (DKIM) Signatures](https://datatracker.ietf.org/doc/html/rfc6376)
- [RFC 6541 - DomainKeys Identified Mail (DKIM) Authorized Third-Party Signatures](https://datatracker.ietf.org/doc/html/rfc6541)
- [RFC 6651 - Extensions to DomainKeys Identified Mail (DKIM) for Failure Reporting](https://datatracker.ietf.org/doc/html/rfc6651)
- [RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)](https://datatracker.ietf.org/doc/html/rfc8032)
- [RFC 4686 - Analysis of Threats Motivating DomainKeys Identified Mail (DKIM)](https://datatracker.ietf.org/doc/html/rfc4686)
- [RFC 5016 - Requirements for a DomainKeys Identified Mail (DKIM) Signing Practices Protocol](https://datatracker.ietf.org/doc/html/rfc5016)
- [RFC 5585 - DomainKeys Identified Mail (DKIM) Service Overview](https://datatracker.ietf.org/doc/html/rfc5585)
- [RFC 5672 - DomainKeys Identified Mail (DKIM) Signatures -- Update](https://datatracker.ietf.org/doc/html/rfc5672)
- [RFC 5863 - DomainKeys Identified Mail (DKIM) Development, Deployment, and Operations](https://datatracker.ietf.org/doc/html/rfc5863)
- [RFC 6377 - DomainKeys Identified Mail (DKIM) and Mailing Lists](https://datatracker.ietf.org/doc/html/rfc6377)

### SPF
- [RFC 7208 - Sender Policy Framework (SPF)](https://datatracker.ietf.org/doc/html/rfc7208)
- [RFC 6652 - Sender Policy Framework (SPF) Authentication Failure Reporting Using the Abuse Reporting Format](https://datatracker.ietf.org/doc/html/rfc6652)

### DMARC
- [RFC 7489 - Domain-based Message Authentication, Reporting, and Conformance (DMARC)](https://datatracker.ietf.org/doc/html/rfc7489)
- [RFC 8617 - The Authenticated Received Chain (ARC) Protocol](https://datatracker.ietf.org/doc/html/rfc8617)
- [RFC 8601 - Message Header Field for Indicating Message Authentication Status](https://datatracker.ietf.org/doc/html/rfc8601)
- [RFC 8616 - Email Authentication for Internationalized Mail](https://datatracker.ietf.org/doc/html/rfc8616)
- [RFC 7960 - Interoperability Issues between Domain-based Message Authentication, Reporting, and Conformance (DMARC) and Indirect Email Flows](https://datatracker.ietf.org/doc/html/rfc7960)

### ARF
- [RFC 5965 - An Extensible Format for Email Feedback Reports](https://datatracker.ietf.org/doc/html/rfc5965)
- [RFC 6430 - Email Feedback Report Type Value: not-spam](https://datatracker.ietf.org/doc/html/rfc6430)
- [RFC 6590 - Redaction of Potentially Sensitive Data from Mail Abuse Reports](https://datatracker.ietf.org/doc/html/rfc6590)
- [RFC 6591 - Authentication Failure Reporting Using the Abuse Reporting Format](https://datatracker.ietf.org/doc/html/rfc6591)
- [RFC 6650 - Creation and Use of Email Feedback Reports: An Applicability Statement for the Abuse Reporting Format (ARF)](https://datatracker.ietf.org/doc/html/rfc6650)

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Copyright

Copyright (C) 2020-2022, Stalwart Labs Ltd.

