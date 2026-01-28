# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of CAP-SRP seriously. If you believe you have found a security vulnerability, please report it to us responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to:

**security@veritaschain.org**

Please include the following information:

1. **Type of vulnerability** (e.g., cryptographic weakness, information disclosure, etc.)
2. **Full path of source file(s)** related to the vulnerability
3. **Step-by-step instructions** to reproduce the issue
4. **Proof-of-concept or exploit code** (if possible)
5. **Impact assessment** - what an attacker could achieve

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours
- **Initial Assessment**: We will provide an initial assessment within 5 business days
- **Status Updates**: We will keep you informed of our progress
- **Credit**: We will credit you (if desired) in our security advisories

### Scope

The following are in scope for security reports:

- CAP-SRP core library (`cap_srp/core/`)
- Cryptographic implementations (Ed25519 signing, Merkle trees)
- Hash chain integrity mechanisms
- Dashboard authentication/authorization (if applicable)

The following are out of scope:

- Vulnerabilities in third-party dependencies (report to the respective project)
- Social engineering attacks
- Physical attacks
- Denial of service attacks that don't reveal exploitable vulnerabilities

## Security Considerations

### Cryptographic Choices

CAP-SRP uses the following cryptographic primitives:

| Component | Algorithm | Standard |
|-----------|-----------|----------|
| Signing | Ed25519 | RFC 8032 |
| Hashing | SHA-256 | FIPS 180-4 |
| Merkle Tree | RFC 6962 format | Certificate Transparency |

### Key Management

- Private keys should never be stored in source code or logs
- Use environment variables or secure key management systems
- Rotate keys periodically according to your security policy

### Data Privacy

CAP-SRP is designed with privacy in mind:

- Prompts are never stored - only their SHA-256 hashes
- User context is hashed before storage
- Generated content is referenced by hash only

### Audit Trail Integrity

The security of CAP-SRP depends on:

1. **Hash chain integrity** - Each event links to the previous
2. **Ed25519 signatures** - Events cannot be forged
3. **Merkle proofs** - Third parties can verify inclusion
4. **External anchoring** - TSA timestamps prevent backdating

## Best Practices

When deploying CAP-SRP:

1. **Protect signing keys** - Use HSMs or secure key storage
2. **Monitor the log** - Set up alerts for chain breaks
3. **External anchoring** - Regularly anchor Merkle roots to TSA
4. **Backup strategy** - Maintain secure backups of the event log
5. **Access control** - Limit who can write to the event log

## Public Key Disclosure

For transparency, here are the public keys used to sign CAP-SRP releases:

```
Release Signing Key: (To be added upon first release)
```

## Acknowledgments

We thank the security researchers who have helped improve CAP-SRP:

- (Your name could be here!)

---

*Last updated: January 2026*
