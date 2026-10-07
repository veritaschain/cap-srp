# Changelog

All notable changes to CAP-SRP will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Documentation and public claims
- Correct repository clone paths, contributor instructions and package URLs.
- Align CAP terminology and references with released CAP v1.0 and VAP v1.2 Draft 3.
- Disclose the published review mapping, unresolved divergences and lack of established conformance.
- Limit completeness claims to recorded/anchored scope; disclose pre-measurement drops and PoC anchoring limitations.
- Replace unconditional legal compliance labels in the CLI and dashboard with local evidence results.

### Added
- Initial project structure

## [0.1.0] - 2026-01-28

### Added

#### Core Features
- **Event Types**: `GEN_ATTEMPT`, `GEN`, `GEN_DENY`, `GEN_ERROR`
- **Risk Categories**: 16 categories including NCII_RISK, CSAM_RISK, REAL_PERSON_DEEPFAKE
- **UUIDv7 Event IDs**: Time-sortable unique identifiers
- **Hash Chain Linking**: Each event references the previous event's hash
- **Ed25519 Signatures**: All events are digitally signed
- **Merkle Tree**: Efficient inclusion proofs (O(log n))

#### Completeness Invariant
- Local attempt/outcome relationship: `Σ ATTEMPTS = Σ GEN + Σ DENY + Σ ERROR`
- Mismatches need investigation; they are not proof of fraud or anchored completeness
- Pending attempt detection
- Orphan outcome detection
- Duplicate outcome detection

#### Verification
- `CompletenessVerifier`: Verify the completeness invariant
- `ChainVerifier`: Verify hash chain integrity
- `MerkleVerifier`: Verify Merkle inclusion proofs
- `full_verification()`: Combined verification function

#### Dashboard
- Streamlit-based web interface
- Real-time completeness monitoring
- Denial breakdown by risk category
- Event explorer with filters
- Export functionality (JSON, Markdown reports)

#### CLI
- `cap-srp generate`: Generate demo events
- `cap-srp verify`: Verify event logs
- `cap-srp dashboard`: Launch web dashboard

### Security
- Ed25519 cryptographic signatures (RFC 8032)
- SHA-256 hashing throughout
- Merkle tree proofs (RFC 6962 inspired)
- Privacy-preserving: Only hashes stored, not raw prompts

### Documentation
- Comprehensive README with architecture diagrams
- API documentation
- Regulatory mapping (EU AI Act, DSA, California AB 853)
- Example scripts

### Standards Alignment
- IETF draft-kamimura-scitt-vcp
- RFC 6962 (Certificate Transparency)
- RFC 3161 (Time-Stamp Protocol) ready
- ISO/IEC 24970:2025 compatible

[Unreleased]: https://github.com/veritaschain/cap-srp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/veritaschain/cap-srp/releases/tag/v0.1.0
