# CAP-SRP: Refusal Provenance Dashboard

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

**Tamper-evident records of reported AI generation attempts and refusal decisions.**

CAP-SRP provides a Python logging library, CLI and Streamlit dashboard for exploring recorded generation outcomes. Its demonstrations use synthetic decisions; they do not evaluate a live model's safeguards.

## Canonical specifications and status

**CAP means Content / Creative AI Profile**, a domain profile of the **Verifiable AI Provenance Framework (VAP)**. SRP means **Safe Refusal Provenance**.

- [CAP v1.0 — released specification](https://github.com/veritaschain/cap-spec/blob/main/docs/CAP-Specification-v1.0.md)
- [VAP v1.2 — framework specification](https://github.com/veritaschain/vap-spec/blob/main/spec/v1.2/VAP_Framework_Specification.md) (currently Draft 3)
- [CAP v1.0 / VAP v1.2 Draft 3 conformance mapping](https://github.com/veritaschain/cap-spec/blob/main/docs/conformance/CAP-v1.0-VAP-v1.2-Draft3-Conformance-Mapping.md) — **review draft**
- [Minimal change proposal](https://github.com/veritaschain/cap-spec/blob/main/docs/conformance/CAP-VAP-v1.2-Minimal-Change-Proposal.md) — **unadopted**

**Status checked 2026-10-08 JST:** the mapping is published for review, but identifies unresolved normative divergences. **CAP v1.0 conformance to VAP v1.2 has not been established.** Neither publication of the mapping nor this PoC establishes conformance or certification. CAP v1.0 remains the released CAP specification; the proposal does not amend it. This repository demonstrates selected SRP mechanisms and does not claim full CAP v1.0 or VAP v1.2 conformance.

In particular, CAP v1.0 permits optional external anchoring at Bronze, whereas VAP v1.2 INT-006 requires it at every conformance level. Signed batch scope, continuity, policy binding and data-model requirements also remain unresolved. A local hash chain, Merkle root or passing PoC test is not a substitute for those requirements.

This is a **first-party PoC**, not independent implementation evidence. The [canonical CAP implementation disclosure](https://github.com/veritaschain/cap-spec#implementation-status-mandatory-disclosure) reports zero external implementations and zero Evidence Packs accepted in proceedings as of September 2026.

## What this PoC demonstrates

| Mechanism | Demonstrated scope | Limitation |
| --- | --- | --- |
| Ed25519 signatures and hash chain | Integrity checks on the supplied event records; signatures can be checked when a public key is supplied | The public key must be independently authenticated; signatures do not prove the truth of a decision |
| Attempt/outcome verification | Counts and attempt-ID matching for `GEN`, `GEN_DENY` and `GEN_ERROR` | Checks only supplied records; not a complete VAP batch verifier |
| Merkle tree and inclusion proofs | Experimental membership/root-checking APIs | Existing proof-verification tests fail; not independently validated. A root supplied with the same export is not an independent anchor |
| Dashboard and reports | Record statistics and local verification results | A PASS is not legal compliance, certification or proof of model safety |

**External anchoring is not implemented end to end in this PoC.** The code contains an `AnchoredMerkleRoot` data container and an optional TSA dependency, but the Quick Start does not obtain or authenticate RFC 3161 receipts, signed VAP AnchorRecords or anchor continuity. Architectural anchoring diagrams describe an integration target, not an executed verification path.

## Completeness Invariant: scope and limits

The canonical CAP relationship is:

```text
COUNT(GEN_ATTEMPT) = COUNT(GEN) + COUNT(GEN_DENY) + COUNT(GEN_ERROR)
```

For a closed set of recorded attempts, outcomes must be linked by attempt ID and checked for missing, orphan and duplicate outcomes. **Equal aggregate counts alone are insufficient.** Attempts still in progress, or outcomes crossing a time-window boundary, must be distinguished from missing terminal outcomes; a failed check does not by itself prove fraud.

**Independent completeness claims cover recorded and externally anchored requests, at anchor/batch granularity.** Hashes, signatures, full batch scope and independently authenticated commitments must be verified separately. A Merkle inclusion proof shows membership of one event, not completeness of the entire batch.

What these mechanisms cannot establish:

- **Pre-measurement drops:** a request never recorded as `GEN_ATTEMPT` leaves nothing to detect.
- **Uncommitted omissions:** removing an attempt and its outcome together can preserve the count equation. Local self-consistency does not establish a complete history without an independent commitment.
- **Truth of the underlying decision:** signed records attribute a statement to a key; they do not establish that the producer accurately described model execution or used adequate safeguards.
- **Universal non-generation or safety:** a recorded `GEN_DENY` does not prove that harmful content never existed or was never generated elsewhere. SRP records decisions after the fact; it does not itself block, filter or prevent generation.

These limits follow the canonical CAP README and VAP v1.2 §§1.6, 4.1.7 and 11.1. See the mapping for the distinction between SRP attempt/outcome checks and VAP anchored-batch completeness.

## Quick Start

### 1. Install

```bash
git clone https://github.com/veritaschain/cap-srp.git
cd cap-srp

python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

### 2. Run the dashboard

```bash
streamlit run cap_srp/dashboard/app.py
# Open http://localhost:8501
```

### 3. Generate demo records

```bash
python examples/demo_generate_events.py --events 1000 --output data/demo_events.json
```

The generated records are synthetic. The local schemas describe this PoC's wire format; they are not canonical CAP/VAP conformance tests. See the known failures below before using schema validation as a gate.

### 4. Check records in memory

Use the Python example under **Event model** below for a working local attempt/outcome check.

The JSON-file commands `cap-srp verify`, `cap-srp report` and `examples/demo_verify_completeness.py` currently encounter an event-type deserialization error on the generated demo export. They are not a working end-to-end verification path. Authenticate keys and reference commitments independently before relying on producer evidence; no command here authenticates an external anchor.

## Event model

| Event | Recorded meaning |
| --- | --- |
| `GEN_ATTEMPT` | A request was reported received before evaluation |
| `GEN` | Successful generation was reported |
| `GEN_DENY` | A refusal and its risk/policy context were reported |
| `GEN_ERROR` | A technical failure was reported |

Outcomes reference their attempt. The local model uses snake_case fields such as `event_id`, `attempt_id`, `prompt_hash`, `policy_version` and `model_id`. These are implementation-specific examples, not the canonical CAP v1.0 schema or a VAP v1.2 envelope. Existing event bytes and signature inputs are unchanged by this documentation alignment.

```python
from cap_srp import CAPLogger, CompletenessVerifier, RiskCategory

logger = CAPLogger()
attempt = logger.log_attempt(prompt_hash="sha256:example")
logger.log_denial(
    attempt_id=attempt.event_id,
    risk_category=RiskCategory.NCII_RISK,
    risk_score=0.94,
)
result = CompletenessVerifier().verify(logger.events)
print(result.is_valid)  # Local attempt/outcome check only
```

## Regulatory relevance and legal scope

Refusal records may support assessment of logging, oversight and audit obligations, including EU AI Act Article 12 where applicable. They do not establish fulfillment of those obligations, content-removal duties, retention periods or GDPR erasure requirements. A timestamp is not a retention system, and hashing a prompt does not automatically anonymize personal data.

> **Legal scope (VAP v1.2 §1.6).** VAP and its domain profiles define mechanisms for producing **cryptographically verifiable evidence** of AI system decisions. Conformance to VAP or any profile: (a) does **not** constitute compliance with the EU AI Act, GDPR, MiFID II/III, CAT Rule 613, NIS2, FDA SaMD guidance, or any other law or regulation; (b) does **not** constitute a legal determination that any technical mechanism (including crypto-shredding) satisfies a specific legal obligation; (c) does **not** warrant the correctness, fairness, or safety of the underlying AI decisions — only the integrity, completeness (at anchor granularity), and attributability of their records. VAP generates evidence; competent authorities and courts evaluate it.

See [regulatory relevance notes](docs/REGULATORY_MAPPING.md) for the boundary between evidence capabilities and legal determinations.

## Development and tests

```bash
pytest tests/ -v
pytest tests/ --cov=cap_srp --cov-report=html
pytest tests/test_verifier.py -v
```

For SSH cloning:

```bash
git clone git@github.com:veritaschain/cap-srp.git
cd cap-srp
pip install -e ".[dev]"
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Test success verifies tested PoC behavior, not specification conformance.

### Known implementation failures

During the 2026-10-08 JST documentation check, the existing suite had **91 passes and 6 failures**: one Merkle proof-verification test and five schema/example-validation tests. The same six failures reproduce on the unchanged base commit `3359ea7963ea3ff8c945b9488877b5aacf89bc2c`; its UUID sorting test also failed (90 passes / 7 failures). The schema failures include a mismatch between the emitted `ed25519:` signature prefix and the schema pattern. JSON event-type deserialization also prevents the demo-file verification/report commands above from completing.

These are existing implementation limitations, not successful conformance results. This update changes documentation and displayed/generated explanations; it does not repair cryptographic algorithms, event deserialization or schemas. The in-memory README example and event-generation demo were exercised successfully.

## Repository guide

- `cap_srp/core/`: event model, logger, signing, Merkle tree and local verifiers
- `cap_srp/cli.py`: commands for local verification and evidence reports
- `cap_srp/dashboard/app.py`: Streamlit demo dashboard
- `schemas/`: local PoC JSON Schemas
- `examples/`: synthetic record generation and verification
- `tests/`: existing test suite
- [Architecture](docs/ARCHITECTURE.md), [API](docs/API.md), [Security](SECURITY.md)
- [Earlier SRP PoC](https://github.com/veritaschain/cap-safe-refusal-provenance): separate legacy implementation with additional limitations

## License and contact

[Apache License 2.0](LICENSE). VeritasChain Standards Organization (VSO).

- Website: https://veritaschain.org
- Email: info@veritaschain.org
- GitHub: https://github.com/veritaschain/cap-srp

*Verify, Don't Trust.*
