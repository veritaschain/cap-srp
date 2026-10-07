# Regulatory relevance of CAP-SRP evidence

This document describes potential evidence uses, not a compliance checklist or certification.
CAP means **Content / Creative AI Profile**; SRP means **Safe Refusal Provenance**.

## Regulatory relevance and legal scope

Refusal records may support assessment of logging, oversight and audit obligations, including EU AI Act Article 12 where applicable. They do not establish fulfillment of those obligations, content-removal duties, retention periods or GDPR erasure requirements. A timestamp is not a retention system, and hashing a prompt does not automatically anonymize personal data.

> **Legal scope (VAP v1.2 §1.6).** VAP and its domain profiles define mechanisms for producing **cryptographically verifiable evidence** of AI system decisions. Conformance to VAP or any profile: (a) does **not** constitute compliance with the EU AI Act, GDPR, MiFID II/III, CAT Rule 613, NIS2, FDA SaMD guidance, or any other law or regulation; (b) does **not** constitute a legal determination that any technical mechanism (including crypto-shredding) satisfies a specific legal obligation; (c) does **not** warrant the correctness, fairness, or safety of the underlying AI decisions — only the integrity, completeness (at anchor granularity), and attributability of their records. VAP generates evidence; competent authorities and courts evaluate it.

## Evidence capabilities and limits

| Capability | Potential evidence use | Not established by the PoC |
| --- | --- | --- |
| Request/outcome records | Inspection of reported decisions and policy context | Truth of model behavior, safeguard adequacy or universal non-generation |
| Hash chain and optional signature verification | Integrity and attribution of supplied records | Independently authenticated issuer identity unless trust material is supplied |
| Attempt/outcome checks | Local counts and reference consistency | Pre-measurement capture, anchored full-batch completeness or absence of paired omissions |
| Merkle proofs | Membership in a stated root | Independent timestamp, complete batch disclosure or anchor continuity |
| Exported reports | Material for human audit review | Legal compliance, certification or acceptance in a proceeding |

The code has no end-to-end TSA submission/receipt verification path. Retention, access control, removal workflows, privacy protection, deployment scope and applicable legal duties require separate implementation and assessment. Report PASS labels concern local checks only.

## Canonical references

- [CAP regulatory relevance notes](https://github.com/veritaschain/cap-spec#regulatory-alignment)
- [CAP v1.0 specification](https://github.com/veritaschain/cap-spec/blob/main/docs/CAP-Specification-v1.0.md)
- [VAP v1.2 §1.6 and integrity requirements](https://github.com/veritaschain/vap-spec/blob/main/spec/v1.2/VAP_Framework_Specification.md)
- [Draft CAP/VAP mapping](https://github.com/veritaschain/cap-spec/blob/main/docs/conformance/CAP-v1.0-VAP-v1.2-Draft3-Conformance-Mapping.md): published for review; unresolved divergences; conformance not established.

## Generate a local evidence report

```bash
cap-srp report data/demo_events.json
```

This existing command currently fails on the generated demo JSON because of event-type deserialization; see the [known implementation failures](../README.md#known-implementation-failures). Its report template does not make a regulatory determination and does not independently authenticate external anchors.
