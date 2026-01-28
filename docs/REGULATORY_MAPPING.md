# CAP-SRP Regulatory Mapping

This document maps CAP-SRP capabilities to regulatory requirements across major jurisdictions.

## Executive Summary

CAP-SRP (Content Authenticity Protocol - Safe Refusal Provenance) provides cryptographic audit trail capabilities that address requirements from multiple regulatory frameworks:

| Framework | Jurisdiction | Key Requirements | CAP-SRP Coverage |
|-----------|--------------|-----------------|------------------|
| EU AI Act (Article 12) | European Union | Automatic logging, tamper-evidence | ✅ Full |
| Digital Services Act | European Union | Content moderation transparency | ✅ Full |
| ISO/IEC 24970:2025 | International | AI system logging standard | ✅ Full |
| MiFID II RTS 25 | European Union | Algorithmic trading records | ✅ Via VCP |
| MAS AI RMF | Singapore | AI transparency & accountability | ✅ Full |
| NIST AI RMF | United States | Govern, Map, Measure, Manage | ✅ Full |
| California AB 853 | California, USA | AI transparency requirements | ✅ Full |

---

## EU AI Act (Regulation 2024/1689)

### Article 12: Record-Keeping

> "High-risk AI systems shall technically allow for the automatic recording of events (logs) over the lifetime of the system."

#### Requirements Mapping

| Article 12 Requirement | CAP-SRP Implementation |
|------------------------|------------------------|
| **12(1)** Automatic event recording | ✅ All events auto-logged via sidecar pattern |
| **12(2)(a)** Risk situation identification | ✅ `risk_category` + `risk_score` fields |
| **12(2)(b)** Post-market monitoring | ✅ Continuous event stream + Merkle anchoring |
| **12(2)(c)** Operation monitoring | ✅ Session tracking, model versioning |
| **12(3)** Biometric identification specifics | ✅ Timestamp precision, database references |
| Tamper-evidence (implied) | ✅ Hash chain + Ed25519 signatures |
| Third-party verifiability (implied) | ✅ Merkle proofs + external TSA anchoring |

#### Implementation Notes

```python
# Article 12(2)(a) - Risk identification
event = GenerationDenial(
    risk_category=RiskCategory.NCII_RISK,
    risk_score=0.94,
    denial_reason="POLICY_VIOLATION:NCII_DETECTED"
)

# Article 12(2)(b) - Post-market monitoring
# Continuous logging with external anchoring
logger.export_events("audit_archive.json")
anchored_root = AnchoredMerkleRoot(
    root_hash=logger.merkle_root,
    anchor_type="RFC3161",
    anchor_timestamp=datetime.now(timezone.utc).isoformat()
)
```

### Article 19: Automatically Generated Logs

> "Providers of high-risk AI systems shall keep the logs... for a period appropriate to the intended purpose, of at least six months."

| Requirement | CAP-SRP Implementation |
|-------------|------------------------|
| Automatic generation | ✅ Events auto-generated |
| 6+ month retention | ✅ External TSA anchoring provides long-term proof |
| Control over logs | ✅ Sidecar pattern keeps logs separate from AI system |

---

## EU Digital Services Act (DSA)

### Article 15: Transparency Reporting

> "Providers of intermediary services shall make publicly available... information on content moderation engaged in at its own initiative."

| Requirement | CAP-SRP Implementation |
|-------------|------------------------|
| Content moderation statistics | ✅ `get_statistics()` provides aggregated data |
| Moderation categories | ✅ `RiskCategory` enum for standardized reporting |
| Automated decision metrics | ✅ Denial rate, category breakdown |

### Article 34-35: Systemic Risk Assessment

| Requirement | CAP-SRP Implementation |
|-------------|------------------------|
| Risk identification | ✅ Real-time risk categorization |
| Audit trail for enforcement | ✅ Merkle proofs for regulatory verification |
| Document preservation | ✅ Cryptographic integrity guarantees |

### Grok Crisis Response Capabilities

The January 2026 EU investigation into X/Grok highlighted the need for:

| DSA Enforcement Need | CAP-SRP Solution |
|---------------------|------------------|
| Prove safety filters exist | ✅ Cryptographic denial records |
| Demonstrate refusal rate | ✅ Completeness Invariant verification |
| Independent verification | ✅ Third-party Merkle proof verification |
| Historical audit | ✅ Hash chain enables retroactive verification |

---

## ISO/IEC DIS 24970:2025 (AI System Logging)

This draft standard provides implementation guidance for EU AI Act Article 12.

### Logging Framework Requirements

| ISO/IEC 24970 Section | CAP-SRP Implementation |
|-----------------------|------------------------|
| Logging strategy definition | ✅ Event types defined in specification |
| Regulatory/ethical compliance | ✅ Maps to EU AI Act, DSA |
| Normal operation triggers | ✅ `GEN_ATTEMPT` on every request |
| Monitoring triggers | ✅ All event types logged |
| Human oversight triggers | ✅ Support for `human_override` logging |
| Error logging | ✅ `GEN_ERROR` event type |
| Contextual data | ✅ `session_id`, `model_id`, `policy_version` |
| Secure storage | ✅ Hash chain + external anchoring |
| Retention compliance | ✅ TSA provides legal timestamp |
| Access controls | ✅ Ed25519 signatures for authenticity |
| Flexibility (SW/HW) | ✅ Sidecar pattern works with any implementation |

---

## Singapore MAS AI Risk Management Guidelines

### FEAT Principles Alignment

| FEAT Principle | CAP-SRP Implementation |
|----------------|------------------------|
| **Fairness** | ✅ Denial patterns analyzable for bias detection |
| **Ethics** | ✅ Risk categories align with ethical guidelines |
| **Accountability** | ✅ Immutable audit trail with signatures |
| **Transparency** | ✅ Third-party verifiable proofs |

### AI Governance Requirements (2025 Consultation)

| MAS Requirement | CAP-SRP Implementation |
|-----------------|------------------------|
| AI inventory & risk assessment | ✅ Events tagged with `model_id`, `risk_category` |
| Lifecycle controls | ✅ `policy_version` tracking |
| Data governance | ✅ Hash-only storage (no raw data) |
| Explainability | ✅ Decision factors can be logged |
| Human oversight | ✅ Override logging support |
| Third-party AI risk | ✅ Independent verification possible |

---

## NIST AI Risk Management Framework

### Function Mapping

| NIST AI RMF Function | CAP-SRP Implementation |
|---------------------|------------------------|
| **GOVERN** | Cryptographic signatures prove oversight |
| **MAP** | Risk categories map AI system risks |
| **MEASURE** | Statistics provide performance metrics |
| **MANAGE** | Completeness verification enables control |

### Trustworthy AI Characteristics

| Characteristic | CAP-SRP Support |
|----------------|-----------------|
| Valid and Reliable | ✅ Merkle proofs ensure data integrity |
| Safe | ✅ Denial records prove safety measures |
| Secure and Resilient | ✅ Cryptographic tamper evidence |
| Accountable and Transparent | ✅ Full audit trail |
| Explainable and Interpretable | ✅ Structured event data |
| Privacy-Enhanced | ✅ Hash-only storage, crypto-shredding ready |
| Fair | ✅ Analyzable for bias patterns |

---

## California AB 853 (AI Transparency Act)

Effective August 2, 2026.

| AB 853 Requirement | CAP-SRP Implementation |
|-------------------|------------------------|
| AI-generated content disclosure | ✅ `c2pa_manifest_id` for C2PA integration |
| Safety measure documentation | ✅ `policy_version`, denial records |
| Audit trail for enforcement | ✅ Full event history with proofs |
| Third-party verification | ✅ Merkle proofs |

---

## MiFID II / MiFIR (via VCP Integration)

CAP-SRP extends the VeritasChain Protocol (VCP) for non-trading AI systems.

### RTS 25 Requirements (Algorithmic Trading)

| RTS 25 Requirement | VCP/CAP-SRP Implementation |
|-------------------|---------------------------|
| Timestamping (microsecond) | ✅ ISO 8601 with microseconds |
| Order sequence tracking | ✅ UUIDv7 sortable IDs |
| Decision factor logging | ✅ Extensible event schema |
| 5-year retention | ✅ External anchoring for long-term proof |

---

## Implementation Checklist

### For EU AI Act Compliance

```markdown
□ Deploy CAP-SRP sidecar with AI system
□ Configure RiskCategory mapping for your use case
□ Enable external TSA anchoring (RFC 3161)
□ Set up 6+ month retention policy
□ Generate compliance reports for Article 19
□ Implement human oversight logging
□ Document policy_version control process
```

### For DSA Compliance

```markdown
□ Implement denial category reporting
□ Configure public statistics endpoint
□ Set up Merkle proof export for regulators
□ Document content moderation policies in denial_reason
□ Enable real-time monitoring dashboard
```

### For MAS AI RMF

```markdown
□ Map RiskCategory to FEAT principles
□ Implement bias monitoring on denial patterns
□ Configure third-party verification capabilities
□ Document AI inventory with model_id
□ Enable human override logging
```

---

## Compliance Evidence Generation

### Regulatory Report Template

```python
from cap_srp import CAPLogger, CompletenessVerifier

logger = CAPLogger()
# ... logging events ...

# Generate compliance evidence
stats = logger.get_statistics()
verifier = CompletenessVerifier()
result = verifier.verify(logger.events)

report = f"""
COMPLIANCE REPORT
=================
Generated: {datetime.now(timezone.utc).isoformat()}
Model: {logger._model_id}
Policy: {logger._policy_version}

COMPLETENESS VERIFICATION
Status: {'PASS' if result.is_valid else 'FAIL'}
Total Attempts: {result.total_attempts}
Total Outcomes: {result.total_outcomes}
Pending: {len(result.pending_attempts)}

STATISTICS
Denial Rate: {stats['denial_rate']*100:.2f}%
Error Rate: {stats['error_rate']*100:.2f}%

MERKLE ROOT
{logger.merkle_root}

DENIAL CATEGORIES
"""
for cat, count in stats['denial_categories'].items():
    report += f"  {cat}: {count}\n"

print(report)
```

---

## References

1. **EU AI Act**: Regulation (EU) 2024/1689
2. **Digital Services Act**: Regulation (EU) 2022/2065
3. **ISO/IEC DIS 24970:2025**: AI System Logging (Draft)
4. **MAS AI RMF**: Consultation Paper, November 2025
5. **NIST AI RMF**: AI 100-1 (January 2023)
6. **California AB 853**: AI Transparency Act (2024)
7. **MiFID II RTS 25**: Commission Delegated Regulation (EU) 2017/589

---

*© 2026 VeritasChain Standards Organization*  
*Document: VSO-DOC-CAPMAP-001*  
*Version: 1.0*
