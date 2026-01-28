# CAP-SRP: Refusal Provenance Dashboard

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![IETF Draft](https://img.shields.io/badge/IETF-draft--kamimura--scitt--vcp-green.svg)](https://datatracker.ietf.org/doc/draft-kamimura-scitt-vcp/)

**Cryptographic proof that AI systems refused to generate harmful content.**

> "When regulators ask for evidence that your AI's safety filters worked, 'trust us' is no longer an acceptable answer."

---

## 🎯 What This Solves

### The Problem

In January 2026, the EU Commission opened a formal investigation into X/Grok after the AI generated millions of non-consensual intimate images. When asked for evidence that safety systems worked, X could only offer internal logs—**self-reported, unverifiable, and potentially modified**.

Current AI systems face a fundamental accountability gap:

| Question | Current State | With CAP-SRP |
|----------|---------------|--------------|
| "Did your AI refuse this request?" | "Trust our logs" | Cryptographic proof |
| "Were all dangerous requests blocked?" | "We think so" | Completeness Invariant verification |
| "Can we independently verify?" | No | Yes, via Merkle proofs + external anchoring |
| "Has the log been modified?" | Unknown | Mathematically impossible without detection |

### The Solution

CAP-SRP (Content Authenticity Protocol - Safe Refusal Provenance) creates **tamper-evident, externally verifiable records** of every AI generation request and its outcome—whether approved, denied, or failed.

```
                    ┌─────────────────────────────────────────┐
                    │         COMPLETENESS INVARIANT          │
                    │                                         │
                    │   Σ ATTEMPTS = Σ GEN + Σ DENY + Σ ERROR │
                    │                                         │
                    │   If this equation fails, fraud detected│
                    └─────────────────────────────────────────┘
```

---

## ✨ Features

- **🔐 Cryptographic Signing**: Every event signed with Ed25519
- **⛓️ Hash Chain Integrity**: Tamper-evident linked records
- **🌳 Merkle Tree Proofs**: O(log n) verification of any event
- **⏰ External Anchoring**: RFC 3161 timestamp authority support
- **✅ Completeness Verification**: Mathematical proof that no events are missing
- **📊 Real-time Dashboard**: Visual compliance monitoring
- **🔍 Audit Trail Explorer**: Drill down into any decision
- **📋 Regulatory Reports**: One-click compliance documentation

---

## 🚀 Quick Start

### 1. Install

```bash
git clone https://github.com/veritaschain/cap-srp-dashboard.git
cd cap-srp-dashboard

python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -e ".[dev]"   # includes test/lint tools
```

### 2. Run Dashboard

```bash
streamlit run cap_srp/dashboard/app.py
# Open http://localhost:8501
```

### 3. Validate Schema

```bash
pytest -k schema          # schema validity + example validation
```

### 4. Generate Demo

```bash
python examples/demo_generate_events.py --events 1000 --output data/demo_events.json
```

### 5. Verify Completeness

```bash
python examples/demo_verify_completeness.py --input data/demo_events.json

# Or via CLI
cap-srp verify data/demo_events.json
```

---

## 📐 Architecture

### Event Types

```python
class EventType(Enum):
    GEN_ATTEMPT = "GEN_ATTEMPT"  # Request received (logged BEFORE evaluation)
    GEN = "GEN"                  # Generation completed successfully
    GEN_DENY = "GEN_DENY"        # Generation refused (safety filter triggered)
    GEN_ERROR = "GEN_ERROR"      # Generation failed (technical error)
```

### Risk Categories (for GEN_DENY events)

```python
class RiskCategory(Enum):
    NCII_RISK = "NCII_RISK"                    # Non-consensual intimate imagery
    CSAM_RISK = "CSAM_RISK"                    # Child sexual abuse material
    REAL_PERSON_DEEPFAKE = "REAL_PERSON_DEEPFAKE"  # Deepfakes of real people
    VIOLENCE_GRAPHIC = "VIOLENCE_GRAPHIC"      # Graphic violence
    HATE_CONTENT = "HATE_CONTENT"              # Hate speech/imagery
    SELF_HARM = "SELF_HARM"                    # Self-harm promotion
    ILLEGAL_ACTIVITY = "ILLEGAL_ACTIVITY"      # Illegal activities
    OTHER = "OTHER"                            # Other policy violations
```

### Event Structure

```json
{
  "event_id": "019478a1-b2c3-7def-8901-234567890abc",
  "event_type": "GEN_DENY",
  "timestamp": "2026-01-28T14:23:45.123456Z",
  "prompt_hash": "sha256:a1b2c3d4e5f6...",
  "user_context_hash": "sha256:f6e5d4c3b2a1...",
  "session_id": "sess_abc123",
  "risk_category": "NCII_RISK",
  "risk_score": 0.94,
  "policy_version": "v2.3.1",
  "model_id": "image-gen-v3",
  "previous_hash": "sha256:9876543210...",
  "signature": "ed25519:MEUCIQDx..."
}
```

### System Flow

```
User Request
     │
     ▼
┌─────────────────────────────────────────────────────────────┐
│                    CAP-SRP SIDECAR                          │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Step 1: Log GEN_ATTEMPT                             │   │
│  │         (Commitment Point - BEFORE evaluation)      │   │
│  └─────────────────────────────────────────────────────┘   │
│                         │                                   │
│                         ▼                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Step 2: Safety Evaluation                           │   │
│  │         ├── SAFE ────► Log GEN (output_hash)       │   │
│  │         ├── UNSAFE ──► Log GEN_DENY (risk_info)    │   │
│  │         └── ERROR ───► Log GEN_ERROR (error_info)  │   │
│  └─────────────────────────────────────────────────────┘   │
│                         │                                   │
│                         ▼                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Step 3: Chain Linking                               │   │
│  │         current_hash = SHA256(event + prev_hash)    │   │
│  │         signature = Ed25519.sign(current_hash)      │   │
│  └─────────────────────────────────────────────────────┘   │
│                         │                                   │
│                         ▼                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Step 4: Merkle Tree Update (periodic)               │   │
│  │         • Compute new Merkle root                   │   │
│  │         • Anchor to external TSA (RFC 3161)         │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔬 Completeness Invariant

The **Completeness Invariant** is the mathematical guarantee that no events have been added, removed, or modified:

```
For any time window [t₀, t₁]:

    COUNT(GEN_ATTEMPT) = COUNT(GEN) + COUNT(GEN_DENY) + COUNT(GEN_ERROR)
```

### Why This Matters

1. **No Hidden Generations**: Every `GEN` must have a corresponding `GEN_ATTEMPT`
2. **No Hidden Approvals**: Can't add fake "approvals" without the attempt record
3. **No Deleted Denials**: Can't remove denial records without breaking the equation
4. **Fraud Detection**: Any manipulation breaks the invariant

### Verification

```python
from cap_srp.core.verifier import CompletenessVerifier

verifier = CompletenessVerifier()
result = verifier.verify(events)

if result.is_valid:
    print(f"✅ Completeness verified: {result.total_attempts} events")
else:
    print(f"❌ Completeness violation detected!")
    print(f"   Expected: {result.expected_count}")
    print(f"   Actual: {result.actual_count}")
    print(f"   Missing: {result.missing_events}")
```

---

## 📊 Dashboard Screenshots

### Compliance Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  REFUSAL PROVENANCE DASHBOARD                                       │
│  ═══════════════════════════════════════════════════════════════    │
│                                                                     │
│  System: ImageGenAI-v3.2       Status: ✅ COMPLIANT                 │
│  Provider: Example Corp         Last Event: 2026-01-28 14:23:45    │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  COMPLETENESS VERIFICATION                                          │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                     │
│  Total Attempts: 1,247,893    [████████████████████] 100%          │
│  ├── Generated:    823,456    [█████████████░░░░░░░]  66%          │
│  ├── Denied:       419,234    [███████░░░░░░░░░░░░░]  34%          │
│  └── Errors:         5,203    [█░░░░░░░░░░░░░░░░░░░]  <1%          │
│                                                                     │
│  Invariant Status: ✅ VERIFIED (Σ = 1,247,893)                      │
│  Hash Chain: ✅ INTACT (2,847 blocks verified)                      │
│  External Anchor: ✅ TSA + 3 Witnesses                              │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Denial Breakdown

```
┌─────────────────────────────────────────────────────────────────────┐
│  DENIAL BREAKDOWN BY RISK CATEGORY                                  │
│  ═══════════════════════════════════════════════════════════════    │
│                                                                     │
│  NCII_RISK            [███████████████░░░░]  187,234  45%          │
│  CSAM_RISK            [███████░░░░░░░░░░░░]   92,108  22%          │
│  REAL_PERSON_DEEPFAKE [██████░░░░░░░░░░░░░]   71,456  17%          │
│  VIOLENCE_GRAPHIC     [███░░░░░░░░░░░░░░░░]   43,234  10%          │
│  OTHER                [██░░░░░░░░░░░░░░░░░]   25,202   6%          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📋 Regulatory Mapping

### EU AI Act Article 12

| Requirement | CAP-SRP Implementation |
|-------------|------------------------|
| Automatic event recording | All events logged automatically via sidecar |
| Risk situation identification | `risk_category` + `risk_score` fields |
| Post-market monitoring | Continuous event stream + periodic reports |
| Deployer monitoring | Dashboard + API access for oversight |
| Tamper-evident storage | Hash chain + Ed25519 signatures |
| 6+ month retention | External TSA anchoring for long-term proof |

### EU Digital Services Act (DSA)

| Requirement | CAP-SRP Implementation |
|-------------|------------------------|
| Systemic risk assessment | Denial pattern analysis + anomaly detection |
| Content moderation transparency | Public denial statistics (aggregated) |
| Audit access | Merkle proof export for independent verification |
| Documentation for enforcement | One-click regulatory report generation |

### California AI Transparency Act (AB 853)

| Requirement | CAP-SRP Implementation |
|-------------|------------------------|
| AI-generated content disclosure | `output_hash` + C2PA integration ready |
| Safety measure documentation | `policy_version` + denial reasoning |
| Audit trail maintenance | Complete event history with proofs |

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=cap_srp --cov-report=html

# Run specific test file
pytest tests/test_completeness.py -v
```

---

## 📁 Project Structure

```
cap-srp-dashboard/
├── README.md                 # This file
├── LICENSE                   # Apache 2.0 License
├── requirements.txt          # Python dependencies
├── setup.py                  # Package installation
├── pyproject.toml           # Modern Python packaging
├── .gitignore               # Git ignore rules
│
├── cap_srp/                  # Main package
│   ├── __init__.py
│   ├── core/                 # Core functionality
│   │   ├── __init__.py
│   │   ├── events.py        # Event type definitions
│   │   ├── logger.py        # Event logging with signatures
│   │   ├── signer.py        # Ed25519 cryptographic signing
│   │   ├── merkle.py        # Merkle tree implementation
│   │   └── verifier.py      # Completeness verification
│   │
│   ├── dashboard/            # Web dashboard
│   │   ├── __init__.py
│   │   └── app.py           # Streamlit dashboard
│   │
│   └── utils/                # Utilities
│       ├── __init__.py
│       └── helpers.py       # Helper functions
│
├── tests/                    # Test suite
│   ├── __init__.py
│   ├── test_events.py
│   ├── test_logger.py
│   ├── test_merkle.py
│   └── test_verifier.py
│
├── examples/                 # Example scripts
│   ├── demo_generate_events.py
│   └── demo_verify_completeness.py
│
├── docs/                     # Documentation
│   ├── ARCHITECTURE.md
│   ├── API.md
│   └── REGULATORY_MAPPING.md
│
└── data/                     # Sample data
    └── .gitkeep
```

---

## 🔗 Related Projects

- **[VCP Specification](https://github.com/veritaschain/vcp-spec)**: VeritasChain Protocol for algorithmic trading
- **[IETF SCITT](https://datatracker.ietf.org/wg/scitt/about/)**: Supply Chain Integrity, Transparency and Trust
- **[C2PA](https://c2pa.org/)**: Coalition for Content Provenance and Authenticity

---

## 📄 Standards Alignment

- **IETF draft-kamimura-scitt-vcp**: VCP as SCITT Profile
- **RFC 6962**: Certificate Transparency (Merkle tree inspiration)
- **RFC 3161**: Time-Stamp Protocol (external anchoring)
- **ISO/IEC 24970:2025**: AI System Logging (complementary standard)

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone with SSH
git clone git@github.com:veritaschain/cap-srp-dashboard.git

# Install development dependencies
pip install -e ".[dev]"

# Run pre-commit hooks
pre-commit install
```

---

## 📜 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

## 📧 Contact

- **Organization**: VeritasChain Standards Organization (VSO)
- **Email**: info@veritaschain.org
- **Website**: https://veritaschain.org
- **IETF Draft**: https://datatracker.ietf.org/doc/draft-kamimura-scitt-vcp/

---

## 🙏 Acknowledgments

This project builds upon:
- The IETF SCITT Working Group's foundational work on supply chain transparency
- Certificate Transparency (RFC 6962) concepts
- The broader AI safety and accountability community

---

*"Verify, Don't Trust" — VeritasChain Standards Organization*
