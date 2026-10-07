# CAP-SRP Architecture

## Overview

CAP-SRP (Content / Creative AI Profile - Safe Refusal Provenance) demonstrates tamper-evident records of reported refusal decisions. See the [README](../README.md) for canonical CAP/VAP status and proof limits. External anchoring below is an integration target, not an implemented end-to-end path.

## Core Components

### 1. Event System

```
┌─────────────────────────────────────────────────────────────────────┐
│                         EVENT TYPES                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  GEN_ATTEMPT ─────────────────────────────────────────────────────  │
│  │  • Logged BEFORE safety evaluation (Commitment Point)           │
│  │  • Contains: prompt_hash, user_context_hash, timestamp           │
│  │  • Purpose: Ensures every request is recorded                    │
│  │                                                                  │
│  ├──► GEN ────────────────────────────────────────────────────────  │
│  │    • Logged when generation succeeds                             │
│  │    • Contains: output_hash, c2pa_manifest_id                     │
│  │                                                                  │
│  ├──► GEN_DENY ───────────────────────────────────────────────────  │
│  │    • Logged when safety filter blocks generation                 │
│  │    • Contains: risk_category, risk_score, denial_reason          │
│  │    • Core value proposition of CAP-SRP                           │
│  │                                                                  │
│  └──► GEN_ERROR ──────────────────────────────────────────────────  │
│       • Logged when technical error occurs                          │
│       • Contains: error_code, error_message                         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 2. Hash Chain

Every event is linked to the previous event via cryptographic hashing:

```
Event 1                 Event 2                 Event 3
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ previous_hash:  │    │ previous_hash:  │    │ previous_hash:  │
│ "" (genesis)    │    │ hash(Event 1)   │    │ hash(Event 2)   │
│                 │    │                 │    │                 │
│ current_hash:   │───►│ current_hash:   │───►│ current_hash:   │
│ hash(content)   │    │ hash(content)   │    │ hash(content)   │
│                 │    │                 │    │                 │
│ signature:      │    │ signature:      │    │ signature:      │
│ Ed25519(hash)   │    │ Ed25519(hash)   │    │ Ed25519(hash)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

**Properties:**
- Any modification changes all subsequent hashes
- Signatures prevent event forgery
- Chain proves temporal ordering

### 3. Merkle Tree

Events are organized into a Merkle tree for efficient verification:

```
                    ┌─────────────────┐
                    │   Merkle Root   │
                    │    (anchor)     │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
        ┌─────┴─────┐                 ┌─────┴─────┐
        │  H(01)    │                 │  H(23)    │
        └─────┬─────┘                 └─────┬─────┘
              │                             │
        ┌─────┴─────┐                 ┌─────┴─────┐
        │           │                 │           │
    ┌───┴───┐   ┌───┴───┐        ┌───┴───┐   ┌───┴───┐
    │Event 0│   │Event 1│        │Event 2│   │Event 3│
    └───────┘   └───────┘        └───────┘   └───────┘
```

**Verification Properties:**
- O(log n) proof size for any event
- Root can be externally anchored (TSA, blockchain)
- Inclusion proofs alone do not prove append-only growth or full-batch completeness

### 4. Completeness Invariant

For a closed set of recorded attempts:

```text
COUNT(GEN_ATTEMPT) = COUNT(GEN) + COUNT(GEN_DENY) + COUNT(GEN_ERROR)
```

Match outcomes by attempt ID; counts alone are insufficient. Pending attempts and
cross-boundary outcomes can cause mismatches without fraud. The PoC checks local
records. Independent completeness requires authenticated anchors and batch scope;
pre-measurement drops and uncommitted paired omissions remain outside the claim.

## Data Flow

```
                                USER REQUEST
                                     │
                                     ▼
┌────────────────────────────────────────────────────────────────────────┐
│                          AI SYSTEM                                      │
│                                                                         │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │                     CAP-SRP SIDECAR                             │  │
│   │                                                                 │  │
│   │  ┌──────────────────────────────────────────────────────────┐  │  │
│   │  │ 1. COMMITMENT POINT                                      │  │  │
│   │  │    • Hash prompt (privacy preserving)                    │  │  │
│   │  │    • Log GEN_ATTEMPT                                     │  │  │
│   │  │    • Sign with Ed25519                                   │  │  │
│   │  │    • Add to hash chain                                   │  │  │
│   │  └──────────────────────────────────────────────────────────┘  │  │
│   │                            │                                    │  │
│   │                            ▼                                    │  │
│   │  ┌──────────────────────────────────────────────────────────┐  │  │
│   │  │ 2. SAFETY EVALUATION                                     │  │  │
│   │  │    • Run through safety classifiers                      │  │  │
│   │  │    • Determine risk category and score                   │  │  │
│   │  └──────────────────────────────────────────────────────────┘  │  │
│   │                            │                                    │  │
│   │             ┌──────────────┼──────────────┐                    │  │
│   │             ▼              ▼              ▼                    │  │
│   │         ┌───────┐    ┌──────────┐   ┌──────────┐              │  │
│   │         │ SAFE  │    │  UNSAFE  │   │  ERROR   │              │  │
│   │         └───┬───┘    └────┬─────┘   └────┬─────┘              │  │
│   │             │             │              │                     │  │
│   │             ▼             ▼              ▼                     │  │
│   │  ┌──────────────┐ ┌─────────────┐ ┌─────────────┐             │  │
│   │  │ 3a. Log GEN  │ │3b. Log DENY │ │3c. Log ERROR│             │  │
│   │  │ output_hash  │ │risk_category│ │ error_code  │             │  │
│   │  │ c2pa_id      │ │ risk_score  │ │ message     │             │  │
│   │  └──────────────┘ └─────────────┘ └─────────────┘             │  │
│   │                            │                                    │  │
│   │                            ▼                                    │  │
│   │  ┌──────────────────────────────────────────────────────────┐  │  │
│   │  │ 4. MERKLE TREE UPDATE                                    │  │  │
│   │  │    • Add event hash as leaf                              │  │  │
│   │  │    • Recompute Merkle root                               │  │  │
│   │  │    • Periodically anchor to TSA                          │  │  │
│   │  └──────────────────────────────────────────────────────────┘  │  │
│   │                                                                 │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
└────────────────────────────────────────────────────────────────────────┘
```

## Cryptographic Primitives

### Ed25519 Signatures

- **Algorithm**: EdDSA with Curve25519
- **Key Size**: 32 bytes (private), 32 bytes (public)
- **Signature Size**: 64 bytes
- **Why**: Fast, deterministic, widely supported (RFC 8032)

### SHA-256 Hashing

- **Leaf Hash**: `SHA256(0x00 || data)`
- **Node Hash**: `SHA256(0x01 || left || right)`
- **Why**: 0x00/0x01 prefix prevents second-preimage attacks

### RFC 3161 Timestamp Authority

- **Purpose**: External time proof
- **Integration**: Periodic Merkle root anchoring
- **Why**: Proves log state at specific time, even if keys compromised later

## Security Properties

| Property | Mechanism | Scope / limitation |
|----------|-----------|-----------|
| Integrity | Hash chain + signatures | Detects inconsistency against verified records/commitments; not producer truth |
| Non-repudiation | Ed25519 signatures | Attribution to a separately authenticated signing key |
| Temporal ordering | Hash chain + TSA | Recorded order; external TSA path requires separate implementation |
| Completeness | Invariant check | Supplied attempt/outcome consistency only; pre-measurement drops undetectable |
| Privacy | Hash-only storage | Prompt hashes can remain linkable; free-text metadata needs privacy review |
| Verifiability | Merkle proofs | Third parties can verify |

## Integration Patterns

### Sidecar Pattern

```
┌─────────────────┐      ┌─────────────────┐
│   AI System     │      │  CAP-SRP        │
│                 │      │  Sidecar        │
│  ┌───────────┐  │      │                 │
│  │ Generate  │──┼──────┼─► Log Events   │
│  │ Endpoint  │  │      │                 │
│  └───────────┘  │      │  ┌───────────┐  │
│                 │      │  │ Event     │  │
│  ┌───────────┐  │      │  │ Store     │  │
│  │ Safety    │──┼──────┼─►└───────────┘  │
│  │ Filter    │  │      │                 │
│  └───────────┘  │      │  ┌───────────┐  │
│                 │      │  │ Merkle    │  │
└─────────────────┘      │  │ Tree      │  │
                         │  └───────────┘  │
                         └─────────────────┘
```

### API Integration

```python
from cap_srp import CAPLogger, RiskCategory

# Initialize once
logger = CAPLogger(model_id="your-model-v1")

# In your generation endpoint
def generate(prompt: str, user_id: str):
    # 1. Commitment point (BEFORE safety check)
    attempt = logger.log_attempt(
        prompt_hash=hash(prompt),
        user_context_hash=hash(user_id)
    )
    
    # 2. Safety evaluation
    risk = evaluate_safety(prompt)
    
    if risk.is_safe:
        # 3a. Generate and log success
        output = model.generate(prompt)
        logger.log_generation(
            attempt_id=attempt.event_id,
            output_hash=hash(output)
        )
        return output
    else:
        # 3b. Log denial
        logger.log_denial(
            attempt_id=attempt.event_id,
            risk_category=risk.category,
            risk_score=risk.score
        )
        return RefusalResponse()
```

## Standards Alignment

- **IETF SCITT**: Supply Chain Integrity, Transparency and Trust
- **RFC 6962**: Certificate Transparency (Merkle tree design)
- **RFC 3161**: Time-Stamp Protocol (external anchoring)
- **RFC 8032**: Ed25519 signatures
- **ISO/IEC 24970:2025**: AI System Logging (complementary)
- **EU AI Act Article 12**: Record-keeping requirements

## Future Extensions

1. **Post-Quantum Cryptography**: Migration path to Dilithium signatures
2. **Multi-Log Transparency**: Multiple independent witnesses
3. **Zero-Knowledge Proofs**: Prove denial without revealing category
4. **Regulatory APIs**: Direct feeds to supervisory authorities
