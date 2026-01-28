# CAP-SRP Architecture

## Overview

CAP-SRP (Content Authenticity Protocol - Safe Refusal Provenance) provides cryptographic infrastructure for proving that AI systems refused to generate harmful content.

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
- Proves tree grew append-only

### 4. Completeness Invariant

The mathematical guarantee:

```
For any time window [t₀, t₁]:

    COUNT(GEN_ATTEMPT) = COUNT(GEN) + COUNT(GEN_DENY) + COUNT(GEN_ERROR)

If this equation fails:
    → Events have been added, removed, or modified
    → FRAUD DETECTED
```

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

| Property | Mechanism | Guarantee |
|----------|-----------|-----------|
| Integrity | Hash chain + signatures | Cannot modify without detection |
| Non-repudiation | Ed25519 signatures | Signer cannot deny signing |
| Temporal ordering | Hash chain + TSA | Events provably ordered |
| Completeness | Invariant check | Cannot hide events |
| Privacy | Hash-only storage | Prompts never stored |
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
