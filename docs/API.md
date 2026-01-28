# CAP-SRP API Reference

Complete API documentation for the CAP-SRP library.

## Table of Contents

- [Core Module](#core-module)
  - [CAPLogger](#caplogger)
  - [Event Types](#event-types)
  - [Signer](#signer)
  - [Merkle Tree](#merkle-tree)
  - [Verifier](#verifier)
- [Dashboard Module](#dashboard-module)
- [Utilities](#utilities)

---

## Core Module

### CAPLogger

The main event logging class for CAP-SRP.

```python
from cap_srp import CAPLogger

logger = CAPLogger(
    private_key=None,       # Optional: Ed25519 private key (32 bytes)
    model_id="default",     # Model identifier
    policy_version="v1.0.0" # Policy version string
)
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `events` | `List[CAPEvent]` | Copy of all logged events |
| `event_count` | `int` | Number of logged events |
| `merkle_root` | `Optional[str]` | Current Merkle root (hex) |
| `public_key` | `str` | Signer's public key (base64) |

#### Methods

##### `log_attempt()`

Log a generation attempt (commitment point).

```python
attempt = logger.log_attempt(
    prompt_hash: str,           # SHA-256 hash of the prompt
    session_id: str = "",       # Session identifier
    user_context_hash: str = "", # Optional user context hash
    model_id: str = None,       # Override default model
    policy_version: str = None  # Override default policy
) -> GenerationAttempt
```

##### `log_generation()`

Log a successful generation.

```python
success = logger.log_generation(
    attempt_id: str,            # Reference to GEN_ATTEMPT
    output_hash: str,           # Hash of generated content
    c2pa_manifest_id: str = None, # Optional C2PA manifest
    session_id: str = "",
    model_id: str = None,
    policy_version: str = None
) -> GenerationSuccess
```

##### `log_denial()`

Log a generation denial.

```python
denial = logger.log_denial(
    attempt_id: str,            # Reference to GEN_ATTEMPT
    risk_category: RiskCategory, # Category of detected risk
    risk_score: float = 0.0,    # Confidence (0.0-1.0)
    denial_reason: str = "",    # Machine-readable reason
    session_id: str = "",
    model_id: str = None,
    policy_version: str = None
) -> GenerationDenial
```

##### `log_error()`

Log a generation error.

```python
error = logger.log_error(
    attempt_id: str,            # Reference to GEN_ATTEMPT
    error_code: str,            # Machine-readable error code
    error_message: str = "",    # Human-readable message
    session_id: str = "",
    model_id: str = None,
    policy_version: str = None
) -> GenerationError
```

##### `get_inclusion_proof()`

Get a Merkle inclusion proof for an event.

```python
proof = logger.get_inclusion_proof(
    event_index: int  # Index of the event
) -> InclusionProof
```

##### `get_statistics()`

Get statistics about the event log.

```python
stats = logger.get_statistics() -> Dict[str, Any]

# Returns:
{
    "total_events": int,
    "attempts": int,
    "generations": int,
    "denials": int,
    "errors": int,
    "denial_rate": float,
    "error_rate": float,
    "denial_categories": Dict[str, int],
    "completeness": {
        "is_complete": bool,
        "attempts": int,
        "outcomes": int,
        "pending": int
    },
    "merkle_root": str,
    "merkle_size": int
}
```

##### `export_events()` / `import_events()`

Export/import events to/from JSON file.

```python
logger.export_events("events.json")
logger.import_events("events.json")
```

---

### Event Types

#### EventType Enum

```python
from cap_srp import EventType

EventType.GEN_ATTEMPT  # Generation attempt (commitment point)
EventType.GEN          # Successful generation
EventType.GEN_DENY     # Generation denied
EventType.GEN_ERROR    # Generation error
```

#### RiskCategory Enum

```python
from cap_srp import RiskCategory

# Sexual content risks
RiskCategory.NCII_RISK           # Non-consensual intimate imagery
RiskCategory.CSAM_RISK           # Child sexual abuse material
RiskCategory.SEXUAL_EXPLICIT     # Explicit sexual content

# Deepfake and identity risks
RiskCategory.REAL_PERSON_DEEPFAKE
RiskCategory.IDENTITY_FRAUD

# Violence and harm
RiskCategory.VIOLENCE_GRAPHIC
RiskCategory.SELF_HARM
RiskCategory.TERRORISM

# Hate and discrimination
RiskCategory.HATE_CONTENT
RiskCategory.DISCRIMINATION

# Illegal activities
RiskCategory.ILLEGAL_ACTIVITY
RiskCategory.DRUG_RELATED
RiskCategory.WEAPONS

# Misinformation
RiskCategory.MISINFORMATION
RiskCategory.ELECTION_INTERFERENCE

# Privacy
RiskCategory.PRIVACY_VIOLATION
RiskCategory.PII_EXPOSURE

# Other
RiskCategory.COPYRIGHT_VIOLATION
RiskCategory.SPAM
RiskCategory.OTHER
```

#### Event Classes

##### GenerationAttempt

```python
@dataclass
class GenerationAttempt(CAPEvent):
    event_type: EventType = EventType.GEN_ATTEMPT
    prompt_hash: str = ""
    user_context_hash: str = ""
```

##### GenerationSuccess

```python
@dataclass
class GenerationSuccess(CAPEvent):
    event_type: EventType = EventType.GEN
    attempt_id: str = ""
    output_hash: str = ""
    c2pa_manifest_id: Optional[str] = None
```

##### GenerationDenial

```python
@dataclass
class GenerationDenial(CAPEvent):
    event_type: EventType = EventType.GEN_DENY
    attempt_id: str = ""
    risk_category: Optional[RiskCategory] = None
    risk_score: float = 0.0
    denial_reason: str = ""
```

##### GenerationError

```python
@dataclass
class GenerationError(CAPEvent):
    event_type: EventType = EventType.GEN_ERROR
    attempt_id: str = ""
    error_code: str = ""
    error_message: str = ""
```

---

### Signer

Ed25519 digital signature functionality.

```python
from cap_srp import Ed25519Signer

# Create with new key pair
signer = Ed25519Signer()

# Create from existing private key
signer = Ed25519Signer(private_key=bytes)
signer = Ed25519Signer.from_private_key_b64(base64_string)
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `public_key` | `bytes` | 32-byte public key |
| `public_key_b64` | `str` | Base64-encoded public key |
| `private_key` | `bytes` | 32-byte private key |
| `private_key_b64` | `str` | Base64-encoded private key |

#### Methods

```python
# Sign data
result = signer.sign(data: bytes) -> SignatureResult
result = signer.sign_string(data: str) -> SignatureResult

# Verify signature
result = signer.verify(data: bytes, signature: bytes) -> VerificationResult
result = signer.verify_b64(data: bytes, signature_b64: str) -> VerificationResult

# Static verification with public key
result = Ed25519Signer.verify_with_public_key(
    data: bytes,
    signature: bytes,
    public_key: bytes
) -> VerificationResult
```

---

### Merkle Tree

RFC 6962-compatible Merkle tree implementation.

```python
from cap_srp import MerkleTree, InclusionProof

tree = MerkleTree()
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `size` | `int` | Number of leaves |
| `root` | `Optional[str]` | Root hash (hex) |
| `root_bytes` | `Optional[bytes]` | Root hash (bytes) |

#### Methods

```python
# Add leaf
index = tree.add_leaf(leaf_hash: str) -> int
index = tree.add_leaf_bytes(leaf_data: bytes) -> int

# Get inclusion proof
proof = tree.get_inclusion_proof(index: int) -> InclusionProof

# Verify proof (static method)
is_valid = MerkleTree.verify_inclusion_proof(
    leaf_hash: str,
    proof: InclusionProof,
    expected_root: str
) -> bool

# Serialization
tree.to_dict() -> dict
tree.to_json() -> str

# Create from existing leaves
tree = MerkleTree.from_leaves(leaf_hashes: List[str])
```

#### InclusionProof

```python
@dataclass
class InclusionProof:
    leaf_index: int
    leaf_hash: str
    proof_hashes: List[str]
    proof_directions: List[int]  # 0=left, 1=right
    tree_size: int
    root_hash: str
    
    def to_dict() -> dict
    def to_json() -> str
```

---

### Verifier

Verification functionality for completeness and chain integrity.

#### CompletenessVerifier

```python
from cap_srp import CompletenessVerifier

verifier = CompletenessVerifier()
result = verifier.verify(events: List[CAPEvent]) -> CompletenessResult
```

##### CompletenessResult

```python
@dataclass
class CompletenessResult:
    is_valid: bool
    total_attempts: int
    total_generations: int
    total_denials: int
    total_errors: int
    pending_attempts: List[str]
    orphan_outcomes: List[str]
    duplicate_outcomes: List[str]
    error_message: Optional[str]
    
    @property
    def total_outcomes(self) -> int
    
    @property
    def denial_rate(self) -> float
```

#### ChainVerifier

```python
from cap_srp import ChainVerifier

verifier = ChainVerifier(public_key: Optional[str] = None)
result = verifier.verify(
    events: List[CAPEvent],
    verify_signatures: bool = True
) -> ChainVerificationResult
```

##### ChainVerificationResult

```python
@dataclass
class ChainVerificationResult:
    is_valid: bool
    events_verified: int
    first_invalid_index: Optional[int]
    error_message: Optional[str]
    invalid_hashes: List[Tuple[int, str, str]]
    invalid_signatures: List[int]
```

#### Full Verification

```python
from cap_srp import full_verification

result = full_verification(
    events: List[CAPEvent],
    public_key: Optional[str] = None,
    expected_merkle_root: Optional[str] = None
) -> FullVerificationResult
```

---

## Dashboard Module

Launch the Streamlit dashboard:

```python
from cap_srp.dashboard import main
main()
```

Or from command line:

```bash
python -m cap_srp.dashboard.app
# or
streamlit run cap_srp/dashboard/app.py
```

---

## Utilities

### Helper Functions

```python
from cap_srp.utils import (
    hash_prompt,
    hash_content,
    format_timestamp,
    parse_timestamp,
    generate_session_id
)

# Hash a prompt (with optional salt)
hash_prompt("user prompt", salt="optional") -> str

# Hash binary content
hash_content(b"binary data") -> str

# Format/parse timestamps
format_timestamp() -> str  # Current UTC time
format_timestamp(datetime_obj) -> str
parse_timestamp("2026-01-28T12:00:00Z") -> datetime

# Generate session ID
generate_session_id() -> str  # "sess_abc123def456"
generate_session_id("custom") -> str  # "custom_abc123def456"
```

---

## Error Handling

All verification methods return result objects with `is_valid` boolean and `error_message` for details. They do not raise exceptions for verification failures.

```python
result = verifier.verify(events)
if not result.is_valid:
    print(f"Verification failed: {result.error_message}")
```

Exceptions are raised for:
- Invalid parameters (ValueError)
- Missing required fields (ValueError)
- Duplicate outcomes for same attempt (ValueError)
- Index out of range (IndexError)

---

## Thread Safety

`CAPLogger` uses a reentrant lock (`threading.RLock`) for all public methods. Multiple threads can safely log events concurrently.

```python
import threading

logger = CAPLogger()

def worker(thread_id):
    for i in range(100):
        attempt = logger.log_attempt(
            prompt_hash=hash_data(f"thread_{thread_id}_prompt_{i}")
        )
        logger.log_generation(
            attempt_id=attempt.event_id,
            output_hash=hash_data(f"thread_{thread_id}_output_{i}")
        )

threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()

# All events properly logged and chain intact
```

---

## Version Compatibility

- Python 3.10+
- Compatible with both PyNaCl and cryptography libraries
- JSON serialization follows RFC 8259
- Timestamps follow ISO 8601 with timezone
- UUIDs follow RFC 4122 (UUIDv7 for ordering)

---

*© 2026 VeritasChain Standards Organization*
