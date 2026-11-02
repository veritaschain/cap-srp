"""
CAP-SRP Event Definitions

This module defines the core event types for the Content / Creative AI Profile
Safe Refusal Provenance (CAP-SRP) system.

Event Types:
    - GEN_ATTEMPT: Logged when a generation request is received (BEFORE evaluation)
    - GEN: Logged when generation completes successfully
    - GEN_DENY: Logged when generation is refused due to safety concerns
    - GEN_ERROR: Logged when generation fails due to technical errors

The key innovation is the "Commitment Point" - logging GEN_ATTEMPT before
the safety evaluation ensures that:
1. Every request is recorded regardless of outcome
2. The Completeness Invariant can be verified:
   
   Σ ATTEMPT = Σ GEN + Σ DENY + Σ ERROR
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from dataclasses import dataclass, field, asdict, fields
import hashlib
import json
import math
import os
import secrets
import threading
import time
import uuid


class EventType(Enum):
    """Types of events in the CAP-SRP event stream."""
    
    GEN_ATTEMPT = "GEN_ATTEMPT"  # Generation attempt (commitment point)
    GEN = "GEN"                  # Successful generation
    GEN_DENY = "GEN_DENY"        # Generation denied (safety filter)
    GEN_ERROR = "GEN_ERROR"      # Generation failed (technical error)


class RiskCategory(Enum):
    """
    Risk categories for denied generations.
    
    Based on common AI safety policy violations and aligned with:
    - EU DSA illegal content definitions
    - EU AI Act high-risk classifications
    - Major AI provider content policies
    """
    
    # Sexual content risks
    NCII_RISK = "NCII_RISK"                        # Non-consensual intimate imagery
    CSAM_RISK = "CSAM_RISK"                        # Child sexual abuse material
    SEXUAL_EXPLICIT = "SEXUAL_EXPLICIT"            # Explicit sexual content
    
    # Deepfake and identity risks
    REAL_PERSON_DEEPFAKE = "REAL_PERSON_DEEPFAKE"  # Deepfakes of real people
    IDENTITY_FRAUD = "IDENTITY_FRAUD"              # Identity fraud/impersonation
    
    # Violence and harm
    VIOLENCE_GRAPHIC = "VIOLENCE_GRAPHIC"          # Graphic violence
    SELF_HARM = "SELF_HARM"                        # Self-harm promotion
    TERRORISM = "TERRORISM"                        # Terrorism-related content
    
    # Hate and discrimination
    HATE_CONTENT = "HATE_CONTENT"                  # Hate speech/imagery
    DISCRIMINATION = "DISCRIMINATION"              # Discriminatory content
    
    # Illegal activities
    ILLEGAL_ACTIVITY = "ILLEGAL_ACTIVITY"          # General illegal activities
    DRUG_RELATED = "DRUG_RELATED"                  # Drug-related content
    WEAPONS = "WEAPONS"                            # Weapons-related content
    
    # Misinformation
    MISINFORMATION = "MISINFORMATION"              # False information
    ELECTION_INTERFERENCE = "ELECTION_INTERFERENCE"  # Election manipulation
    
    # Privacy
    PRIVACY_VIOLATION = "PRIVACY_VIOLATION"        # Privacy violations
    PII_EXPOSURE = "PII_EXPOSURE"                  # Personal information exposure
    
    # Other
    COPYRIGHT_VIOLATION = "COPYRIGHT_VIOLATION"    # Copyright infringement
    SPAM = "SPAM"                                  # Spam/manipulation
    OTHER = "OTHER"                                # Other policy violations


_uuid_lock = threading.Lock()
_uuid_timestamp_ms = -1
_uuid_random = 0
_UUID_RANDOM_MAX = (1 << 74) - 1
_UUID_TIMESTAMP_MAX = (1 << 48) - 1


def _reset_uuid_state_after_fork() -> None:
    """A child must not inherit a locked mutex or its parent's counter."""
    global _uuid_lock, _uuid_timestamp_ms, _uuid_random
    _uuid_lock = threading.Lock()
    _uuid_timestamp_ms = -1
    _uuid_random = 0


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_uuid_state_after_fork)


def generate_event_id() -> str:
    """Generate a process-local monotonic UUIDv7 (RFC 9562 section 6.2).

    The 74 random bits form a randomly seeded counter. Calls within the same
    millisecond, or after a clock rollback, increment that counter under a
    lock. Counter exhaustion raises instead of wrapping or inventing time.
    Ordering is local to this process, not across restarts or machines. These
    identifiers are not secrets or trusted timestamps.
    """
    global _uuid_timestamp_ms, _uuid_random
    with _uuid_lock:
        timestamp_ms = time.time_ns() // 1_000_000
        if not 0 <= timestamp_ms <= _UUID_TIMESTAMP_MAX:
            raise ValueError("Clock is outside the UUIDv7 timestamp range")
        if timestamp_ms > _uuid_timestamp_ms:
            random_bits = secrets.randbits(74)
        else:
            timestamp_ms = _uuid_timestamp_ms
            if _uuid_random == _UUID_RANDOM_MAX:
                raise OverflowError("UUIDv7 counter exhausted; wait for the clock to advance")
            random_bits = _uuid_random + 1

        _uuid_timestamp_ms = timestamp_ms
        _uuid_random = random_bits
        uuid_int = timestamp_ms << 80
        uuid_int |= 0x7 << 76  # Version 7
        uuid_int |= (random_bits >> 62) << 64
        uuid_int |= 0x2 << 62  # RFC variant
        uuid_int |= random_bits & ((1 << 62) - 1)
        return str(uuid.UUID(int=uuid_int))


def hash_data(data: str) -> str:
    """
    Create a SHA-256 hash of the input data.
    
    Args:
        data: The string data to hash
        
    Returns:
        str: SHA-256 hash with 'sha256:' prefix
    """
    return f"sha256:{hashlib.sha256(data.encode()).hexdigest()}"


@dataclass
class CAPEvent:
    """
    Base class for all CAP-SRP events.
    
    All events share these common fields for chain integrity and verification.
    
    Attributes:
        event_id: Unique UUIDv7 identifier
        event_type: Type of event (GEN_ATTEMPT, GEN, GEN_DENY, GEN_ERROR)
        timestamp: ISO 8601 timestamp with timezone
        session_id: Session identifier for grouping related events
        model_id: Identifier for the AI model
        policy_version: Version of the safety policy in effect
        previous_hash: Hash of the previous event (chain linking)
        current_hash: Hash of this event's content
        signature: Ed25519 signature of current_hash
    """
    
    event_id: str = field(default_factory=generate_event_id)
    event_type: EventType = EventType.GEN_ATTEMPT
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id: str = ""
    model_id: str = ""
    policy_version: str = "v1.0.0"
    previous_hash: str = ""
    current_hash: str = ""
    signature: str = ""
    
    def compute_hash(self) -> str:
        """
        Compute the hash of this event's content.
        
        The hash includes all fields except current_hash and signature,
        ensuring the integrity of the event data.
        
        Returns:
            str: SHA-256 hash of the event content
        """
        # Create a dict excluding hash and signature fields
        content = {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "model_id": self.model_id,
            "policy_version": self.policy_version,
            "previous_hash": self.previous_hash,
        }
        
        # Add subclass-specific fields
        if hasattr(self, 'prompt_hash'):
            content["prompt_hash"] = self.prompt_hash
        if hasattr(self, 'user_context_hash'):
            content["user_context_hash"] = self.user_context_hash
        if hasattr(self, 'output_hash'):
            content["output_hash"] = self.output_hash
        if hasattr(self, 'attempt_id'):
            content["attempt_id"] = self.attempt_id
        if hasattr(self, 'risk_category'):
            content["risk_category"] = self.risk_category.value if self.risk_category else None
        if hasattr(self, 'risk_score'):
            content["risk_score"] = self.risk_score
        if hasattr(self, 'denial_reason'):
            content["denial_reason"] = self.denial_reason
        if hasattr(self, 'error_code'):
            content["error_code"] = self.error_code
        if hasattr(self, 'error_message'):
            content["error_message"] = self.error_message
        if hasattr(self, 'c2pa_manifest_id'):
            content["c2pa_manifest_id"] = self.c2pa_manifest_id
            
        # Canonical JSON serialization (sorted keys, no whitespace)
        canonical = json.dumps(content, sort_keys=True, separators=(',', ':'))
        return hash_data(canonical)
    
    def to_dict(self) -> dict:
        """Convert event to dictionary for serialization."""
        d = asdict(self)
        d['event_type'] = self.event_type.value
        if hasattr(self, 'risk_category') and self.risk_category:
            d['risk_category'] = self.risk_category.value
        return d
    
    def to_json(self) -> str:
        """Convert event to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class GenerationAttempt(CAPEvent):
    """
    Event logged when a generation request is received.
    
    This is the "Commitment Point" - it MUST be logged BEFORE the safety
    evaluation to ensure all requests are recorded regardless of outcome.
    
    Privacy Note: The prompt itself is NOT stored - only a hash of the prompt.
    This allows verification without exposing potentially sensitive content.
    
    Attributes:
        prompt_hash: SHA-256 hash of the original prompt
        user_context_hash: Hash of user context (optional, for privacy)
    """
    
    event_type: EventType = field(default=EventType.GEN_ATTEMPT)
    prompt_hash: str = ""
    user_context_hash: str = ""
    
    def __post_init__(self):
        if not self.event_id:
            self.event_id = generate_event_id()
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class GenerationSuccess(CAPEvent):
    """
    Event logged when generation completes successfully.
    
    Attributes:
        attempt_id: Reference to the corresponding GEN_ATTEMPT event
        output_hash: Hash of the generated content
        c2pa_manifest_id: Optional C2PA manifest identifier for the output
    """
    
    event_type: EventType = field(default=EventType.GEN)
    attempt_id: str = ""  # Links to the GEN_ATTEMPT event
    output_hash: str = ""
    c2pa_manifest_id: Optional[str] = None
    
    def __post_init__(self):
        if not self.event_id:
            self.event_id = generate_event_id()
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class GenerationDenial(CAPEvent):
    """
    Event logged when generation is refused due to safety concerns.
    
    This is the core of CAP-SRP's value proposition - cryptographic proof
    that the AI system refused to generate harmful content.
    
    Attributes:
        attempt_id: Reference to the corresponding GEN_ATTEMPT event
        risk_category: Category of detected risk
        risk_score: Confidence score (0.0 to 1.0)
        denial_reason: Machine-readable denial code
    """
    
    event_type: EventType = field(default=EventType.GEN_DENY)
    attempt_id: str = ""  # Links to the GEN_ATTEMPT event
    risk_category: Optional[RiskCategory] = None
    risk_score: float = 0.0
    denial_reason: str = ""
    
    def __post_init__(self):
        if not self.event_id:
            self.event_id = generate_event_id()
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class GenerationError(CAPEvent):
    """
    Event logged when generation fails due to technical errors.
    
    This is separate from GEN_DENY to distinguish between safety refusals
    and technical failures. Both contribute to the Completeness Invariant.
    
    Attributes:
        attempt_id: Reference to the corresponding GEN_ATTEMPT event
        error_code: Machine-readable error code
        error_message: Human-readable error description
    """
    
    event_type: EventType = field(default=EventType.GEN_ERROR)
    attempt_id: str = ""  # Links to the GEN_ATTEMPT event
    error_code: str = ""
    error_message: str = ""
    
    def __post_init__(self):
        if not self.event_id:
            self.event_id = generate_event_id()
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


def create_event_from_dict(data: dict) -> CAPEvent:
    """Restore the exact fields emitted by ``CAPEvent.to_dict()``.

    This is a serialized-record parser, not a convenience event constructor.
    Missing or unknown fields and invalid JSON value types raise ``ValueError``;
    no IDs, timestamps or signed fields are silently generated or discarded.
    Hash and signature authentication remain the verifier's responsibility.
    """
    if not isinstance(data, dict):
        raise ValueError("Event must be a JSON object")
    if not isinstance(data.get("event_type"), str):
        raise ValueError("event_type must be a string")
    event_type = EventType(data["event_type"])
    event_class = {
        EventType.GEN_ATTEMPT: GenerationAttempt,
        EventType.GEN: GenerationSuccess,
        EventType.GEN_DENY: GenerationDenial,
        EventType.GEN_ERROR: GenerationError,
    }[event_type]
    field_names = {item.name for item in fields(event_class)}
    if set(data) != field_names:
        raise ValueError("Event fields do not match the serialized event type")

    # Work on a copy: callers may retain the original JSON for hashing/audit.
    restored = data.copy()
    for name, value in data.items():
        if name == "risk_score":
            if type(value) not in (int, float) or not 0 <= value <= 1 or not math.isfinite(value):
                raise ValueError("risk_score must be a finite number between zero and one")
        elif name in ("risk_category", "c2pa_manifest_id") and value is None:
            continue
        elif not isinstance(value, str):
            raise ValueError(f"{name} must be a string")
    for name in ("event_id", "timestamp"):
        if not restored[name]:
            raise ValueError(f"{name} must not be empty")
    restored["event_type"] = event_type
    if "risk_category" in restored and restored["risk_category"] is not None:
        restored["risk_category"] = RiskCategory(restored["risk_category"])
    return event_class(**restored)
