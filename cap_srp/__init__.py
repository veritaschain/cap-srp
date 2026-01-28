"""
CAP-SRP: Content Authenticity Protocol - Safe Refusal Provenance

Cryptographic proof that AI systems refused to generate harmful content.

This library provides:
- Event logging with Ed25519 signatures
- Hash chain integrity for tamper evidence
- Merkle tree proofs for efficient verification
- Completeness invariant verification
- Dashboard for compliance monitoring

Example:
    >>> from cap_srp import CAPLogger, EventType, RiskCategory
    >>> 
    >>> logger = CAPLogger()
    >>> 
    >>> # Log a generation attempt
    >>> attempt = logger.log_attempt(prompt_hash="sha256:abc123...")
    >>> 
    >>> # Log a denial
    >>> denial = logger.log_denial(
    ...     attempt_id=attempt.event_id,
    ...     risk_category=RiskCategory.NCII_RISK,
    ...     risk_score=0.94
    ... )
    >>> 
    >>> # Verify completeness
    >>> from cap_srp import CompletenessVerifier
    >>> verifier = CompletenessVerifier()
    >>> result = verifier.verify(logger.get_events())
    >>> print(f"Valid: {result.is_valid}")

License:
    Apache License 2.0

Copyright:
    2025-2026 VeritasChain Standards Organization
"""

__version__ = "0.1.0"
__author__ = "VeritasChain Standards Organization"
__email__ = "info@veritaschain.org"
__license__ = "Apache-2.0"

from cap_srp.core.events import (
    CAPEvent,
    EventType,
    RiskCategory,
    GenerationAttempt,
    GenerationSuccess,
    GenerationDenial,
    GenerationError,
)
from cap_srp.core.logger import CAPLogger
from cap_srp.core.signer import Ed25519Signer
from cap_srp.core.merkle import MerkleTree
from cap_srp.core.verifier import (
    CompletenessVerifier,
    ChainVerifier,
    CompletenessResult,
    ChainVerificationResult,
)

__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    # Events
    "CAPEvent",
    "EventType",
    "RiskCategory",
    "GenerationAttempt",
    "GenerationSuccess",
    "GenerationDenial",
    "GenerationError",
    # Core components
    "CAPLogger",
    "Ed25519Signer",
    "MerkleTree",
    # Verification
    "CompletenessVerifier",
    "ChainVerifier",
    "CompletenessResult",
    "ChainVerificationResult",
]
