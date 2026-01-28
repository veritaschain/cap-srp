"""
CAP-SRP Core Module

This module contains the core functionality for the Content Authenticity Protocol
Safe Refusal Provenance (CAP-SRP) system.

Submodules:
    - events: Event type definitions
    - logger: Main event logging functionality
    - signer: Ed25519 cryptographic signing
    - merkle: Merkle tree for inclusion proofs
    - verifier: Completeness and chain verification
"""

from cap_srp.core.events import (
    CAPEvent,
    EventType,
    RiskCategory,
    GenerationAttempt,
    GenerationSuccess,
    GenerationDenial,
    GenerationError,
    generate_event_id,
    hash_data,
    create_event_from_dict
)

from cap_srp.core.logger import CAPLogger, create_demo_logger

from cap_srp.core.signer import (
    Ed25519Signer,
    SignatureResult,
    VerificationResult,
    generate_key_pair,
    generate_key_pair_b64
)

from cap_srp.core.merkle import (
    MerkleTree,
    InclusionProof,
    ConsistencyProof,
    AnchoredMerkleRoot
)

from cap_srp.core.verifier import (
    CompletenessVerifier,
    ChainVerifier,
    MerkleVerifier,
    CompletenessResult,
    ChainVerificationResult,
    FullVerificationResult,
    full_verification
)

__all__ = [
    # Events
    "CAPEvent",
    "EventType",
    "RiskCategory",
    "GenerationAttempt",
    "GenerationSuccess",
    "GenerationDenial",
    "GenerationError",
    "generate_event_id",
    "hash_data",
    "create_event_from_dict",
    # Logger
    "CAPLogger",
    "create_demo_logger",
    # Signer
    "Ed25519Signer",
    "SignatureResult",
    "VerificationResult",
    "generate_key_pair",
    "generate_key_pair_b64",
    # Merkle
    "MerkleTree",
    "InclusionProof",
    "ConsistencyProof",
    "AnchoredMerkleRoot",
    # Verifier
    "CompletenessVerifier",
    "ChainVerifier",
    "MerkleVerifier",
    "CompletenessResult",
    "ChainVerificationResult",
    "FullVerificationResult",
    "full_verification",
]
