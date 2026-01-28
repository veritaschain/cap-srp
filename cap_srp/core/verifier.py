"""
CAP-SRP Verification Module

This module provides verification functionality for CAP-SRP event logs:
1. Completeness Verification - ensures ATTEMPTS = GENERATIONS + DENIALS + ERRORS
2. Chain Verification - ensures hash chain integrity
3. Signature Verification - verifies Ed25519 signatures
4. Merkle Proof Verification - verifies inclusion proofs

The Completeness Invariant is the core mathematical guarantee that makes
CAP-SRP valuable for regulatory compliance:

    For any time window [t₀, t₁]:
    COUNT(GEN_ATTEMPT) = COUNT(GEN) + COUNT(GEN_DENY) + COUNT(GEN_ERROR)

If this equation fails, it proves that events have been added, removed, or
modified - providing mathematical fraud detection.

Usage:
    >>> from cap_srp.core.verifier import CompletenessVerifier, ChainVerifier
    >>> 
    >>> # Verify completeness
    >>> completeness_verifier = CompletenessVerifier()
    >>> result = completeness_verifier.verify(events)
    >>> print(f"Complete: {result.is_valid}")
    >>> 
    >>> # Verify chain integrity
    >>> chain_verifier = ChainVerifier()
    >>> result = chain_verifier.verify(events)
    >>> print(f"Chain intact: {result.is_valid}")
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple
from datetime import datetime

from cap_srp.core.events import (
    CAPEvent,
    EventType,
    RiskCategory,
    GenerationAttempt,
    GenerationSuccess,
    GenerationDenial,
    GenerationError,
    hash_data
)
from cap_srp.core.signer import Ed25519Signer
from cap_srp.core.merkle import MerkleTree, InclusionProof


@dataclass
class CompletenessResult:
    """
    Result of a completeness verification.
    
    Attributes:
        is_valid: True if the completeness invariant holds
        total_attempts: Number of GEN_ATTEMPT events
        total_generations: Number of GEN events
        total_denials: Number of GEN_DENY events
        total_errors: Number of GEN_ERROR events
        pending_attempts: Attempt IDs without corresponding outcomes
        orphan_outcomes: Outcome IDs without corresponding attempts
        error_message: Description of any issues found
    """
    is_valid: bool
    total_attempts: int = 0
    total_generations: int = 0
    total_denials: int = 0
    total_errors: int = 0
    pending_attempts: List[str] = field(default_factory=list)
    orphan_outcomes: List[str] = field(default_factory=list)
    duplicate_outcomes: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    
    @property
    def total_outcomes(self) -> int:
        """Total number of outcome events (GEN + DENY + ERROR)."""
        return self.total_generations + self.total_denials + self.total_errors
    
    @property
    def denial_rate(self) -> float:
        """Rate of denials among completed attempts."""
        if self.total_outcomes == 0:
            return 0.0
        return self.total_denials / self.total_outcomes
    
    def to_dict(self) -> dict:
        return {
            "is_valid": self.is_valid,
            "total_attempts": self.total_attempts,
            "total_generations": self.total_generations,
            "total_denials": self.total_denials,
            "total_errors": self.total_errors,
            "total_outcomes": self.total_outcomes,
            "pending_attempts": len(self.pending_attempts),
            "orphan_outcomes": len(self.orphan_outcomes),
            "duplicate_outcomes": len(self.duplicate_outcomes),
            "denial_rate": self.denial_rate,
            "error_message": self.error_message
        }


@dataclass
class ChainVerificationResult:
    """
    Result of a hash chain verification.
    
    Attributes:
        is_valid: True if the entire chain is valid
        events_verified: Number of events successfully verified
        first_invalid_index: Index of first invalid event (if any)
        error_message: Description of any issues found
        invalid_hashes: List of (index, expected, actual) tuples for invalid hashes
        invalid_signatures: List of indices with invalid signatures
    """
    is_valid: bool
    events_verified: int = 0
    first_invalid_index: Optional[int] = None
    error_message: Optional[str] = None
    invalid_hashes: List[Tuple[int, str, str]] = field(default_factory=list)
    invalid_signatures: List[int] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "is_valid": self.is_valid,
            "events_verified": self.events_verified,
            "first_invalid_index": self.first_invalid_index,
            "error_message": self.error_message,
            "invalid_hash_count": len(self.invalid_hashes),
            "invalid_signature_count": len(self.invalid_signatures)
        }


class CompletenessVerifier:
    """
    Verifies the Completeness Invariant for CAP-SRP event logs.
    
    The Completeness Invariant states:
        COUNT(GEN_ATTEMPT) = COUNT(GEN) + COUNT(GEN_DENY) + COUNT(GEN_ERROR)
    
    This is verified by:
    1. Counting all GEN_ATTEMPT events
    2. Counting all outcome events (GEN, GEN_DENY, GEN_ERROR)
    3. Matching each outcome to its corresponding attempt
    4. Identifying any orphan outcomes or pending attempts
    """
    
    def verify(self, events: List[CAPEvent]) -> CompletenessResult:
        """
        Verify the completeness invariant for a list of events.
        
        Args:
            events: List of CAP events to verify
            
        Returns:
            CompletenessResult: Detailed verification result
        """
        # Collect attempt IDs
        attempt_ids: Set[str] = set()
        attempts: List[GenerationAttempt] = []
        
        # Collect outcome events and their attempt references
        outcomes: Dict[str, List[CAPEvent]] = {}  # attempt_id -> [outcomes]
        
        generations = 0
        denials = 0
        errors = 0
        
        for event in events:
            if event.event_type == EventType.GEN_ATTEMPT:
                attempt_ids.add(event.event_id)
                attempts.append(event)
            
            elif event.event_type == EventType.GEN:
                generations += 1
                attempt_id = event.attempt_id
                if attempt_id not in outcomes:
                    outcomes[attempt_id] = []
                outcomes[attempt_id].append(event)
            
            elif event.event_type == EventType.GEN_DENY:
                denials += 1
                attempt_id = event.attempt_id
                if attempt_id not in outcomes:
                    outcomes[attempt_id] = []
                outcomes[attempt_id].append(event)
            
            elif event.event_type == EventType.GEN_ERROR:
                errors += 1
                attempt_id = event.attempt_id
                if attempt_id not in outcomes:
                    outcomes[attempt_id] = []
                outcomes[attempt_id].append(event)
        
        # Find orphan outcomes (outcomes without corresponding attempts)
        orphan_outcomes = []
        for attempt_id in outcomes.keys():
            if attempt_id not in attempt_ids:
                orphan_outcomes.append(attempt_id)
        
        # Find pending attempts (attempts without outcomes)
        outcome_attempt_ids = set(outcomes.keys())
        pending_attempts = [aid for aid in attempt_ids if aid not in outcome_attempt_ids]
        
        # Find duplicate outcomes (multiple outcomes for same attempt)
        duplicate_outcomes = []
        for attempt_id, outcome_list in outcomes.items():
            if len(outcome_list) > 1:
                duplicate_outcomes.append(attempt_id)
        
        # Determine validity
        total_attempts = len(attempts)
        total_outcomes = generations + denials + errors
        
        is_valid = (
            total_attempts == total_outcomes and
            len(orphan_outcomes) == 0 and
            len(duplicate_outcomes) == 0
        )
        
        error_message = None
        if not is_valid:
            issues = []
            if total_attempts != total_outcomes:
                issues.append(f"Count mismatch: {total_attempts} attempts vs {total_outcomes} outcomes")
            if orphan_outcomes:
                issues.append(f"{len(orphan_outcomes)} orphan outcomes found")
            if duplicate_outcomes:
                issues.append(f"{len(duplicate_outcomes)} duplicate outcomes found")
            if pending_attempts:
                issues.append(f"{len(pending_attempts)} pending attempts")
            error_message = "; ".join(issues)
        
        return CompletenessResult(
            is_valid=is_valid,
            total_attempts=total_attempts,
            total_generations=generations,
            total_denials=denials,
            total_errors=errors,
            pending_attempts=pending_attempts,
            orphan_outcomes=orphan_outcomes,
            duplicate_outcomes=duplicate_outcomes,
            error_message=error_message
        )
    
    def verify_window(
        self,
        events: List[CAPEvent],
        start_time: datetime,
        end_time: datetime
    ) -> CompletenessResult:
        """
        Verify completeness for events within a time window.
        
        Args:
            events: List of all events
            start_time: Start of the verification window
            end_time: End of the verification window
            
        Returns:
            CompletenessResult: Verification result for the window
        """
        # Filter events by timestamp
        filtered_events = []
        for event in events:
            event_time = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
            if start_time <= event_time <= end_time:
                filtered_events.append(event)
        
        return self.verify(filtered_events)


class ChainVerifier:
    """
    Verifies the hash chain integrity of CAP-SRP event logs.
    
    Verification includes:
    1. Hash continuity - each event's previous_hash matches prior event's current_hash
    2. Hash correctness - each event's current_hash is correctly computed
    3. Signature validity - each event's signature is valid for its hash
    """
    
    def __init__(self, public_key: Optional[str] = None):
        """
        Initialize the chain verifier.
        
        Args:
            public_key: Base64-encoded public key for signature verification.
                       If not provided, signature verification is skipped.
        """
        self._public_key = public_key
    
    def verify(
        self,
        events: List[CAPEvent],
        verify_signatures: bool = True
    ) -> ChainVerificationResult:
        """
        Verify the hash chain integrity.
        
        Args:
            events: List of events to verify (must be in order)
            verify_signatures: Whether to verify Ed25519 signatures
            
        Returns:
            ChainVerificationResult: Detailed verification result
        """
        if not events:
            return ChainVerificationResult(is_valid=True, events_verified=0)
        
        invalid_hashes = []
        invalid_signatures = []
        previous_hash = ""
        
        for i, event in enumerate(events):
            # Verify previous_hash chain link
            if event.previous_hash != previous_hash:
                invalid_hashes.append((
                    i,
                    f"Expected previous_hash: {previous_hash[:16]}...",
                    f"Got: {event.previous_hash[:16]}..." if event.previous_hash else "empty"
                ))
            
            # Verify current_hash computation
            computed_hash = event.compute_hash()
            if event.current_hash != computed_hash:
                invalid_hashes.append((
                    i,
                    f"Expected hash: {computed_hash[:16]}...",
                    f"Got: {event.current_hash[:16]}..."
                ))
            
            # Verify signature if requested and public key available
            if verify_signatures and self._public_key and event.signature:
                sig_parts = event.signature.split(':')
                if len(sig_parts) == 2 and sig_parts[0] == 'ed25519':
                    result = Ed25519Signer.verify_with_public_key_b64(
                        event.current_hash.encode('utf-8'),
                        sig_parts[1],
                        self._public_key
                    )
                    if not result.is_valid:
                        invalid_signatures.append(i)
            
            # Update previous hash for next iteration
            previous_hash = event.current_hash
        
        is_valid = len(invalid_hashes) == 0 and len(invalid_signatures) == 0
        
        error_message = None
        if not is_valid:
            issues = []
            if invalid_hashes:
                issues.append(f"{len(invalid_hashes)} invalid hashes")
            if invalid_signatures:
                issues.append(f"{len(invalid_signatures)} invalid signatures")
            error_message = "; ".join(issues)
        
        return ChainVerificationResult(
            is_valid=is_valid,
            events_verified=len(events),
            first_invalid_index=invalid_hashes[0][0] if invalid_hashes else None,
            error_message=error_message,
            invalid_hashes=invalid_hashes,
            invalid_signatures=invalid_signatures
        )


class MerkleVerifier:
    """
    Verifies Merkle proofs for CAP-SRP events.
    """
    
    @staticmethod
    def verify_inclusion(
        event_hash: str,
        proof: InclusionProof,
        expected_root: str
    ) -> bool:
        """
        Verify that an event is included in the Merkle tree.
        
        Args:
            event_hash: Hash of the event to verify
            proof: Inclusion proof from the logger
            expected_root: Expected Merkle root
            
        Returns:
            bool: True if the proof is valid
        """
        return MerkleTree.verify_inclusion_proof(event_hash, proof, expected_root)
    
    @staticmethod
    def verify_event_inclusion(
        event: CAPEvent,
        proof: InclusionProof,
        expected_root: str
    ) -> bool:
        """
        Verify that a specific event is included in the Merkle tree.
        
        Args:
            event: The event to verify
            proof: Inclusion proof for the event
            expected_root: Expected Merkle root
            
        Returns:
            bool: True if the event is validly included
        """
        # First verify the event's hash matches the proof's leaf hash
        computed_hash = event.compute_hash()
        if computed_hash != event.current_hash:
            return False
        
        # Then verify the Merkle proof
        return MerkleTree.verify_inclusion_proof(
            event.current_hash,
            proof,
            expected_root
        )


@dataclass
class FullVerificationResult:
    """
    Result of a complete verification (completeness + chain + optional Merkle).
    """
    is_valid: bool
    completeness: CompletenessResult
    chain: ChainVerificationResult
    merkle_root_valid: Optional[bool] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "is_valid": self.is_valid,
            "completeness": self.completeness.to_dict(),
            "chain": self.chain.to_dict(),
            "merkle_root_valid": self.merkle_root_valid,
            "error_message": self.error_message
        }


def full_verification(
    events: List[CAPEvent],
    public_key: Optional[str] = None,
    expected_merkle_root: Optional[str] = None
) -> FullVerificationResult:
    """
    Perform complete verification of a CAP-SRP event log.
    
    This combines:
    1. Completeness verification
    2. Hash chain verification
    3. Signature verification (if public key provided)
    4. Merkle root verification (if expected root provided)
    
    Args:
        events: List of events to verify
        public_key: Optional base64 public key for signature verification
        expected_merkle_root: Optional expected Merkle root to verify against
        
    Returns:
        FullVerificationResult: Complete verification results
    """
    # Completeness verification
    completeness_verifier = CompletenessVerifier()
    completeness_result = completeness_verifier.verify(events)
    
    # Chain verification
    chain_verifier = ChainVerifier(public_key)
    chain_result = chain_verifier.verify(events, verify_signatures=bool(public_key))
    
    # Merkle root verification (if expected root provided)
    merkle_root_valid = None
    if expected_merkle_root:
        tree = MerkleTree()
        for event in events:
            tree.add_leaf(event.current_hash)
        merkle_root_valid = (tree.root == expected_merkle_root)
    
    # Overall validity
    is_valid = completeness_result.is_valid and chain_result.is_valid
    if merkle_root_valid is not None:
        is_valid = is_valid and merkle_root_valid
    
    error_message = None
    if not is_valid:
        issues = []
        if not completeness_result.is_valid:
            issues.append(f"Completeness: {completeness_result.error_message}")
        if not chain_result.is_valid:
            issues.append(f"Chain: {chain_result.error_message}")
        if merkle_root_valid is False:
            issues.append("Merkle root mismatch")
        error_message = " | ".join(issues)
    
    return FullVerificationResult(
        is_valid=is_valid,
        completeness=completeness_result,
        chain=chain_result,
        merkle_root_valid=merkle_root_valid,
        error_message=error_message
    )
