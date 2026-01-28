"""
CAP-SRP Event Logger

This module provides the main logging functionality for CAP-SRP events.
It handles event creation, signing, chain linking, and Merkle tree updates.

Key Features:
    - Automatic hash chain linking
    - Ed25519 digital signatures
    - Merkle tree integration
    - Completeness invariant support
    - Thread-safe operations

Usage:
    >>> from cap_srp.core.logger import CAPLogger
    >>> from cap_srp.core.events import RiskCategory
    >>> 
    >>> # Create logger
    >>> logger = CAPLogger()
    >>> 
    >>> # Log a generation attempt (MUST be first)
    >>> attempt = logger.log_attempt(
    ...     prompt_hash="sha256:abc123...",
    ...     session_id="sess_001",
    ...     model_id="image-gen-v3"
    ... )
    >>> 
    >>> # Later, log the outcome
    >>> # Option A: Successful generation
    >>> success = logger.log_generation(
    ...     attempt_id=attempt.event_id,
    ...     output_hash="sha256:def456..."
    ... )
    >>> 
    >>> # Option B: Denied generation
    >>> denial = logger.log_denial(
    ...     attempt_id=attempt.event_id,
    ...     risk_category=RiskCategory.NCII_RISK,
    ...     risk_score=0.94
    ... )
    >>> 
    >>> # Option C: Error
    >>> error = logger.log_error(
    ...     attempt_id=attempt.event_id,
    ...     error_code="E001",
    ...     error_message="GPU memory exceeded"
    ... )
"""

import json
import threading
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pathlib import Path

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
from cap_srp.core.signer import Ed25519Signer, SignatureResult
from cap_srp.core.merkle import MerkleTree, InclusionProof


class CAPLogger:
    """
    Main event logger for CAP-SRP.
    
    Handles the complete lifecycle of event logging:
    1. Event creation with proper fields
    2. Hash chain linking to previous event
    3. Ed25519 digital signature
    4. Merkle tree leaf addition
    
    Thread Safety:
        All public methods are thread-safe using a reentrant lock.
    
    Attributes:
        events: List of all logged events
        merkle_tree: Merkle tree for inclusion proofs
        signer: Ed25519 signer for event signatures
    """
    
    def __init__(
        self,
        private_key: Optional[bytes] = None,
        model_id: str = "default-model",
        policy_version: str = "v1.0.0"
    ):
        """
        Initialize the logger.
        
        Args:
            private_key: Optional Ed25519 private key. If not provided,
                        a new key pair will be generated.
            model_id: Default model identifier for events
            policy_version: Default policy version for events
        """
        self._lock = threading.RLock()
        self._events: List[CAPEvent] = []
        self._merkle_tree = MerkleTree()
        self._signer = Ed25519Signer(private_key)
        self._model_id = model_id
        self._policy_version = policy_version
        self._previous_hash = ""
        
        # Track attempt-to-outcome mapping for completeness verification
        self._attempt_outcomes: Dict[str, str] = {}  # attempt_id -> outcome_event_id
    
    @property
    def events(self) -> List[CAPEvent]:
        """Get a copy of all logged events."""
        with self._lock:
            return self._events.copy()
    
    @property
    def event_count(self) -> int:
        """Get the number of logged events."""
        with self._lock:
            return len(self._events)
    
    @property
    def merkle_root(self) -> Optional[str]:
        """Get the current Merkle root."""
        with self._lock:
            return self._merkle_tree.root
    
    @property
    def public_key(self) -> str:
        """Get the signer's public key (base64)."""
        return self._signer.public_key_b64
    
    def _sign_and_add_event(self, event: CAPEvent) -> CAPEvent:
        """
        Internal method to sign an event and add it to the chain.
        
        Args:
            event: The event to process
            
        Returns:
            CAPEvent: The processed event with hash and signature
        """
        # Set previous hash (chain linking)
        event.previous_hash = self._previous_hash
        
        # Compute event hash
        event.current_hash = event.compute_hash()
        
        # Sign the hash
        sig_result = self._signer.sign_string(event.current_hash)
        event.signature = f"ed25519:{sig_result.signature_b64}"
        
        # Add to Merkle tree
        self._merkle_tree.add_leaf(event.current_hash)
        
        # Update previous hash for next event
        self._previous_hash = event.current_hash
        
        # Store event
        self._events.append(event)
        
        return event
    
    def log_attempt(
        self,
        prompt_hash: str,
        session_id: str = "",
        user_context_hash: str = "",
        model_id: Optional[str] = None,
        policy_version: Optional[str] = None
    ) -> GenerationAttempt:
        """
        Log a generation attempt (commitment point).
        
        This MUST be called BEFORE the safety evaluation to ensure
        all requests are recorded regardless of outcome.
        
        Args:
            prompt_hash: SHA-256 hash of the prompt (NOT the prompt itself)
            session_id: Session identifier for grouping related events
            user_context_hash: Optional hash of user context (for privacy)
            model_id: Override default model ID
            policy_version: Override default policy version
            
        Returns:
            GenerationAttempt: The logged attempt event
        """
        with self._lock:
            event = GenerationAttempt(
                event_id=generate_event_id(),
                timestamp=datetime.now(timezone.utc).isoformat(),
                session_id=session_id,
                model_id=model_id or self._model_id,
                policy_version=policy_version or self._policy_version,
                prompt_hash=prompt_hash,
                user_context_hash=user_context_hash
            )
            
            return self._sign_and_add_event(event)
    
    def log_generation(
        self,
        attempt_id: str,
        output_hash: str,
        c2pa_manifest_id: Optional[str] = None,
        session_id: str = "",
        model_id: Optional[str] = None,
        policy_version: Optional[str] = None
    ) -> GenerationSuccess:
        """
        Log a successful generation.
        
        Args:
            attempt_id: The event_id of the corresponding GEN_ATTEMPT
            output_hash: SHA-256 hash of the generated content
            c2pa_manifest_id: Optional C2PA manifest ID
            session_id: Session identifier
            model_id: Override default model ID
            policy_version: Override default policy version
            
        Returns:
            GenerationSuccess: The logged success event
            
        Raises:
            ValueError: If attempt_id already has an outcome logged
        """
        with self._lock:
            if attempt_id in self._attempt_outcomes:
                raise ValueError(f"Attempt {attempt_id} already has outcome logged")
            
            event = GenerationSuccess(
                event_id=generate_event_id(),
                timestamp=datetime.now(timezone.utc).isoformat(),
                session_id=session_id,
                model_id=model_id or self._model_id,
                policy_version=policy_version or self._policy_version,
                attempt_id=attempt_id,
                output_hash=output_hash,
                c2pa_manifest_id=c2pa_manifest_id
            )
            
            result = self._sign_and_add_event(event)
            self._attempt_outcomes[attempt_id] = result.event_id
            return result
    
    def log_denial(
        self,
        attempt_id: str,
        risk_category: RiskCategory,
        risk_score: float = 0.0,
        denial_reason: str = "",
        session_id: str = "",
        model_id: Optional[str] = None,
        policy_version: Optional[str] = None
    ) -> GenerationDenial:
        """
        Log a generation denial.
        
        This is the core value proposition of CAP-SRP - cryptographic
        proof that the AI refused to generate harmful content.
        
        Args:
            attempt_id: The event_id of the corresponding GEN_ATTEMPT
            risk_category: Category of detected risk
            risk_score: Confidence score (0.0 to 1.0)
            denial_reason: Machine-readable denial code
            session_id: Session identifier
            model_id: Override default model ID
            policy_version: Override default policy version
            
        Returns:
            GenerationDenial: The logged denial event
            
        Raises:
            ValueError: If attempt_id already has an outcome logged
        """
        with self._lock:
            if attempt_id in self._attempt_outcomes:
                raise ValueError(f"Attempt {attempt_id} already has outcome logged")
            
            event = GenerationDenial(
                event_id=generate_event_id(),
                timestamp=datetime.now(timezone.utc).isoformat(),
                session_id=session_id,
                model_id=model_id or self._model_id,
                policy_version=policy_version or self._policy_version,
                attempt_id=attempt_id,
                risk_category=risk_category,
                risk_score=risk_score,
                denial_reason=denial_reason
            )
            
            result = self._sign_and_add_event(event)
            self._attempt_outcomes[attempt_id] = result.event_id
            return result
    
    def log_error(
        self,
        attempt_id: str,
        error_code: str,
        error_message: str = "",
        session_id: str = "",
        model_id: Optional[str] = None,
        policy_version: Optional[str] = None
    ) -> GenerationError:
        """
        Log a generation error.
        
        Args:
            attempt_id: The event_id of the corresponding GEN_ATTEMPT
            error_code: Machine-readable error code
            error_message: Human-readable error description
            session_id: Session identifier
            model_id: Override default model ID
            policy_version: Override default policy version
            
        Returns:
            GenerationError: The logged error event
            
        Raises:
            ValueError: If attempt_id already has an outcome logged
        """
        with self._lock:
            if attempt_id in self._attempt_outcomes:
                raise ValueError(f"Attempt {attempt_id} already has outcome logged")
            
            event = GenerationError(
                event_id=generate_event_id(),
                timestamp=datetime.now(timezone.utc).isoformat(),
                session_id=session_id,
                model_id=model_id or self._model_id,
                policy_version=policy_version or self._policy_version,
                attempt_id=attempt_id,
                error_code=error_code,
                error_message=error_message
            )
            
            result = self._sign_and_add_event(event)
            self._attempt_outcomes[attempt_id] = result.event_id
            return result
    
    def get_inclusion_proof(self, event_index: int) -> InclusionProof:
        """
        Get a Merkle inclusion proof for an event.
        
        Args:
            event_index: Index of the event in the log
            
        Returns:
            InclusionProof: Proof that can verify event membership
        """
        with self._lock:
            return self._merkle_tree.get_inclusion_proof(event_index)
    
    def get_event_by_id(self, event_id: str) -> Optional[CAPEvent]:
        """Find an event by its event_id."""
        with self._lock:
            for event in self._events:
                if event.event_id == event_id:
                    return event
            return None
    
    def get_events_by_type(self, event_type: EventType) -> List[CAPEvent]:
        """Get all events of a specific type."""
        with self._lock:
            return [e for e in self._events if e.event_type == event_type]
    
    def get_events_by_session(self, session_id: str) -> List[CAPEvent]:
        """Get all events for a specific session."""
        with self._lock:
            return [e for e in self._events if e.session_id == session_id]
    
    def get_denials_by_category(self, category: RiskCategory) -> List[GenerationDenial]:
        """Get all denials of a specific risk category."""
        with self._lock:
            denials = self.get_events_by_type(EventType.GEN_DENY)
            return [d for d in denials if d.risk_category == category]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the event log.
        
        Returns:
            dict: Statistics including counts by type, risk category breakdown, etc.
        """
        with self._lock:
            attempts = len([e for e in self._events if e.event_type == EventType.GEN_ATTEMPT])
            generations = len([e for e in self._events if e.event_type == EventType.GEN])
            denials = len([e for e in self._events if e.event_type == EventType.GEN_DENY])
            errors = len([e for e in self._events if e.event_type == EventType.GEN_ERROR])
            
            # Denial breakdown by category
            denial_events = [e for e in self._events if e.event_type == EventType.GEN_DENY]
            category_counts = {}
            for event in denial_events:
                cat = event.risk_category.value if event.risk_category else "UNKNOWN"
                category_counts[cat] = category_counts.get(cat, 0) + 1
            
            # Completeness check
            outcomes_total = generations + denials + errors
            is_complete = (attempts == outcomes_total)
            
            return {
                "total_events": len(self._events),
                "attempts": attempts,
                "generations": generations,
                "denials": denials,
                "errors": errors,
                "denial_rate": denials / attempts if attempts > 0 else 0,
                "error_rate": errors / attempts if attempts > 0 else 0,
                "denial_categories": category_counts,
                "completeness": {
                    "is_complete": is_complete,
                    "attempts": attempts,
                    "outcomes": outcomes_total,
                    "pending": attempts - outcomes_total
                },
                "merkle_root": self._merkle_tree.root,
                "merkle_size": self._merkle_tree.size
            }
    
    def export_events(self, filepath: str):
        """
        Export all events to a JSON file.
        
        Args:
            filepath: Path to the output file
        """
        with self._lock:
            events_data = [event.to_dict() for event in self._events]
            export_data = {
                "version": "1.0.0",
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "public_key": self.public_key,
                "merkle_root": self.merkle_root,
                "event_count": len(self._events),
                "events": events_data
            }
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
    
    def import_events(self, filepath: str):
        """
        Import events from a JSON file.
        
        Note: This replaces all current events and rebuilds the tree.
        
        Args:
            filepath: Path to the input file
        """
        with self._lock:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            # Clear current state
            self._events = []
            self._merkle_tree = MerkleTree()
            self._previous_hash = ""
            self._attempt_outcomes = {}
            
            # Import events
            for event_data in data.get('events', []):
                event = create_event_from_dict(event_data)
                self._events.append(event)
                self._merkle_tree.add_leaf(event.current_hash)
                self._previous_hash = event.current_hash
                
                # Track outcomes
                if hasattr(event, 'attempt_id') and event.attempt_id:
                    self._attempt_outcomes[event.attempt_id] = event.event_id


def create_demo_logger() -> CAPLogger:
    """
    Create a logger with demo events for testing.
    
    Returns:
        CAPLogger: Logger with sample events
    """
    import random
    
    logger = CAPLogger(model_id="demo-image-gen-v3", policy_version="v2.3.1")
    
    risk_categories = [
        (RiskCategory.NCII_RISK, 0.45),
        (RiskCategory.CSAM_RISK, 0.22),
        (RiskCategory.REAL_PERSON_DEEPFAKE, 0.17),
        (RiskCategory.VIOLENCE_GRAPHIC, 0.10),
        (RiskCategory.OTHER, 0.06)
    ]
    
    for i in range(100):
        session_id = f"sess_{i // 10:03d}"
        prompt_hash = hash_data(f"demo_prompt_{i}")
        
        # Log attempt
        attempt = logger.log_attempt(
            prompt_hash=prompt_hash,
            session_id=session_id
        )
        
        # Determine outcome
        outcome_roll = random.random()
        
        if outcome_roll < 0.66:
            # 66% - successful generation
            logger.log_generation(
                attempt_id=attempt.event_id,
                output_hash=hash_data(f"demo_output_{i}"),
                session_id=session_id
            )
        elif outcome_roll < 0.99:
            # 33% - denial
            # Select category based on weights
            rand = random.random()
            cumulative = 0
            selected_category = RiskCategory.OTHER
            for category, weight in risk_categories:
                cumulative += weight
                if rand < cumulative:
                    selected_category = category
                    break
            
            logger.log_denial(
                attempt_id=attempt.event_id,
                risk_category=selected_category,
                risk_score=0.7 + random.random() * 0.3,
                session_id=session_id
            )
        else:
            # 1% - error
            logger.log_error(
                attempt_id=attempt.event_id,
                error_code="E001",
                error_message="Demo error",
                session_id=session_id
            )
    
    return logger
