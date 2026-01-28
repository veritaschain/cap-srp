"""
Tests for CAP-SRP Verifier Module

Tests cover:
- Completeness Invariant verification
- Hash chain integrity
- Fraud detection scenarios
"""

import pytest
from datetime import datetime, timezone

from cap_srp.core.events import (
    EventType,
    RiskCategory,
    GenerationAttempt,
    GenerationSuccess,
    GenerationDenial,
    GenerationError,
    hash_data
)
from cap_srp.core.logger import CAPLogger
from cap_srp.core.verifier import (
    CompletenessVerifier,
    ChainVerifier,
    full_verification
)


class TestCompletenessVerifier:
    """Test the Completeness Invariant verification."""
    
    def test_empty_log_is_valid(self):
        """Empty log should be valid."""
        verifier = CompletenessVerifier()
        result = verifier.verify([])
        assert result.is_valid
        assert result.total_attempts == 0
    
    def test_single_complete_sequence(self):
        """Single attempt + outcome should be valid."""
        logger = CAPLogger()
        
        attempt = logger.log_attempt(prompt_hash=hash_data("test"))
        logger.log_generation(
            attempt_id=attempt.event_id,
            output_hash=hash_data("output")
        )
        
        verifier = CompletenessVerifier()
        result = verifier.verify(logger.events)
        
        assert result.is_valid
        assert result.total_attempts == 1
        assert result.total_generations == 1
        assert result.total_denials == 0
        assert result.total_errors == 0
    
    def test_multiple_complete_sequences(self):
        """Multiple complete sequences should be valid."""
        logger = CAPLogger()
        
        # 10 generations
        for i in range(10):
            attempt = logger.log_attempt(prompt_hash=hash_data(f"test{i}"))
            logger.log_generation(
                attempt_id=attempt.event_id,
                output_hash=hash_data(f"output{i}")
            )
        
        # 5 denials
        for i in range(5):
            attempt = logger.log_attempt(prompt_hash=hash_data(f"deny{i}"))
            logger.log_denial(
                attempt_id=attempt.event_id,
                risk_category=RiskCategory.NCII_RISK
            )
        
        # 2 errors
        for i in range(2):
            attempt = logger.log_attempt(prompt_hash=hash_data(f"error{i}"))
            logger.log_error(
                attempt_id=attempt.event_id,
                error_code="E001"
            )
        
        verifier = CompletenessVerifier()
        result = verifier.verify(logger.events)
        
        assert result.is_valid
        assert result.total_attempts == 17
        assert result.total_generations == 10
        assert result.total_denials == 5
        assert result.total_errors == 2
    
    def test_pending_attempt_is_invalid(self):
        """Attempt without outcome should be invalid."""
        logger = CAPLogger()
        
        # Create attempt but no outcome
        attempt = logger.log_attempt(prompt_hash=hash_data("test"))
        
        verifier = CompletenessVerifier()
        result = verifier.verify(logger.events)
        
        assert not result.is_valid
        assert result.total_attempts == 1
        assert result.total_outcomes == 0
        assert len(result.pending_attempts) == 1
        assert attempt.event_id in result.pending_attempts
    
    def test_orphan_outcome_is_invalid(self):
        """Outcome without matching attempt should be invalid."""
        # Create events manually to simulate orphan
        attempt = GenerationAttempt(prompt_hash=hash_data("test"))
        
        # Generation with wrong attempt_id
        generation = GenerationSuccess(
            attempt_id="non-existent-attempt-id",
            output_hash=hash_data("output")
        )
        
        verifier = CompletenessVerifier()
        result = verifier.verify([attempt, generation])
        
        assert not result.is_valid
        assert len(result.orphan_outcomes) == 1
    
    def test_duplicate_outcome_is_invalid(self):
        """Multiple outcomes for same attempt should be invalid."""
        attempt = GenerationAttempt(prompt_hash=hash_data("test"))
        
        # Two outcomes for same attempt
        generation1 = GenerationSuccess(
            attempt_id=attempt.event_id,
            output_hash=hash_data("output1")
        )
        generation2 = GenerationSuccess(
            attempt_id=attempt.event_id,
            output_hash=hash_data("output2")
        )
        
        verifier = CompletenessVerifier()
        result = verifier.verify([attempt, generation1, generation2])
        
        assert not result.is_valid
        assert len(result.duplicate_outcomes) == 1
    
    def test_denial_rate_calculation(self):
        """Denial rate should be calculated correctly."""
        logger = CAPLogger()
        
        # 3 generations
        for i in range(3):
            attempt = logger.log_attempt(prompt_hash=hash_data(f"gen{i}"))
            logger.log_generation(
                attempt_id=attempt.event_id,
                output_hash=hash_data(f"output{i}")
            )
        
        # 7 denials (70% denial rate)
        for i in range(7):
            attempt = logger.log_attempt(prompt_hash=hash_data(f"deny{i}"))
            logger.log_denial(
                attempt_id=attempt.event_id,
                risk_category=RiskCategory.CSAM_RISK
            )
        
        verifier = CompletenessVerifier()
        result = verifier.verify(logger.events)
        
        assert result.is_valid
        assert abs(result.denial_rate - 0.7) < 0.001


class TestChainVerifier:
    """Test hash chain integrity verification."""
    
    def test_valid_chain(self):
        """Properly linked chain should be valid."""
        logger = CAPLogger()
        
        attempt = logger.log_attempt(prompt_hash=hash_data("test"))
        logger.log_generation(
            attempt_id=attempt.event_id,
            output_hash=hash_data("output")
        )
        
        verifier = ChainVerifier(logger.public_key)
        result = verifier.verify(logger.events)
        
        assert result.is_valid
        assert result.events_verified == 2
        assert len(result.invalid_hashes) == 0
    
    def test_broken_chain_detected(self):
        """Broken previous_hash link should be detected."""
        logger = CAPLogger()
        
        attempt = logger.log_attempt(prompt_hash=hash_data("test"))
        logger.log_generation(
            attempt_id=attempt.event_id,
            output_hash=hash_data("output")
        )
        
        # Tamper with the chain
        events = logger.events
        events[1].previous_hash = "tampered_hash"
        
        verifier = ChainVerifier()
        result = verifier.verify(events, verify_signatures=False)
        
        assert not result.is_valid
        assert len(result.invalid_hashes) > 0
    
    def test_tampered_content_detected(self):
        """Modified event content should be detected."""
        logger = CAPLogger()
        
        attempt = logger.log_attempt(prompt_hash=hash_data("test"))
        logger.log_generation(
            attempt_id=attempt.event_id,
            output_hash=hash_data("output")
        )
        
        # Tamper with event content
        events = logger.events
        events[0].prompt_hash = "tampered_prompt_hash"
        
        verifier = ChainVerifier()
        result = verifier.verify(events, verify_signatures=False)
        
        assert not result.is_valid


class TestFullVerification:
    """Test combined verification."""
    
    def test_full_verification_valid(self):
        """Complete verification should pass for valid log."""
        logger = CAPLogger()
        
        for i in range(5):
            attempt = logger.log_attempt(prompt_hash=hash_data(f"test{i}"))
            if i % 2 == 0:
                logger.log_generation(
                    attempt_id=attempt.event_id,
                    output_hash=hash_data(f"output{i}")
                )
            else:
                logger.log_denial(
                    attempt_id=attempt.event_id,
                    risk_category=RiskCategory.NCII_RISK
                )
        
        result = full_verification(
            logger.events,
            public_key=logger.public_key,
            expected_merkle_root=logger.merkle_root
        )
        
        assert result.is_valid
        assert result.completeness.is_valid
        assert result.chain.is_valid
        assert result.merkle_root_valid
    
    def test_full_verification_invalid_completeness(self):
        """Should fail if completeness is invalid."""
        logger = CAPLogger()
        
        # Create pending attempt
        logger.log_attempt(prompt_hash=hash_data("test"))
        
        result = full_verification(logger.events)
        
        assert not result.is_valid
        assert not result.completeness.is_valid
    
    def test_full_verification_invalid_merkle(self):
        """Should fail if Merkle root doesn't match."""
        logger = CAPLogger()
        
        attempt = logger.log_attempt(prompt_hash=hash_data("test"))
        logger.log_generation(
            attempt_id=attempt.event_id,
            output_hash=hash_data("output")
        )
        
        result = full_verification(
            logger.events,
            expected_merkle_root="wrong_root"
        )
        
        assert not result.is_valid
        assert result.merkle_root_valid is False


class TestFraudDetection:
    """Test various fraud scenarios."""
    
    def test_detect_deleted_denial(self):
        """Should detect if denial records are deleted."""
        logger = CAPLogger()
        
        # Create some legitimate events
        attempt1 = logger.log_attempt(prompt_hash=hash_data("safe"))
        logger.log_generation(
            attempt_id=attempt1.event_id,
            output_hash=hash_data("output1")
        )
        
        # Create a denial
        attempt2 = logger.log_attempt(prompt_hash=hash_data("unsafe"))
        denial = logger.log_denial(
            attempt_id=attempt2.event_id,
            risk_category=RiskCategory.CSAM_RISK
        )
        
        # Simulate deletion of denial by removing it
        events = [e for e in logger.events if e.event_id != denial.event_id]
        
        # Verification should detect the problem
        verifier = CompletenessVerifier()
        result = verifier.verify(events)
        
        # Should be invalid because attempt2 has no outcome
        assert not result.is_valid
        assert len(result.pending_attempts) == 1
    
    def test_detect_fabricated_generation(self):
        """Should detect fabricated generation records."""
        logger = CAPLogger()
        
        attempt = logger.log_attempt(prompt_hash=hash_data("test"))
        logger.log_denial(
            attempt_id=attempt.event_id,
            risk_category=RiskCategory.NCII_RISK
        )
        
        # Try to add fabricated generation for same attempt
        # This should raise an error from the logger
        with pytest.raises(ValueError):
            logger.log_generation(
                attempt_id=attempt.event_id,
                output_hash=hash_data("fake_output")
            )
    
    def test_detect_rate_anomaly(self):
        """Denial rate statistics can detect anomalies."""
        logger = CAPLogger()
        
        # Normal operation: ~30% denial rate
        for i in range(70):
            attempt = logger.log_attempt(prompt_hash=hash_data(f"gen{i}"))
            logger.log_generation(
                attempt_id=attempt.event_id,
                output_hash=hash_data(f"output{i}")
            )
        
        for i in range(30):
            attempt = logger.log_attempt(prompt_hash=hash_data(f"deny{i}"))
            logger.log_denial(
                attempt_id=attempt.event_id,
                risk_category=RiskCategory.VIOLENCE_GRAPHIC
            )
        
        verifier = CompletenessVerifier()
        result = verifier.verify(logger.events)
        
        # Should be valid but we can see the denial rate
        assert result.is_valid
        assert 0.29 < result.denial_rate < 0.31
        
        # A sudden drop in denial rate (e.g., 5%) would be suspicious
        # This provides audit capability
