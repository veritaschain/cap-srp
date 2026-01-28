"""
Unit tests for CAP-SRP Logger Module
"""

import pytest
import json
import tempfile
from pathlib import Path

from cap_srp.core.logger import CAPLogger, create_demo_logger
from cap_srp.core.events import (
    EventType,
    RiskCategory,
    GenerationAttempt,
    GenerationDenial,
    hash_data
)


class TestCAPLogger:
    """Tests for CAPLogger class."""
    
    def test_create_logger(self):
        logger = CAPLogger()
        assert logger.event_count == 0
        assert logger.merkle_root is None
    
    def test_create_logger_with_custom_settings(self):
        logger = CAPLogger(
            model_id="test-model",
            policy_version="v2.0.0"
        )
        assert logger._model_id == "test-model"
        assert logger._policy_version == "v2.0.0"
    
    def test_log_attempt(self):
        logger = CAPLogger()
        attempt = logger.log_attempt(
            prompt_hash="sha256:abc123",
            session_id="sess_001"
        )
        
        assert isinstance(attempt, GenerationAttempt)
        assert attempt.prompt_hash == "sha256:abc123"
        assert attempt.session_id == "sess_001"
        assert logger.event_count == 1
    
    def test_log_generation(self):
        logger = CAPLogger()
        attempt = logger.log_attempt(prompt_hash="sha256:abc")
        
        success = logger.log_generation(
            attempt_id=attempt.event_id,
            output_hash="sha256:output123"
        )
        
        assert success.event_type == EventType.GEN
        assert success.attempt_id == attempt.event_id
        assert logger.event_count == 2
    
    def test_log_denial(self):
        logger = CAPLogger()
        attempt = logger.log_attempt(prompt_hash="sha256:abc")
        
        denial = logger.log_denial(
            attempt_id=attempt.event_id,
            risk_category=RiskCategory.NCII_RISK,
            risk_score=0.95
        )
        
        assert denial.event_type == EventType.GEN_DENY
        assert denial.risk_category == RiskCategory.NCII_RISK
        assert denial.risk_score == 0.95
    
    def test_log_error(self):
        logger = CAPLogger()
        attempt = logger.log_attempt(prompt_hash="sha256:abc")
        
        error = logger.log_error(
            attempt_id=attempt.event_id,
            error_code="E001",
            error_message="Test error"
        )
        
        assert error.event_type == EventType.GEN_ERROR
        assert error.error_code == "E001"
    
    def test_duplicate_outcome_raises_error(self):
        logger = CAPLogger()
        attempt = logger.log_attempt(prompt_hash="sha256:abc")
        
        logger.log_generation(
            attempt_id=attempt.event_id,
            output_hash="sha256:output"
        )
        
        with pytest.raises(ValueError, match="already has outcome"):
            logger.log_denial(
                attempt_id=attempt.event_id,
                risk_category=RiskCategory.NCII_RISK
            )
    
    def test_hash_chain_linking(self):
        logger = CAPLogger()
        
        attempt1 = logger.log_attempt(prompt_hash="sha256:abc1")
        logger.log_generation(attempt_id=attempt1.event_id, output_hash="sha256:out1")
        
        attempt2 = logger.log_attempt(prompt_hash="sha256:abc2")
        
        events = logger.events
        assert events[0].previous_hash == ""  # First event has no previous
        assert events[1].previous_hash == events[0].current_hash
        assert events[2].previous_hash == events[1].current_hash
    
    def test_merkle_root_updates(self):
        logger = CAPLogger()
        assert logger.merkle_root is None
        
        attempt = logger.log_attempt(prompt_hash="sha256:abc")
        root1 = logger.merkle_root
        assert root1 is not None
        
        logger.log_generation(attempt_id=attempt.event_id, output_hash="sha256:out")
        root2 = logger.merkle_root
        assert root2 is not None
        assert root2 != root1
    
    def test_get_event_by_id(self):
        logger = CAPLogger()
        attempt = logger.log_attempt(prompt_hash="sha256:abc")
        
        found = logger.get_event_by_id(attempt.event_id)
        assert found is not None
        assert found.event_id == attempt.event_id
        
        not_found = logger.get_event_by_id("nonexistent")
        assert not_found is None
    
    def test_get_events_by_type(self):
        logger = CAPLogger()
        
        attempt1 = logger.log_attempt(prompt_hash="sha256:abc1")
        logger.log_generation(attempt_id=attempt1.event_id, output_hash="sha256:out1")
        
        attempt2 = logger.log_attempt(prompt_hash="sha256:abc2")
        logger.log_denial(
            attempt_id=attempt2.event_id,
            risk_category=RiskCategory.NCII_RISK
        )
        
        attempts = logger.get_events_by_type(EventType.GEN_ATTEMPT)
        assert len(attempts) == 2
        
        denials = logger.get_events_by_type(EventType.GEN_DENY)
        assert len(denials) == 1
    
    def test_get_denials_by_category(self):
        logger = CAPLogger()
        
        attempt1 = logger.log_attempt(prompt_hash="sha256:abc1")
        logger.log_denial(
            attempt_id=attempt1.event_id,
            risk_category=RiskCategory.NCII_RISK
        )
        
        attempt2 = logger.log_attempt(prompt_hash="sha256:abc2")
        logger.log_denial(
            attempt_id=attempt2.event_id,
            risk_category=RiskCategory.CSAM_RISK
        )
        
        attempt3 = logger.log_attempt(prompt_hash="sha256:abc3")
        logger.log_denial(
            attempt_id=attempt3.event_id,
            risk_category=RiskCategory.NCII_RISK
        )
        
        ncii_denials = logger.get_denials_by_category(RiskCategory.NCII_RISK)
        assert len(ncii_denials) == 2
        
        csam_denials = logger.get_denials_by_category(RiskCategory.CSAM_RISK)
        assert len(csam_denials) == 1
    
    def test_get_statistics(self):
        logger = CAPLogger()
        
        # Add various events
        attempt1 = logger.log_attempt(prompt_hash="sha256:abc1")
        logger.log_generation(attempt_id=attempt1.event_id, output_hash="sha256:out1")
        
        attempt2 = logger.log_attempt(prompt_hash="sha256:abc2")
        logger.log_denial(
            attempt_id=attempt2.event_id,
            risk_category=RiskCategory.NCII_RISK
        )
        
        attempt3 = logger.log_attempt(prompt_hash="sha256:abc3")
        logger.log_error(
            attempt_id=attempt3.event_id,
            error_code="E001"
        )
        
        stats = logger.get_statistics()
        
        assert stats['total_events'] == 6
        assert stats['attempts'] == 3
        assert stats['generations'] == 1
        assert stats['denials'] == 1
        assert stats['errors'] == 1
        assert stats['completeness']['is_complete'] == True
    
    def test_get_inclusion_proof(self):
        logger = CAPLogger()
        
        attempt = logger.log_attempt(prompt_hash="sha256:abc")
        logger.log_generation(attempt_id=attempt.event_id, output_hash="sha256:out")
        
        proof = logger.get_inclusion_proof(0)
        
        assert proof.leaf_index == 0
        assert proof.tree_size == 2
        assert proof.root_hash == logger.merkle_root
    
    def test_export_import_events(self):
        logger = CAPLogger(model_id="test-model")
        
        attempt = logger.log_attempt(prompt_hash="sha256:abc")
        logger.log_generation(attempt_id=attempt.event_id, output_hash="sha256:out")
        
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            filepath = f.name
        
        try:
            logger.export_events(filepath)
            
            # Verify export file
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            assert data['event_count'] == 2
            assert len(data['events']) == 2
            
            # Import into new logger
            new_logger = CAPLogger()
            new_logger.import_events(filepath)
            
            assert new_logger.event_count == 2
        finally:
            Path(filepath).unlink(missing_ok=True)


class TestCreateDemoLogger:
    """Tests for demo logger creation."""
    
    def test_create_demo_logger(self):
        logger = create_demo_logger()
        
        assert logger.event_count > 0
        
        stats = logger.get_statistics()
        assert stats['attempts'] > 0
        assert stats['completeness']['is_complete'] == True
    
    def test_demo_logger_has_denials(self):
        logger = create_demo_logger()
        stats = logger.get_statistics()
        
        assert stats['denials'] > 0
        assert len(stats['denial_categories']) > 0


class TestLoggerThreadSafety:
    """Tests for thread safety of logger."""
    
    def test_concurrent_logging(self):
        import threading
        
        logger = CAPLogger()
        errors = []
        
        def log_events():
            try:
                for i in range(10):
                    attempt = logger.log_attempt(
                        prompt_hash=hash_data(f"prompt_{threading.current_thread().name}_{i}")
                    )
                    logger.log_generation(
                        attempt_id=attempt.event_id,
                        output_hash=hash_data(f"output_{i}")
                    )
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=log_events) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert logger.event_count == 100  # 5 threads * 10 iterations * 2 events
