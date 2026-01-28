"""
Tests for CAP-SRP Events Module

Tests cover:
- Event type creation
- Hash computation
- UUIDv7 generation
- Serialization/deserialization
"""

import pytest
from datetime import datetime, timezone
import json

from cap_srp.core.events import (
    EventType,
    RiskCategory,
    CAPEvent,
    GenerationAttempt,
    GenerationSuccess,
    GenerationDenial,
    GenerationError,
    generate_event_id,
    hash_data,
    create_event_from_dict
)


class TestEventTypes:
    """Test EventType enum."""
    
    def test_event_type_values(self):
        """Verify all event types have correct values."""
        assert EventType.GEN_ATTEMPT.value == "GEN_ATTEMPT"
        assert EventType.GEN.value == "GEN"
        assert EventType.GEN_DENY.value == "GEN_DENY"
        assert EventType.GEN_ERROR.value == "GEN_ERROR"
    
    def test_event_type_iteration(self):
        """Verify all expected event types exist."""
        types = list(EventType)
        assert len(types) == 4


class TestRiskCategories:
    """Test RiskCategory enum."""
    
    def test_critical_categories_exist(self):
        """Verify critical risk categories are defined."""
        assert RiskCategory.NCII_RISK.value == "NCII_RISK"
        assert RiskCategory.CSAM_RISK.value == "CSAM_RISK"
        assert RiskCategory.REAL_PERSON_DEEPFAKE.value == "REAL_PERSON_DEEPFAKE"
        assert RiskCategory.VIOLENCE_GRAPHIC.value == "VIOLENCE_GRAPHIC"
    
    def test_all_categories_have_string_values(self):
        """Verify all categories have proper string values."""
        for category in RiskCategory:
            assert isinstance(category.value, str)
            assert len(category.value) > 0


class TestEventIdGeneration:
    """Test UUIDv7 event ID generation."""
    
    def test_generates_valid_uuid_format(self):
        """Event IDs should be valid UUID format."""
        event_id = generate_event_id()
        # UUID format: 8-4-4-4-12 = 36 characters
        assert len(event_id) == 36
        assert event_id.count('-') == 4
    
    def test_generates_unique_ids(self):
        """Each call should generate unique ID."""
        ids = [generate_event_id() for _ in range(1000)]
        assert len(set(ids)) == 1000
    
    def test_ids_are_sortable(self):
        """UUIDv7 should be time-sortable."""
        id1 = generate_event_id()
        id2 = generate_event_id()
        # Later ID should sort after earlier ID
        assert id2 > id1


class TestHashData:
    """Test hash_data function."""
    
    def test_hash_format(self):
        """Hash should have sha256: prefix."""
        result = hash_data("test")
        assert result.startswith("sha256:")
    
    def test_hash_length(self):
        """SHA-256 produces 64-character hex string."""
        result = hash_data("test")
        # sha256: prefix (7) + 64 hex chars = 71
        assert len(result) == 71
    
    def test_hash_deterministic(self):
        """Same input should produce same hash."""
        hash1 = hash_data("test")
        hash2 = hash_data("test")
        assert hash1 == hash2
    
    def test_different_inputs_different_hashes(self):
        """Different inputs should produce different hashes."""
        hash1 = hash_data("test1")
        hash2 = hash_data("test2")
        assert hash1 != hash2


class TestGenerationAttempt:
    """Test GenerationAttempt event."""
    
    def test_default_event_type(self):
        """Default event type should be GEN_ATTEMPT."""
        event = GenerationAttempt()
        assert event.event_type == EventType.GEN_ATTEMPT
    
    def test_creates_with_prompt_hash(self):
        """Should store prompt hash."""
        event = GenerationAttempt(
            prompt_hash="sha256:abc123",
            session_id="sess_001"
        )
        assert event.prompt_hash == "sha256:abc123"
        assert event.session_id == "sess_001"
    
    def test_auto_generates_event_id(self):
        """Should auto-generate event_id."""
        event = GenerationAttempt()
        assert event.event_id is not None
        assert len(event.event_id) == 36
    
    def test_auto_generates_timestamp(self):
        """Should auto-generate timestamp."""
        event = GenerationAttempt()
        assert event.timestamp is not None
        # Should be valid ISO format
        datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
    
    def test_compute_hash(self):
        """Should compute deterministic hash."""
        event = GenerationAttempt(
            event_id="test-id",
            timestamp="2026-01-28T00:00:00Z",
            prompt_hash="sha256:test"
        )
        hash1 = event.compute_hash()
        hash2 = event.compute_hash()
        assert hash1 == hash2
        assert hash1.startswith("sha256:")


class TestGenerationDenial:
    """Test GenerationDenial event."""
    
    def test_default_event_type(self):
        """Default event type should be GEN_DENY."""
        event = GenerationDenial()
        assert event.event_type == EventType.GEN_DENY
    
    def test_creates_with_risk_category(self):
        """Should store risk category and score."""
        event = GenerationDenial(
            attempt_id="attempt-123",
            risk_category=RiskCategory.NCII_RISK,
            risk_score=0.95
        )
        assert event.attempt_id == "attempt-123"
        assert event.risk_category == RiskCategory.NCII_RISK
        assert event.risk_score == 0.95
    
    def test_to_dict_includes_risk_category(self):
        """Serialization should include risk category."""
        event = GenerationDenial(
            risk_category=RiskCategory.CSAM_RISK
        )
        d = event.to_dict()
        assert d['risk_category'] == 'CSAM_RISK'


class TestGenerationSuccess:
    """Test GenerationSuccess event."""
    
    def test_default_event_type(self):
        """Default event type should be GEN."""
        event = GenerationSuccess()
        assert event.event_type == EventType.GEN
    
    def test_creates_with_output_hash(self):
        """Should store output hash and optional C2PA ID."""
        event = GenerationSuccess(
            attempt_id="attempt-123",
            output_hash="sha256:output123",
            c2pa_manifest_id="c2pa:manifest123"
        )
        assert event.output_hash == "sha256:output123"
        assert event.c2pa_manifest_id == "c2pa:manifest123"


class TestGenerationError:
    """Test GenerationError event."""
    
    def test_default_event_type(self):
        """Default event type should be GEN_ERROR."""
        event = GenerationError()
        assert event.event_type == EventType.GEN_ERROR
    
    def test_creates_with_error_info(self):
        """Should store error code and message."""
        event = GenerationError(
            attempt_id="attempt-123",
            error_code="E001",
            error_message="GPU memory exceeded"
        )
        assert event.error_code == "E001"
        assert event.error_message == "GPU memory exceeded"


class TestEventSerialization:
    """Test event serialization and deserialization."""
    
    def test_to_dict_preserves_data(self):
        """to_dict should preserve all event data."""
        event = GenerationAttempt(
            prompt_hash="sha256:test",
            session_id="sess_001",
            model_id="model-v1"
        )
        d = event.to_dict()
        
        assert d['prompt_hash'] == "sha256:test"
        assert d['session_id'] == "sess_001"
        assert d['model_id'] == "model-v1"
        assert d['event_type'] == "GEN_ATTEMPT"
    
    def test_to_json_produces_valid_json(self):
        """to_json should produce valid JSON string."""
        event = GenerationAttempt(prompt_hash="sha256:test")
        json_str = event.to_json()
        
        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed['prompt_hash'] == "sha256:test"
    
    def test_create_event_from_dict_attempt(self):
        """Should recreate GenerationAttempt from dict."""
        original = GenerationAttempt(
            event_id="test-id",
            prompt_hash="sha256:test",
            session_id="sess_001"
        )
        d = original.to_dict()
        
        recreated = create_event_from_dict(d)
        
        assert isinstance(recreated, GenerationAttempt)
        assert recreated.event_id == original.event_id
        assert recreated.prompt_hash == original.prompt_hash
    
    def test_create_event_from_dict_denial(self):
        """Should recreate GenerationDenial from dict."""
        original = GenerationDenial(
            event_id="test-id",
            attempt_id="attempt-123",
            risk_category=RiskCategory.NCII_RISK,
            risk_score=0.95
        )
        d = original.to_dict()
        
        recreated = create_event_from_dict(d)
        
        assert isinstance(recreated, GenerationDenial)
        assert recreated.risk_category == RiskCategory.NCII_RISK
        assert recreated.risk_score == 0.95
    
    def test_create_event_from_dict_invalid_type(self):
        """Should raise error for invalid event type."""
        with pytest.raises(ValueError):
            create_event_from_dict({'event_type': 'INVALID'})
    
    def test_create_event_from_dict_missing_type(self):
        """Should raise error for missing event type."""
        with pytest.raises(ValueError):
            create_event_from_dict({})
