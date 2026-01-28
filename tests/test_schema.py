"""
Tests for CAP-SRP JSON Schema Validation

Two-tiered validation:
1. Schema validity: schemas are valid JSON Schema, references resolve
2. Example validation: generated events pass schema validation
"""

import json
import pytest
from pathlib import Path

# Try to import jsonschema, skip tests if not available
try:
    import jsonschema
    from jsonschema import Draft202012Validator, RefResolver
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

from cap_srp.core.logger import CAPLogger
from cap_srp.core.events import RiskCategory, hash_data


SCHEMA_DIR = Path(__file__).parent.parent / "schemas"


def load_schema(name: str) -> dict:
    """Load a schema from the schemas directory."""
    schema_path = SCHEMA_DIR / f"{name}.json"
    with open(schema_path) as f:
        return json.load(f)


def get_resolver() -> RefResolver:
    """Create a resolver for schema references."""
    schema_store = {}
    for schema_file in SCHEMA_DIR.glob("*.json"):
        with open(schema_file) as f:
            schema = json.load(f)
            if "$id" in schema:
                schema_store[schema["$id"]] = schema
    
    base_schema = load_schema("event")
    return RefResolver.from_schema(base_schema, store=schema_store)


# =============================================================================
# Tier 1: Schema Validity Tests
# =============================================================================

@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
class TestSchemaValidity:
    """Tier 1: Schemas are valid JSON Schema and references resolve."""
    
    def test_all_schemas_load(self):
        """All schema files should be valid JSON."""
        schema_files = ["event", "gen-attempt", "gen-success", "gen-deny", "gen-error"]
        for name in schema_files:
            schema = load_schema(name)
            assert "$schema" in schema or "$id" in schema, f"{name}.json missing $schema or $id"
    
    def test_all_schemas_have_required_fields(self):
        """Each event schema should have $schema, $id, title, type."""
        event_schemas = ["gen-attempt", "gen-success", "gen-deny", "gen-error"]
        for name in event_schemas:
            schema = load_schema(name)
            assert "$schema" in schema, f"{name}.json missing $schema"
            assert "$id" in schema, f"{name}.json missing $id"
            assert "title" in schema, f"{name}.json missing title"
            assert schema.get("type") == "object", f"{name}.json should have type: object"
    
    def test_all_event_schemas_have_discriminator(self):
        """Each event schema should have event_type as const (discriminator)."""
        event_schemas = ["gen-attempt", "gen-success", "gen-deny", "gen-error"]
        expected_types = {
            "gen-attempt": "GEN_ATTEMPT",
            "gen-success": "GEN",
            "gen-deny": "GEN_DENY",
            "gen-error": "GEN_ERROR",
        }
        for name in event_schemas:
            schema = load_schema(name)
            props = schema.get("properties", {})
            event_type = props.get("event_type", {})
            assert "const" in event_type, f"{name}.json event_type should be const"
            assert event_type["const"] == expected_types[name], \
                f"{name}.json event_type const mismatch"
            assert "event_type" in schema.get("required", []), \
                f"{name}.json should require event_type"
    
    def test_all_event_schemas_strict_properties(self):
        """Each event schema should have additionalProperties: false."""
        event_schemas = ["gen-attempt", "gen-success", "gen-deny", "gen-error"]
        for name in event_schemas:
            schema = load_schema(name)
            assert schema.get("additionalProperties") is False, \
                f"{name}.json should have additionalProperties: false"
    
    def test_event_schema_has_discriminator_info(self):
        """event.json should document discriminator field."""
        schema = load_schema("event")
        assert "event_type" in schema.get("required", []), \
            "event.json should require event_type"
        props = schema.get("properties", {})
        assert "event_type" in props, "event.json should define event_type"
        assert "enum" in props["event_type"], "event.json event_type should have enum"
    
    def test_event_schema_references_resolve(self):
        """event.json oneOf references should all resolve."""
        resolver = get_resolver()
        event_schema = load_schema("event")
        
        assert "oneOf" in event_schema, "event.json should have oneOf"
        
        for ref_obj in event_schema["oneOf"]:
            ref = ref_obj.get("$ref")
            assert ref is not None, "Each oneOf item should have $ref"
            # This will raise if reference doesn't resolve
            with resolver.resolving(ref) as resolved:
                assert "event_type" in resolved.get("properties", {}), \
                    f"Referenced schema {ref} should have event_type property"
    
    def test_schema_validator_can_be_created(self):
        """Draft202012Validator should instantiate for all schemas."""
        resolver = get_resolver()
        schema_files = ["gen-attempt", "gen-success", "gen-deny", "gen-error"]
        
        for name in schema_files:
            schema = load_schema(name)
            # This will raise if schema is invalid
            validator = Draft202012Validator(schema, resolver=resolver)
            Draft202012Validator.check_schema(schema)


# =============================================================================
# Tier 2: Example Validation Tests
# =============================================================================

@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
class TestExampleValidation:
    """Tier 2: Generated events pass schema validation."""
    
    @pytest.fixture
    def resolver(self):
        return get_resolver()
    
    @pytest.fixture
    def logger(self):
        return CAPLogger(model_id="test-model", policy_version="v1.0.0")
    
    def test_gen_attempt_example(self, logger, resolver):
        """GEN_ATTEMPT event should validate against schema."""
        schema = load_schema("gen-attempt")
        validator = Draft202012Validator(schema, resolver=resolver)
        
        attempt = logger.log_attempt(
            prompt_hash=hash_data("test prompt"),
            session_id="sess_001"
        )
        
        event_dict = attempt.to_dict()
        validator.validate(event_dict)  # Raises if invalid
    
    def test_gen_success_example(self, logger, resolver):
        """GEN (success) event should validate against schema."""
        schema = load_schema("gen-success")
        validator = Draft202012Validator(schema, resolver=resolver)
        
        attempt = logger.log_attempt(prompt_hash=hash_data("test"))
        gen = logger.log_generation(
            attempt_id=attempt.event_id,
            output_hash=hash_data("output")
        )
        
        event_dict = gen.to_dict()
        validator.validate(event_dict)
    
    def test_gen_deny_example(self, logger, resolver):
        """GEN_DENY event should validate against schema."""
        schema = load_schema("gen-deny")
        validator = Draft202012Validator(schema, resolver=resolver)
        
        attempt = logger.log_attempt(prompt_hash=hash_data("test"))
        denial = logger.log_denial(
            attempt_id=attempt.event_id,
            risk_category=RiskCategory.NCII_RISK,
            risk_score=0.95,
            denial_reason="POLICY_VIOLATION:NCII_DETECTED"
        )
        
        event_dict = denial.to_dict()
        validator.validate(event_dict)
    
    def test_gen_error_example(self, logger, resolver):
        """GEN_ERROR event should validate against schema."""
        schema = load_schema("gen-error")
        validator = Draft202012Validator(schema, resolver=resolver)
        
        attempt = logger.log_attempt(prompt_hash=hash_data("test"))
        error = logger.log_error(
            attempt_id=attempt.event_id,
            error_code="E001",
            error_message="GPU memory exceeded"
        )
        
        event_dict = error.to_dict()
        validator.validate(event_dict)
    
    def test_all_risk_categories_valid(self, logger, resolver):
        """All RiskCategory enum values should be valid in schema."""
        schema = load_schema("gen-deny")
        validator = Draft202012Validator(schema, resolver=resolver)
        
        for category in RiskCategory:
            attempt = logger.log_attempt(prompt_hash=hash_data(f"test_{category}"))
            denial = logger.log_denial(
                attempt_id=attempt.event_id,
                risk_category=category
            )
            
            event_dict = denial.to_dict()
            validator.validate(event_dict)


# =============================================================================
# Negative Tests: Invalid Events Should Fail
# =============================================================================

@pytest.mark.skipif(not HAS_JSONSCHEMA, reason="jsonschema not installed")
class TestSchemaRejection:
    """Invalid events should fail schema validation."""
    
    @pytest.fixture
    def resolver(self):
        return get_resolver()
    
    def test_missing_required_field_fails(self, resolver):
        """Missing required field should fail validation."""
        schema = load_schema("gen-attempt")
        validator = Draft202012Validator(schema, resolver=resolver)
        
        invalid_event = {
            "event_id": "01947a1b-0001-7000-0000-000000000001",
            "event_type": "GEN_ATTEMPT",
            "timestamp": "2026-01-28T12:00:00Z"
            # Missing: prompt_hash
        }
        
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(invalid_event)
    
    def test_wrong_event_type_fails(self, resolver):
        """Wrong event_type for schema should fail validation."""
        schema = load_schema("gen-attempt")
        validator = Draft202012Validator(schema, resolver=resolver)
        
        wrong_type_event = {
            "event_id": "01947a1b-0001-7000-0000-000000000001",
            "event_type": "GEN_DENY",  # Wrong type for gen-attempt schema
            "timestamp": "2026-01-28T12:00:00Z",
            "prompt_hash": "sha256:" + "a" * 64
        }
        
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(wrong_type_event)
    
    def test_invalid_hash_format_fails(self, resolver):
        """Invalid hash format should fail validation."""
        schema = load_schema("gen-attempt")
        validator = Draft202012Validator(schema, resolver=resolver)
        
        invalid_hash_event = {
            "event_id": "01947a1b-0001-7000-0000-000000000001",
            "event_type": "GEN_ATTEMPT",
            "timestamp": "2026-01-28T12:00:00Z",
            "prompt_hash": "not-a-valid-hash"  # Should be sha256:...
        }
        
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(invalid_hash_event)
    
    def test_risk_score_out_of_bounds_fails(self, resolver):
        """Risk score outside 0.0-1.0 should fail validation."""
        schema = load_schema("gen-deny")
        validator = Draft202012Validator(schema, resolver=resolver)
        
        invalid_score = {
            "event_id": "01947a1b-0001-7000-0000-000000000001",
            "event_type": "GEN_DENY",
            "timestamp": "2026-01-28T12:00:00Z",
            "attempt_id": "01947a1b-0000-7000-0000-000000000001",
            "risk_category": "NCII_RISK",
            "risk_score": 1.5  # Invalid: > 1.0
        }
        
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(invalid_score)
