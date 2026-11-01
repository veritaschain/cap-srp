"""Actual CLI/JSON boundary tests with authentic synthetic Ed25519 signatures."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

from click.testing import CliRunner
import pytest

from cap_srp.cli import main
from cap_srp.core.events import EventType, RiskCategory, create_event_from_dict, hash_data
from cap_srp.core.logger import CAPLogger
from cap_srp.core.serialization import load_event_log
from cap_srp.core.verifier import full_verification


FIXTURE = Path(__file__).parent / "fixtures" / "signed-events-before-deserialization-fix.json"
PUBLIC_KEY = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
ROOT = "b3abdcba1a2d04ec9d3b5015029e830c66ddc3d5cc4a6a08c22583054e9971fc"
EXPECTED_TRUST_CONTEXT = {
    "scope": "LOCAL_SUPPLIED_RECORDS",
    "trust_material": "FILE_DECLARED",
    "producer_identity": "NOT_CHECKED",
    "external_anchor": "NOT_CHECKED",
    "source_completeness": "NOT_CHECKED",
}


@pytest.fixture
def payload():
    return json.loads(FIXTURE.read_text())


def write_payload(tmp_path, payload):
    path = tmp_path / "events.json"
    path.write_text(json.dumps(payload))
    return path


def test_existing_signed_bytes_round_trip_for_all_four_types(payload):
    original = deepcopy(payload)
    events = [create_event_from_dict(item) for item in payload["events"]]
    assert payload == original  # No mutation of the caller's JSON.
    assert {event.event_type for event in events} == set(EventType)
    assert events[3].risk_category is RiskCategory.OTHER
    assert [event.to_dict() for event in events] == original["events"]
    assert all(event.compute_hash() == raw["current_hash"] for event, raw in zip(events, original["events"]))
    result = full_verification(events, public_key=PUBLIC_KEY, expected_merkle_root=ROOT)
    assert result.is_valid
    assert result.chain.signature_status == "VALID"
    assert result.merkle_root_valid


@pytest.mark.parametrize("index", [0, 1, 3, 5])
def test_unknown_signed_field_is_not_discarded(payload, index):
    payload["events"][index]["unverified_extra"] = "cannot silently ignore this"
    with pytest.raises(ValueError, match="fields"):
        create_event_from_dict(payload["events"][index])


@pytest.mark.parametrize("name", ["event_id", "timestamp", "signature", "current_hash", "previous_hash", "session_id", "user_context_hash"])
def test_missing_serialized_field_is_not_defaulted(payload, name):
    del payload["events"][0][name]
    with pytest.raises(ValueError):
        create_event_from_dict(payload["events"][0])


@pytest.mark.parametrize("name,value", [("event_id", ""), ("timestamp", ""), ("event_type", 1), ("session_id", None), ("current_hash", []), ("signature", False)])
def test_invalid_event_field_types_are_rejected(payload, name, value):
    payload["events"][0][name] = value
    with pytest.raises(ValueError):
        create_event_from_dict(payload["events"][0])


@pytest.mark.parametrize("value", [True, "0.5", float("nan"), float("inf"), -0.1, 1.1, 10**1000])
def test_invalid_risk_score_is_not_coerced(payload, value):
    payload["events"][3]["risk_score"] = value
    with pytest.raises(ValueError):
        create_event_from_dict(payload["events"][3])


@pytest.mark.parametrize("value", [None, "", "UNKNOWN", [], 1])
def test_risk_category_preserved_or_rejected_explicitly(payload, value):
    payload["events"][3]["risk_category"] = value
    if value is None:
        event = create_event_from_dict(payload["events"][3])
        assert event.risk_category is None
        assert event.to_dict() == payload["events"][3]
    else:
        with pytest.raises(ValueError):
            create_event_from_dict(payload["events"][3])


def test_numeric_representation_and_unicode_are_not_normalized(payload):
    row = payload["events"][3]
    row["session_id"] = "日本語-e\u0301"
    row["risk_score"] = 1
    integer = create_event_from_dict(row)
    row["risk_score"] = 1.0
    floating = create_event_from_dict(row)
    assert type(integer.risk_score) is int
    assert type(floating.risk_score) is float
    assert integer.compute_hash() != floating.compute_hash()
    assert floating.to_dict()["session_id"] == row["session_id"]


def test_generated_export_is_verified_and_reported_through_cli(tmp_path):
    path = tmp_path / "generated.json"
    runner = CliRunner()
    generated = runner.invoke(main, ["generate", "--events", "20", "--seed", "42", "--denial-rate", "0.4", "--error-rate", "0.2", "--output", str(path)])
    assert generated.exit_code == 0, generated.output
    original = path.read_bytes()
    verification = runner.invoke(main, ["verify", str(path), "--json-output"])
    assert verification.exit_code == 0, verification.output
    result = json.loads(verification.output)
    assert result["is_valid"] is True
    assert result["trust_context"] == EXPECTED_TRUST_CONTEXT
    assert result["chain"]["signature_status"] == "VALID"
    assert result["chain"]["events_verified"] == 40
    report = tmp_path / "report.txt"
    reporting = runner.invoke(main, ["report", str(path), "--output", str(report)])
    assert reporting.exit_code == 0, reporting.output
    assert "Overall: ✅ PASS" in report.read_text()
    assert "Signatures: VALID" in report.read_text()
    assert "not independent trust material" in report.read_text()
    assert path.read_bytes() == original


def test_cli_accepts_fixed_pre_repair_signed_fixture():
    result = CliRunner().invoke(main, ["verify", str(FIXTURE), "--json-output"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["is_valid"] is True
    assert data["trust_context"] == EXPECTED_TRUST_CONTEXT
    assert data["completeness"]["total_attempts"] == 3
    assert data["completeness"]["total_generations"] == 1
    assert data["completeness"]["total_denials"] == 1
    assert data["completeness"]["total_errors"] == 1


@pytest.mark.parametrize("signature", ["", "unsupported:value", "ed25519:" + "A" * 86 + "=="])
def test_cli_and_report_do_not_pass_unverified_signatures(tmp_path, payload, signature):
    for row in payload["events"]:
        row["signature"] = signature
    path = write_payload(tmp_path, payload)
    runner = CliRunner()
    checked = runner.invoke(main, ["verify", str(path), "--json-output"])
    assert checked.exit_code == 1
    result = json.loads(checked.output)
    assert result["is_valid"] is False
    assert result["trust_context"] == EXPECTED_TRUST_CONTEXT
    assert result["chain"]["signature_status"] == "INVALID"
    report = runner.invoke(main, ["report", str(path)])
    assert report.exit_code == 1
    assert "Overall: ❌ FAIL" in report.output
    assert "Signatures: INVALID" in report.output


def test_missing_public_key_remains_indeterminate(tmp_path, payload):
    del payload["public_key"]
    path = write_payload(tmp_path, payload)
    checked = CliRunner().invoke(main, ["verify", str(path), "--json-output"])
    assert checked.exit_code == 1
    result = json.loads(checked.output)
    assert result["is_valid"] is False
    assert result["chain"]["signature_status"] == "INDETERMINATE"


@pytest.mark.parametrize("bad_json", ["[]", "{}", '{"events": {}}', '{"events": [], "event_count": true}', '{"events": [], "event_count": 1}', '{"events": [], "version": "2.0"}', '{"events": [], "public_key": []}', '{"events": [], "merkle_root": {}}', '{"events": [], "extra": true}', '{"events": [], "exported_at": null}', '{"events": [], "events": []}', '{"events": [], "event_count": NaN}', '{"events":'])
def test_cli_rejects_malformed_or_ambiguous_json(tmp_path, bad_json):
    path = tmp_path / "bad.json"
    path.write_text(bad_json)
    for command in ("verify", "report"):
        result = CliRunner().invoke(main, [command, str(path)])
        assert result.exit_code == 1
        assert "Invalid event log:" in result.output
        assert "PASSED" not in result.output


def test_duplicate_keys_inside_event_are_rejected(tmp_path, payload):
    serialized = json.dumps(payload)
    serialized = serialized.replace('"risk_score": 0.5', '"risk_score": 0.0, "risk_score": 0.5')
    path = tmp_path / "duplicate.json"
    path.write_text(serialized)
    result = CliRunner().invoke(main, ["verify", str(path)])
    assert result.exit_code == 1
    assert "Duplicate JSON object key" in result.output


def test_import_retains_existing_bytes_and_does_not_claim_signer_identity():
    logger = CAPLogger()
    logger.import_events(FIXTURE)
    raw, _ = load_event_log(FIXTURE)
    assert [event.to_dict() for event in logger.events] == raw["events"]
    assert full_verification(logger.events, PUBLIC_KEY, ROOT).is_valid
    assert logger.public_key != PUBLIC_KEY  # Import does not replace the caller's signer.


def test_failed_import_keeps_original_logger_state(tmp_path, payload):
    logger = CAPLogger()
    first = logger.log_attempt(prompt_hash=hash_data("existing"))
    logger.log_generation(attempt_id=first.event_id, output_hash=hash_data("output"))
    original = [event.to_dict() for event in logger.events]
    original_root = logger.merkle_root
    payload["events"][3]["unverified"] = True
    path = write_payload(tmp_path, payload)
    with pytest.raises(ValueError):
        logger.import_events(path)
    assert [event.to_dict() for event in logger.events] == original
    assert logger.merkle_root == original_root
    next_event = logger.log_attempt(prompt_hash=hash_data("after failed import"))
    assert next_event.previous_hash == original[-1]["current_hash"]


@pytest.mark.parametrize("variant,expected_valid", [("valid", True), ("no_key", False), ("empty_root", False), ("no_signatures", False)])
def test_demo_script_uses_the_same_fail_closed_verifier(tmp_path, payload, variant, expected_valid):
    if variant == "no_key":
        del payload["public_key"]
    elif variant == "empty_root":
        payload["merkle_root"] = ""
    elif variant == "no_signatures":
        for row in payload["events"]:
            row["signature"] = ""
    path = write_payload(tmp_path, payload)
    report = tmp_path / "demo-report.json"
    script = Path(__file__).parent.parent / "examples" / "demo_verify_completeness.py"
    result = subprocess.run([sys.executable, str(script), "-i", str(path), "--report", str(report)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == (0 if expected_valid else 1), result.stdout + result.stderr
    report_data = json.loads(report.read_text())
    assert report_data["overall_valid"] is expected_valid
    assert report_data["trust_context"] == EXPECTED_TRUST_CONTEXT
    assert "producer identity is not authenticated" in result.stdout
