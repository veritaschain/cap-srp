"""CLI output must remain parseable and must preserve the evidence it describes."""

import json
import os
from pathlib import Path
import subprocess
import sys

from click.testing import CliRunner
import pytest

from cap_srp.cli import main


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/signed-events-before-deserialization-fix.json"
DEMO = ROOT / "examples/demo_verify_completeness.py"


def run_cli(*arguments, cwd):
    return subprocess.run(
        [sys.executable, "-m", "cap_srp.cli", *map(str, arguments)],
        cwd=cwd, capture_output=True, text=True, timeout=15,
    )


def run_report(command, source, output, cwd):
    if command == "cli":
        return run_cli("report", source, "--output", output, cwd=cwd)
    return subprocess.run(
        [sys.executable, str(DEMO), "--input", str(source), "--report", str(output)],
        cwd=cwd, capture_output=True, text=True, timeout=15,
    )


@pytest.mark.parametrize("missing_key", [False, True])
def test_verbose_json_output_is_one_json_document(tmp_path, missing_key):
    source = tmp_path / "events.json"
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    if missing_key:
        del payload["public_key"]
    source.write_text(json.dumps(payload), encoding="utf-8")
    original = source.read_bytes()

    result = run_cli("verify", source, "--verbose", "--json-output", cwd=tmp_path)

    assert result.returncode == (1 if missing_key else 0)
    output = json.loads(result.stdout)
    assert output["is_valid"] is (not missing_key)
    assert output["trust_context"]["producer_identity"] == "NOT_CHECKED"
    assert "Verifying 6 events..." in result.stderr
    assert "Traceback" not in result.stderr
    assert source.read_bytes() == original


@pytest.mark.parametrize("command", ["cli", "demo"])
@pytest.mark.parametrize("alias", ["same", "relative", "symlink", "hardlink"])
def test_report_cannot_overwrite_input_through_a_path_alias(tmp_path, command, alias):
    source = tmp_path / "events.json"
    original = FIXTURE.read_bytes()
    source.write_bytes(original)
    if alias == "same":
        output = source
    elif alias == "relative":
        output = Path("events.json")
    else:
        output = tmp_path / "report.txt"
        if alias == "symlink":
            output.symlink_to(source)
        else:
            os.link(source, output)

    result = run_report(command, source, output, tmp_path)

    assert result.returncode == 1
    assert "Report output must not refer to the input event log" in result.stdout + result.stderr
    assert "Traceback" not in result.stderr
    assert source.read_bytes() == original
    assert "Report saved to:" not in result.stdout
    assert "Report exported to:" not in result.stdout


@pytest.mark.parametrize("command", ["cli", "demo"])
def test_distinct_report_output_still_works_from_another_directory(tmp_path, command):
    source = tmp_path / "証拠.json"
    original = FIXTURE.read_bytes()
    source.write_bytes(original)
    output = tmp_path / "検証結果.txt"
    output.write_text("previous report", encoding="utf-8")

    result = run_report(command, source, output, tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr
    if command == "cli":
        assert "Overall: ✅ PASS" in output.read_text(encoding="utf-8")
    else:
        assert json.loads(output.read_text(encoding="utf-8"))["overall_valid"] is True
    assert source.read_bytes() == original


@pytest.mark.parametrize("command", ["cli", "demo"])
def test_unwritable_report_destination_has_a_clean_failure(tmp_path, command):
    source = tmp_path / "events.json"
    original = FIXTURE.read_bytes()
    source.write_bytes(original)
    destination = tmp_path / "directory"
    destination.mkdir()

    result = run_report(command, source, destination, tmp_path)

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert source.read_bytes() == original
    assert "Report saved to:" not in result.stdout
    assert "Report exported to:" not in result.stdout


@pytest.mark.parametrize("command", ["cli", "demo"])
def test_looping_output_symlink_has_a_clean_failure(tmp_path, command):
    source = tmp_path / "events.json"
    original = FIXTURE.read_bytes()
    source.write_bytes(original)
    destination = tmp_path / "loop.txt"
    destination.symlink_to(destination.name)

    result = run_report(command, source, destination, tmp_path)

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert source.read_bytes() == original
    assert destination.is_symlink()
    assert "Report saved to:" not in result.stdout
    assert "Report exported to:" not in result.stdout


@pytest.mark.parametrize("child_exit", [0, 7])
def test_dashboard_uses_the_installed_app_and_propagates_child_status(tmp_path, monkeypatch, child_exit):
    # The child is controlled here: this checks launcher behavior, not browser rendering.
    launched = []

    def launch(arguments):
        app = Path(arguments[arguments.index("run") + 1])
        launched.append(app)
        if not app.is_file():
            return subprocess.CompletedProcess(arguments, 2)
        return subprocess.CompletedProcess(arguments, child_exit)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(subprocess, "run", launch)
    result = CliRunner().invoke(main, ["dashboard", "--port", "8502"])

    assert result.exit_code == child_exit, result.output
    assert launched == [(ROOT / "cap_srp/dashboard/app.py").resolve()]
    assert launched[0].is_file()
