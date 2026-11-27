"""Session filters must retain attempts and their outcomes in generated demo data."""

from click.testing import CliRunner
from streamlit.testing.v1 import AppTest

from cap_srp.cli import main
from cap_srp.core.events import EventType
from cap_srp.core.serialization import load_event_log


def assert_session_links(events):
    attempts = {
        event.event_id: event.session_id
        for event in events
        if event.event_type == EventType.GEN_ATTEMPT
    }
    assert len(set(attempts.values())) > 1
    assert "" not in attempts.values()
    assert {event.event_type for event in events} == set(EventType)
    for event in events:
        if event.event_type != EventType.GEN_ATTEMPT:
            assert event.session_id == attempts[event.attempt_id]


def test_cli_generated_outcomes_share_the_attempt_session(tmp_path):
    output = tmp_path / "demo.json"
    result = CliRunner().invoke(main, [
        "generate", "--events", "25", "--seed", "4", "--error-rate", "0.25",
        "--output", str(output),
    ])
    assert result.exit_code == 0, result.output
    _, events = load_event_log(output)
    assert_session_links(events)


def test_dashboard_custom_demo_outcomes_share_the_attempt_session():
    app = AppTest.from_string("""
import random
from cap_srp.dashboard.app import render_sidebar
random.seed(4)
render_sidebar()
""")
    app.run(timeout=20)
    custom = next(button for button in app.sidebar.button if "Custom Demo" in button.label)
    custom.click().run(timeout=20)
    assert not app.exception
    assert_session_links(app.session_state["logger"].events)
