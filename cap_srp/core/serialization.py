"""Strict loading of the local CAP-SRP JSON export format.

Parsing preserves serialized event values. It does not authenticate the key,
root, event content, metadata or producer; call the verifier separately.
"""

import json

from cap_srp.core.events import create_event_from_dict


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate JSON object key")
        result[name] = value
    return result


def _reject_constant(value):
    raise ValueError("Non-finite JSON number")


def load_event_log(filepath):
    """Return ``(metadata_and_raw_events, restored_events)`` or raise.

    Accepted fields are the version-1 export envelope; ``events`` is required.
    Missing trust material is passed to the fail-closed verifier, not invented.
    """
    with open(filepath, "r", encoding="utf-8") as source:
        data = json.load(source, object_pairs_hook=_unique_object,
                         parse_constant=_reject_constant)
    if not isinstance(data, dict):
        raise ValueError("Event log must be a JSON object")
    allowed = {"version", "exported_at", "public_key", "merkle_root", "event_count", "events"}
    if set(data) - allowed:
        raise ValueError("Unknown event-log envelope field")
    if not isinstance(data.get("events"), list):
        raise ValueError("events must be a JSON array")
    if "version" in data and data["version"] != "1.0.0":
        raise ValueError("Unsupported event-log version")
    if "exported_at" in data and not isinstance(data["exported_at"], str):
        raise ValueError("exported_at must be a string")
    for name in ("public_key", "merkle_root"):
        if name in data and data[name] is not None and not isinstance(data[name], str):
            raise ValueError(f"{name} must be a string or null")
    if "event_count" in data:
        if type(data["event_count"]) is not int or data["event_count"] != len(data["events"]):
            raise ValueError("event_count does not match the supplied events")
    return data, [create_event_from_dict(item) for item in data["events"]]
