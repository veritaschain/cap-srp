# CAP-SRP JSON Schemas

JSON Schema definitions for this PoC's local event format. These schemas are not the canonical CAP v1.0 schemas or a VAP v1.2 envelope. Validation does not establish CAP/VAP conformance; see the [current status and limits](../README.md#canonical-specifications-and-status).

## Architecture

```
event.json (Entry Point)
    │
    └── oneOf ──┬── gen-attempt.json   GEN_ATTEMPT
                ├── gen-success.json   GEN (success)
                ├── gen-deny.json      GEN_DENY
                └── gen-error.json     GEN_ERROR
```

**Usage:** Always reference `event.json` as the entry point. It uses `oneOf` to dispatch to the correct event-specific schema based on `event_type`.

## Files

| File | Event Type | Description |
|------|------------|-------------|
| `event.json` | — | **Entry point**: Union schema (oneOf) |
| `gen-attempt.json` | `GEN_ATTEMPT` | Generation attempt (logged BEFORE evaluation) |
| `gen-success.json` | `GEN` | Generation succeeded |
| `gen-deny.json` | `GEN_DENY` | Generation denied (safety filter triggered) |
| `gen-error.json` | `GEN_ERROR` | Generation failed (system error) |

## Schema URIs

All schemas include `$schema` and `$id`:

```
$schema: https://json-schema.org/draft/2020-12/schema
$id:     https://veritaschain.org/schemas/cap-srp/v0.1/{filename}
```

## Usage

### Python (jsonschema)

```python
import json
import jsonschema
from pathlib import Path

# Load schema
schema_path = Path(__file__).parent / "schemas" / "gen-deny.json"
with open(schema_path) as f:
    schema = json.load(f)

# Validate event
event = {
    "event_id": "01947a1b-0001-7000-0000-000000000001",
    "event_type": "GEN_DENY",
    "timestamp": "2026-01-28T12:00:00Z",
    "attempt_id": "01947a1b-0000-7000-0000-000000000001",
    "risk_category": "NCII_RISK",
    "risk_score": 0.95
}

jsonschema.validate(event, schema)  # Raises if invalid
```

### JavaScript/Node.js (ajv)

```javascript
import Ajv from "ajv";
import addFormats from "ajv-formats";
import schema from "./schemas/gen-deny.json";

const ajv = new Ajv();
addFormats(ajv);
const validate = ajv.compile(schema);

const event = {
  event_id: "01947a1b-0001-7000-0000-000000000001",
  event_type: "GEN_DENY",
  // ...
};

if (!validate(event)) {
  console.error(validate.errors);
}
```

## Risk Categories

The `risk_category` field in GEN_DENY uses the following taxonomy:

| Category | Description |
|----------|-------------|
| `NCII_RISK` | Non-consensual intimate imagery |
| `CSAM_RISK` | Child sexual abuse material |
| `REAL_PERSON_DEEPFAKE` | Deepfake of identifiable person |
| `SEXUAL_EXPLICIT` | Explicit sexual content |
| `VIOLENCE_GRAPHIC` | Graphic violence |
| `HATE_CONTENT` | Hate speech/imagery |
| `TERRORISM` | Terrorism-related content |
| `SELF_HARM` | Self-harm promotion |
| `ILLEGAL_ACTIVITY` | Illegal activities |
| `DRUG_RELATED` | Drug-related content |
| `WEAPONS` | Weapons instructions |
| `MISINFORMATION` | Misinformation |
| `ELECTION_INTERFERENCE` | Election interference |
| `PRIVACY_VIOLATION` | Privacy violations |
| `PII_EXPOSURE` | PII exposure |
| `COPYRIGHT_VIOLATION` | Copyright infringement |
| `IDENTITY_FRAUD` | Identity fraud |
| `DISCRIMINATION` | Discriminatory content |
| `SPAM` | Spam content |
| `OTHER` | Other policy violations |

## Completeness Invariant

All events must satisfy the CAP v1.0 SRP attempt–outcome invariant (CAP v1.0 §13):

```
Σ GEN_ATTEMPT = Σ GEN + Σ GEN_DENY + Σ GEN_ERROR
```

Every recorded GEN_ATTEMPT must have exactly one corresponding outcome event. A request that was never recorded leaves nothing to detect. This profile-level invariant is distinct from the VAP v1.2 Completeness Invariant (INT-008).

## Standards Alignment

These schemas are a local PoC format, informed by CAP v1.0 (VSO-CAP-SPEC-001) §12–§14 and the SRP event set (GEN_ATTEMPT, GEN, GEN_DENY, GEN_ERROR). They are not the CAP v1.0 Appendix A schemas and not a VAP v1.2 envelope. No conformance to CAP, VAP, ISO/IEC 24970 or any regulation is claimed.
