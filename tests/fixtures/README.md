# Synthetic serialization compatibility fixture

`signed-events-before-deserialization-fix.json` was emitted using the event,
signing and Merkle implementations at commit
`2f8f2a1ea97ba862851a325fb943961c1202a224`, before the UUID/parser follow-up.
It contains three synthetic attempts and one outcome of each type. IDs,
timestamps, model/session names and prompt/output texts were fixed test values.
The Ed25519 key uses the deliberately public test seed `bytes(range(32))`.
It is not a production key or real refusal record.

The fixture is kept as previously signed bytes: the tests restore all event
types, reproduce their existing hashes, verify their existing signatures and
check the fixed root. No real or previously published evidence pack is changed.
