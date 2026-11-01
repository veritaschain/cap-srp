# Verification hardening (draft change, 1 November 2026)

This repair concerns the legacy CAP-SRP implementation, not a new normative CAP/VAP version, external audit or production approval.

## Changed contract

`MerkleTree.verify_inclusion_proof(event_digest, proof, expected_root)` now uses the caller's original event digest (the value passed to `add_leaf`, optionally with `sha256:`). It applies the leaf-domain hash itself. Passing `proof.leaf_hash` as the target is no longer accepted: that circular invocation never identified the intended event. Existing positive tests now use their original input digests; no failing test was removed.

The verifier validates digest widths, size/index types and range, direction and path length, root consistency and the entire path. The tree construction and existing event/hash/signature bytes are unchanged. Structural consistency does NOT independently authenticate the proof's claimed tree size or index: the caller must bind them to an authenticated tree head / expected position. The supplied root must come from a trusted channel. External anchors and consistency proofs are not validated by this repair.

`ChainVerifier.verify` defaults to requiring actual Ed25519 signature verification. Missing/unsupported/malformed signatures with an available key are INVALID. A missing/malformed public key is INDETERMINATE and cannot set `is_valid=True`. Empty logs do not count as authenticated success. `signature_status` is included in the result dictionary. Explicit `verify_signatures=False` remains available for local hash-only inspection and reports NOT_CHECKED; its `is_valid` is not authentication.

`full_verification` no longer disables signatures when the caller omits a key. Users of the prior no-key success behavior must provide a separately trusted key or explicitly perform hash-only inspection. Neither a supplied public key nor this verifier proves provider identity, source completeness, trusted time, clinical correctness, legal conformity or certification.

## Evidence

The first regression-only commit (3611891c3489bb1c61238563e8634c8416476e0f) deliberately ran against the unchanged implementation. Run 41298211206 reported 18 cases, 16 failures, zero errors/skips. These are failing test cases, not 16 distinct vulnerabilities. Source and JUnit output were retained as a workflow artifact.

The initial repaired source passed 115 local cases covering the new regression suite and existing Merkle/verifier/logger/event tests on Python 3.13.5. CI results are recorded in the PR separately; local success is not CI success. At that point the existing JSON-schema and UUID ordering issues remained visible in the full-suite job. No data in the examples, no previously signed evidence and no standard specification were rewritten.

## Local wire-schema follow-up

Rechecking PR #3 at `342b009bacc2e78e58d3a6b0c478688ba13930a9` on Python 3.12 reproduced five schema failures (126 passes). The four event schemas described bare Base64 signatures and `prev_hash`, while the unchanged serializer emits `ed25519:` followed by Base64 and `previous_hash`. It also emits an empty `user_context_hash` when the caller supplies no optional context digest.

The local PoC schemas now describe those existing representations. Signature syntax requires canonical padded Base64 for exactly 64 bytes, including zero padding bits. Negative cases cover unsupported algorithms, missing prefixes, invalid lengths, trailing newlines, wrong chain-field names and invalid nonempty optional hashes. `additionalProperties: false` is retained. Generated records of all four types also validate through `event.json` with an explicit local reference registry; validation does not depend on a website fetch. Schema structure validation still does not authenticate a signature; the mandatory signature checks in `full_verification` remain necessary.

The follow-up also distinguishes an omitted expected Merkle root (`None`) from an explicitly supplied empty root: the latter is a failed root comparison, not a request to skip the check. README and API guidance now describe the implemented contract.

Local validation after the follow-up: 184 passes and one failure in the 185-case full suite. The remaining failure is the existing `test_ids_are_sortable` assertion when two random UUIDv7 values share a millisecond. The generator and its test have not been changed or skipped. This follow-up changes no serializer bytes, signatures, tree construction, normative CAP/VAP document or published evidence fixture.
