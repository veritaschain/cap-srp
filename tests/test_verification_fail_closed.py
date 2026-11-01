"""Synthetic regression tests for target binding and mandatory signatures."""
import base64
import copy
import hashlib
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cap_srp.core.merkle import MerkleTree
from cap_srp.core.verifier import ChainVerifier


def event_digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def signed_event():
    private = Ed25519PrivateKey.generate()
    current = 'sha256:' + event_digest('synthetic-event')
    event = SimpleNamespace(previous_hash='', current_hash=current,
        compute_hash=lambda: current,
        signature='ed25519:' + base64.b64encode(private.sign(current.encode())).decode())
    public = base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    return event, public


def test_valid_target_and_signed_event_still_pass():
    digest = event_digest('A')
    tree = MerkleTree.from_leaves([digest])
    assert tree.verify_inclusion_proof(digest, tree.get_inclusion_proof(0), tree.root)
    event, public = signed_event()
    assert ChainVerifier(public).verify([event]).is_valid


def test_proof_for_a_rejects_target_b():
    tree = MerkleTree.from_leaves([event_digest('A'), event_digest('B')])
    assert not tree.verify_inclusion_proof(event_digest('B'), tree.get_inclusion_proof(0), tree.root)


@pytest.mark.parametrize('signature', [None, '', 'rsa:unverified', 'ed25519', 'ed25519:', 'ed25519:a:b'])
def test_requested_signature_verification_rejects_missing_or_unsupported(signature):
    event, public = signed_event()
    event.signature = signature
    result = ChainVerifier(public).verify([event])
    assert not result.is_valid
    assert result.first_invalid_index == 0


def test_requested_signature_verification_requires_public_key():
    event, _ = signed_event()
    assert not ChainVerifier().verify([event]).is_valid


@pytest.mark.parametrize('field,value', [('tree_size', 0), ('leaf_index', -1), ('leaf_index', 3),
    ('tree_size', True), ('leaf_index', True), ('root_hash', '0' * 64),
    ('proof_directions', []), ('proof_directions', [3, 1])])
def test_proof_rejects_inconsistent_metadata(field, value):
    digest = event_digest('A')
    tree = MerkleTree.from_leaves([digest, event_digest('B'), event_digest('C')])
    proof = tree.get_inclusion_proof(0)
    setattr(proof, field, value)
    assert not tree.verify_inclusion_proof(digest, proof, tree.root)


def test_signature_failure_cannot_be_hidden_by_valid_hashes():
    event, public = signed_event()
    event.signature = 'ed25519:' + base64.b64encode(bytes(64)).decode()
    result = ChainVerifier(public).verify([event])
    assert not result.is_valid
    assert result.first_invalid_index == 0
