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


@pytest.mark.parametrize('replacement', ['', 'unknown:signature'])
def test_real_logger_full_verification_rejects_removed_or_unsupported_signatures(replacement):
    from cap_srp.core.logger import CAPLogger
    from cap_srp.core.verifier import full_verification
    from cap_srp.core.events import hash_data
    logger = CAPLogger()
    attempt = logger.log_attempt(prompt_hash=hash_data('synthetic prompt'))
    logger.log_generation(attempt_id=attempt.event_id, output_hash=hash_data('synthetic output'))
    assert full_verification(logger.events, logger.public_key, logger.merkle_root).is_valid
    for event in logger.events:
        event.signature = replacement
    result = full_verification(logger.events, logger.public_key, logger.merkle_root)
    assert not result.is_valid
    assert result.chain.signature_status == 'INVALID'
    assert len(result.chain.invalid_signatures) == len(logger.events)


def test_full_verification_and_empty_input_do_not_authenticate_without_a_key():
    from cap_srp.core.logger import CAPLogger
    from cap_srp.core.verifier import full_verification
    from cap_srp.core.events import hash_data
    logger = CAPLogger()
    attempt = logger.log_attempt(prompt_hash=hash_data('synthetic prompt'))
    logger.log_generation(attempt_id=attempt.event_id, output_hash=hash_data('synthetic output'))
    result = full_verification(logger.events, expected_merkle_root=logger.merkle_root)
    assert not result.is_valid
    assert result.chain.signature_status == 'INDETERMINATE'
    assert not full_verification([]).is_valid
    assert not ChainVerifier(logger.public_key).verify([]).is_valid


def test_explicit_hash_only_check_reports_signatures_not_checked():
    event, _ = signed_event()
    event.signature = ''
    result = ChainVerifier().verify([event], verify_signatures=False)
    assert result.is_valid
    assert result.signature_status == 'NOT_CHECKED'
    assert result.to_dict()['signature_status'] == 'NOT_CHECKED'


@pytest.mark.parametrize('key', ['', 'not base64', 'A' * 44, base64.b64encode(bytes(31)).decode()])
def test_malformed_key_is_indeterminate_not_success(key):
    event, _ = signed_event()
    result = ChainVerifier(key).verify([event])
    assert not result.is_valid
    assert result.signature_status == 'INDETERMINATE'


def test_all_small_tree_positions_match_separate_recursive_reference():
    def root(data):
        if len(data) == 1:
            return hashlib.sha256(b'\x00' + bytes.fromhex(data[0])).digest()
        k = 1 << ((len(data) - 1).bit_length() - 1)
        return hashlib.sha256(b'\x01' + root(data[:k]) + root(data[k:])).digest()
    for size in range(1, 34):
        data = [event_digest(f'leaf:{i}') for i in range(size)]
        tree = MerkleTree.from_leaves(data)
        assert tree.root == root(data).hex()
        for index, digest in enumerate(data):
            proof = tree.get_inclusion_proof(index)
            assert tree.verify_inclusion_proof(digest, proof, tree.root)
            assert tree.verify_inclusion_proof('sha256:' + digest, proof, tree.root)
            assert not tree.verify_inclusion_proof(event_digest('not in tree'), proof, tree.root)


@pytest.mark.parametrize('hash_value', [None, '', 'g' * 64, '0' * 63, '0 ' * 32, 'sha256:' * 2 + '0' * 64])
def test_malformed_target_digest_returns_false(hash_value):
    tree = MerkleTree.from_leaves([event_digest('A')])
    assert not tree.verify_inclusion_proof(hash_value, tree.get_inclusion_proof(0), tree.root)


def test_trailing_proof_step_is_rejected():
    target = event_digest('A')
    tree = MerkleTree.from_leaves([target, event_digest('B')])
    proof = tree.get_inclusion_proof(0)
    proof.proof_hashes.append('0' * 64)
    proof.proof_directions.append(1)
    assert not tree.verify_inclusion_proof(target, proof, tree.root)


def test_explicit_empty_expected_root_does_not_skip_merkle_verification():
    from cap_srp.core.logger import CAPLogger
    from cap_srp.core.verifier import full_verification
    from cap_srp.core.events import hash_data
    logger = CAPLogger()
    attempt = logger.log_attempt(prompt_hash=hash_data('synthetic prompt'))
    logger.log_generation(attempt.event_id, hash_data('synthetic output'))
    result = full_verification(logger.events, logger.public_key, expected_merkle_root='')
    assert not result.is_valid
    assert result.merkle_root_valid is False
