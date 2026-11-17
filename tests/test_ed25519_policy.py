"""Both supported backends must enforce the same bounded Ed25519 input policy."""

import base64
import builtins
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/signed-events-before-deserialization-fix.json"
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
# Published RFC 8032 section 7.1 test 1 (synthetic, public test seed).
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)
SMALL_ORDER = tuple(map(bytes.fromhex, (
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
)))
NONCANONICAL = tuple(
    (y | (sign << 255)).to_bytes(32, "little")
    for y in range(P, 2**255) for sign in (0, 1)
) + tuple((y | (1 << 255)).to_bytes(32, "little") for y in (1, P - 1))


def encoded(value):
    return base64.b64encode(value).decode("ascii")


@pytest.fixture(params=["pynacl", "cryptography"])
def signer_module(request, monkeypatch):
    """Actually import each backend, including the real ImportError fallback."""
    name = "cap_srp_signer_test_" + request.param
    spec = importlib.util.spec_from_file_location(name, ROOT / "cap_srp/core/signer.py")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    original_import = builtins.__import__

    def without_nacl(name, *args, **kwargs):
        if name == "nacl" or name.startswith("nacl."):
            raise ImportError("exercise the supported cryptography fallback")
        return original_import(name, *args, **kwargs)

    with monkeypatch.context() as context:
        if request.param == "cryptography":
            context.setattr(builtins, "__import__", without_nacl)
        spec.loader.exec_module(module)
    assert module.NACL_AVAILABLE is (request.param == "pynacl")
    return module


def test_rfc8032_vector_and_public_apis(signer_module):
    signer = signer_module.Ed25519Signer.from_private_key(SEED)
    assert signer.public_key == PUBLIC
    assert signer.sign(b"").signature == SIGNATURE
    assert signer.verify(b"", SIGNATURE).is_valid
    assert signer.verify_b64(b"", encoded(SIGNATURE)).is_valid
    assert signer.verify_with_public_key(b"", SIGNATURE, PUBLIC).is_valid
    assert signer.verify_with_public_key_b64(b"", encoded(SIGNATURE), encoded(PUBLIC)).is_valid
    assert not signer.verify(b"changed", SIGNATURE).is_valid
    other_key = signer_module.Ed25519Signer.from_private_key(bytes(range(32))).public_key
    assert not signer.verify_with_public_key(b"", SIGNATURE, other_key).is_valid
    generated = signer.sign("日本語-e\u0301".encode())
    assert signer.verify("日本語-e\u0301".encode(), generated.signature).is_valid
    assert not signer.verify("日本語-é".encode(), generated.signature).is_valid


def test_table_exhausts_eight_distinct_small_order_points():
    # Independent test-only decoding/doubling, RFC 8032 sections 5.1.3–5.1.4.
    # Production delegates curve decoding and the signature equation to a library.
    d = -121665 * pow(121666, -1, P) % P
    root_minus_one = pow(2, (P - 1) // 4, P)
    decoded = set()
    for raw in SMALL_ORDER:
        integer = int.from_bytes(raw, "little")
        y, sign = integer & (2**255 - 1), integer >> 255
        xx = (y * y - 1) * pow(d * y * y + 1, -1, P) % P
        x = pow(xx, (P + 3) // 8, P)
        if x * x % P != xx:
            x = x * root_minus_one % P
        assert x * x % P == xx
        if x & 1 != sign:
            x = -x % P
        assert x & 1 == sign
        assert (x, y) not in decoded
        decoded.add((x, y))
        for _ in range(3):
            product = d * x * x * y * y % P
            x, y = (
                2 * x * y * pow(1 + product, -1, P) % P,
                (y * y + x * x) * pow(1 - product, -1, P) % P,
            )
        assert (x, y) == (0, 1)
    assert len(decoded) == 8


@pytest.mark.parametrize("point,reason", [
    *((point, "small-order") for point in SMALL_ORDER),
    *((point, "noncanonical") for point in NONCANONICAL),
])
def test_point_policy_covers_public_key_and_signature_r(signer_module, point, reason):
    signer = signer_module.Ed25519Signer.from_private_key(SEED)
    invalid_r = point + SIGNATURE[32:]
    results = (
        signer.verify_with_public_key(b"", SIGNATURE, point),
        signer.verify_with_public_key_b64(b"", encoded(SIGNATURE), encoded(point)),
        signer.verify_with_public_key(b"", invalid_r, PUBLIC),
        signer.verify(b"", invalid_r),
        signer.verify_b64(b"", encoded(invalid_r)),
    )
    for result in results:
        assert not result.is_valid
        assert reason in result.error_message


@pytest.mark.parametrize("scalar", [L, L + 1, 2**256 - 1])
def test_out_of_range_scalar_is_rejected_before_backend(signer_module, scalar):
    signature = SIGNATURE[:32] + scalar.to_bytes(32, "little")
    signer = signer_module.Ed25519Signer.from_private_key(SEED)
    for result in (signer.verify(b"", signature),
                   signer.verify_with_public_key(b"", signature, PUBLIC)):
        assert not result.is_valid
        assert "scalar must be less" in result.error_message


@pytest.mark.parametrize("scalar", [0, L - 1])
def test_in_range_scalar_still_requires_valid_signature_equation(signer_module, scalar):
    signature = SIGNATURE[:32] + scalar.to_bytes(32, "little")
    result = signer_module.Ed25519Signer.verify_with_public_key(b"", signature, PUBLIC)
    assert not result.is_valid
    assert "scalar must be less" not in result.error_message


@pytest.mark.parametrize("value", [None, "text", 32, [], b"", bytes(31), bytes(33)])
def test_bad_public_key_shape_is_a_failed_verification(signer_module, value):
    result = signer_module.Ed25519Signer.verify_with_public_key(b"", SIGNATURE, value)
    assert not result.is_valid
    assert "32 bytes" in result.error_message


@pytest.mark.parametrize("value", [None, "text", 64, [], b"", bytes(63), bytes(65)])
def test_bad_signature_shape_is_a_failed_verification(signer_module, value):
    signer = signer_module.Ed25519Signer.from_private_key(SEED)
    for result in (signer.verify(b"", value),
                   signer.verify_with_public_key(b"", value, PUBLIC)):
        assert not result.is_valid
        assert "64 bytes" in result.error_message


@pytest.mark.parametrize("backend", ["pynacl", "cryptography"])
@pytest.mark.parametrize("forged", [False, True])
@pytest.mark.parametrize("command", ["verify", "report"])
def test_actual_cli_fixed_signed_log_and_identity_forgery(tmp_path, backend, forged, command):
    original = FIXTURE.read_bytes()
    payload = json.loads(original)
    if forged:
        payload["public_key"] = encoded(SMALL_ORDER[0])
        for event in payload["events"]:
            event["signature"] = "ed25519:" + encoded(SMALL_ORDER[0] + bytes(32))
    path = tmp_path / "events.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    # Fresh process: all CLI/verifier imports use the selected real backend.
    script = '''
import builtins
import sys
original_import = builtins.__import__
backend = sys.argv.pop(1)
def without_nacl(name, *args, **kwargs):
    if name == "nacl" or name.startswith("nacl."):
        raise ImportError("exercise the supported cryptography fallback")
    return original_import(name, *args, **kwargs)
if backend == "cryptography":
    builtins.__import__ = without_nacl
from cap_srp.core.signer import NACL_AVAILABLE
assert NACL_AVAILABLE is (backend == "pynacl")
from cap_srp.cli import main
main()
'''
    args = [sys.executable, "-c", script, backend, command, str(path)]
    if command == "verify":
        args.append("--json-output")
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=20)
    assert result.returncode == (1 if forged else 0), result.stdout + result.stderr
    if command == "verify":
        report = json.loads(result.stdout)
        assert report["is_valid"] is (not forged)
        assert report["chain"]["signature_status"] == ("INVALID" if forged else "VALID")
        assert report["completeness"]["is_valid"] is True
        assert report["merkle_root_valid"] is True
        assert report["trust_context"]["producer_identity"] == "NOT_CHECKED"
    else:
        assert ("Overall: ❌ FAIL" if forged else "Overall: ✅ PASS") in result.stdout
        assert ("Signatures: INVALID" if forged else "Signatures: VALID") in result.stdout
    assert FIXTURE.read_bytes() == original
