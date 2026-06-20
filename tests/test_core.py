"""Unit tests for the cryptographic core: canonicalisation, signed records, did:key."""

import pytest

from nanda_core import crypto, didkey
from nanda_core.canonical import canonicalize


def test_jcs_is_order_independent():
    a = canonicalize({"b": 1, "a": 2})
    b = canonicalize({"a": 2, "b": 1})
    assert a == b == b'{"a":2,"b":1}'


def test_jcs_normalises_numbers():
    # 1.0 -> 1 (ECMAScript number formatting), per RFC 8785.
    assert canonicalize({"n": 1.0}) == b'{"n":1}'


def test_sign_and_verify_record_roundtrip():
    priv = crypto.generate_private_key()
    rec = {"agent_id": "nanda:x", "ttl": 3600}
    signed = crypto.sign_record(rec, priv, verification_method="did:key:zX#zX")
    assert "proof" in signed and signed["proof"]["sig"]
    assert crypto.verify_record(signed, priv.public_key()) is True


def test_tamper_is_detected():
    priv = crypto.generate_private_key()
    signed = crypto.sign_record({"ttl": 3600}, priv)
    signed["ttl"] = 9999  # mutate a signed field
    assert crypto.verify_record(signed, priv.public_key()) is False


def test_wrong_key_is_rejected():
    priv = crypto.generate_private_key()
    other = crypto.generate_private_key()
    signed = crypto.sign_record({"ttl": 3600}, priv)
    assert crypto.verify_record(signed, other.public_key()) is False


def test_missing_proof_fails_closed():
    priv = crypto.generate_private_key()
    assert crypto.verify_record({"ttl": 3600}, priv.public_key()) is False


def test_wrong_length_signature_fails_closed():
    # A valid-base64 but wrong-length signature must return False, not raise.
    priv = crypto.generate_private_key()
    signed = crypto.sign_record({"ttl": 3600}, priv)
    signed["proof"]["sig"] = crypto.b64u_encode(b"too-short")
    assert crypto.verify_record(signed, priv.public_key()) is False


def test_did_key_roundtrip_and_prefix():
    priv = crypto.generate_private_key()
    did = didkey.did_from_private(priv)
    assert did.startswith("did:key:z6Mk")  # Ed25519 multicodec signature
    recovered = didkey.decode_did_key(did)
    # The recovered key verifies a signature made by the original.
    sig = priv.sign(b"hello")
    assert crypto.verify_bytes(recovered, sig, b"hello") is True


def test_did_key_verification_method_has_fragment():
    priv = crypto.generate_private_key()
    did = didkey.did_from_private(priv)
    vm = didkey.verification_method(did)
    assert vm == f"{did}#{did.removeprefix('did:key:')}"
    # decode_did_key tolerates the fragment form (used as JWT kid).
    assert didkey.decode_did_key(vm).public_bytes_raw() == priv.public_key().public_bytes_raw()


def test_decode_rejects_garbage():
    for bad in ["", "did:web:example.com", "did:key:Qxxx", "did:key:z!!!"]:
        with pytest.raises(ValueError):
            didkey.decode_did_key(bad)
