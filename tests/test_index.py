"""Integration tests for the lean index service (in-process, no network)."""

from fastapi.testclient import TestClient

from index.app import app
from nanda_core import crypto, didkey

client = TestClient(app)


def _register(name="urn:agent:acme:translator"):
    return client.post(
        "/register",
        json={
            "agent_name": name,
            "agent_did": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            "primary_facts_url": "http://facts-primary:8000/facts/x",
            "private_facts_url": "http://facts-neutral:8000/facts/x",
            "ttl": 3600,
        },
    )


def test_register_requires_agent_did():
    """agent_did is mandatory: every signed AgentAddr must bind an identity."""
    r = client.post(
        "/register",
        json={
            "agent_name": "urn:agent:acme:no-did",
            "primary_facts_url": "http://facts-primary:8000/facts/x",
            "ttl": 3600,
        },
    )
    assert r.status_code == 422


def test_register_then_resolve_is_signed_by_resolver():
    r = _register("urn:agent:acme:t1")
    assert r.status_code == 200
    resolver_did = client.get("/resolver").json()["did"]

    signed = client.get("/resolve", params={"name": "urn:agent:acme:t1"}).json()
    assert signed["agent_name"] == "urn:agent:acme:t1"
    assert signed["proof"]["verificationMethod"].startswith(resolver_did)

    pub = didkey.decode_did_key(signed["proof"]["verificationMethod"])
    assert crypto.verify_record(signed, pub) is True


def test_resolve_unknown_is_404():
    assert client.get("/resolve", params={"name": "urn:agent:nope"}).status_code == 404


def test_tampered_resolution_fails_verification():
    _register("urn:agent:acme:t2")
    signed = client.get("/resolve", params={"name": "urn:agent:acme:t2"}).json()
    pub = didkey.decode_did_key(signed["proof"]["verificationMethod"])
    signed["primary_facts_url"] = "http://evil.example/facts"
    assert crypto.verify_record(signed, pub) is False
