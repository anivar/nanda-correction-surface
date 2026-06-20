"""Integration tests for the AgentFacts host (store, serve, append contestation)."""
from fastapi.testclient import TestClient

from facts.app import app

client = TestClient(app)

AGENT_ID = "nanda:abc-123"
BUNDLE = {
    "agent_id": AGENT_ID,
    "agent_did": "did:key:z6MkAgent",
    "agent_name": "urn:agent:acme:t",
    "label": "T",
    "provider_vc": "provider.jwt.token",
    "auditor_vc": "auditor.jwt.token",
    "contestations": [],
}


def test_put_get_roundtrip_preserves_vcs():
    assert client.put(f"/facts/{AGENT_ID}", json=BUNDLE).status_code == 200
    got = client.get(f"/facts/{AGENT_ID}").json()
    assert got["provider_vc"] == "provider.jwt.token"
    assert got["auditor_vc"] == "auditor.jwt.token"


def test_missing_facts_is_404():
    assert client.get("/facts/nanda:does-not-exist").status_code == 404


def test_append_contestation():
    client.put(f"/facts/{AGENT_ID}", json=BUNDLE)
    r = client.post(f"/facts/{AGENT_ID}/contestations", json={"contestation_id": "c1", "x": 1})
    assert r.status_code == 200 and r.json()["contestations"] == 1
    got = client.get(f"/facts/{AGENT_ID}").json()
    assert got["contestations"][0]["contestation_id"] == "c1"
