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


def test_contestation_dedup_by_id():
    client.put(f"/facts/{AGENT_ID}", json=BUNDLE)  # resets contestations
    c = {"contestation_id": "dup1", "x": 1}
    client.post(f"/facts/{AGENT_ID}/contestations", json=c)
    r2 = client.post(f"/facts/{AGENT_ID}/contestations", json=c)
    assert r2.json().get("duplicate") is True
    got = client.get(f"/facts/{AGENT_ID}").json()
    assert sum(1 for x in got["contestations"] if x.get("contestation_id") == "dup1") == 1


def test_severance_is_permanent_first_write_wins():
    # Exit is irrevocable at the host: once a severance is filed, a later POST (e.g.
    # a third party forging one to evict the real exit) must NOT overwrite it.
    aid = "nanda:sev-permanent"
    client.put(f"/facts/{aid}", json={**BUNDLE, "agent_id": aid})
    first = {"agent_did": "did:key:z6MkAgent", "proof": {"sig": "first"}}
    forged = {"agent_did": "did:key:z6MkAttacker", "proof": {"sig": "second"}}
    assert client.post(f"/facts/{aid}/severance", json=first).status_code == 200
    r2 = client.post(f"/facts/{aid}/severance", json=forged)
    assert r2.json().get("duplicate") is True
    got = client.get(f"/facts/{aid}").json()
    assert got["severance"] == first  # the original exit survives the overwrite attempt


def test_severance_preserved_across_reput():
    # Re-hosting the bundle (PUT) must not erase a filed severance — otherwise the
    # contested party could un-sever simply by re-PUTting.
    aid = "nanda:sev-reput"
    client.put(f"/facts/{aid}", json={**BUNDLE, "agent_id": aid})
    sev = {"agent_did": "did:key:z6MkAgent", "proof": {"sig": "abc"}}
    client.post(f"/facts/{aid}/severance", json=sev)
    client.put(f"/facts/{aid}", json={**BUNDLE, "agent_id": aid})  # re-PUT carries no severance
    got = client.get(f"/facts/{aid}").json()
    assert got["severance"] == sev
