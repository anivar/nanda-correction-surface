"""Tests for the Tier-3 agent runtime the client acts on after verification."""
from fastapi.testclient import TestClient

from agent.app import app

client = TestClient(app)


def test_healthz():
    assert client.get("/healthz").json()["status"] == "ok"


def test_translator_invoke():
    r = client.post("/agents/translator/invoke", json={"input": "hello", "task": "demo"})
    assert r.status_code == 200 and r.json()["output"] == "[fr] olleh"


def test_unknown_slug_uppercases():
    r = client.post("/agents/whatever/invoke", json={"input": "hi"})
    assert r.json()["output"] == "HI"
