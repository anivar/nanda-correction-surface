"""Tests for the protocol explorer trace engine and app (in-process, no services)."""

from fastapi.testclient import TestClient

from explorer.app import app
from explorer.trace import SCENARIOS, walk

client = TestClient(app)


def test_every_scenario_produces_a_trace():
    for s in SCENARIOS:
        r = walk(s)
        assert r["scenario"] == s and r["steps"]


def test_resolve_completes_with_boundary():
    r = walk("resolve")
    assert r["refused"] is False
    assert any(st["boundary"] for st in r["steps"])  # the paper→extension boundary is drawn


def test_tamper_fails_closed_early():
    r = walk("tamper")
    assert r["refused"] is True
    assert r["steps"][-1]["status"] == "fail"


def test_spoof_fails_closed():
    assert walk("spoof")["refused"] is True


def test_exit_fails_closed_at_extension():
    r = walk("exit")
    assert r["refused"] is True
    assert any(st["layer"] == "extension" for st in r["steps"])


def test_contest_surfaces_extension_step():
    r = walk("contest")
    assert r["refused"] is False
    assert any(st["layer"] == "extension" for st in r["steps"])


def test_unknown_scenario_defaults_to_resolve():
    assert walk("nonexistent")["scenario"] == "resolve"


def test_app_endpoints():
    assert client.get("/healthz").json()["status"] == "ok"
    assert len(client.get("/api/scenarios").json()["scenarios"]) == len(SCENARIOS)
    assert client.get("/").status_code == 200
    assert client.get("/api/walk", params={"scenario": "exit"}).json()["refused"] is True
