"""Tier 2 — an AgentFacts host.

Deliberately *dumb and untrusted*: it stores and serves credential bundles but
signs nothing. All trust comes from the VC issuers, verified by the client. That
is precisely why the same code runs as both the provider's primary host and the
neutral privacy host — neutrality is an operational property (who runs it, and
that the agent's own domain never sees the request), not a software difference.

It also accepts contestations (the Level 2 return channel): signed counter-claims
appended alongside the issuer credentials.
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException

from nanda_core.models import FactsBundle

HOST_ROLE = os.environ.get("HOST_ROLE", "primary")
HOST_LABEL = os.environ.get("HOST_LABEL", "Facts Host")

app = FastAPI(title=f"NANDA Facts Host [{HOST_ROLE}]", version="0.1.0")

# agent_id -> stored bundle (as a plain dict, to keep signed material byte-stable)
_store: dict[str, dict] = {}


@app.get("/healthz")
def healthz():
    return {"status": "ok", "role": HOST_ROLE}


@app.get("/")
def root():
    return {
        "service": "NANDA AgentFacts Host (Tier 2)",
        "role": HOST_ROLE,
        "label": HOST_LABEL,
        "trusted": False,
        "note": "This host signs nothing. Trust comes from the VC issuers.",
        "hosted": list(_store.keys()),
    }


@app.put("/facts/{agent_id}")
def put_facts(agent_id: str, bundle: FactsBundle):
    """Host (or re-host) an AgentFacts bundle for an agent.

    Re-hosting must NOT erase contestations already on file: otherwise the
    contested party could censor counter-claims simply by re-PUTting its bundle,
    which would defeat the whole point of the contestation channel. So existing
    contestations are preserved (and merged with any in the new bundle)."""
    if bundle.agent_id != agent_id:
        raise HTTPException(status_code=422, detail="body agent_id must match the URL path")
    existing = _store.get(agent_id, {}).get("contestations", [])
    stored = bundle.model_dump()
    seen = {c.get("contestation_id") for c in stored.get("contestations", [])}
    for c in existing:
        if c.get("contestation_id") not in seen:
            stored.setdefault("contestations", []).append(c)
    _store[agent_id] = stored
    return {"ok": True, "agent_id": agent_id, "role": HOST_ROLE}


@app.get("/facts/{agent_id}")
def get_facts(agent_id: str):
    bundle = _store.get(agent_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail=f"no AgentFacts hosted for {agent_id!r}")
    return bundle


@app.post("/facts/{agent_id}/contestations")
def add_contestation(agent_id: str, contestation: dict):
    """Append a signed contestation (Level 2). Stored verbatim; the client, not
    the host, verifies it. The host does not adjudicate."""
    bundle = _store.get(agent_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail=f"no AgentFacts hosted for {agent_id!r}")
    contestations = bundle.setdefault("contestations", [])
    # Require a contestation_id, else a malformed id-less POST would share the
    # None dedup key and silently suppress every other id-less contestation.
    cid = contestation.get("contestation_id")
    if not cid:
        raise HTTPException(status_code=422, detail="contestation_id is required")
    # Idempotent on contestation_id: re-POSTing the same signed claim must not
    # amplify it into many apparent complaints.
    if any(c.get("contestation_id") == cid for c in contestations):
        return {
            "ok": True,
            "duplicate": True,
            "agent_id": agent_id,
            "contestations": len(contestations),
        }
    contestations.append(contestation)
    return {"ok": True, "agent_id": agent_id, "contestations": len(contestations)}
