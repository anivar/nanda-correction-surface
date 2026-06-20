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

from fastapi import FastAPI, HTTPException, Request

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
    prior = _store.get(agent_id, {})
    existing = prior.get("contestations", [])
    stored = bundle.model_dump()
    seen = {c.get("contestation_id") for c in stored.get("contestations", [])}
    for c in existing:
        if c.get("contestation_id") not in seen:
            stored.setdefault("contestations", []).append(c)
    # A severance, once filed, is permanent: re-hosting cannot un-sever an identity
    # (the host can't forge the agent's key anyway). Preserve any prior severance.
    if prior.get("severance") and not stored.get("severance"):
        stored["severance"] = prior["severance"]
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


@app.post("/facts/{agent_id}/severance")
def set_severance(agent_id: str, severance: dict):
    """Record a self-sovereign severance (the agent has exited this identity).
    Stored verbatim; the client verifies it was signed by the retiring identity."""
    bundle = _store.get(agent_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail=f"no AgentFacts hosted for {agent_id!r}")
    bundle["severance"] = severance
    return {"ok": True, "agent_id": agent_id, "severed": True}


@app.get("/registry/{agent_id}")
def enterprise_registry(agent_id: str, request: Request):
    """Enterprise-routed indirection (paper Table 1): the index points here, and the
    registry hands back where the facts actually live. One extra hop versus a
    NANDA-native entry that points straight at the facts."""
    base = str(request.base_url).rstrip("/")
    return {"agent_id": agent_id, "facts_url": f"{base}/facts/{agent_id}", "registry": HOST_LABEL}
