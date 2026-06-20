"""Tier 1 — the lean NANDA index.

Responsibilities, and nothing more:
  - hold a stable Ed25519 *resolver* key (the index's signing identity)
  - register agents: turn a registration into a signed, cacheable AgentAddr
  - resolve an AgentName to that signed AgentAddr

The index never stores or serves AgentFacts metadata — only the lean pointer
record. That separation is the whole point of the architecture: the high-churn
metadata lives at the facts hosts and can change without ever touching the index.
"""

from __future__ import annotations

import uuid

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from nanda_core import config
from nanda_core.keystore import Identity, load_or_create_private_key
from nanda_core.models import AgentAddr, sign_agentaddr

app = FastAPI(title="NANDA Lean Index", version="0.1.0")

# Stable resolver identity, persisted under shared/ so it survives restarts.
config.ensure_shared_dir()
_resolver = Identity(
    name="index-resolver", private_key=load_or_create_private_key(config.RESOLVER_KEY_PATH)
)

# In-memory registry. A real index would be a replicated KV store; for the
# prototype the running process is the store (register, then resolve, same run).
_by_name: dict[str, dict] = {}
_by_id: dict[str, dict] = {}


# Stubbed VC-Status-List: a set of revoked credential ids. Production would be an
# issuer-hosted W3C Bitstring Status List; here the index serves a simple set the
# client refreshes at resolve time.
_revoked: set[str] = set()


class RegisterRequest(BaseModel):
    agent_name: str
    primary_facts_url: str
    agent_id: str | None = None
    agent_did: str | None = None
    registration_type: str = "native"  # native | enterprise | did (quilt entry type)
    enterprise_registry_url: str | None = None
    private_facts_url: str | None = None
    adaptive_resolver_url: str | None = None
    ttl: int = 3600


class RevokeRequest(BaseModel):
    credential_id: str


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/")
def root():
    return {
        "service": "NANDA Lean Index (Tier 1)",
        "resolver_did": _resolver.did,
        "registered": len(_by_name),
        "endpoints": {
            "register": "POST /register",
            "resolve": "GET /resolve?name=<AgentName>",
            "resolver_key": "GET /resolver",
            "list": "GET /agents",
        },
    }


@app.get("/resolver")
def resolver_info():
    """Publish the resolver's public identity so a client can pin it in its trust
    policy out-of-band. (The client does NOT fetch this at resolve time — that
    would defeat the trust anchor; it is pinned at setup.)"""
    return {
        "did": _resolver.did,
        "verificationMethod": _resolver.verification_method,
    }


@app.post("/register")
def register(req: RegisterRequest):
    agent_id = req.agent_id or f"nanda:{uuid.uuid4()}"
    addr = AgentAddr(
        agent_id=agent_id,
        agent_name=req.agent_name,
        agent_did=req.agent_did,
        registration_type=req.registration_type,
        primary_facts_url=req.primary_facts_url,
        enterprise_registry_url=req.enterprise_registry_url,
        private_facts_url=req.private_facts_url,
        adaptive_resolver_url=req.adaptive_resolver_url,
        ttl=req.ttl,
    )
    signed = sign_agentaddr(addr, _resolver)
    _by_name[req.agent_name] = signed
    _by_id[agent_id] = signed
    return signed


@app.get("/resolve")
def resolve(name: str):
    """AgentName -> signed AgentAddr. The first hop of every resolution path."""
    signed = _by_name.get(name)
    if signed is None:
        raise HTTPException(status_code=404, detail=f"no agent registered as {name!r}")
    return JSONResponse(signed)


@app.get("/agents")
def list_agents():
    """Debug/visualisation: the names currently in the index."""
    return {
        "count": len(_by_name),
        "agents": [
            {
                "agent_name": n,
                "agent_id": a["agent_id"],
                "registration_type": a.get("registration_type", "native"),
                "ttl": a["ttl"],
            }
            for n, a in _by_name.items()
        ],
    }


@app.post("/revoke")
def revoke(req: RevokeRequest):
    """Mark a credential id revoked (stubbed VC-Status-List). Issuer-authorised in
    production; open here for the demo."""
    _revoked.add(req.credential_id)
    return {"ok": True, "revoked_count": len(_revoked)}


@app.get("/revocations")
def revocations():
    """The current revocation set, refreshed by clients at resolve time."""
    return {"revoked": sorted(_revoked)}
