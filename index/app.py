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

from nanda_core import config, crypto
from nanda_core.didkey import decode_did_key
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


# Stubbed VC-Status-List. Production would be an issuer-hosted W3C Bitstring Status
# List; here the index serves issuer-signed revocations the client refreshes at
# resolve time. Least authority: only a credential's OWN issuer can revoke it —
# every entry carries the issuer's signature over the credential id, and the client
# both verifies that signature and matches it to the credential's issuer.
_revocations: dict[str, dict] = {}  # credential_id -> {credential_id, issuer_did, signature}


class RegisterRequest(BaseModel):
    agent_name: str
    primary_facts_url: str
    agent_did: str  # the agent's did:key — required, so every AgentAddr binds an identity
    agent_id: str | None = None
    registration_type: str = "native"  # native | enterprise | did (quilt entry type)
    enterprise_registry_url: str | None = None
    private_facts_url: str | None = None
    adaptive_resolver_url: str | None = None
    ttl: int = 3600


class RevokeRequest(BaseModel):
    credential_id: str
    issuer_did: str  # the issuer revoking ITS OWN credential
    signature: str  # Ed25519 over credential_id, by issuer_did (base64url)


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
    """Record an issuer-authorised revocation. The caller must prove control of
    issuer_did by signing the credential_id with it — so no one can revoke a
    credential they did not issue."""
    try:
        pub = decode_did_key(req.issuer_did)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"bad issuer did:key: {exc}") from exc
    if not crypto.verify_bytes(pub, crypto.b64u_decode(req.signature), req.credential_id.encode()):
        raise HTTPException(status_code=403, detail="revocation signature invalid for issuer_did")
    _revocations[req.credential_id] = req.model_dump()
    return {"ok": True, "revoked_count": len(_revocations)}


@app.get("/revocations")
def revocations():
    """The current issuer-signed revocations, refreshed by clients at resolve time.
    Each entry is independently verifiable; the client honours only revocations
    signed by the credential's own (trusted) issuer."""
    return {"revoked": list(_revocations.values())}
