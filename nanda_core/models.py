"""Schema models for the three NANDA artefacts plus the contestation extension.

Pydantic is used to *build and validate* artefacts. Signed artefacts then travel
as plain dicts (model_dump + a `proof`/JWT), because a signature is over a specific
JSON value and we must not let a re-serialisation step quietly change it. So: build
with these models, sign, then pass dicts/JWTs over the wire.

Layering (see the paper, §III–V):
  - AgentAddr        : Tier 1, lean index record (Ed25519 over JCS)
  - AgentFactsSubject: Tier 2 payload, carried inside a W3C VC (JWT, vc-jose-cose)
  - Contestation     : the affected-party counter-claim (our extension)
"""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field

from . import crypto
from .keystore import Identity


# --- Tier 1: the lean index record --------------------------------------------

class AgentAddr(BaseModel):
    """The signed, cacheable pointer record the index returns. Kept lean: it holds
    identity + pointers + ttl, never the metadata itself."""
    agent_id: str               # globally unique machine id, e.g. nanda:<uuid>
    agent_name: str             # human URN, e.g. urn:agent:acme:translator
    primary_facts_url: str      # AgentFacts on the provider's own domain
    private_facts_url: Optional[str] = None      # AgentFacts on a neutral host (privacy path)
    adaptive_resolver_url: Optional[str] = None  # optional dynamic routing (Tier 3)
    ttl: int = 3600             # cache duration, seconds


def sign_agentaddr(addr: AgentAddr, resolver: Identity) -> dict:
    """Produce the signed AgentAddr dict the index serves."""
    return crypto.sign_record(
        addr.model_dump(),
        resolver.private_key,
        verification_method=resolver.verification_method,
    )


# --- Tier 2: the AgentFacts metadata (credentialSubject of a VC) ---------------

class Provider(BaseModel):
    name: str
    url: str
    did: Optional[str] = None


class Endpoints(BaseModel):
    static: List[str] = Field(default_factory=list)        # stable URIs (TTL 1-6h)
    rotating: List[str] = Field(default_factory=list)      # short-lived (TTL 5-15m)
    adaptive_resolver: Optional[str] = None                # programmable routing (TTL 30-60s)


class Authentication(BaseModel):
    methods: List[str] = Field(default_factory=list)       # e.g. ["oauth2", "jwt"]
    requiredScopes: List[str] = Field(default_factory=list)


class Capabilities(BaseModel):
    modalities: List[str] = Field(default_factory=list)    # e.g. ["text", "audio"]
    streaming: bool = False
    batch: bool = False
    authentication: Authentication = Field(default_factory=Authentication)


class Skill(BaseModel):
    id: str
    description: str
    inputModes: List[str] = Field(default_factory=list)
    outputModes: List[str] = Field(default_factory=list)


class Evaluations(BaseModel):
    performanceScore: Optional[float] = None
    availability90d: Optional[str] = None
    lastAudited: Optional[str] = None
    auditorID: Optional[str] = None


class AgentFactsSubject(BaseModel):
    """The credentialSubject of an AgentFacts VC. Fields map onto (and superset)
    the Google A2A Agent Card — see docs/a2a-mapping.md."""
    id: str                       # the agent's did:key (subject identity)
    agent_name: str
    label: str
    description: str = ""
    version: str = "1.0.0"
    documentationUrl: Optional[str] = None
    jurisdiction: Optional[str] = None
    provider: Optional[Provider] = None
    endpoints: Endpoints = Field(default_factory=Endpoints)
    capabilities: Capabilities = Field(default_factory=Capabilities)
    skills: List[Skill] = Field(default_factory=list)
    evaluations: Optional[Evaluations] = None


# --- The bundle a facts host stores and serves --------------------------------

class FactsBundle(BaseModel):
    """What lives at primary_facts_url / private_facts_url.

    `provider_vc` and `auditor_vc` are JWT-VCs (vc-jose-cose). `contestations` is
    the return channel: signed counter-claims appended after issuance, by parties
    other than the issuers. They are stored as raw signed dicts so their
    signatures survive round-tripping."""
    agent_id: str
    agent_did: str
    agent_name: str
    label: str
    provider_vc: str
    auditor_vc: Optional[str] = None
    contestations: List[dict] = Field(default_factory=list)


# --- Level 2 extension: the contestation (affected-party counter-claim) --------

class InteractionReceipt(BaseModel):
    """Evidence that the contestant actually interacted with the agent. Signed by
    the agent's own key, so it cannot be fabricated by the contestant. This is the
    (stubbed) standing primitive: it binds a counter-claim to a real interaction."""
    interaction_id: str
    agent_id: str              # the registry handle (nanda:<uuid>) the interaction was with
    agent_did: str
    counterparty: str          # the affected party's did:key
    summary: str = ""
    timestamp: str


class Contestation(BaseModel):
    """A signed counter-claim from a party the agent acted upon. Travels alongside
    AgentFacts and is surfaced to clients next to the issuers' claims."""
    contestation_id: str
    type: str = "Contestation"
    agent_id: str
    agent_did: str
    interaction_id: str
    contestant: str            # affected party's did:key
    statement: str
    category: str = "service-dispute"
    created: str
    receipt: dict              # an InteractionReceipt, agent-signed (sign_record form)
