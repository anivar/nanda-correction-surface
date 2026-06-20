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

import datetime as dt

from pydantic import BaseModel, Field

from . import crypto
from .keystore import Identity


def _utc_now_iso() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- Tier 1: the lean index record --------------------------------------------


class AgentAddr(BaseModel):
    """The signed, cacheable pointer record the index returns. Kept lean: it holds
    identity + pointers + ttl, never the metadata itself."""

    agent_id: str  # globally unique machine id, e.g. nanda:<uuid>
    agent_name: str  # human URN, e.g. urn:agent:acme:translator
    agent_did: str | None = None  # the agent's did:key — binds the signed pointer to the VC subject
    # Quilt registration type (paper Table 1): native | enterprise | did.
    registration_type: str = "native"
    primary_facts_url: str  # AgentFacts on the provider's own domain
    private_facts_url: str | None = None  # AgentFacts on a neutral host (privacy path)
    # Enterprise-routed entries point at a registry that yields the facts URL.
    enterprise_registry_url: str | None = None
    adaptive_resolver_url: str | None = None  # optional dynamic routing (Tier 3)
    ttl: int = 3600  # cache duration, seconds
    issued_at: str | None = None  # ISO-8601 UTC; set at sign time so ttl is enforceable


def sign_agentaddr(addr: AgentAddr, resolver: Identity) -> dict:
    """Produce the signed AgentAddr dict the index serves. Stamps issued_at (so the
    signed ttl has an anchor to expire from) before signing."""
    body = addr.model_dump()
    body["issued_at"] = body.get("issued_at") or _utc_now_iso()
    return crypto.sign_record(
        body,
        resolver.private_key,
        verification_method=resolver.verification_method,
    )


# --- Tier 2: the AgentFacts metadata (credentialSubject of a VC) ---------------


class Provider(BaseModel):
    name: str
    url: str
    did: str | None = None


class Endpoints(BaseModel):
    static: list[str] = Field(default_factory=list)  # stable URIs (TTL 1-6h)
    rotating: list[str] = Field(default_factory=list)  # short-lived (TTL 5-15m)
    adaptive_resolver: str | None = None  # programmable routing (TTL 30-60s)


class Authentication(BaseModel):
    methods: list[str] = Field(default_factory=list)  # e.g. ["oauth2", "jwt"]
    requiredScopes: list[str] = Field(default_factory=list)


class Capabilities(BaseModel):
    modalities: list[str] = Field(default_factory=list)  # e.g. ["text", "audio"]
    streaming: bool = False
    batch: bool = False
    authentication: Authentication = Field(default_factory=Authentication)


class Skill(BaseModel):
    id: str
    description: str
    inputModes: list[str] = Field(default_factory=list)
    outputModes: list[str] = Field(default_factory=list)


class Evaluations(BaseModel):
    performanceScore: float | None = None
    availability90d: str | None = None
    lastAudited: str | None = None
    auditorID: str | None = None


class AgentFactsSubject(BaseModel):
    """The credentialSubject of an AgentFacts VC. Fields map onto (and superset)
    the Google A2A Agent Card — see docs/a2a-mapping.md."""

    id: str  # the agent's did:key (subject identity)
    agent_name: str
    label: str
    description: str = ""
    version: str = "1.0.0"
    documentationUrl: str | None = None
    jurisdiction: str | None = None
    provider: Provider | None = None
    endpoints: Endpoints = Field(default_factory=Endpoints)
    capabilities: Capabilities = Field(default_factory=Capabilities)
    skills: list[Skill] = Field(default_factory=list)
    evaluations: Evaluations | None = None


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
    auditor_vc: str | None = None
    contestations: list[dict] = Field(default_factory=list)
    # A self-sovereign severance (if the agent has exited this identity). Signed by
    # the agent's own key; renders the prior authority inexecutable on the subject's
    # say-so, optionally naming a successor identity.
    severance: dict | None = None


# --- Level 2 extension: the contestation (affected-party counter-claim) --------


class InteractionReceipt(BaseModel):
    """Evidence that the contestant actually interacted with the agent. Signed by
    the agent's own key, so it cannot be fabricated by the contestant. This is the
    (stubbed) standing primitive: it binds a counter-claim to a real interaction."""

    interaction_id: str
    agent_id: str  # the registry handle (nanda:<uuid>) the interaction was with
    agent_did: str
    counterparty: str  # the affected party's did:key
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
    contestant: str  # affected party's did:key
    statement: str
    category: str = "service-dispute"
    created: str
    receipt: dict  # an InteractionReceipt, agent-signed (sign_record form)


class Severance(BaseModel):
    """A self-sovereign exit: the agent, with its own key, retires this identity so
    that prior delegated authority becomes inexecutable — without asking any issuer
    or registry (a did:key has no upstream endpoint to petition). Optionally names a
    successor identity so the agent can re-participate on fair terms."""

    type: str = "Severance"
    agent_id: str
    agent_did: str  # the identity being retired (must match the signer)
    successor_did: str | None = None  # the new self-sovereign identity, if any
    reason: str = ""
    created: str
