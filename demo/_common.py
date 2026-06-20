"""Shared scaffolding for the demo scripts: the two agents, http helpers, state.

The two agents are intentionally different so the demo exercises both resolution
paths and a real auditor claim:
  - translator  → resolved via the PRIMARY (provider-hosted) path
  - summarizer  → resolved via the PRIVATE (neutral-host) path, and later contested
"""

from __future__ import annotations

import uuid

import httpx

from issuer import issue_auditor_credential, issue_provider_credential
from nanda_core import config
from nanda_core.keystore import Identity, read_json, write_json
from nanda_core.models import (
    AgentFactsSubject,
    Capabilities,
    Endpoints,
    Evaluations,
    FactsBundle,
    Provider,
    Skill,
)

# --- the two demonstration agents ---------------------------------------------

AGENTS = [
    {
        "agent_name": "urn:agent:acme:translator",
        "label": "TranslationAssistant",
        "slug": "translator",
        "description": "Autonomous agent for low-latency multilingual translation",
        "version": "1.2.1",
        "jurisdiction": "USA",
        "modalities": ["text", "audio"],
        "streaming": True,
        "auth_methods": ["oauth2", "jwt"],
        "scopes": ["translate:real-time", "language:detect"],
        "skills": [
            {
                "id": "translation",
                "description": "Real-time translation between >25 languages",
                "inputModes": ["text", "audio/ogg"],
                "outputModes": ["text", "audio/wav"],
            }
        ],
        "evaluations": {
            "performanceScore": 4.8,
            "availability90d": "99.93%",
            "auditorID": "Capabilities Auditor v2.1",
        },
        "path": "primary",
    },
    {
        "agent_name": "urn:agent:acme:summarizer",
        "label": "SummaryAssistant",
        "slug": "summarizer",
        "description": "Topic-guided abstractive summarisation",
        "version": "0.9.0",
        "jurisdiction": "USA",
        "modalities": ["text"],
        "streaming": False,
        "auth_methods": ["oauth2"],
        "scopes": ["summarize:doc"],
        "skills": [
            {
                "id": "summarisation",
                "description": "Topic-guided abstractive summarisation",
                "inputModes": ["text"],
                "outputModes": ["text"],
            }
        ],
        "evaluations": {
            "performanceScore": 4.5,
            "availability90d": "99.50%",
            "auditorID": "Capabilities Auditor v2.1",
        },
        "path": "private",
    },
]


# --- http helpers -------------------------------------------------------------


def get_json(url: str, **params) -> dict:
    r = httpx.get(url, params=params or None, timeout=10.0)
    r.raise_for_status()
    return r.json()


def put_json(url: str, body: dict) -> dict:
    r = httpx.put(url, json=body, timeout=10.0)
    r.raise_for_status()
    return r.json()


def post_json(url: str, body: dict) -> dict:
    r = httpx.post(url, json=body, timeout=10.0)
    r.raise_for_status()
    return r.json()


# --- demo state ---------------------------------------------------------------


def save_state(state: dict) -> None:
    config.ensure_shared_dir()
    write_json(config.DEMO_STATE_PATH, state)


def load_state() -> dict:
    return read_json(config.DEMO_STATE_PATH)


def new_agent_id() -> str:
    return f"nanda:{uuid.uuid4()}"


# --- helpers shared by the correction-surface extension demos ----------------------------


def load_issuers() -> tuple[Identity, Identity]:
    """Reconstruct the SAME provider + auditor issuers register.py used, so VCs the
    extension demos issue are trusted by the already-pinned client trust policy."""
    s = load_state()
    return (
        Identity.from_secret_dict(s["issuer_secrets"]["provider"]),
        Identity.from_secret_dict(s["issuer_secrets"]["auditor"]),
    )


def build_bundle(
    agent: Identity,
    *,
    agent_id: str,
    agent_name: str,
    label: str,
    slug: str,
    provider: Identity,
    auditor: Identity,
) -> dict:
    """Build an AgentFacts bundle (provider VC + auditor VC) for an agent."""
    subject = AgentFactsSubject(
        id=agent.did,
        agent_name=agent_name,
        label=label,
        description=f"{label} agent",
        provider=Provider(name="ACME Corp", url="https://acme.example", did=provider.did),
        endpoints=Endpoints(static=[f"{config.AGENT_URL}/agents/{slug}/invoke"]),
        capabilities=Capabilities(modalities=["text"]),
        skills=[Skill(id=slug, description=label, inputModes=["text"], outputModes=["text"])],
        evaluations=Evaluations(performanceScore=4.6, availability90d="99.0%"),
    )
    provider_vc = issue_provider_credential(provider, subject)
    auditor_vc = issue_auditor_credential(
        auditor,
        agent.did,
        Evaluations(performanceScore=4.6),
        {"level": "verified", "issuer": "ACME Independent Audits"},
    )
    return FactsBundle(
        agent_id=agent_id,
        agent_did=agent.did,
        agent_name=agent_name,
        label=label,
        provider_vc=provider_vc,
        auditor_vc=auditor_vc,
    ).model_dump()


def host_bundle(agent_id: str, bundle: dict) -> tuple[str, str]:
    """Host the bundle on both facts hosts; return (primary_url, private_url)."""
    primary = f"{config.FACTS_PRIMARY_URL}/facts/{agent_id}"
    private = f"{config.FACTS_NEUTRAL_URL}/facts/{agent_id}"
    put_json(primary, bundle)
    put_json(private, bundle)
    return primary, private
