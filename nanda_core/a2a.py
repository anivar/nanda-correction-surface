"""Project a verified AgentFacts subject down to a Google A2A Agent Card.

The paper claims AgentFacts is a *superset* of the A2A Agent Card. This makes the
claim concrete and testable in both directions:

  - down: an A2A-only client can consume a NANDA agent by projecting its
    (verified) AgentFacts to a standard Agent Card;
  - up: a plain A2A card gains what NANDA adds — cryptographic attestation by
    issuers, a privacy path, TTL-scoped routing, and contestations.

A2A Agent Cards are published at /.well-known/agent-card.json. Field mapping is
documented in docs/a2a-mapping.md.
"""

from __future__ import annotations


def to_agent_card(subject: dict) -> dict:
    """Map an AgentFacts credentialSubject to an A2A Agent Card (v1.0 shape)."""
    caps = subject.get("capabilities") or {}
    auth = caps.get("authentication") or {}
    provider = subject.get("provider") or {}
    modalities = caps.get("modalities") or []
    static = (subject.get("endpoints") or {}).get("static") or []

    card = {
        "name": subject.get("label"),
        "description": subject.get("description", ""),
        "url": static[0] if static else None,
        "version": subject.get("version"),
        "provider": {"organization": provider.get("name"), "url": provider.get("url")},
        "capabilities": {"streaming": bool(caps.get("streaming", False))},
        "defaultInputModes": modalities,
        "defaultOutputModes": modalities,
        "skills": [
            {
                "id": s.get("id"),
                "name": s.get("id"),
                "description": s.get("description", ""),
                "inputModes": s.get("inputModes", []),
                "outputModes": s.get("outputModes", []),
            }
            for s in subject.get("skills", [])
        ],
    }

    methods = auth.get("methods") or []
    if methods:
        card["securitySchemes"] = {m: {"type": m} for m in methods}
        card["security"] = [{m: auth.get("requiredScopes", [])} for m in methods]
    return card
