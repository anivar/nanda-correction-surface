"""Shared scaffolding for the demo scripts: the two agents, http helpers, state.

The two agents are intentionally different so the demo exercises both resolution
paths and a real auditor claim:
  - translator  → resolved via the PRIMARY (provider-hosted) path
  - summarizer  → resolved via the PRIVATE (neutral-host) path, and later contested
"""

from __future__ import annotations

import uuid

import httpx

from nanda_core import config
from nanda_core.keystore import read_json, write_json

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
