"""Service URLs and shared paths, from the environment with localhost defaults.

In docker-compose the services find each other by name (http://index:8000, …);
run locally, everything is on localhost with distinct ports. Both modes set the
same variable names, so nothing else in the code needs to know which it is.
"""

from __future__ import annotations

import os

INDEX_URL = os.environ.get("INDEX_URL", "http://localhost:8000")
FACTS_PRIMARY_URL = os.environ.get("FACTS_PRIMARY_URL", "http://localhost:8001")
FACTS_NEUTRAL_URL = os.environ.get("FACTS_NEUTRAL_URL", "http://localhost:8002")
AGENT_URL = os.environ.get("AGENT_URL", "http://localhost:8003")

SHARED_DIR = os.environ.get("SHARED_DIR", "shared")
TRUST_POLICY_PATH = os.path.join(SHARED_DIR, "trust_policy.json")
DEMO_STATE_PATH = os.path.join(SHARED_DIR, "demo_state.json")
RESOLVER_KEY_PATH = os.path.join(SHARED_DIR, "resolver.key")


def ensure_shared_dir() -> str:
    os.makedirs(SHARED_DIR, exist_ok=True)
    return SHARED_DIR
