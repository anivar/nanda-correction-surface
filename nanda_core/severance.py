"""Self-sovereign severance — the exit primitive.

Contestation lets a party the agent acted upon attach a portable refusal signal so
that *others* can refuse the agent. Severance is the other half: the agent — the
subject — severs its *own* binding, with its *own* key, rendering prior delegated
authority **inexecutable**. It does not petition an issuer or a registry to do so,
because a `did:key` has no upstream endpoint to ask: the right to sever lives with
the key holder. It may name a successor identity, so the agent can leave the old
binding and still participate on fair terms.

Both severance and contestation are *portable, censorship-resistant refusal
signals*: signed and carried with the facts, so the party being left cannot erase
them — it cannot forge the key. The facts host preserves them across re-hosting.
"""

from __future__ import annotations

import datetime as dt

from . import crypto, vc
from .didkey import decode_did_key
from .keystore import Identity
from .models import Severance


def sign_severance(
    agent: Identity, agent_id: str, *, successor_did: str | None = None, reason: str = ""
) -> dict:
    """The agent retires its own identity (`agent.did`) for registry entry
    `agent_id`, signed by its own key — the last authoritative act of that key."""
    body = Severance(
        agent_id=agent_id,
        agent_did=agent.did,
        successor_did=successor_did,
        reason=reason,
        created=vc.iso(dt.datetime.now(dt.UTC)),
    ).model_dump()
    return crypto.sign_record(
        body, agent.private_key, verification_method=agent.verification_method
    )


def verify_severance(
    severance: dict | None,
    *,
    expected_agent_did: str,
    expected_agent_id: str | None = None,
) -> bool:
    """Valid iff the severance is signed by the very identity it retires. Only the
    holder of `agent_did` can sever `agent_did` — exit is self-sovereign, and no one
    else (issuer, registry, host) can forge it.

    When `expected_agent_id` (the resolved registry handle) is supplied it must also
    match the signed `agent_id`, so a severance filed against one registry entry
    cannot be replayed onto another that merely shares the same key."""
    if not severance:
        return False
    if severance.get("agent_did") != expected_agent_did:
        return False
    if expected_agent_id is not None and severance.get("agent_id") != expected_agent_id:
        return False
    signer = str((severance.get("proof") or {}).get("verificationMethod", "")).split("#", 1)[0]
    if signer != expected_agent_did:
        return False
    try:
        return crypto.verify_record(severance, decode_did_key(expected_agent_did))
    except ValueError:
        return False
