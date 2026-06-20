"""Level 2 — the contestation dual: the affected-party half of the trust object.

The paper's AgentFacts is one-way: issuers attest *to* the agent, and nothing
carries a claim back from the party the agent acts *upon*. Every lever in the
NANDA stack sits with an operator, an issuer or a registry — none with the
governed party. This module adds the first primitive that party controls: a
signed counter-claim that travels with the facts and is surfaced to clients.

The hard part of any such system is **standing**: who is entitled to contest?
Building real standing infrastructure is out of scope (and would be a project of
its own). We stub it with a verifiable, non-circular primitive:

  - An **interaction receipt** is signed by the *agent's own key*, acknowledging
    that it interacted with a given counterparty under a given interaction id.
    The contestant cannot forge this — only the agent can.
  - A **contestation** is signed by the *affected party* and embeds that receipt.

A client then has standing iff: the contestant's signature verifies, the embedded
receipt's (agent) signature verifies, and the receipt names this contestant as
the counterparty for the referenced interaction. In other words: you may contest
an interaction the agent itself acknowledged having with you. (Limitation, stated
plainly in the README: a hostile agent could withhold receipts. Production
standing would use a mutually-signed interaction log or a notary — see next steps.)
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

from . import crypto, vc
from .didkey import decode_did_key
from .keystore import Identity
from .models import Contestation, InteractionReceipt


def mint_interaction_receipt(
    agent: Identity, agent_id: str, counterparty_did: str, summary: str = ""
) -> tuple[dict, str]:
    """The agent acknowledges an interaction with `counterparty_did`. Returns the
    signed receipt and its interaction id. The receipt binds BOTH the agent's
    did:key and its registry handle (agent_id), so it cannot be replayed as
    standing for a different registry entry that happens to share the key. In a
    real deployment the agent endpoint would issue this at interaction time."""
    interaction_id = f"int:{uuid.uuid4()}"
    body = InteractionReceipt(
        interaction_id=interaction_id,
        agent_id=agent_id,
        agent_did=agent.did,
        counterparty=counterparty_did,
        summary=summary,
        timestamp=vc.iso(dt.datetime.now(dt.UTC)),
    ).model_dump()
    signed = crypto.sign_record(
        body, agent.private_key, verification_method=agent.verification_method
    )
    return signed, interaction_id


def file_contestation(
    contestant: Identity,
    *,
    agent_id: str,
    agent_did: str,
    interaction_id: str,
    statement: str,
    receipt: dict,
    category: str = "service-dispute",
) -> dict:
    """The affected party files a signed counter-claim bound to a prior interaction."""
    body = Contestation(
        contestation_id=f"contest:{uuid.uuid4()}",
        agent_id=agent_id,
        agent_did=agent_did,
        interaction_id=interaction_id,
        contestant=contestant.did,
        statement=statement,
        category=category,
        created=vc.iso(dt.datetime.now(dt.UTC)),
        receipt=receipt,
    ).model_dump()
    return crypto.sign_record(
        body, contestant.private_key, verification_method=contestant.verification_method
    )


@dataclass
class ContestationVerdict:
    valid: bool
    reason: str
    contestant: str | None = None
    statement: str | None = None
    interaction_id: str | None = None
    category: str | None = None


def verify_contestation(
    contestation: dict, *, expected_agent_did: str, expected_agent_id: str | None = None
) -> ContestationVerdict:
    """Verify a contestation's signature AND its standing. Fails closed: any check
    that does not pass yields valid=False with a reason.

    `expected_agent_id` (the resolved registry handle) is checked when supplied,
    so a contestation legitimately filed against one registry entry cannot be
    grafted onto another that merely shares the same key."""
    contestant = contestation.get("contestant")
    statement = contestation.get("statement")
    interaction_id = contestation.get("interaction_id")
    category = contestation.get("category")

    def bad(reason: str) -> ContestationVerdict:
        return ContestationVerdict(False, reason, contestant, statement, interaction_id, category)

    # 1. The contestation must be signed by the party it names as contestant.
    proof = contestation.get("proof") or {}
    signer_did = str(proof.get("verificationMethod", "")).split("#", 1)[0]
    if not contestant or signer_did != contestant:
        return bad("contestation not signed by the named contestant")
    try:
        if not crypto.verify_record(contestation, decode_did_key(contestant)):
            return bad("contestant signature invalid")
    except ValueError as exc:
        return bad(f"bad contestant did:key: {exc}")

    # 2. The embedded interaction receipt must be signed by THIS agent.
    receipt = contestation.get("receipt") or {}
    if receipt.get("agent_did") != expected_agent_did:
        return bad("receipt is for a different agent")
    try:
        if not crypto.verify_record(receipt, decode_did_key(expected_agent_did)):
            return bad("interaction receipt signature invalid (not signed by the agent)")
    except ValueError as exc:
        return bad(f"bad agent did:key on receipt: {exc}")

    # 3. Standing: the receipt must bind this contestant to this interaction,
    #    and to this exact agent (did AND registry handle).
    if receipt.get("counterparty") != contestant:
        return bad("receipt counterparty does not match contestant (no standing)")
    if receipt.get("interaction_id") != interaction_id:
        return bad("receipt interaction_id does not match contestation")
    if contestation.get("agent_did") != expected_agent_did:
        return bad("contestation agent_did does not match resolved agent")
    if receipt.get("agent_id") != contestation.get("agent_id"):
        return bad(
            "receipt agent_id does not match contestation (no standing for this registry entry)"
        )
    if expected_agent_id is not None and contestation.get("agent_id") != expected_agent_id:
        return bad("contestation agent_id does not match resolved agent")

    return ContestationVerdict(
        True,
        "verified: signed by contestant with acknowledged standing",
        contestant,
        statement,
        interaction_id,
        category,
    )
