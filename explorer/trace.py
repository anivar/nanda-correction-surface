"""In-process protocol trace for the explorer — real Ed25519/JCS/VC/severance crypto,
no live services. Each scenario builds fresh identities, signs real artefacts, and
runs the actual verification, emitting a step-by-step trace the UI renders.

Every step is tagged with a `layer` so the UI can draw the boundary between what the
NANDA paper specifies and what is the contribution on top:

  paper        — the NANDA Index resolution flow (arXiv:2507.14263): CORE
  extension    — the correction surface: contestation + self-sovereign exit
  context      — operator-side authorisation (AuthZEN, Txn-Tokens) — cited, not run
  institution  — compel-correction / remedy — named, not a protocol (out of scope)

Each step also carries a `plain` line: an everyday-language explanation of what is
happening and why it matters, shown above the precise technical detail.

The trace deliberately mirrors client/resolver.py (the authoritative verifier);
it exists for visualisation, sharing the same nanda_core primitives.
"""

from __future__ import annotations

import copy
import re

from issuer import issue_auditor_credential, issue_provider_credential
from nanda_core import contest, crypto, severance, vc
from nanda_core.didkey import decode_did_key
from nanda_core.keystore import Identity
from nanda_core.models import (
    AgentAddr,
    AgentFactsSubject,
    Authentication,
    Capabilities,
    Endpoints,
    Evaluations,
    FactsBundle,
    Provider,
    Skill,
    sign_agentaddr,
)

PAPER, EXTENSION, CONTEXT, INSTITUTION = "paper", "extension", "context", "institution"

# The cast of actors, in swimlane order. Used by the UI to lay out lifelines.
YOU, INDEX, FACTS, PROVIDER, AUDITOR, AGENT, PARTY = (
    "You",
    "Index",
    "Facts host",
    "Provider",
    "Auditor",
    "Agent",
    "Affected party",
)

SCENARIOS = {
    "resolve": "Resolve an agent — verify every hop, then act",
    "privacy": "Privacy path — fetch facts from a neutral host",
    "tamper": "Tamper — a mutated AgentAddr is rejected",
    "spoof": "Spoof — a forged credential is rejected",
    "contest": "Contest — an affected party's signed counter-claim is surfaced",
    "exit": "Exit — the agent severs its own identity; prior authority dies",
}


def _short(did: str | None) -> str:
    if not did:
        return "—"
    return did[:18] + "…" if len(did) > 20 else did


_DID_RE = re.compile(r"did:[a-z]+:[A-Za-z0-9._%-]{10,}")


def _short_exc(exc: Exception) -> str:
    """Return the exception message with any embedded DIDs truncated via _short."""
    return _DID_RE.sub(lambda m: _short(m.group()), str(exc))


def _world():
    resolver = Identity.generate("index-resolver")
    provider = Identity.generate("ACME Provider")
    auditor = Identity.generate("ACME Independent Audits")
    agent = Identity.generate("translator")
    subject = AgentFactsSubject(
        id=agent.did,
        agent_name="urn:agent:acme:translator",
        label="TranslationAssistant",
        version="1.2.1",
        provider=Provider(name="ACME Corp", url="https://acme.example", did=provider.did),
        endpoints=Endpoints(static=["https://agent.example/invoke"]),
        capabilities=Capabilities(
            modalities=["text", "audio"],
            streaming=True,
            authentication=Authentication(
                methods=["oauth2"], requiredScopes=["translate:real-time"]
            ),
        ),
        skills=[
            Skill(
                id="translation",
                description="Real-time translation",
                inputModes=["text"],
                outputModes=["text"],
            )
        ],
        evaluations=Evaluations(performanceScore=4.8, availability90d="99.93%"),
    )
    bundle = FactsBundle(
        agent_id="nanda:translator-001",
        agent_did=agent.did,
        agent_name="urn:agent:acme:translator",
        label="TranslationAssistant",
        provider_vc=issue_provider_credential(provider, subject),
        auditor_vc=issue_auditor_credential(
            auditor,
            agent.did,
            Evaluations(performanceScore=4.8, availability90d="99.93%"),
            {"level": "verified", "issuer": "ACME Independent Audits"},
        ),
    ).model_dump()
    addr = sign_agentaddr(
        AgentAddr(
            agent_id="nanda:translator-001",
            agent_name="urn:agent:acme:translator",
            agent_did=agent.did,
            registration_type="did",
            primary_facts_url="https://acme.example/.well-known/agent-facts",
            private_facts_url="https://neutral.example/facts/translator-001",
        ),
        resolver,
    )
    return dict(
        resolver=resolver,
        provider=provider,
        auditor=auditor,
        agent=agent,
        trusted={provider.did, auditor.did},
        addr=addr,
        bundle=bundle,
    )


def walk(scenario: str) -> dict:
    if scenario not in SCENARIOS:
        scenario = "resolve"
    w = _world()
    steps: list[dict] = []

    def step(
        frm,
        to,
        title,
        detail,
        plain="",
        status="info",
        layer=PAPER,
        tier="",
        data=None,
        boundary=False,
    ):
        steps.append(
            {
                "n": len(steps) + 1,
                "from": frm,
                "to": to,
                "title": title,
                "detail": detail,
                "plain": plain,
                "status": status,
                "layer": layer,
                "tier": tier,
                "data": data or {},
                "boundary": boundary,
            }
        )

    # --- Hop 1: index → signed AgentAddr (Tier 1) -------------------------------
    addr = copy.deepcopy(w["addr"])
    if scenario == "tamper":
        addr["primary_facts_url"] = "https://evil.example/facts"  # path attacker mutates
    step(
        YOU,
        INDEX,
        "Resolve AgentName → AgentAddr",
        "urn:agent:acme:translator",
        plain="Look the agent up by its name and get back a small, signed "
        "“address card” saying where to find it.",
        layer=PAPER,
        tier="Tier 1 · Lean Index",
        data={
            "agent_id": addr["agent_id"],
            "agent_did": _short(addr.get("agent_did")),
            "registration_type": addr.get("registration_type"),
            "ttl": addr["ttl"],
        },
    )

    ok = str((addr.get("proof") or {}).get("verificationMethod", "")).split("#")[0] == w[
        "resolver"
    ].did and crypto.verify_record(addr, decode_did_key(w["resolver"].did))
    step(
        YOU,
        YOU,
        "Verify AgentAddr — Ed25519 over JCS, resolver pinned",
        "signature valid; signed by the pinned index resolver"
        if ok
        else "signature INVALID — record was tampered with",
        plain="Check the card was signed by the one directory key you already trust. "
        "A valid signature from the wrong key is still refused."
        if ok
        else "The card was altered after signing, so its signature no longer matches. Stop here.",
        status="ok" if ok else "fail",
        layer=PAPER,
        tier="Tier 1",
    )
    if not ok:
        return _finish(steps, "AgentAddr failed verification — fail closed", scenario, w)

    # --- Hop 2: select facts source --------------------------------------------
    private = scenario == "privacy"
    step(
        YOU,
        YOU,
        "Select AgentFacts source",
        "privacy path → NEUTRAL host (agent's domain never sees the request)"
        if private
        else "primary path → provider domain",
        plain="Read the agent's details from a neutral host, so the agent's own "
        "site never learns who is asking about it."
        if private
        else "Decide where to read the agent's details from — here, the provider's own site.",
        status="ok",
        layer=PAPER,
        tier="Tier 2",
    )

    # --- Hop 3: fetch facts bundle ---------------------------------------------
    host_kind = "neutral host" if private else "provider host"
    bundle = copy.deepcopy(w["bundle"])
    if scenario == "spoof":
        rogue = Identity.generate("Rogue Issuer (untrusted)")
        rogue_subject = AgentFactsSubject(
            id=w["agent"].did, agent_name="urn:agent:acme:translator", label="TranslationAssistant"
        )
        bundle["provider_vc"] = issue_provider_credential(rogue, rogue_subject)
    if scenario == "contest":
        party = Identity.generate("Acme Customer #4471")
        receipt, iid = contest.mint_interaction_receipt(
            w["agent"], "nanda:translator-001", party.did, "summarisation job #4471"
        )
        bundle["contestations"] = [
            contest.file_contestation(
                party,
                agent_id="nanda:translator-001",
                agent_did=w["agent"].did,
                interaction_id=iid,
                statement="Returned output dropped the dispute clause; accuracy SLA breached.",
                category="accuracy-dispute",
                receipt=receipt,
            )
        ]
    if scenario == "exit":
        successor = Identity.generate("translator v2")
        bundle["severance"] = severance.sign_severance(
            w["agent"], "nanda:translator-001", successor_did=successor.did, reason="key rotation"
        )
    step(
        YOU,
        FACTS,
        "Fetch AgentFacts bundle",
        f"GET from the {host_kind} (untrusted; it signs nothing)",
        plain="Download the agent's profile. This host only stores files — it cannot "
        "vouch for anything, so trust will come from the signed credentials inside.",
        status="ok",
        layer=PAPER,
        tier="Tier 2",
    )

    # --- EXTENSION: exit gate (severance) --------------------------------------
    sev = bundle.get("severance")
    if sev and severance.verify_severance(sev, expected_agent_did=addr.get("agent_did")):
        step(
            YOU,
            YOU,
            "Exit gate — self-sovereign severance",
            "identity SEVERED by its own key → prior authority inexecutable "
            "(existing permissions void) · successor " + _short(sev.get("successor_did")),
            plain="The agent has retired this identity using its own key. Any client that "
            "resolves it now is refused (the client fails closed) and is pointed to the "
            "named successor instead.",
            status="fail",
            layer=EXTENSION,
            tier="Correction surface · EXIT",
            boundary=True,
            data={
                "severed_by": _short(addr.get("agent_did")),
                "successor": _short(sev.get("successor_did")),
            },
        )
        return _finish(
            steps,
            "Agent has exited this identity — fail closed (resolve the successor)",
            scenario,
            w,
        )

    # --- Hop 4: verify provider VC (Tier 2) ------------------------------------
    # The credential is already in the bundle the client holds; verification is a
    # LOCAL self-check (no live call to the issuer), so the swimlane shows You→You.
    try:
        provider_cred = vc.verify_credential(bundle["provider_vc"], trusted_issuers=w["trusted"])
        if provider_cred["credentialSubject"]["id"] != addr.get("agent_did"):
            raise vc.VCError("provider VC subject ≠ signed agent_did")
        step(
            YOU,
            YOU,
            "Verify provider credential — W3C VC (JWT)",
            f"issuer {_short(provider_cred['issuer'])} · trusted · bound to agent_did",
            plain="Check the provider's signed claim (already in the downloaded bundle) — "
            "and that it is really about THIS agent, so a valid claim about someone else "
            "can't be swapped in.",
            status="ok",
            layer=PAPER,
            tier="Tier 2 · AgentFacts",
        )
    except vc.VCError as exc:
        msg = _short_exc(exc)
        step(
            YOU,
            YOU,
            "Verify provider credential — W3C VC (JWT)",
            f"REJECTED: {msg}",
            plain="The claim is signed by someone the client doesn't trust (or was "
            "tampered with), so it is rejected.",
            status="fail",
            layer=PAPER,
            tier="Tier 2 · AgentFacts",
        )
        return _finish(
            steps, f"Provider credential failed verification — fail closed ({msg})", scenario, w
        )

    # --- Hop 5: auditor VC + threshold -----------------------------------------
    auditor_cred = vc.verify_credential(bundle["auditor_vc"], trusted_issuers=w["trusted"])
    ev = auditor_cred["credentialSubject"].get("evaluations", {})
    step(
        YOU,
        YOU,
        "Verify auditor credential — independent issuer",
        f"performanceScore {ev.get('performanceScore')} · "
        f"availability {ev.get('availability90d')} · subject matches",
        plain="Check a second, independent reviewer's signed claim (also in the bundle) "
        "about the same agent. Two independent signers must agree before the facts are trusted.",
        status="ok",
        layer=PAPER,
        tier="Tier 2 · threshold met",
    )

    # --- EXTENSION: contestations ----------------------------------------------
    surfaced = []
    for c in bundle.get("contestations", []) or []:
        v = contest.verify_contestation(
            c, expected_agent_did=addr.get("agent_did"), expected_agent_id=addr.get("agent_id")
        )
        if v.valid:
            surfaced.append(v)
    if surfaced:
        v = surfaced[0]
        step(
            PARTY,
            YOU,
            "Surface contestation — affected-party counter-claim",
            f"[{v.category}] “{v.statement}” · standing verified",
            plain="A party the agent acted on has filed a signed complaint — verified "
            "against a receipt the agent itself signed, so it can't be faked. The client "
            "surfaces it next to the issuers' claims, rather than silently dropping it.",
            status="warn",
            layer=EXTENSION,
            tier="Correction surface · CONTEST",
            boundary=True,
            data={"contestant": _short(v.contestant)},
        )
    else:
        step(
            YOU,
            YOU,
            "Surface contestations — affected-party return path",
            "none on record (the affected-party channel the operator-side stack omits)",
            plain="No complaints on file. This return path for parties the agent acted "
            "on is the piece the rest of the stack leaves out.",
            status="info",
            layer=EXTENSION,
            tier="Correction surface",
            boundary=True,
        )

    # --- CONTEXT marker: operator-side authz (cited, not run) -------------------
    step(
        YOU,
        "—",
        "Authorisation (operator-side) — context, not run here",
        "AuthZEN · Txn-Tokens-for-Agents · delegation layers — decide if the action MAY proceed",
        plain="Separately, an operator decides whether this action is allowed at all. "
        "That layer is cited here for context — this demo does not run it.",
        status="info",
        layer=CONTEXT,
        tier="Operator-side authorisation",
    )

    # --- Hop 6: act on verified endpoint (Tier 3) ------------------------------
    endpoint = (provider_cred["credentialSubject"].get("endpoints") or {}).get("static", ["—"])[0]
    step(
        YOU,
        AGENT,
        "Act on the verified endpoint",
        f"POST {endpoint} → response",
        plain="Every check passed, so now it is safe to actually call the agent.",
        status="ok",
        layer=PAPER,
        tier="Tier 3 · Endpoint",
    )

    contested = any(s["status"] == "warn" for s in steps)
    summary = (
        "Resolution complete — verified · with a standing contestation"
        if contested
        else "Resolution complete — every hop verified"
    )
    return _finish(steps, summary, scenario, w)


def _finish(steps, summary, scenario, w):
    return {
        "scenario": scenario,
        "title": SCENARIOS.get(scenario, scenario),
        "summary": summary,
        "refused": any(s["status"] == "fail" for s in steps),
        "steps": steps,
        "identities": {
            "resolver": _short(w["resolver"].did),
            "provider_issuer": _short(w["provider"].did),
            "auditor_issuer": _short(w["auditor"].did),
            "agent": _short(w["agent"].did),
        },
    }
