"""Step 4 — spoof demo: the client rejects forged AgentFacts credentials.

Two distinct forgeries, both caught at the VC hop, both fail closed:

  1. **Untrusted issuer.** A rogue agent self-issues a perfectly well-formed VC
     from an issuer that is not in the client's trust policy. The signature is
     valid — but the signer is not trusted, so it is rejected.
  2. **Tampered credential.** A genuine VC from a *trusted* issuer is mutated.
     The JWS signature no longer matches, so it is rejected regardless of issuer.

Run via `python -m demo.spoof`.
"""

from __future__ import annotations

from client import console as C
from client.resolver import NandaClient, VerificationFailure
from issuer import issue_provider_credential
from nanda_core import config
from nanda_core.keystore import Identity
from nanda_core.models import AgentFactsSubject, Endpoints, FactsBundle
from nanda_core.trust import TrustPolicy

from . import _common as X


def _register_rogue(name: str, provider_vc: str, agent_did: str, label: str) -> str:
    agent_id = X.new_agent_id()
    bundle = FactsBundle(
        agent_id=agent_id,
        agent_did=agent_did,
        agent_name=name,
        label=label,
        provider_vc=provider_vc,
        auditor_vc=None,
    ).model_dump()
    primary = f"{config.FACTS_PRIMARY_URL}/facts/{agent_id}"
    X.put_json(primary, bundle)
    X.post_json(
        f"{config.INDEX_URL}/register",
        {
            "agent_id": agent_id,
            "agent_name": name,
            "primary_facts_url": primary,
            "ttl": 3600,
        },
    )
    return name


def _expect_rejected(client: NandaClient, name: str, scenario: str) -> bool:
    try:
        client.resolve(name, path="primary", act=False)
        print(C.fail(f"{scenario}: ACCEPTED — security failure!"))
        return False
    except VerificationFailure as exc:
        print(C.ok(f"{scenario}: rejected ({exc})\n"))
        return True


def main() -> None:
    print(C.rule("STEP 4 — spoof: client rejects forged AgentFacts credentials"))
    policy = TrustPolicy.load(config.TRUST_POLICY_PATH)
    client = NandaClient(policy, config.INDEX_URL, verbose=True)
    ok = True

    # Scenario 1 — a valid signature, but from an issuer that is NOT trusted.
    print(C.bold("\nScenario 1 — credential from an untrusted issuer"))
    rogue_issuer = Identity.generate("Rogue Issuer (not in trust policy)")
    rogue_agent = Identity.generate("rogue-agent")
    subject = AgentFactsSubject(
        id=rogue_agent.did,
        agent_name="urn:agent:rogue:translator",
        label="RogueTranslator",
        endpoints=Endpoints(static=[f"{config.AGENT_URL}/agents/translator/invoke"]),
    )
    forged_vc = issue_provider_credential(rogue_issuer, subject)
    name1 = _register_rogue(
        "urn:agent:rogue:translator", forged_vc, rogue_agent.did, "RogueTranslator"
    )
    ok &= _expect_rejected(client, name1, "untrusted-issuer credential")

    # Scenario 2 — a genuine, trusted-issuer credential, then mutated.
    print(C.bold("Scenario 2 — tampered credential from a trusted issuer"))
    genuine_agent = X.load_state()["agents"][0]
    genuine_addr = X.get_json(f"{config.INDEX_URL}/resolve", name=genuine_agent["agent_name"])
    genuine_bundle = X.get_json(genuine_addr["primary_facts_url"])
    head, payload, sig = genuine_bundle["provider_vc"].split(".")
    mid = len(payload) // 2
    tampered_payload = payload[:mid] + ("A" if payload[mid] != "A" else "B") + payload[mid + 1 :]
    tampered_vc = ".".join([head, tampered_payload, sig])
    name2 = _register_rogue(
        "urn:agent:rogue:tampered", tampered_vc, genuine_agent["did"], "TamperedFacts"
    )
    ok &= _expect_rejected(client, name2, "tampered trusted-issuer credential")

    print(
        C.ok(C.bold("spoof demo passed — both forgeries rejected, fail closed"))
        if ok
        else C.fail(C.bold("spoof demo FAILED"))
    )
    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
