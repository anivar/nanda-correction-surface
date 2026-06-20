"""Step 6 — exit: self-sovereign severance (key rotation).

The agent retires its own identity *with its own key*, rendering prior delegated
authority **inexecutable** — no issuer or registry is petitioned, because a
`did:key` has no upstream endpoint to ask. It names a successor identity and
continues to participate on fair terms. Run via `python -m demo.exit`.
"""

from __future__ import annotations

from client import console as C
from client.resolver import NandaClient, VerificationFailure
from nanda_core import config, severance
from nanda_core.keystore import Identity
from nanda_core.trust import TrustPolicy

from . import _common as X


def _register(
    agent: Identity, agent_id: str, name: str, provider: Identity, auditor: Identity
) -> None:
    bundle = X.build_bundle(
        agent,
        agent_id=agent_id,
        agent_name=name,
        label="ExitableAgent",
        slug="translator",
        provider=provider,
        auditor=auditor,
    )
    primary, private = X.host_bundle(agent_id, bundle)
    X.post_json(
        f"{config.INDEX_URL}/register",
        {
            "agent_id": agent_id,
            "agent_name": name,
            "agent_did": agent.did,
            "primary_facts_url": primary,
            "private_facts_url": private,
            "ttl": 3600,
        },
    )


def main() -> None:
    print(C.rule("STEP 6 — exit: self-sovereign severance (key rotation)"))
    provider, auditor = X.load_issuers()
    policy = TrustPolicy.load(config.TRUST_POLICY_PATH)
    client = NandaClient(policy, config.INDEX_URL, verbose=False)

    # 1. Identity v1 registers and resolves cleanly.
    v1 = Identity.generate("exitable v1")
    id1, name = X.new_agent_id(), "urn:agent:acme:exitable"
    _register(v1, id1, name, provider, auditor)
    client.resolve(name, act=False)
    print(C.ok(f"v1 resolves — agent_did {v1.did}\n"))

    # 2. Key rotation: a successor identity v2 registers under a new name.
    v2 = Identity.generate("exitable v2")
    id2, name2 = X.new_agent_id(), "urn:agent:acme:exitable-v2"
    _register(v2, id2, name2, provider, auditor)
    print(C.ok(f"successor identity registered — agent_did {v2.did}"))

    # 3. v1 severs ITSELF, signed by its own key, naming v2 as successor.
    sev = severance.sign_severance(v1, id1, successor_did=v2.did, reason="key rotation")
    X.post_json(f"{config.FACTS_PRIMARY_URL}/facts/{id1}/severance", sev)
    X.post_json(f"{config.FACTS_NEUTRAL_URL}/facts/{id1}/severance", sev)
    print(C.ok("severance filed — signed by v1's own key, no issuer asked\n"))

    # 4. Resolving v1 now fails closed: prior authority is inexecutable.
    print(C.bold("Re-resolving the severed identity:"))
    client.verbose = True
    try:
        client.resolve(name, act=False)
        print(C.fail("severed identity still resolved — FAILURE"))
        raise SystemExit(1)
    except VerificationFailure as exc:
        print(C.ok(f"refused: {exc}\n"))

    # 5. The successor resolves and continues — participation on fair terms.
    print(C.bold("Resolving the successor identity:"))
    client.resolve(name2, act=False)
    print(
        C.ok(
            C.bold(
                "exit demo passed — prior authority inexecutable; "
                "agent continues under a successor identity"
            )
        )
    )


if __name__ == "__main__":
    main()
