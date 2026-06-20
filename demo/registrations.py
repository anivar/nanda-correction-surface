"""Step 7 — registration-type mixing: native + enterprise-routed + DID-based.

The brief notes mixing registration types belongs in Level 2. The index is a quilt
(paper Table 1): a NANDA-native entry points straight at the facts; an
enterprise-routed entry takes one extra hop through a registry; a DID-based entry
is resolved by the agent's own DID. Run via `python -m demo.registrations`.
"""

from __future__ import annotations

from client import console as C
from client.resolver import NandaClient
from nanda_core import config
from nanda_core.keystore import Identity
from nanda_core.trust import TrustPolicy

from . import _common as X


def main() -> None:
    print(C.rule("STEP 7 — registration types: native | enterprise-routed | DID-based"))
    provider, auditor = X.load_issuers()
    policy = TrustPolicy.load(config.TRUST_POLICY_PATH)
    client = NandaClient(policy, config.INDEX_URL)

    # Enterprise-routed: index -> enterprise registry -> facts (one extra hop).
    ent = Identity.generate("enterprise agent")
    ent_id, ent_name = X.new_agent_id(), "urn:agent:globex:assistant"
    bundle = X.build_bundle(
        ent,
        agent_id=ent_id,
        agent_name=ent_name,
        label="GlobexAssistant",
        slug="summarizer",
        provider=provider,
        auditor=auditor,
    )
    primary, _ = X.host_bundle(ent_id, bundle)
    X.post_json(
        f"{config.INDEX_URL}/register",
        {
            "agent_id": ent_id,
            "agent_name": ent_name,
            "agent_did": ent.did,
            "registration_type": "enterprise",
            "enterprise_registry_url": f"{config.FACTS_PRIMARY_URL}/registry/{ent_id}",
            "primary_facts_url": primary,
            "ttl": 3600,
        },
    )
    print(C.bold("\nEnterprise-routed (resolved via a registry indirection):"))
    client.resolve(ent_name, act=False)

    # DID-based: the agent's NAME is its own DID — identity is the anchor.
    did_agent = Identity.generate("did agent")
    did_id = X.new_agent_id()
    did_name = did_agent.did
    bundle2 = X.build_bundle(
        did_agent,
        agent_id=did_id,
        agent_name=did_name,
        label="DidAgent",
        slug="translator",
        provider=provider,
        auditor=auditor,
    )
    p2, pr2 = X.host_bundle(did_id, bundle2)
    X.post_json(
        f"{config.INDEX_URL}/register",
        {
            "agent_id": did_id,
            "agent_name": did_name,
            "agent_did": did_agent.did,
            "registration_type": "did",
            "primary_facts_url": p2,
            "private_facts_url": pr2,
            "ttl": 3600,
        },
    )
    print(C.bold("DID-based (resolved by the agent's own DID):"))
    client.resolve(did_name, act=False)

    print(C.ok(C.bold("registration-type demo passed — native + enterprise-routed + DID-based")))


if __name__ == "__main__":
    main()
