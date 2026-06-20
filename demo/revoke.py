"""Step 8 — revocation: the client refuses a revoked credential (VC-Status-List stub).

The client refreshes the revocation set at resolve time (revocation is dynamic
state, unlike the pinned trust anchors). Run via `python -m demo.revoke`.
"""

from __future__ import annotations

import jwt as pyjwt

from client import console as C
from client.resolver import NandaClient, VerificationFailure
from nanda_core import config
from nanda_core.keystore import Identity
from nanda_core.trust import TrustPolicy

from . import _common as X


def main() -> None:
    print(C.rule("STEP 8 — revocation: client refuses a revoked credential"))
    provider, auditor = X.load_issuers()
    policy = TrustPolicy.load(config.TRUST_POLICY_PATH)
    client = NandaClient(
        policy, config.INDEX_URL, revocation_url=f"{config.INDEX_URL}/revocations", verbose=False
    )

    agent = Identity.generate("revocable agent")
    aid, name = X.new_agent_id(), "urn:agent:acme:revocable"
    bundle = X.build_bundle(
        agent,
        agent_id=aid,
        agent_name=name,
        label="RevocableAgent",
        slug="translator",
        provider=provider,
        auditor=auditor,
    )
    primary, private = X.host_bundle(aid, bundle)
    X.post_json(
        f"{config.INDEX_URL}/register",
        {
            "agent_id": aid,
            "agent_name": name,
            "agent_did": agent.did,
            "primary_facts_url": primary,
            "private_facts_url": private,
            "ttl": 3600,
        },
    )
    client.resolve(name, act=False)
    print(C.ok("baseline: resolves before revocation\n"))

    # Revoke the provider credential by its id (read unverified, just to get the id).
    cred_id = pyjwt.decode(bundle["provider_vc"], options={"verify_signature": False})["id"]
    X.post_json(f"{config.INDEX_URL}/revoke", {"credential_id": cred_id})
    print(C.ok(f"revoked provider credential {cred_id}"))

    print(C.bold("\nRe-resolving after revocation:"))
    try:
        client.resolve(name, act=False)
        print(C.fail("revoked credential still accepted — FAILURE"))
        raise SystemExit(1)
    except VerificationFailure as exc:
        print(C.ok(f"refused: {exc}"))
    print(C.ok(C.bold("revocation demo passed — live status check, fail closed")))


if __name__ == "__main__":
    main()
