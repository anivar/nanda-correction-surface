"""Step 1 — register two agents end-to-end.

Creates the issuers (provider + independent auditor), and for each agent:
  1. mints the agent's own did:key identity,
  2. builds its AgentFacts and issues a provider VC and an auditor VC,
  3. hosts the bundle on BOTH facts hosts (so either resolution path works),
  4. registers it in the lean index, which returns a signed AgentAddr.

Finally it writes the client trust policy (pinning the resolver + the two issuer
DIDs) and the demo state. Run via `python -m demo.register`.
"""

from __future__ import annotations

from client import console as C
from issuer import issue_auditor_credential, issue_provider_credential
from nanda_core import config
from nanda_core.keystore import Identity
from nanda_core.models import (
    AgentFactsSubject,
    Authentication,
    Capabilities,
    Endpoints,
    Evaluations,
    FactsBundle,
    Provider,
    Skill,
)
from nanda_core.trust import TrustPolicy

from . import _common as X


def _build_subject(agent: Identity, spec: dict, provider: Identity) -> AgentFactsSubject:
    slug = spec["slug"]
    return AgentFactsSubject(
        id=agent.did,
        agent_name=spec["agent_name"],
        label=spec["label"],
        description=spec["description"],
        version=spec["version"],
        jurisdiction=spec.get("jurisdiction"),
        provider=Provider(name="ACME Corp", url="https://acme.example", did=provider.did),
        endpoints=Endpoints(static=[f"{config.AGENT_URL}/agents/{slug}/invoke"]),
        capabilities=Capabilities(
            modalities=spec["modalities"],
            streaming=spec["streaming"],
            authentication=Authentication(
                methods=spec["auth_methods"], requiredScopes=spec["scopes"]
            ),
        ),
        skills=[Skill(**s) for s in spec["skills"]],
        evaluations=Evaluations(**spec["evaluations"]),
    )


def main() -> dict:
    config.ensure_shared_dir()
    print(C.rule("STEP 1 — register two agents (index + AgentFacts + VCs)"))

    # Issuers: provider self-asserts; an independent auditor attests + certifies.
    provider = Identity.generate("ACME Provider")
    auditor = Identity.generate("ACME Independent Audits")
    print(C.info(f"provider issuer  {provider.did}"))
    print(C.info(f"auditor issuer   {auditor.did}"))

    resolver = X.get_json(f"{config.INDEX_URL}/resolver")
    print(C.info(f"index resolver   {resolver['did']}"))
    print()

    agents_state = []
    for spec in X.AGENTS:
        agent = Identity.generate(spec["slug"])
        agent_id = X.new_agent_id()
        subject = _build_subject(agent, spec, provider)

        provider_vc = issue_provider_credential(provider, subject)
        certification = {"level": "verified", "issuer": "ACME Independent Audits"}
        auditor_vc = issue_auditor_credential(
            auditor, agent.did, Evaluations(**spec["evaluations"]), certification
        )

        bundle = FactsBundle(
            agent_id=agent_id,
            agent_did=agent.did,
            agent_name=spec["agent_name"],
            label=spec["label"],
            provider_vc=provider_vc,
            auditor_vc=auditor_vc,
        ).model_dump()

        # Host on BOTH facts hosts: provider domain and neutral host.
        primary_url = f"{config.FACTS_PRIMARY_URL}/facts/{agent_id}"
        private_url = f"{config.FACTS_NEUTRAL_URL}/facts/{agent_id}"
        X.put_json(primary_url, bundle)
        X.put_json(private_url, bundle)

        # Register in the lean index -> signed AgentAddr.
        signed_addr = X.post_json(
            f"{config.INDEX_URL}/register",
            {
                "agent_id": agent_id,
                "agent_name": spec["agent_name"],
                "primary_facts_url": primary_url,
                "private_facts_url": private_url,
                "ttl": 3600,
            },
        )

        print(C.ok(f"registered {spec['agent_name']}"))
        print(C.info(f"agent_id   {agent_id}"))
        print(C.info(f"agent did  {agent.did}"))
        print(C.info(f"resolve via {spec['path']} path"))
        print()

        agents_state.append(
            {
                "agent_id": agent_id,
                "agent_name": spec["agent_name"],
                "label": spec["label"],
                "slug": spec["slug"],
                "did": agent.did,
                "path": spec["path"],
                "secret": agent.to_secret_dict(),  # for the contestation step (shared/ only)
                "addr_proof_signer": signed_addr["proof"]["verificationMethod"],
            }
        )

    # Client trust policy: pin the resolver + both issuers; provider is required.
    policy = TrustPolicy(
        resolver_did=resolver["did"],
        trusted_issuers={provider.did, auditor.did},
        required_issuers={provider.did},
    )
    policy.save(config.TRUST_POLICY_PATH)
    print(C.ok(f"trust policy written → {config.TRUST_POLICY_PATH}"))
    print(C.info(f"resolver pinned   {policy.resolver_did}"))
    print(C.info(f"trusted issuers   {sorted(policy.trusted_issuers)}"))
    print(C.info(f"required issuers  {sorted(policy.required_issuers)}"))

    state = {
        "agents": agents_state,
        "issuers": {"provider": provider.did, "auditor": auditor.did},
    }
    X.save_state(state)
    print(C.ok(f"demo state written → {config.DEMO_STATE_PATH}\n"))
    return state


if __name__ == "__main__":
    main()
