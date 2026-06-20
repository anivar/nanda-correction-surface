"""Step 5 — contest: the affected-party half of the trust object (Level 2).

An affected party files a signed counter-claim, bound to a prior interaction the
agent itself acknowledged, and posts it to the facts hosts. The client, on its
next resolution, verifies the contestation's signature and standing and surfaces
it ALONGSIDE the issuers' claims — neither claim silently overrides the other.

Run via `python -m demo.contest`.
"""

from __future__ import annotations

from client import console as C
from client.resolver import NandaClient
from nanda_core import config, contest
from nanda_core.keystore import Identity
from nanda_core.trust import TrustPolicy

from . import _common as X


def main() -> None:
    print(C.rule("STEP 5 — contest: affected party files a signed counter-claim"))
    state = X.load_state()
    # Contest the agent resolved over the privacy path (the summarizer).
    target = next((a for a in state["agents"] if a["path"] == "private"), state["agents"][-1])
    agent = Identity.from_secret_dict(target["secret"])
    party = Identity.generate("Acme Customer #4471")

    print(C.info(f"agent      {target['agent_name']}  ({agent.did})"))
    print(C.info(f"contestant {party.name}  ({party.did})"))
    print()

    # 1. The agent acknowledges it interacted with this party (the standing anchor).
    receipt, interaction_id = contest.mint_interaction_receipt(
        agent, target["agent_id"], party.did, summary="summarisation job #4471"
    )
    print(C.ok("interaction receipt minted (signed by the AGENT's key)"))
    print(C.info(f"interaction_id {interaction_id}"))

    # 2. The affected party files a signed contestation bound to that interaction.
    contestation = contest.file_contestation(
        party,
        agent_id=target["agent_id"],
        agent_did=agent.did,
        interaction_id=interaction_id,
        statement="Returned summary dropped the dispute clause; accuracy SLA breached.",
        category="accuracy-dispute",
        receipt=receipt,
    )
    print(C.ok("contestation filed (signed by the AFFECTED PARTY's key)"))

    # 3. Post it to the facts hosts (it travels with the AgentFacts).
    for base in (config.FACTS_PRIMARY_URL, config.FACTS_NEUTRAL_URL):
        X.post_json(f"{base}/facts/{target['agent_id']}/contestations", contestation)
    print(C.ok("contestation attached at the facts hosts\n"))

    # 4. Re-resolve: the client now surfaces the verified contestation.
    print(C.bold("Re-resolving with the contestation on record:"))
    policy = TrustPolicy.load(config.TRUST_POLICY_PATH)
    client = NandaClient(policy, config.INDEX_URL)
    result = client.resolve(target["agent_name"], path=target["path"], act=False)

    if any(getattr(v, "valid", False) for v in result.contestations):
        print(
            C.ok(
                C.bold(
                    "contest demo passed — counter-claim verified and surfaced "
                    "alongside the issuers' claims"
                )
            )
        )
    else:
        print(C.fail(C.bold("contest demo FAILED — contestation not surfaced")))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
