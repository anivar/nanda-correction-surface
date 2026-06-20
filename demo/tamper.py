"""Step 3 — tamper demo: the client rejects a mutated AgentAddr.

Models an attacker on the path who alters the signed index record — the classic
attack is redirecting the facts pointer to metadata they control. Because the
AgentAddr is a detached Ed25519 signature over the JCS-canonical bytes, the client
recomputes those bytes, the signature no longer matches, and it refuses to
proceed. Run via `python -m demo.tamper`.
"""
from __future__ import annotations

import copy

from nanda_core import config
from nanda_core.trust import TrustPolicy
from client.resolver import NandaClient, VerificationFailure
from client import console as C
from . import _common as X


def _expect_rejected(client: NandaClient, addr: dict, what: str) -> bool:
    try:
        client.verify_agentaddr(addr)
        print(C.fail(f"{what}: ACCEPTED — this is a security failure!"))
        return False
    except VerificationFailure as exc:
        print(C.ok(f"{what}: rejected ({exc})"))
        return True


def main() -> None:
    print(C.rule("STEP 3 — tamper: client rejects a mutated AgentAddr"))
    policy = TrustPolicy.load(config.TRUST_POLICY_PATH)
    state = X.load_state()
    target = state["agents"][0]["agent_name"]
    client = NandaClient(policy, config.INDEX_URL, verbose=False)

    genuine = X.get_json(f"{config.INDEX_URL}/resolve", name=target)
    print(C.info(f"genuine AgentAddr for {target}"))
    print(C.info(f"primary_facts_url = {genuine['primary_facts_url']}"))
    client.verify_agentaddr(genuine)
    print(C.ok("baseline: genuine record verifies"))
    print()

    ok = True

    # 1. Redirect the facts pointer to an attacker-controlled host.
    redirected = copy.deepcopy(genuine)
    redirected["primary_facts_url"] = "http://evil.example/facts"
    print(C.info("attack 1 — redirect primary_facts_url → http://evil.example/facts"))
    ok &= _expect_rejected(client, redirected, "redirected record")

    # 2. Extend the ttl (cache-poisoning style mutation).
    ttl_bumped = copy.deepcopy(genuine)
    ttl_bumped["ttl"] = 99999999
    print(C.info("attack 2 — inflate ttl to 99999999"))
    ok &= _expect_rejected(client, ttl_bumped, "ttl-inflated record")

    # 3. Flip a byte in the signature itself.
    sig_flipped = copy.deepcopy(genuine)
    sig = sig_flipped["proof"]["sig"]
    sig_flipped["proof"]["sig"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    print(C.info("attack 3 — corrupt the signature bytes"))
    ok &= _expect_rejected(client, sig_flipped, "signature-corrupted record")

    print()
    print(C.ok(C.bold("tamper demo passed — every mutation rejected, fail closed"))
          if ok else C.fail(C.bold("tamper demo FAILED")))
    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
