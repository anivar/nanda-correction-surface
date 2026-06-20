"""Step 2 — resolve both agents as a client.

Loads the pinned trust policy and walks the full resolution path for each agent,
verifying and printing every hop, then acting on the verified endpoint. One agent
is resolved via the provider (primary) path, the other via the neutral (privacy)
path. Run via `python -m demo.resolve`.
"""

from __future__ import annotations

from client import console as C
from client.resolver import NandaClient
from nanda_core import config
from nanda_core.trust import TrustPolicy

from . import _common as X


def main() -> None:
    print(C.rule("STEP 2 — resolve agents as a client (verify every hop)"))
    policy = TrustPolicy.load(config.TRUST_POLICY_PATH)
    state = X.load_state()
    client = NandaClient(policy, config.INDEX_URL)
    for a in state["agents"]:
        client.resolve(a["agent_name"], path=a["path"], act=True)


if __name__ == "__main__":
    main()
