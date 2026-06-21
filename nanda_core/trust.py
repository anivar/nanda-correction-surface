"""Client trust policy — what a client pins, out-of-band, before it resolves anything.

The paper describes federated trust zones whose roots cross-sign. We model the
client-facing half of that as one explicit, inspectable object:

  - `resolver_did`    : the single index-resolver key the client will accept for
                        an AgentAddr signature. Pinning this is what stops an
                        attacker from re-signing a redirected record with their
                        own key — a valid signature is not enough; it must be the
                        *expected* signer.
  - `trusted_issuers` : the VC issuer DIDs the client accepts (provider, auditor…).
  - `required_issuers`: the threshold — issuers that MUST have signed for the
                        facts to count. Here: the provider is required, the
                        auditor is corroboration.
  - `revoked`         : stubbed revocation set (credential ids / status ids). A
                        production build would query a Bitstring Status List.

The policy is established at setup (the demo writes it) and loaded by the client.
The client never fetches its trust anchors at resolve time — that would defeat them.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


@dataclass
class TrustPolicy:
    resolver_did: str
    trusted_issuers: set[str] = field(default_factory=set)
    required_issuers: set[str] = field(default_factory=set)
    revoked: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        # A required issuer the client does not also trust can never be satisfied,
        # which would make every resolution fail closed for an opaque reason. Catch
        # that misconfiguration at construction, not at the first resolve.
        extra = self.required_issuers - self.trusted_issuers
        if extra:
            raise ValueError(f"required_issuers not all in trusted_issuers: {sorted(extra)}")

    def is_revoked(self, credential: dict) -> bool:
        # A credential carrying neither an id nor a credentialStatus.id cannot be
        # pinned in this static set, so it is unrevocable via this path; the live,
        # issuer-signed revocation list in the resolver is the dynamic complement.
        cid = credential.get("id")
        sid = (credential.get("credentialStatus") or {}).get("id")
        return cid in self.revoked or sid in self.revoked

    def to_dict(self) -> dict:
        return {
            "resolver_did": self.resolver_did,
            "trusted_issuers": sorted(self.trusted_issuers),
            "required_issuers": sorted(self.required_issuers),
            "revoked": sorted(self.revoked),
        }

    @classmethod
    def from_dict(cls, d: dict) -> TrustPolicy:
        return cls(
            resolver_did=d["resolver_did"],
            trusted_issuers=set(d.get("trusted_issuers", [])),
            required_issuers=set(d.get("required_issuers", [])),
            revoked=set(d.get("revoked", [])),
        )

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    @classmethod
    def load(cls, path: str) -> TrustPolicy:
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))
