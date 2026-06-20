"""Build and issue the two AgentFacts credentials.

This is where the multi-issuer trust model is made concrete:

  - the **provider** self-asserts the agent's facts (identity, endpoints, skills);
  - an independent **auditor** attests to the agent's evaluations and certifies it.

Both are W3C VCs signed by distinct did:key issuers, so a client can require the
provider claim and treat the auditor claim as independent corroboration — or
demand both. The host serving them is irrelevant to either signature.
"""

from __future__ import annotations

from nanda_core import vc
from nanda_core.keystore import Identity
from nanda_core.models import AgentFactsSubject, Evaluations

AGENTFACTS_TYPE = "AgentFactsCredential"
AUDIT_TYPE = "AgentAuditCredential"


def issue_provider_credential(
    provider: Identity, subject: AgentFactsSubject, *, validity_days: int = 365
) -> str:
    """Provider self-asserts the full AgentFacts about its agent."""
    claims = subject.model_dump(exclude={"id"}, exclude_none=True)
    return vc.issue_credential(
        issuer=provider,
        subject_id=subject.id,
        claims=claims,
        extra_types=[AGENTFACTS_TYPE],
        validity_days=validity_days,
    )


def issue_auditor_credential(
    auditor: Identity,
    agent_did: str,
    evaluations: Evaluations,
    certification: dict,
    *,
    validity_days: int = 365,
) -> str:
    """An independent auditor attests to the agent's evaluations and certifies it.
    Signed by the auditor's own key — its trust does not flow through the provider
    or the host."""
    claims = {
        "evaluations": evaluations.model_dump(exclude_none=True),
        "certification": certification,
    }
    return vc.issue_credential(
        issuer=auditor,
        subject_id=agent_did,
        claims=claims,
        extra_types=[AUDIT_TYPE],
        validity_days=validity_days,
    )
