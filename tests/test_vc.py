"""Tests for the Tier-2 Verifiable Credential layer (JWT-VC / vc-jose-cose)."""
import datetime as dt

import pytest

from nanda_core import vc
from nanda_core.keystore import Identity
from nanda_core.models import AgentFactsSubject, Evaluations
from issuer import issue_provider_credential, issue_auditor_credential


def _subject(agent_did: str) -> AgentFactsSubject:
    return AgentFactsSubject(
        id=agent_did,
        agent_name="urn:agent:acme:translator",
        label="TranslationAssistant",
        version="1.2.1",
    )


def test_provider_credential_verifies_and_carries_subject():
    provider = Identity.generate("provider")
    agent = Identity.generate("agent")
    token = issue_provider_credential(provider, _subject(agent.did))

    cred = vc.verify_credential(token, trusted_issuers={provider.did})
    assert cred["issuer"] == provider.did
    assert cred["credentialSubject"]["id"] == agent.did
    assert cred["credentialSubject"]["agent_name"] == "urn:agent:acme:translator"
    assert "AgentFactsCredential" in cred["type"]


def test_untrusted_issuer_is_rejected():
    provider = Identity.generate("provider")
    agent = Identity.generate("agent")
    token = issue_provider_credential(provider, _subject(agent.did))
    with pytest.raises(vc.VCError, match="not in trust policy"):
        vc.verify_credential(token, trusted_issuers={"did:key:z6MkSomeoneElse"})


def test_tampered_token_is_rejected():
    provider = Identity.generate("provider")
    agent = Identity.generate("agent")
    token = issue_provider_credential(provider, _subject(agent.did))
    head, payload, sig = token.split(".")
    forged = ".".join([head, payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB"), sig])
    with pytest.raises(vc.VCError):
        vc.verify_credential(forged, trusted_issuers={provider.did})


def test_expired_and_not_yet_valid():
    provider = Identity.generate("provider")
    agent = Identity.generate("agent")
    token = issue_provider_credential(provider, _subject(agent.did), validity_days=1)
    far_future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=10)
    with pytest.raises(vc.VCError, match="expired"):
        vc.verify_credential(token, trusted_issuers={provider.did}, now=far_future)
    far_past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=10)
    with pytest.raises(vc.VCError, match="not yet valid"):
        vc.verify_credential(token, trusted_issuers={provider.did}, now=far_past)


def test_auditor_credential_is_independent():
    auditor = Identity.generate("auditor")
    agent = Identity.generate("agent")
    token = issue_auditor_credential(
        auditor,
        agent.did,
        Evaluations(performanceScore=4.8, availability90d="99.9%", auditorID="Audit v2.1"),
        {"level": "verified", "issuer": "ACME Audits"},
    )
    cred = vc.verify_credential(token, trusted_issuers={auditor.did})
    assert cred["issuer"] == auditor.did
    assert cred["credentialSubject"]["evaluations"]["performanceScore"] == 4.8
    assert "AgentAuditCredential" in cred["type"]
