"""Tests for the Tier-2 Verifiable Credential layer (JWT-VC / vc-jose-cose)."""

import datetime as dt

import jwt as pyjwt
import pytest

from issuer import issue_auditor_credential, issue_provider_credential
from nanda_core import vc
from nanda_core.keystore import Identity
from nanda_core.models import AgentFactsSubject, Evaluations


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
    far_future = dt.datetime.now(dt.UTC) + dt.timedelta(days=10)
    with pytest.raises(vc.VCError, match="expired"):
        vc.verify_credential(token, trusted_issuers={provider.did}, now=far_future)
    far_past = dt.datetime.now(dt.UTC) - dt.timedelta(days=10)
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


def _raw_vc(issuer: Identity, *, typ: str, with_until: bool) -> str:
    payload = {
        "@context": [vc.VC_CONTEXT_V2],
        "type": ["VerifiableCredential"],
        "issuer": issuer.did,
        "validFrom": "2020-01-01T00:00:00Z",
        "credentialSubject": {"id": issuer.did},
    }
    if with_until:
        payload["validUntil"] = "2999-01-01T00:00:00Z"
    return pyjwt.encode(
        payload,
        issuer.private_key,
        algorithm="EdDSA",
        headers={"typ": typ, "kid": issuer.verification_method},
    )


def test_non_vc_jwt_rejected_by_typ():
    # A JWT from a trusted issuer but typed as a plain JWT must not pass as a VC.
    issuer = Identity.generate("provider")
    token = _raw_vc(issuer, typ="JWT", with_until=True)
    with pytest.raises(vc.VCError, match="token type"):
        vc.verify_credential(token, trusted_issuers={issuer.did})


def test_unbounded_credential_rejected():
    # Missing validUntil -> rejected by our bounded-validity policy.
    issuer = Identity.generate("provider")
    token = _raw_vc(issuer, typ=vc.JWT_VC_TYP, with_until=False)
    with pytest.raises(vc.VCError, match="validUntil"):
        vc.verify_credential(token, trusted_issuers={issuer.did})


def test_missing_kid_rejected():
    issuer = Identity.generate("provider")
    payload = {
        "@context": [vc.VC_CONTEXT_V2],
        "type": ["VerifiableCredential"],
        "issuer": issuer.did,
        "validFrom": "2020-01-01T00:00:00Z",
        "validUntil": "2999-01-01T00:00:00Z",
        "credentialSubject": {"id": issuer.did},
    }
    token = pyjwt.encode(
        payload, issuer.private_key, algorithm="EdDSA", headers={"typ": vc.JWT_VC_TYP}
    )
    with pytest.raises(vc.VCError, match="no kid"):
        vc.verify_credential(token, trusted_issuers={issuer.did})


def test_issuer_kid_mismatch_rejected():
    # Signed by A (kid=A), but payload claims issuer=B -> rejected even though the
    # signature is valid for A's key and A is trusted.
    a = Identity.generate("issuer-a")
    b = Identity.generate("issuer-b")
    payload = {
        "@context": [vc.VC_CONTEXT_V2],
        "type": ["VerifiableCredential"],
        "issuer": b.did,
        "validFrom": "2020-01-01T00:00:00Z",
        "validUntil": "2999-01-01T00:00:00Z",
        "credentialSubject": {"id": b.did},
    }
    token = pyjwt.encode(
        payload,
        a.private_key,
        algorithm="EdDSA",
        headers={"typ": vc.JWT_VC_TYP, "kid": a.verification_method},
    )
    with pytest.raises(vc.VCError, match="does not match"):
        vc.verify_credential(token, trusted_issuers={a.did, b.did})


def test_unparseable_validity_date_raises_vcerror():
    issuer = Identity.generate("provider")
    payload = {
        "@context": [vc.VC_CONTEXT_V2],
        "type": ["VerifiableCredential"],
        "issuer": issuer.did,
        "validFrom": "2020-01-01T00:00:00Z",
        "validUntil": "not-a-date",
        "credentialSubject": {"id": issuer.did},
    }
    token = pyjwt.encode(
        payload,
        issuer.private_key,
        algorithm="EdDSA",
        headers={"typ": vc.JWT_VC_TYP, "kid": issuer.verification_method},
    )
    with pytest.raises(vc.VCError, match="unparseable validity date"):
        vc.verify_credential(token, trusted_issuers={issuer.did})
