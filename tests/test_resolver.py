"""Integration tests for the full NandaClient.resolve() walk (in-process, no network).

The HTTP hops are stubbed so the test exercises the resolver's verification
orchestration directly: signature pinning, the agent_did binding, issuer trust +
threshold, the auditor/provider subject match, revocation, and fail-closed.
"""
import pytest

from client.resolver import NandaClient, VerificationFailure
from issuer import issue_auditor_credential, issue_provider_credential
from nanda_core import vc
from nanda_core.keystore import Identity
from nanda_core.models import (
    AgentAddr,
    AgentFactsSubject,
    Endpoints,
    Evaluations,
    FactsBundle,
    sign_agentaddr,
)
from nanda_core.trust import TrustPolicy

RESOLVER = Identity.generate("resolver")
PROVIDER = Identity.generate("provider")
AUDITOR = Identity.generate("auditor")
AGENT = Identity.generate("agent")
OTHER = Identity.generate("other-agent")


def _bundle(*, provider_subject=None, auditor_subject=None, with_auditor=True) -> dict:
    subject = AgentFactsSubject(
        id=provider_subject or AGENT.did,
        agent_name="urn:agent:acme:t",
        label="T",
        endpoints=Endpoints(static=["http://agent:8000/agents/translator/invoke"]),
    )
    provider_vc = issue_provider_credential(PROVIDER, subject)
    auditor_vc = None
    if with_auditor:
        auditor_vc = issue_auditor_credential(
            AUDITOR, auditor_subject or AGENT.did,
            Evaluations(performanceScore=4.5), {"level": "verified"},
        )
    return FactsBundle(
        agent_id="nanda:x", agent_did=AGENT.did, agent_name="urn:agent:acme:t",
        label="T", provider_vc=provider_vc, auditor_vc=auditor_vc,
    ).model_dump()


def _addr() -> dict:
    return sign_agentaddr(
        AgentAddr(
            agent_id="nanda:x", agent_name="urn:agent:acme:t", agent_did=AGENT.did,
            primary_facts_url="http://primary:8000/facts/nanda:x",
            private_facts_url="http://neutral:8000/facts/nanda:x",
        ),
        RESOLVER,
    )


def _policy(**over) -> TrustPolicy:
    base = dict(
        resolver_did=RESOLVER.did,
        trusted_issuers={PROVIDER.did, AUDITOR.did},
        required_issuers={PROVIDER.did},
    )
    base.update(over)
    return TrustPolicy(**base)


def _client(policy, addr, bundle) -> NandaClient:
    c = NandaClient(policy, "http://index:8000", verbose=False)

    def fake_get(url, *, params=None, what="resource"):
        return addr if "/resolve" in url else bundle

    c._get_json = fake_get
    return c


def test_happy_primary_path():
    with _client(_policy(), _addr(), _bundle()) as c:
        r = c.resolve("urn:agent:acme:t", path="primary", act=False)
    assert r.facts_host_role == "primary"
    assert r.provider_credential["credentialSubject"]["id"] == AGENT.did
    assert r.auditor_credential is not None


def test_happy_private_path_uses_neutral_host():
    with _client(_policy(), _addr(), _bundle()) as c:
        r = c.resolve("urn:agent:acme:t", path="private", act=False)
    assert r.facts_host_role == "neutral"


def test_wrong_resolver_pin_fails_closed():
    with _client(_policy(resolver_did="did:key:z6MkWrong"), _addr(), _bundle()) as c:
        with pytest.raises(VerificationFailure, match="pinned resolver"):
            c.resolve("urn:agent:acme:t", act=False)


def test_untrusted_issuer_fails_closed():
    with _client(_policy(trusted_issuers={AUDITOR.did}), _addr(), _bundle()) as c:
        with pytest.raises(VerificationFailure):
            c.resolve("urn:agent:acme:t", act=False)


def test_threshold_not_met_fails_closed():
    policy = _policy(required_issuers={AUDITOR.did})
    with _client(policy, _addr(), _bundle(with_auditor=False)) as c:
        with pytest.raises(VerificationFailure, match="required issuers"):
            c.resolve("urn:agent:acme:t", act=False)


def test_agent_did_binding_rejects_substituted_vc():
    # Host serves a validly-issued VC, but for a DIFFERENT agent than AgentAddr names.
    with _client(_policy(), _addr(), _bundle(provider_subject=OTHER.did)) as c:
        with pytest.raises(VerificationFailure, match="does not match the signed AgentAddr"):
            c.resolve("urn:agent:acme:t", act=False)


def test_auditor_subject_must_match_provider():
    with _client(_policy(), _addr(), _bundle(auditor_subject=OTHER.did)) as c:
        with pytest.raises(VerificationFailure, match="different subject"):
            c.resolve("urn:agent:acme:t", act=False)


def test_revoked_credential_fails_closed():
    bundle = _bundle()
    cred = vc.verify_credential(bundle["provider_vc"], trusted_issuers={PROVIDER.did})
    with _client(_policy(revoked={cred["id"]}), _addr(), bundle) as c:
        with pytest.raises(VerificationFailure, match="revoked"):
            c.resolve("urn:agent:acme:t", act=False)
