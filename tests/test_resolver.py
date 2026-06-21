"""Integration tests for the full NandaClient.resolve() walk (in-process, no network).

The HTTP hops are stubbed so the test exercises the resolver's verification
orchestration directly: signature pinning, the agent_did binding, issuer trust +
threshold, the auditor/provider subject match, revocation, and fail-closed.
"""

import pytest

from client.resolver import NandaClient, VerificationFailure
from issuer import issue_auditor_credential, issue_provider_credential
from nanda_core import contest, crypto, severance, vc
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
            AUDITOR,
            auditor_subject or AGENT.did,
            Evaluations(performanceScore=4.5),
            {"level": "verified"},
        )
    return FactsBundle(
        agent_id="nanda:x",
        agent_did=AGENT.did,
        agent_name="urn:agent:acme:t",
        label="T",
        provider_vc=provider_vc,
        auditor_vc=auditor_vc,
    ).model_dump()


def _addr() -> dict:
    return sign_agentaddr(
        AgentAddr(
            agent_id="nanda:x",
            agent_name="urn:agent:acme:t",
            agent_did=AGENT.did,
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
    # trust only the auditor; the provider VC's issuer is therefore untrusted.
    # required_issuers is emptied so the policy itself is valid (required ⊆ trusted);
    # the rejection must come from the credential check, not policy construction.
    policy = _policy(trusted_issuers={AUDITOR.did}, required_issuers=set())
    with _client(policy, _addr(), _bundle()) as c:
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


def test_severed_identity_fails_closed():
    # The subject has exited (severance signed by its own key) -> refuse, name successor.
    bundle = _bundle()
    bundle["severance"] = severance.sign_severance(AGENT, "nanda:x", successor_did=OTHER.did)
    with _client(_policy(), _addr(), bundle) as c:
        with pytest.raises(VerificationFailure, match="severed"):
            c.resolve("urn:agent:acme:t", act=False)


def test_invalid_severance_is_ignored():
    # A severance signed by some OTHER identity cannot retire this agent.
    bundle = _bundle()
    bundle["severance"] = severance.sign_severance(OTHER, "nanda:x")
    with _client(_policy(), _addr(), bundle) as c:
        r = c.resolve("urn:agent:acme:t", act=False)
    assert r.provider_credential["credentialSubject"]["id"] == AGENT.did


def test_missing_agent_did_fails_closed():
    # An AgentAddr with no agent_did cannot bind the VC subject or the exit gate,
    # so the client must refuse it rather than silently skip those checks.
    addr = sign_agentaddr(
        AgentAddr(
            agent_id="nanda:x",
            agent_name="urn:agent:acme:t",
            primary_facts_url="http://primary:8000/facts/nanda:x",
        ),
        RESOLVER,
    )
    with _client(_policy(), addr, _bundle()) as c:
        with pytest.raises(VerificationFailure, match="agent_did"):
            c.resolve("urn:agent:acme:t", act=False)


def test_severance_for_other_entry_is_ignored():
    # A severance validly signed by this key, but for a DIFFERENT registry entry,
    # must not retire this one — the agent_id binding stops the cross-entry replay.
    bundle = _bundle()
    bundle["severance"] = severance.sign_severance(AGENT, "nanda:other", successor_did=OTHER.did)
    with _client(_policy(), _addr(), bundle) as c:
        r = c.resolve("urn:agent:acme:t", act=False)
    assert r.provider_credential["credentialSubject"]["id"] == AGENT.did


def test_enterprise_routed_follows_registry():
    addr = sign_agentaddr(
        AgentAddr(
            agent_id="nanda:x",
            agent_name="urn:agent:globex:a",
            agent_did=AGENT.did,
            registration_type="enterprise",
            primary_facts_url="http://primary/facts/nanda:x",
            enterprise_registry_url="http://primary/registry/nanda:x",
        ),
        RESOLVER,
    )
    bundle = _bundle()
    c = NandaClient(_policy(), "http://index", verbose=False)

    def fake_get(url, *, params=None, what="resource"):
        if "/resolve" in url:
            return addr
        if "/registry/" in url:
            return {"facts_url": "http://primary/facts/nanda:x"}
        return bundle

    c._get_json = fake_get
    with c:
        r = c.resolve("urn:agent:globex:a", act=False)
    assert r.facts_host_role == "enterprise"


def test_live_revocation_list_fails_closed():
    bundle = _bundle()
    cred = vc.verify_credential(bundle["provider_vc"], trusted_issuers={PROVIDER.did})
    cid = cred["id"]
    sig = crypto.b64u_encode(PROVIDER.sign(cid.encode()))  # issuer signs its own credential id
    c = NandaClient(
        _policy(), "http://index", revocation_url="http://index/revocations", verbose=False
    )

    def fake_get(url, *, params=None, what="resource"):
        if "/revocations" in url:
            return {
                "revoked": [{"credential_id": cid, "issuer_did": PROVIDER.did, "signature": sig}]
            }
        if "/resolve" in url:
            return _addr()
        return bundle

    c._get_json = fake_get
    with c:
        with pytest.raises(VerificationFailure, match="revoked"):
            c.resolve("urn:agent:acme:t", act=False)


def test_revocation_by_untrusted_issuer_is_ignored():
    # A revocation signed by a NON-trusted issuer (or for the wrong issuer) is ignored.
    bundle = _bundle()
    cred = vc.verify_credential(bundle["provider_vc"], trusted_issuers={PROVIDER.did})
    cid = cred["id"]
    sig = crypto.b64u_encode(OTHER.sign(cid.encode()))  # OTHER is not a trusted issuer
    c = NandaClient(
        _policy(), "http://index", revocation_url="http://index/revocations", verbose=False
    )

    def fake_get(url, *, params=None, what="resource"):
        if "/revocations" in url:
            return {"revoked": [{"credential_id": cid, "issuer_did": OTHER.did, "signature": sig}]}
        if "/resolve" in url:
            return _addr()
        return bundle

    c._get_json = fake_get
    with c:
        r = c.resolve("urn:agent:acme:t", act=False)  # not revoked -> resolves
    assert r.provider_credential["credentialSubject"]["id"] == AGENT.did


def test_contestations_surfaced_and_deduped():
    # A valid contestation is surfaced once even when duplicated; an id-less one is dropped.
    party = Identity.generate("affected party")
    receipt, iid = contest.mint_interaction_receipt(AGENT, "nanda:x", party.did, "job #1")
    c1 = contest.file_contestation(
        party,
        agent_id="nanda:x",
        agent_did=AGENT.did,
        interaction_id=iid,
        statement="output dropped the dispute clause",
        receipt=receipt,
    )
    bundle = _bundle()
    bundle["contestations"] = [c1, dict(c1), {"statement": "no id, must be dropped"}]
    with _client(_policy(), _addr(), bundle) as c:
        r = c.resolve("urn:agent:acme:t", act=False)
    assert len(r.contestations) == 1
    assert r.contestations[0].contestant == party.did


def test_live_revocation_by_trusted_non_issuer_is_ignored():
    # A revocation signed by a TRUSTED issuer that did NOT issue the credential must
    # not revoke it: only the credential's own issuer can revoke (own-issuer match).
    bundle = _bundle()
    cred = vc.verify_credential(bundle["provider_vc"], trusted_issuers={PROVIDER.did})
    cid = cred["id"]
    sig = crypto.b64u_encode(AUDITOR.sign(cid.encode()))  # AUDITOR is trusted but not the issuer
    c = NandaClient(
        _policy(), "http://index", revocation_url="http://index/revocations", verbose=False
    )

    def fake_get(url, *, params=None, what="resource"):
        if "/revocations" in url:
            return {
                "revoked": [{"credential_id": cid, "issuer_did": AUDITOR.did, "signature": sig}]
            }
        if "/resolve" in url:
            return _addr()
        return bundle

    c._get_json = fake_get
    with c:
        r = c.resolve("urn:agent:acme:t", act=False)  # non-issuer revocation ignored -> resolves
    assert r.provider_credential["credentialSubject"]["id"] == AGENT.did


def test_stale_agentaddr_warns_not_fails():
    # ttl freshness is warn-only (staleness is a cache concern, not tampering):
    # a signed-but-stale AgentAddr must still resolve, not fail closed.
    stale = sign_agentaddr(
        AgentAddr(
            agent_id="nanda:x",
            agent_name="urn:agent:acme:t",
            agent_did=AGENT.did,
            primary_facts_url="http://primary:8000/facts/nanda:x",
            private_facts_url="http://neutral:8000/facts/nanda:x",
            issued_at="2000-01-01T00:00:00Z",
            ttl=1,
        ),
        RESOLVER,
    )
    with _client(_policy(), stale, _bundle()) as c:
        r = c.resolve("urn:agent:acme:t", act=False)
    assert r.provider_credential["credentialSubject"]["id"] == AGENT.did
